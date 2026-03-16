//! SSH-specific ChaCha20-Poly1305 implementation
//!
//! Implements the chacha20-poly1305@openssh.com cipher as defined in
//! the OpenSSH source code. This is NOT the standard RFC 8439 AEAD -
//! it uses two separate ChaCha20 keys and a custom Poly1305 key derivation.

use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::{Poly1305, universal_hash::{UniversalHash, KeyInit}};

/// Tag size for Poly1305
pub const TAG_SIZE: usize = 16;

/// Construct an 8-byte ChaCha20 nonce from the sequence number.
/// OpenSSH uses the original DJB ChaCha20 with 8-byte nonce (not IETF 12-byte).
fn ssh_nonce(sequence_number: u64) -> [u8; 8] {
    sequence_number.to_be_bytes()
}

/// Encrypt a packet using SSH's chacha20-poly1305@openssh.com.
///
/// * `key` - 64-byte key: first 32 bytes = main key, last 32 bytes = header key
/// * `sequence_number` - packet sequence number (used as nonce)
/// * `packet_length` - 4-byte big-endian packet length
/// * `payload` - padding_length + payload + padding (NOT including the length field)
///
/// Returns: encrypted_length(4B) + encrypted_payload + poly1305_tag(16B)
pub fn encrypt(
    key: &[u8],
    sequence_number: u64,
    packet_length_bytes: &[u8; 4],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 64 {
        return Err(format!("ChaCha20-Poly1305 key must be 64 bytes, got {}", key.len()));
    }

    let main_key: &[u8; 32] = key[..32].try_into().unwrap();
    let header_key: &[u8; 32] = key[32..64].try_into().unwrap();
    let nonce = ssh_nonce(sequence_number);

    // Step 1: Encrypt the 4-byte packet length with header_key, counter=0
    let mut encrypted_length = *packet_length_bytes;
    let mut header_cipher = ChaCha20Legacy::new(header_key.into(), nonce.as_ref().into());
    header_cipher.apply_keystream(&mut encrypted_length);

    // Step 2: Generate Poly1305 key from main_key with counter=0
    let mut poly_key_bytes = [0u8; 32];
    let mut main_cipher = ChaCha20Legacy::new(main_key.into(), nonce.as_ref().into());
    main_cipher.apply_keystream(&mut poly_key_bytes);

    // Step 3: Encrypt payload with main_key, counter=1 (skip first 64 bytes used for poly key)
    let mut encrypted_payload = payload.to_vec();
    main_cipher.seek(64u32); // Skip to counter=1 (64 bytes = 1 block)
    main_cipher.apply_keystream(&mut encrypted_payload);

    // Step 4: Compute Poly1305 MAC over encrypted_length + encrypted_payload
    let poly_key = poly1305::Key::from(poly_key_bytes);
    let mut mac = Poly1305::new(&poly_key);
    // SSH Poly1305: MAC over the concatenated encrypted_length + encrypted_payload
    let mut mac_input = Vec::with_capacity(4 + encrypted_payload.len());
    mac_input.extend_from_slice(&encrypted_length);
    mac_input.extend_from_slice(&encrypted_payload);
    // Process as full 16-byte blocks, with the last partial block zero-padded
    for chunk in mac_input.chunks(16) {
        let mut block = poly1305::Block::default();
        block[..chunk.len()].copy_from_slice(chunk);
        mac.update(&[block]);
    }
    let tag_arr = mac.finalize();
    let tag: [u8; 16] = tag_arr.as_slice().try_into().unwrap();

    // Build output: encrypted_length(4B) + encrypted_payload + tag(16B)
    let mut result = Vec::with_capacity(4 + encrypted_payload.len() + TAG_SIZE);
    result.extend_from_slice(&encrypted_length);
    result.extend_from_slice(&encrypted_payload);
    result.extend_from_slice(&tag);
    Ok(result)
}

/// Decrypt the 4-byte packet length using the header key.
/// This is needed to know how many more bytes to read.
pub fn decrypt_length(
    key: &[u8],
    sequence_number: u64,
    encrypted_length: &[u8; 4],
) -> Result<u32, String> {
    if key.len() != 64 {
        return Err(format!("Key must be 64 bytes, got {}", key.len()));
    }

    let header_key: &[u8; 32] = key[32..64].try_into().unwrap();
    let nonce = ssh_nonce(sequence_number);

    let mut length_bytes = *encrypted_length;
    let mut header_cipher = ChaCha20Legacy::new(header_key.into(), nonce.as_ref().into());
    header_cipher.apply_keystream(&mut length_bytes);

    Ok(u32::from_be_bytes(length_bytes))
}

/// Decrypt a full packet and verify the Poly1305 MAC.
///
/// * `key` - 64-byte key
/// * `sequence_number` - packet sequence number
/// * `encrypted_length` - 4 bytes of encrypted length (already read)
/// * `encrypted_payload` - the encrypted payload bytes
/// * `received_tag` - 16-byte Poly1305 tag
///
/// Returns: decrypted payload (padding_length + payload + padding)
pub fn decrypt(
    key: &[u8],
    sequence_number: u64,
    encrypted_length: &[u8; 4],
    encrypted_payload: &[u8],
    received_tag: &[u8; 16],
) -> Result<Vec<u8>, String> {
    if key.len() != 64 {
        return Err(format!("Key must be 64 bytes, got {}", key.len()));
    }

    let main_key: &[u8; 32] = key[..32].try_into().unwrap();
    let nonce = ssh_nonce(sequence_number);

    // Step 1: Generate Poly1305 key
    let mut poly_key_bytes = [0u8; 32];
    let mut main_cipher = ChaCha20Legacy::new(main_key.into(), nonce.as_ref().into());
    main_cipher.apply_keystream(&mut poly_key_bytes);

    // Step 2: Verify Poly1305 MAC BEFORE decrypting
    let poly_key = poly1305::Key::from(poly_key_bytes);
    let mut mac = Poly1305::new(&poly_key);
    let mut mac_input = Vec::with_capacity(4 + encrypted_payload.len());
    mac_input.extend_from_slice(encrypted_length);
    mac_input.extend_from_slice(encrypted_payload);
    mac.update_padded(&mac_input);
    let expected_tag_arr = mac.finalize();
    let expected_tag: [u8; 16] = expected_tag_arr.as_slice().try_into().unwrap();

    if expected_tag.as_slice() != received_tag {
        return Err("Poly1305 MAC verification failed".to_string());
    }

    // Step 3: Decrypt payload with counter=1
    let mut decrypted = encrypted_payload.to_vec();
    main_cipher.seek(64u32);
    main_cipher.apply_keystream(&mut decrypted);

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let key = [0x42u8; 64];
        let seq = 0u64;
        let length_bytes: [u8; 4] = [0, 0, 0, 28]; // packet_length = 28
        let payload = b"Hello, ChaCha20-Poly1305!pad";

        let encrypted = encrypt(&key, seq, &length_bytes, payload).unwrap();
        // Should be 4 + 28 + 16 = 48 bytes
        assert_eq!(encrypted.len(), 4 + payload.len() + TAG_SIZE);

        // Decrypt length
        let enc_len: [u8; 4] = encrypted[..4].try_into().unwrap();
        let dec_len = decrypt_length(&key, seq, &enc_len).unwrap();
        assert_eq!(dec_len, 28);

        // Decrypt payload
        let enc_payload = &encrypted[4..4 + payload.len()];
        let tag: [u8; 16] = encrypted[4 + payload.len()..].try_into().unwrap();
        let decrypted = decrypt(&key, seq, &enc_len, enc_payload, &tag).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_tampered_tag_fails() {
        let key = [0x42u8; 64];
        let seq = 0u64;
        let length_bytes: [u8; 4] = [0, 0, 0, 16];
        let payload = b"test data 123456"; // 16 bytes

        let encrypted = encrypt(&key, seq, &length_bytes, payload).unwrap();
        let enc_len: [u8; 4] = encrypted[..4].try_into().unwrap();
        let enc_payload = &encrypted[4..4 + payload.len()];
        let mut tag: [u8; 16] = encrypted[4 + payload.len()..].try_into().unwrap();
        tag[0] ^= 0x01; // Tamper

        let result = decrypt(&key, seq, &enc_len, enc_payload, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_sequences_produce_different_ciphertext() {
        let key = [0x42u8; 64];
        let length_bytes: [u8; 4] = [0, 0, 0, 16];
        let payload = b"same data 123456";

        let enc1 = encrypt(&key, 0, &length_bytes, payload).unwrap();
        let enc2 = encrypt(&key, 1, &length_bytes, payload).unwrap();
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_nonce_construction() {
        assert_eq!(ssh_nonce(0), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(ssh_nonce(1), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(ssh_nonce(256), [0, 0, 0, 0, 0, 0, 1, 0]);
        assert_eq!(ssh_nonce(3), [0, 0, 0, 0, 0, 0, 0, 3]); // first encrypted packet
    }
}
