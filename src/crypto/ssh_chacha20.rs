//! SSH-specific ChaCha20-Poly1305 implementation
//!
//! Implements the chacha20-poly1305@openssh.com cipher as defined in
//! the OpenSSH source code. This is NOT the standard RFC 8439 AEAD -
//! it uses two separate ChaCha20 keys and a custom Poly1305 key derivation.

use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher};
/// Tag size for Poly1305
pub const TAG_SIZE: usize = 16;

/// Standard Poly1305 MAC computation (poly1305-donna).
/// The `poly1305` crate's UniversalHash API doesn't produce correct output
/// for partial blocks (hibit handling differs). This implements the standard
/// algorithm directly, matching OpenSSH's poly1305_auth().
fn poly1305_auth(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    // Split key into r and s
    let mut r = [0u32; 5];
    let s = [
        u32::from_le_bytes(key[16..20].try_into().unwrap()),
        u32::from_le_bytes(key[20..24].try_into().unwrap()),
        u32::from_le_bytes(key[24..28].try_into().unwrap()),
        u32::from_le_bytes(key[28..32].try_into().unwrap()),
    ];

    // Clamp r
    let t0 = u32::from_le_bytes(key[0..4].try_into().unwrap());
    let t1 = u32::from_le_bytes(key[4..8].try_into().unwrap());
    let t2 = u32::from_le_bytes(key[8..12].try_into().unwrap());
    let t3 = u32::from_le_bytes(key[12..16].try_into().unwrap());

    r[0] = t0 & 0x3ffffff;
    r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    r[4] = (t3 >> 8) & 0x00fffff;

    let s1 = r[1] * 5;
    let s2 = r[2] * 5;
    let s3 = r[3] * 5;
    let s4 = r[4] * 5;

    let mut h = [0u32; 5];
    let mut j = 0usize;

    while j < data.len() {
        let remaining = data.len() - j;
        let mut mp = [0u8; 16];
        let block_len;

        if remaining >= 16 {
            mp.copy_from_slice(&data[j..j + 16]);
            block_len = 16;
        } else {
            mp[..remaining].copy_from_slice(&data[j..]);
            mp[remaining] = 1; // Standard Poly1305 partial block padding
            block_len = remaining;
        }

        let hibit = if block_len == 16 { 1u32 << 24 } else { 0u32 };

        let t0 = u32::from_le_bytes(mp[0..4].try_into().unwrap());
        let t1 = u32::from_le_bytes(mp[4..8].try_into().unwrap());
        let t2 = u32::from_le_bytes(mp[8..12].try_into().unwrap());
        let t3 = u32::from_le_bytes(mp[12..16].try_into().unwrap());

        h[0] = h[0].wrapping_add(t0 & 0x3ffffff);
        h[1] = h[1].wrapping_add(((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
        h[2] = h[2].wrapping_add(((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
        h[3] = h[3].wrapping_add(((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
        h[4] = h[4].wrapping_add((t3 >> 8) | hibit);

        let mut d = [0u64; 5];
        d[0] = h[0] as u64 * r[0] as u64 + h[1] as u64 * s4 as u64 + h[2] as u64 * s3 as u64 + h[3] as u64 * s2 as u64 + h[4] as u64 * s1 as u64;
        d[1] = h[0] as u64 * r[1] as u64 + h[1] as u64 * r[0] as u64 + h[2] as u64 * s4 as u64 + h[3] as u64 * s3 as u64 + h[4] as u64 * s2 as u64;
        d[2] = h[0] as u64 * r[2] as u64 + h[1] as u64 * r[1] as u64 + h[2] as u64 * r[0] as u64 + h[3] as u64 * s4 as u64 + h[4] as u64 * s3 as u64;
        d[3] = h[0] as u64 * r[3] as u64 + h[1] as u64 * r[2] as u64 + h[2] as u64 * r[1] as u64 + h[3] as u64 * r[0] as u64 + h[4] as u64 * s4 as u64;
        d[4] = h[0] as u64 * r[4] as u64 + h[1] as u64 * r[3] as u64 + h[2] as u64 * r[2] as u64 + h[3] as u64 * r[1] as u64 + h[4] as u64 * r[0] as u64;

        let mut c: u32;
        c = (d[0] >> 26) as u32; h[0] = d[0] as u32 & 0x3ffffff;
        d[1] += c as u64; c = (d[1] >> 26) as u32; h[1] = d[1] as u32 & 0x3ffffff;
        d[2] += c as u64; c = (d[2] >> 26) as u32; h[2] = d[2] as u32 & 0x3ffffff;
        d[3] += c as u64; c = (d[3] >> 26) as u32; h[3] = d[3] as u32 & 0x3ffffff;
        d[4] += c as u64; c = (d[4] >> 26) as u32; h[4] = d[4] as u32 & 0x3ffffff;
        h[0] = h[0].wrapping_add(c * 5); c = h[0] >> 26; h[0] &= 0x3ffffff;
        h[1] = h[1].wrapping_add(c);

        j += 16;
    }

    // Final reduction and output
    let mut c: u32;
    c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] = h[2].wrapping_add(c);
    c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] = h[3].wrapping_add(c);
    c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] = h[4].wrapping_add(c);
    c = h[4] >> 26; h[4] &= 0x3ffffff; h[0] = h[0].wrapping_add(c * 5);
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] = h[1].wrapping_add(c);

    let mut g = [0u32; 5];
    g[0] = h[0].wrapping_add(5); c = g[0] >> 26; g[0] &= 0x3ffffff;
    g[1] = h[1].wrapping_add(c); c = g[1] >> 26; g[1] &= 0x3ffffff;
    g[2] = h[2].wrapping_add(c); c = g[2] >> 26; g[2] &= 0x3ffffff;
    g[3] = h[3].wrapping_add(c); c = g[3] >> 26; g[3] &= 0x3ffffff;
    g[4] = h[4].wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g[4] >> 31).wrapping_sub(1);
    for i in 0..5 { g[i] &= mask; h[i] &= !mask; h[i] |= g[i]; }

    let f0 = (h[0] | (h[1] << 26)) as u64 + s[0] as u64;
    let f1 = ((h[1] >> 6) | (h[2] << 20)) as u64 + s[1] as u64 + (f0 >> 32);
    let f2 = ((h[2] >> 12) | (h[3] << 14)) as u64 + s[2] as u64 + (f1 >> 32);
    let f3 = ((h[3] >> 18) | (h[4] << 8)) as u64 + s[3] as u64 + (f2 >> 32);

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
    out[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
    out[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
    out[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());
    out
}

/// Construct an 8-byte DJB ChaCha20 nonce from the sequence number.
/// OpenSSH's native implementation uses DJB ChaCha20 (8-byte nonce).
/// The libcrypto variant maps to IETF via [counter(4) || 0(4) || seqno(8)],
/// but the DJB variant uses seqno directly as the 8-byte nonce.
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

    // OpenSSH key layout: key[0..32]=main_key (payload), key[32..64]=header_key (length)
    // BUT: the SSH KDF derives K1||K2 where K1 is the first 32 bytes.
    // Let's check if OpenSSH's key assignment matches our KDF output.
    let main_key: &[u8; 32] = key[..32].try_into().unwrap();
    let header_key: &[u8; 32] = key[32..64].try_into().unwrap();
    let nonce = ssh_nonce(sequence_number);

    // Step 1: Encrypt the 4-byte packet length with header_key, counter=0
    let mut encrypted_length = *packet_length_bytes;
    let mut header_cipher = ChaCha20Legacy::new(header_key.into(), nonce.as_ref().into());
    header_cipher.apply_keystream(&mut encrypted_length);

    // Step 2: Generate Poly1305 key from main_key with counter=0
    // Use full 64-byte block 0 (only first 32 bytes are the poly key)
    let mut block0 = [0u8; 64];
    let mut main_cipher = ChaCha20Legacy::new(main_key.into(), nonce.as_ref().into());
    main_cipher.apply_keystream(&mut block0);
    let poly_key_bytes: [u8; 32] = block0[..32].try_into().unwrap();

    // Step 3: Encrypt payload with main_key, counter=1
    // Cipher position is now at byte 64 = start of block 1
    let mut encrypted_payload = payload.to_vec();
    main_cipher.apply_keystream(&mut encrypted_payload);

    // Step 4: Compute Poly1305 MAC over encrypted_length + encrypted_payload
    let mut mac_input = Vec::with_capacity(4 + encrypted_payload.len());
    mac_input.extend_from_slice(&encrypted_length);
    mac_input.extend_from_slice(&encrypted_payload);
    let tag = poly1305_auth(&poly_key_bytes, &mac_input);

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

    // Step 1: Generate Poly1305 key from block 0 (consume full 64-byte block)
    let mut block0 = [0u8; 64];
    let mut main_cipher = ChaCha20Legacy::new(main_key.into(), nonce.as_ref().into());
    main_cipher.apply_keystream(&mut block0);
    let poly_key_bytes: [u8; 32] = block0[..32].try_into().unwrap();

    // Step 2: Verify Poly1305 MAC BEFORE decrypting
    let mut mac_input = Vec::with_capacity(4 + encrypted_payload.len());
    mac_input.extend_from_slice(encrypted_length);
    mac_input.extend_from_slice(encrypted_payload);
    let expected_tag = poly1305_auth(&poly_key_bytes, &mac_input);

    if expected_tag != *received_tag {
        return Err("Poly1305 MAC verification failed".to_string());
    }

    // Step 3: Decrypt payload with counter=1 (cipher already at byte 64 after block 0)
    let mut decrypted = encrypted_payload.to_vec();
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
    #[test]
    fn test_chacha20_continuous_keystream() {
        // Verify consuming full block 0 then continuing gives same result as continuous
        let key = [0u8; 32];
        let nonce = [0u8; 8]; // DJB 8-byte nonce

        // Generate 128 bytes of continuous keystream
        let mut full_stream = [0u8; 128];
        let mut c1 = ChaCha20Legacy::new((&key).into(), (&nonce).into());
        c1.apply_keystream(&mut full_stream);

        // Consume full 64-byte block 0, then generate from block 1
        let mut block0 = [0u8; 64];
        let mut c2 = ChaCha20Legacy::new((&key).into(), (&nonce).into());
        c2.apply_keystream(&mut block0);
        assert_eq!(&block0[..32], &full_stream[..32], "first 32 bytes must match");

        let mut payload = [0u8; 32];
        c2.apply_keystream(&mut payload);
        assert_eq!(&payload, &full_stream[64..96], "bytes 64-96 must match (block 1)");
    }

    /// Verify our Poly1305 computation matches RFC 7539 Section 2.5.2 test vector
    #[test]
    fn test_poly1305_rfc7539_vector() {
        let key_hex = "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b";
        let key_bytes: Vec<u8> = (0..key_hex.len()).step_by(2)
            .map(|i| u8::from_str_radix(&key_hex[i..i+2], 16).unwrap())
            .collect();
        let message = b"Cryptographic Forum Research Group";
        let expected_hex = "a8061dc1305136c6c22b8baf0c0127a9";
        let expected: Vec<u8> = (0..expected_hex.len()).step_by(2)
            .map(|i| u8::from_str_radix(&expected_hex[i..i+2], 16).unwrap())
            .collect();

        let key_arr: [u8; 32] = key_bytes.try_into().unwrap();
        let tag = poly1305_auth(&key_arr, message).to_vec();

        assert_eq!(tag, expected, "Poly1305 must match RFC 7539 test vector");
    }

    #[test]
    fn test_nonce_construction() {
        assert_eq!(ssh_nonce(0), [0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(ssh_nonce(1), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(ssh_nonce(256), [0, 0, 0, 0, 0, 0, 1, 0]);
        assert_eq!(ssh_nonce(3), [0, 0, 0, 0, 0, 0, 0, 3]);
    }
}
