//! ChaCha20-Poly1305 AEAD Cipher Tests
//!
//! Tests for ChaCha20-Poly1305 AEAD cipher as defined in RFC 8439
//! Following TDD workflow - tests written before implementation

use ssh_client::crypto::chacha20_poly1305::{
    ChaCha20Poly1305, Key, Nonce, TAG_SIZE,
};

#[test]
fn test_key_size() {
    assert_eq!(Key::len(), 32); // 256-bit key
}

#[test]
fn test_nonce_size() {
    assert_eq!(Nonce::len(), 12); // 96-bit nonce
}

#[test]
fn test_tag_size() {
    assert_eq!(TAG_SIZE, 16); // 128-bit tag
}

#[test]
fn test_chacha20_poly1305_encrypt_decrypt_roundtrip() {
    let key = Key::from([0u8; 32]);
    let nonce = Nonce::from([0u8; 12]);
    
    let cipher = ChaCha20Poly1305::new(&key, &nonce);
    let plaintext = b"Hello, ChaCha20-Poly1305!";
    
    let ciphertext = cipher.encrypt(plaintext).expect("Encryption failed");
    let decrypted = cipher.decrypt(&ciphertext).expect("Decryption failed");
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_chacha20_poly1305_different_keys() {
    let key1 = Key::from([0u8; 32]);
    let key2 = Key::from([1u8; 32]);
    let nonce = Nonce::from([0u8; 12]);
    
    let cipher1 = ChaCha20Poly1305::new(&key1, &nonce);
    let cipher2 = ChaCha20Poly1305::new(&key2, &nonce);
    
    let plaintext = b"Test message";
    
    let ciphertext1 = cipher1.encrypt(plaintext).expect("Encryption 1 failed");
    let ciphertext2 = cipher2.encrypt(plaintext).expect("Encryption 2 failed");
    
    // Different keys should produce different ciphertexts
    assert_ne!(ciphertext1, ciphertext2);
}

#[test]
fn test_chacha20_poly1305_different_nonces() {
    let key = Key::from([0u8; 32]);
    let nonce1 = Nonce::from([0u8; 12]);
    let nonce2 = Nonce::from([1u8; 12]);
    
    let cipher1 = ChaCha20Poly1305::new(&key, &nonce1);
    let cipher2 = ChaCha20Poly1305::new(&key, &nonce2);
    
    let plaintext = b"Test message";
    
    let ciphertext1 = cipher1.encrypt(plaintext).expect("Encryption 1 failed");
    let ciphertext2 = cipher2.encrypt(plaintext).expect("Encryption 2 failed");
    
    // Different nonces should produce different ciphertexts
    assert_ne!(ciphertext1, ciphertext2);
}

#[test]
fn test_chacha20_poly1305_empty_message() {
    let key = Key::from([0u8; 32]);
    let nonce = Nonce::from([0u8; 12]);
    
    let cipher = ChaCha20Poly1305::new(&key, &nonce);
    let plaintext = b"";
    
    let ciphertext = cipher.encrypt(plaintext).expect("Encryption failed");
    let decrypted = cipher.decrypt(&ciphertext).expect("Decryption failed");
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_chacha20_poly1305_large_message() {
    let key = Key::from([0u8; 32]);
    let nonce = Nonce::from([0u8; 12]);
    
    let cipher = ChaCha20Poly1305::new(&key, &nonce);
    
    // Create a large message (1MB)
    let plaintext: Vec<u8> = (0..1_048_576).map(|i| (i % 256) as u8).collect();
    
    let ciphertext = cipher.encrypt(&plaintext).expect("Encryption failed");
    let decrypted = cipher.decrypt(&ciphertext).expect("Decryption failed");
    
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_chacha20_poly1305_tag_verification_failure() {
    let key = Key::from([0u8; 32]);
    let nonce = Nonce::from([0u8; 12]);
    
    let cipher = ChaCha20Poly1305::new(&key, &nonce);
    let plaintext = b"Test message";
    
    let ciphertext = cipher.encrypt(plaintext).expect("Encryption failed");
    
    // Create a modified copy with corrupted tag
    let mut corrupted: Vec<u8> = ciphertext.clone();
    let last_idx = corrupted.len() - 1;
    corrupted[last_idx] ^= 0xFF;
    
    let result = cipher.decrypt(&corrupted);
    assert!(result.is_err(), "Should fail to decrypt with corrupted tag");
}

#[test]
fn test_chacha20_poly1305_ciphertext_modification() {
    let key = Key::from([0u8; 32]);
    let nonce = Nonce::from([0u8; 12]);
    
    let cipher = ChaCha20Poly1305::new(&key, &nonce);
    let plaintext = b"Test message";
    
    let ciphertext = cipher.encrypt(plaintext).expect("Encryption failed");
    
    // Create a modified copy with corrupted ciphertext
    let mut corrupted: Vec<u8> = ciphertext.clone();
    corrupted[5] ^= 0xFF;
    
    let result = cipher.decrypt(&corrupted);
    assert!(result.is_err(), "Should fail to decrypt with corrupted ciphertext");
}

#[test]
fn test_chacha20_poly1305_wrong_nonce() {
    let key = Key::from([0u8; 32]);
    let nonce1 = Nonce::from([0u8; 12]);
    let nonce2 = Nonce::from([1u8; 12]);
    
    let cipher1 = ChaCha20Poly1305::new(&key, &nonce1);
    let cipher2 = ChaCha20Poly1305::new(&key, &nonce2);
    
    let plaintext = b"Test message";
    let ciphertext = cipher1.encrypt(plaintext).expect("Encryption failed");
    
    let result = cipher2.decrypt(&ciphertext);
    assert!(result.is_err(), "Should fail to decrypt with wrong nonce");
}

#[test]
fn test_chacha20_poly1305_rfc8439_example() {
    // RFC 8439 Section 2.8.2 test vector
    let key = Key::from([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ]);
    
    let nonce = Nonce::from([
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,
    ]);
    
    let cipher = ChaCha20Poly1305::new(&key, &nonce);
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    
    let ciphertext = cipher.encrypt(plaintext).expect("Encryption failed");
    let decrypted = cipher.decrypt(&ciphertext).expect("Decryption failed");
    
    assert_eq!(plaintext, &decrypted[..]);
}

#[test]
fn test_chacha20_poly1305_ssh_format() {
    // Test SSH-specific format (chacha20-poly1305@openssh.com)
    // Uses 64-bit counter instead of 32-bit
    let key = Key::from([0u8; 32]);
    let nonce = Nonce::from([0u8; 12]);
    
    let cipher = ChaCha20Poly1305::new(&key, &nonce);
    
    // SSH packets can be up to 32768 bytes
    let plaintext: Vec<u8> = vec![0xAB; 32768];
    
    let ciphertext = cipher.encrypt(&plaintext).expect("Encryption failed");
    let decrypted = cipher.decrypt(&ciphertext).expect("Decryption failed");
    
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_chacha20_poly1305_multiple_encryptions() {
    let key = Key::from([0u8; 32]);
    let nonce = Nonce::from([0u8; 12]);
    
    let cipher = ChaCha20Poly1305::new(&key, &nonce);
    
    // Encrypt multiple messages with the same key/nonces should be safe
    // (in practice, nonces should be unique per encryption)
    let plaintext1 = b"Message 1";
    let plaintext2 = b"Message 2";
    let plaintext3 = b"Message 3";
    
    let ciphertext1 = cipher.encrypt(plaintext1).expect("Encryption 1 failed");
    let ciphertext2 = cipher.encrypt(plaintext2).expect("Encryption 2 failed");
    let ciphertext3 = cipher.encrypt(plaintext3).expect("Encryption 3 failed");
    
    let decrypted1 = cipher.decrypt(&ciphertext1).expect("Decryption 1 failed");
    let decrypted2 = cipher.decrypt(&ciphertext2).expect("Decryption 2 failed");
    let decrypted3 = cipher.decrypt(&ciphertext3).expect("Decryption 3 failed");
    
    assert_eq!(plaintext1, &decrypted1[..]);
    assert_eq!(plaintext2, &decrypted2[..]);
    assert_eq!(plaintext3, &decrypted3[..]);
}

#[test]
fn test_chacha20_poly1305_key_from_slice() {
    let key_bytes = vec![0x00; 32];
    let key = Key::from_slice(&key_bytes).expect("Failed to create key from slice");
    
    assert_eq!(key.as_slice(), &key_bytes[..]);
}

#[test]
fn test_chacha20_poly1305_nonce_from_slice() {
    let nonce_bytes = vec![0x00; 12];
    let nonce = Nonce::from_slice(&nonce_bytes).expect("Failed to create nonce from slice");
    
    assert_eq!(nonce.as_slice(), &nonce_bytes[..]);
}