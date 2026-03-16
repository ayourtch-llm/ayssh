//! AES-GCM cipher tests for SSH

use ayssh::crypto::cipher::{aes_gcm_decrypt, aes_gcm_encrypt, CipherError};

/// Test basic encryption and decryption
#[test]
fn test_aes_gcm_encrypt_decrypt() {
    let key = vec![0x00; 32]; // 256-bit key
    let nonce = vec![0x00; 12]; // 96-bit nonce
    let plaintext = b"Hello, SSH World!";
    
    let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
    let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
    
    assert_eq!(decrypted, plaintext);
}

/// Test that different keys produce different ciphertexts
#[test]
fn test_aes_gcm_different_keys() {
    let key1 = vec![0x00; 32];
    let key2 = vec![0xFF; 32];
    let nonce = vec![0x00; 12];
    let plaintext = b"test data";
    
    let ct1 = aes_gcm_encrypt(&key1, &nonce, plaintext).unwrap();
    let ct2 = aes_gcm_encrypt(&key2, &nonce, plaintext).unwrap();
    
    assert_ne!(ct1, ct2);
}

/// Test that different nonces produce different ciphertexts
#[test]
fn test_aes_gcm_different_nonces() {
    let key = vec![0x00; 32];
    let nonce1 = vec![0x00; 12];
    let nonce2 = vec![0x01; 12];
    let plaintext = b"test data";
    
    let ct1 = aes_gcm_encrypt(&key, &nonce1, plaintext).unwrap();
    let ct2 = aes_gcm_encrypt(&key, &nonce2, plaintext).unwrap();
    
    assert_ne!(ct1, ct2);
}

/// Test empty plaintext
#[test]
fn test_aes_gcm_empty_plaintext() {
    let key = vec![0x00; 32];
    let nonce = vec![0x00; 12];
    let plaintext = b"";
    
    let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
    let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
    
    assert_eq!(decrypted, plaintext);
}

/// Test authentication failure (tampered ciphertext)
#[test]
fn test_aes_gcm_auth_failure() {
    let key = vec![0x00; 32];
    let nonce = vec![0x00; 12];
    let plaintext = b"secret data";
    
    let mut ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
    
    // Tamper with the ciphertext
    ciphertext[0] ^= 0xFF;
    
    let result = aes_gcm_decrypt(&key, &nonce, &ciphertext);
    assert!(result.is_err());
}

/// Test authentication failure (wrong key)
#[test]
fn test_aes_gcm_wrong_key() {
    let key1 = vec![0x00; 32];
    let key2 = vec![0xFF; 32];
    let nonce = vec![0x00; 12];
    let plaintext = b"secret data";
    
    let ciphertext = aes_gcm_encrypt(&key1, &nonce, plaintext).unwrap();
    
    let result = aes_gcm_decrypt(&key2, &nonce, &ciphertext);
    assert!(result.is_err());
}

/// Test authentication failure (wrong nonce)
#[test]
fn test_aes_gcm_wrong_nonce() {
    let key = vec![0x00; 32];
    let nonce1 = vec![0x00; 12];
    let nonce2 = vec![0x01; 12];
    let plaintext = b"secret data";
    
    let ciphertext = aes_gcm_encrypt(&key, &nonce1, plaintext).unwrap();
    
    let result = aes_gcm_decrypt(&key, &nonce2, &ciphertext);
    assert!(result.is_err());
}

/// Test large plaintext
#[test]
fn test_aes_gcm_large_plaintext() {
    let key = vec![0x00; 32];
    let nonce = vec![0x00; 12];
    let plaintext = vec![0xAA; 1024 * 1024]; // 1MB
    
    let ciphertext = aes_gcm_encrypt(&key, &nonce, &plaintext).unwrap();
    let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
    
    assert_eq!(decrypted, plaintext);
}

/// Test cipher provides authenticated encryption
#[test]
fn test_aes_gcm_authenticated() {
    let key = vec![0x00; 32];
    let nonce = vec![0x00; 12];
    let plaintext = b"important message";
    
    let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
    
    // Verify ciphertext is longer than plaintext (contains auth tag)
    assert!(ciphertext.len() > plaintext.len());
    
    // Verify decryption works
    let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Test with random-looking key and nonce
#[test]
fn test_aes_gcm_random_key_nonce() {
    let key: Vec<u8> = (0..32).map(|i| ((i * 7 + 3) % 256) as u8).collect();
    let nonce: Vec<u8> = (0..12).map(|i| ((i * 11 + 5) % 256) as u8).collect();
    let plaintext = b"random test";
    
    let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
    let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
    
    assert_eq!(decrypted, plaintext);
}

/// Test cipher error handling
#[test]
fn test_cipher_error() {
    let key = vec![0x00; 32];
    let nonce = vec![0x00; 12];
    let ciphertext = vec![0xFF; 100]; // Invalid ciphertext
    
    let result = aes_gcm_decrypt(&key, &nonce, &ciphertext);
    assert!(result.is_err());
    
    let err = result.unwrap_err();
    assert_eq!(err, CipherError::AuthenticationFailed);
}

/// Test key size validation
#[test]
fn test_aes_gcm_key_size() {
    let key = vec![0x00; 16]; // Wrong key size (128-bit instead of 256-bit)
    let nonce = vec![0x00; 12];
    let plaintext = b"test";
    
    let result = aes_gcm_encrypt(&key, &nonce, plaintext);
    assert!(result.is_err());
}

/// Test nonce size validation
#[test]
fn test_aes_gcm_nonce_size() {
    let key = vec![0x00; 32];
    let nonce = vec![0x00; 8]; // Wrong nonce size (64-bit instead of 96-bit)
    let plaintext = b"test";
    
    let result = aes_gcm_encrypt(&key, &nonce, plaintext);
    assert!(result.is_err());
}