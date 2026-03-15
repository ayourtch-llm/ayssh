//! Encryption tests for SSH transport layer

use ssh_client::transport::cipher::CipherState;
use ssh_client::crypto::cipher::CipherError;
use ssh_client::crypto::kdf::kdf;

#[test]
fn test_cipher_initialization() {
    let shared_secret = b"dh_shared_secret_data";
    let session_id = b"ssh_session_id_hash";
    let enc_key = vec![0x00; 32];
    let mac_key = vec![0x01; 32];
    
    let cipher = CipherState::new(shared_secret, session_id, &enc_key, &mac_key);
    
    // Cipher should be initialized - just check it doesn't panic
    let _ = cipher.clone();
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let shared_secret = b"dh_shared_secret_data";
    let session_id = b"ssh_session_id_hash";
    let enc_key = vec![0x00; 32];
    let mac_key = vec![0x01; 32];
    
    let mut cipher = CipherState::new(shared_secret, session_id, &enc_key, &mac_key);
    let plaintext = b"Hello SSH World!";
    
    let ciphertext = cipher.encrypt(plaintext).unwrap();
    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_auth_failure_tampered() {
    let shared_secret = b"dh_shared_secret_data";
    let session_id = b"ssh_session_id_hash";
    let enc_key = vec![0x00; 32];
    let mac_key = vec![0x01; 32];
    
    let mut cipher = CipherState::new(shared_secret, session_id, &enc_key, &mac_key);
    let plaintext = b"secret data";
    
    let mut ciphertext = cipher.encrypt(plaintext).unwrap();
    ciphertext[0] ^= 0xFF;
    
    let result = cipher.decrypt(&ciphertext);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), CipherError::AuthenticationFailed);
}

#[test]
fn test_key_derivation_consistency() {
    let shared_secret = b"dh_shared_secret_data";
    let session_id = b"ssh_session_id_hash";
    
    let enc_key1 = kdf(shared_secret, session_id, 1, 32);
    let enc_key2 = kdf(shared_secret, session_id, 1, 32);
    
    assert_eq!(enc_key1, enc_key2);
}

#[test]
fn test_different_enc_keys_different_ciphertexts() {
    let shared_secret = b"dh_shared_secret_data";
    let session_id = b"ssh_session_id_hash";
    let mac_key = vec![0x01; 32];
    
    let enc_key1 = vec![0x00; 32];
    let enc_key2 = vec![0xFF; 32];
    
    let mut cipher1 = CipherState::new(shared_secret, session_id, &enc_key1, &mac_key);
    let mut cipher2 = CipherState::new(shared_secret, session_id, &enc_key2, &mac_key);
    
    let plaintext = b"test data";
    let ct1 = cipher1.encrypt(plaintext).unwrap();
    let ct2 = cipher2.encrypt(plaintext).unwrap();
    
    assert_ne!(ct1, ct2);
}

#[test]
fn test_large_data_encryption() {
    let shared_secret = b"dh_shared_secret_data";
    let session_id = b"ssh_session_id_hash";
    let enc_key = vec![0x00; 32];
    let mac_key = vec![0x01; 32];
    
    let mut cipher = CipherState::new(shared_secret, session_id, &enc_key, &mac_key);
    let plaintext = vec![0xAA; 1024 * 1024]; // 1MB
    
    let ciphertext = cipher.encrypt(&plaintext).unwrap();
    let decrypted = cipher.decrypt(&ciphertext).unwrap();
    
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_nonce_increment() {
    let shared_secret = b"dh_shared_secret_data";
    let session_id = b"ssh_session_id_hash";
    let enc_key = vec![0x00; 32];
    let mac_key = vec![0x01; 32];
    
    let mut cipher = CipherState::new(shared_secret, session_id, &enc_key, &mac_key);
    let plaintext = b"test";
    
    let ct1 = cipher.encrypt(plaintext).unwrap();
    let ct2 = cipher.encrypt(plaintext).unwrap();
    
    // Different nonces should produce different ciphertexts
    assert_ne!(ct1, ct2);
}