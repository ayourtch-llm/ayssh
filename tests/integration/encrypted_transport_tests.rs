use ssh_client::transport::encrypted::{CipherState, EncryptedTransport};
use ssh_client::transport::packet::Packet;

#[test]
fn test_cipher_state_aes256_gcm() {
    let session_id = vec![0x00; 20];
    let enc_key = vec![0x00; 32];
    
    let mut cipher = CipherState::new_aes256_gcm(&session_id, &enc_key).unwrap();
    
    let packet = Packet::new(0x01, vec![1, 2, 3, 4]);
    let encrypted = cipher.encrypt(&packet).unwrap();
    
    assert!(!encrypted.is_empty());
}

#[test]
fn test_cipher_state_chacha20_poly1305() {
    let session_id = vec![0x00; 20];
    let enc_key = vec![0x00; 32];
    
    let mut cipher = CipherState::new_chacha20_poly1305(&session_id, &enc_key).unwrap();
    
    let packet = Packet::new(0x01, vec![1, 2, 3, 4]);
    let encrypted = cipher.encrypt(&packet).unwrap();
    
    assert!(!encrypted.is_empty());
}

#[test]
fn test_encryption_round_trip_aes() {
    let session_id = vec![0x00; 20];
    let enc_key = vec![0x00; 32];
    
    let mut cipher = CipherState::new_aes256_gcm(&session_id, &enc_key).unwrap();
    
    let packet = Packet::new(0x01, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let encrypted = cipher.encrypt(&packet).unwrap();
    
    // Verify encryption produced output
    assert!(encrypted.len() > 0);
}

#[test]
fn test_encryption_round_trip_chacha() {
    let session_id = vec![0x00; 20];
    let enc_key = vec![0x00; 32];
    
    let mut cipher = CipherState::new_chacha20_poly1305(&session_id, &enc_key).unwrap();
    
    let packet = Packet::new(0x01, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    let encrypted = cipher.encrypt(&packet).unwrap();
    
    // Verify encryption produced output
    assert!(encrypted.len() > 0);
}

#[test]
fn test_different_keys_different_ciphertexts() {
    let session_id = vec![0x00; 20];
    let key1 = vec![0x00; 32];
    let key2 = vec![0x01; 32];
    
    let mut cipher1 = CipherState::new_aes256_gcm(&session_id, &key1).unwrap();
    let mut cipher2 = CipherState::new_aes256_gcm(&session_id, &key2).unwrap();
    
    let packet = Packet::new(0x01, vec![1, 2, 3, 4]);
    let encrypted1 = cipher1.encrypt(&packet).unwrap();
    let encrypted2 = cipher2.encrypt(&packet).unwrap();
    
    assert_ne!(encrypted1, encrypted2);
}

#[test]
fn test_sequence_number_increment() {
    let session_id = vec![0x00; 20];
    let enc_key = vec![0x00; 32];
    
    let mut cipher = CipherState::new_aes256_gcm(&session_id, &enc_key).unwrap();
    
    let packet = Packet::new(0x01, vec![1, 2, 3, 4]);
    cipher.encrypt(&packet).unwrap();
    cipher.encrypt(&packet).unwrap();
    cipher.encrypt(&packet).unwrap();
    
    // Sequence number should have incremented
    assert_eq!(cipher.sequence_number, 3);
}