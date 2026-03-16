//! Key Derivation Function (KDF) tests for SSH
//!
//! These tests verify the KDF implementation according to RFC 4253 Section 7.

use ssh_client::crypto::kdf::{kdf, HashAlgorithm};

/// Test simple KDF derivation (32 bytes output)
#[test]
fn test_kdf_simple() {
    let shared_secret = b"shared_secret_data";
    let session_id = b"session_id_data";
    let counter = 1u32;
    let desired_length = 32;
    
    let result = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), desired_length);
}

/// Test multi-block derivation (output > 32 bytes)
#[test]
fn test_kdf_multiblock() {
    let shared_secret = b"shared_secret_data";
    let session_id = b"session_id_data";
    let counter = 1u32;
    let desired_length = 64; // More than one SHA256 block
    
    let result = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), desired_length);
}

/// Test with empty shared secret
#[test]
fn test_kdf_empty_secret() {
    let shared_secret = b"";
    let session_id = b"session_id";
    let counter = 1u32;
    let desired_length = 32;
    
    let result = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), desired_length);
}

/// Test that counter increment produces different output
#[test]
fn test_kdf_counter_increment() {
    let shared_secret = b"secret";
    let session_id = b"session";
    let result1 = kdf(shared_secret, session_id, 1, 32, HashAlgorithm::Sha256);
    let result2 = kdf(shared_secret, session_id, 2, 32, HashAlgorithm::Sha256);
    
    assert_ne!(result1, result2);
}

/// Test SSH key derivation for AES-256 encryption key
#[test]
fn test_kdf_ssh_encryption_key() {
    // Simulate SSH key derivation for AES-256 encryption key
    let shared_secret = b"dh_shared_secret";
    let session_id = b"ssh_session_id_12345";
    let counter = 1u32;
    let desired_length = 32; // AES-256 key
    
    let result = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), 32);
}

/// Test KDF with zero counter
#[test]
fn test_kdf_zero_counter() {
    let shared_secret = b"secret";
    let session_id = b"session";
    let counter = 0u32;
    let desired_length = 32;
    
    let result = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), desired_length);
}

/// Test KDF with large counter value
#[test]
fn test_kdf_large_counter() {
    let shared_secret = b"secret";
    let session_id = b"session";
    let counter = u32::MAX;
    let desired_length = 32;
    
    let result = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), desired_length);
}

/// Test KDF determinism (same inputs produce same output)
#[test]
fn test_kdf_determinism() {
    let shared_secret = b"secret";
    let session_id = b"session";
    let counter = 1u32;
    let desired_length = 32;
    
    let result1 = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    let result2 = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    
    assert_eq!(result1, result2);
}

/// Test KDF produces different outputs for different session IDs
#[test]
fn test_kdf_different_session_id() {
    let shared_secret = b"secret";
    let session_id1 = b"session1";
    let session_id2 = b"session2";
    let counter = 1u32;
    let desired_length = 32;
    
    let result1 = kdf(shared_secret, session_id1, counter, desired_length, HashAlgorithm::Sha256);
    let result2 = kdf(shared_secret, session_id2, counter, desired_length, HashAlgorithm::Sha256);
    
    assert_ne!(result1, result2);
}

/// Test KDF with very long shared secret
#[test]
fn test_kdf_long_secret() {
    let shared_secret = vec![0xAA; 1000];
    let session_id = b"session";
    let counter = 1u32;
    let desired_length = 32;
    
    let result = kdf(&shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), desired_length);
}

/// Test KDF with very long session ID
#[test]
fn test_kdf_long_session_id() {
    let shared_secret = b"secret";
    let session_id = vec![0xBB; 1000];
    let counter = 1u32;
    let desired_length = 32;
    
    let result = kdf(shared_secret, &session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), desired_length);
}

/// Test KDF for 128-bit key (AES-128)
#[test]
fn test_kdf_aes128_key() {
    let shared_secret = b"dh_secret";
    let session_id = b"session";
    let counter = 1u32;
    let desired_length = 16; // AES-128 key
    
    let result = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), 16);
}

/// Test KDF for MAC key (32 bytes for HMAC-SHA256)
#[test]
fn test_kdf_mac_key() {
    let shared_secret = b"dh_secret";
    let session_id = b"session";
    let counter = 2u32; // MAC key uses counter 2
    let desired_length = 32; // HMAC-SHA256 key
    
    let result = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), 32);
}

/// Test KDF produces non-zero output
#[test]
fn test_kdf_non_zero_output() {
    let shared_secret = b"secret";
    let session_id = b"session";
    let counter = 1u32;
    let desired_length = 32;
    
    let result = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    
    // Should not be all zeros
    assert!(!result.iter().all(|&b| b == 0));
}

/// Test KDF with desired_length = 0
#[test]
fn test_kdf_zero_length() {
    let shared_secret = b"secret";
    let session_id = b"session";
    let counter = 1u32;
    let desired_length = 0;
    
    let result = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), 0);
}

/// Test KDF with desired_length = 1
#[test]
fn test_kdf_one_byte() {
    let shared_secret = b"secret";
    let session_id = b"session";
    let counter = 1u32;
    let desired_length = 1;
    
    let result = kdf(shared_secret, session_id, counter, desired_length, HashAlgorithm::Sha256);
    assert_eq!(result.len(), 1);
}