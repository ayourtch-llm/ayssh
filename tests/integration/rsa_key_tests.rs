//! Integration tests for RSA key handling

use ayssh::keys::KeyPair;

/// Test 1: Verify RSA key pair creation
#[test]
fn test_rsa_key_pair_creation() {
    let public_key = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let private_key = vec![0x06, 0x07, 0x08, 0x09, 0x0A];
    
    let key_pair = KeyPair::new("ssh-rsa", public_key.clone(), private_key.clone());
    
    assert_eq!(key_pair.key_type(), "ssh-rsa");
    assert_eq!(key_pair.public_key, public_key);
    assert_eq!(key_pair.private_key, private_key);
}

/// Test 2: Test RSA key with 1024-bit key size
#[test]
fn test_rsa_key_1024bit() {
    let public_key: Vec<u8> = vec![0; 128]; // 1024 bits = 128 bytes
    let private_key: Vec<u8> = vec![0; 256]; // 2048 bits = 256 bytes (typical)
    
    let key_pair = KeyPair::new("ssh-rsa", public_key.clone(), private_key.clone());
    
    assert_eq!(key_pair.public_key.len(), 128);
    assert_eq!(key_pair.private_key.len(), 256);
}

/// Test 3: Test RSA key with 2048-bit key size
#[test]
fn test_rsa_key_2048bit() {
    let public_key: Vec<u8> = vec![0; 256]; // 2048 bits = 256 bytes
    let private_key: Vec<u8> = vec![0; 512]; // 4096 bits = 512 bytes (typical)
    
    let key_pair = KeyPair::new("ssh-rsa", public_key.clone(), private_key.clone());
    
    assert_eq!(key_pair.public_key.len(), 256);
    assert_eq!(key_pair.private_key.len(), 512);
}

/// Test 4: Test RSA key with 4096-bit key size
#[test]
fn test_rsa_key_4096bit() {
    let public_key: Vec<u8> = vec![0; 512]; // 4096 bits = 512 bytes
    let private_key: Vec<u8> = vec![0; 1024]; // 8192 bits = 1024 bytes (typical)
    
    let key_pair = KeyPair::new("ssh-rsa", public_key.clone(), private_key.clone());
    
    assert_eq!(key_pair.public_key.len(), 512);
    assert_eq!(key_pair.private_key.len(), 1024);
}

/// Test 5: Test RSA key signing (placeholder - actual signing not implemented)
#[test]
fn test_rsa_key_signing_placeholder() {
    // RSA signing is not yet implemented in the placeholder
    // This test verifies the KeyPair structure exists and can be created
    let key_pair = KeyPair::new(
        "ssh-rsa",
        vec![0x01, 0x02, 0x03],
        vec![0x04, 0x05, 0x06],
    );
    
    assert_eq!(key_pair.key_type(), "ssh-rsa");
    assert!(!key_pair.public_key.is_empty());
    assert!(!key_pair.private_key.is_empty());
}

/// Test 6: Test RSA key verification (placeholder - actual verification not implemented)
#[test]
fn test_rsa_key_verification_placeholder() {
    // RSA verification is not yet implemented in the placeholder
    // This test verifies the KeyPair structure exists and can be created
    let key_pair = KeyPair::new(
        "ssh-rsa",
        vec![0x01, 0x02, 0x03],
        vec![0x04, 0x05, 0x06],
    );
    
    assert_eq!(key_pair.key_type(), "ssh-rsa");
    assert_eq!(key_pair.public_key.len(), 3);
    assert_eq!(key_pair.private_key.len(), 3);
}

/// Test 7: Test RSA key error handling (empty keys)
#[test]
fn test_rsa_key_empty_keys() {
    let key_pair = KeyPair::new("ssh-rsa", vec![], vec![]);
    
    assert_eq!(key_pair.key_type(), "ssh-rsa");
    assert!(key_pair.public_key.is_empty());
    assert!(key_pair.private_key.is_empty());
}

/// Test 8: Test RSA key with binary data
#[test]
fn test_rsa_key_binary_data() {
    let public_key: Vec<u8> = vec![0x00, 0xFF, 0xAB, 0xCD, 0xEF, 0x12];
    let private_key: Vec<u8> = vec![0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE];
    
    let key_pair = KeyPair::new("ssh-rsa", public_key.clone(), private_key.clone());
    
    assert_eq!(key_pair.public_key, public_key);
    assert_eq!(key_pair.private_key, private_key);
}

/// Test 9: Test RSA key debug implementation
#[test]
fn test_rsa_key_debug() {
    let key_pair = KeyPair::new("ssh-rsa", vec![1, 2, 3], vec![4, 5, 6]);
    let debug_str = format!("{:?}", key_pair);
    
    assert!(debug_str.contains("ssh-rsa"));
    assert!(debug_str.contains("public_key"));
    assert!(debug_str.contains("private_key"));
}

/// Test 10: Test RSA key with different key type strings
#[test]
fn test_rsa_key_different_type_strings() {
    let key1 = KeyPair::new("ssh-rsa", vec![1], vec![2]);
    let key2 = KeyPair::new("RSA", vec![1], vec![2]);
    let key3 = KeyPair::new("rsa-sha2-256", vec![1], vec![2]);
    
    assert_eq!(key1.key_type(), "ssh-rsa");
    assert_eq!(key2.key_type(), "RSA");
    assert_eq!(key3.key_type(), "rsa-sha2-256");
}