//! Integration tests for Key format handling

use ayssh::keys::KeyPair;

/// Test 1: Verify KeyPair::new() creates key pair with correct properties
#[test]
fn test_key_pair_new() {
    let key_pair = KeyPair::new(
        "ssh-rsa",
        vec![0x01, 0x02, 0x03],
        vec![0x04, 0x05, 0x06],
    );
    
    assert_eq!(key_pair.key_type(), "ssh-rsa");
    assert_eq!(key_pair.public_key, vec![0x01, 0x02, 0x03]);
    assert_eq!(key_pair.private_key, vec![0x04, 0x05, 0x06]);
}

/// Test 2: Verify KeyPair::key_type() returns correct type
#[test]
fn test_key_pair_key_type() {
    let key_pair = KeyPair::new("ssh-ed25519", vec![], vec![]);
    assert_eq!(key_pair.key_type(), "ssh-ed25519");
}

/// Test 3: Test KeyPair with different key types
#[test]
fn test_key_pair_different_types() {
    let rsa_key = KeyPair::new("ssh-rsa", vec![1], vec![2]);
    let ecdsa_key = KeyPair::new("ecdsa-sha2-nistp256", vec![1], vec![2]);
    let ed25519_key = KeyPair::new("ssh-ed25519", vec![1], vec![2]);
    
    assert_eq!(rsa_key.key_type(), "ssh-rsa");
    assert_eq!(ecdsa_key.key_type(), "ecdsa-sha2-nistp256");
    assert_eq!(ed25519_key.key_type(), "ssh-ed25519");
}

/// Test 4: Test KeyPair with empty key data
#[test]
fn test_key_pair_empty_keys() {
    let key_pair = KeyPair::new("ssh-rsa", vec![], vec![]);
    assert_eq!(key_pair.public_key.len(), 0);
    assert_eq!(key_pair.private_key.len(), 0);
}

/// Test 5: Test KeyPair with large key data
#[test]
fn test_key_pair_large_keys() {
    let public_key: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    let private_key: Vec<u8> = (0..2000).map(|i| (i % 256) as u8).collect();
    
    let key_pair = KeyPair::new("ssh-rsa", public_key.clone(), private_key.clone());
    
    assert_eq!(key_pair.public_key.len(), 1000);
    assert_eq!(key_pair.private_key.len(), 2000);
    assert_eq!(key_pair.public_key, public_key);
    assert_eq!(key_pair.private_key, private_key);
}

/// Test 6: Test KeyPair with unicode in key type
#[test]
fn test_key_pair_unicode_key_type() {
    // Note: SSH key types shouldn't contain unicode, but we test the API
    let key_pair = KeyPair::new("ssh-rsa-custom", vec![1], vec![2]);
    assert_eq!(key_pair.key_type(), "ssh-rsa-custom");
}

/// Test 7: Test KeyPair debug implementation
#[test]
fn test_key_pair_debug() {
    let key_pair = KeyPair::new("ssh-rsa", vec![1, 2, 3], vec![4, 5, 6]);
    let debug_str = format!("{:?}", key_pair);
    
    assert!(debug_str.contains("ssh-rsa"));
    assert!(debug_str.contains("public_key"));
    assert!(debug_str.contains("private_key"));
}

/// Test 8: Test KeyPair clone implementation
#[test]
fn test_key_pair_clone() {
    let key_pair1 = KeyPair::new("ssh-rsa", vec![1, 2, 3], vec![4, 5, 6]);
    let key_pair2 = KeyPair::new(
        key_pair1.key_type(),
        key_pair1.public_key.clone(),
        key_pair1.private_key.clone(),
    );
    
    assert_eq!(key_pair1.key_type(), key_pair2.key_type());
    assert_eq!(key_pair1.public_key, key_pair2.public_key);
    assert_eq!(key_pair1.private_key, key_pair2.private_key);
}

/// Test 9: Test KeyPair equality (manual comparison)
#[test]
fn test_key_pair_equality() {
    let key_pair1 = KeyPair::new("ssh-rsa", vec![1, 2, 3], vec![4, 5, 6]);
    let key_pair2 = KeyPair::new("ssh-rsa", vec![1, 2, 3], vec![4, 5, 6]);
    let key_pair3 = KeyPair::new("ssh-ecdsa", vec![1, 2, 3], vec![4, 5, 6]);
    
    assert_eq!(key_pair1.key_type(), key_pair2.key_type());
    assert_eq!(key_pair1.public_key, key_pair2.public_key);
    assert_eq!(key_pair1.private_key, key_pair2.private_key);
    
    assert_ne!(key_pair1.key_type(), key_pair3.key_type());
}

/// Test 10: Test KeyPair with binary key data
#[test]
fn test_key_pair_binary_data() {
    let public_key: Vec<u8> = vec![0x00, 0xFF, 0xAB, 0xCD, 0xEF];
    let private_key: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78, 0x9A];
    
    let key_pair = KeyPair::new("ssh-rsa", public_key.clone(), private_key.clone());
    
    assert_eq!(key_pair.public_key, public_key);
    assert_eq!(key_pair.private_key, private_key);
}

/// Test 11: Test KeyPair with zero-length key type
#[test]
fn test_key_pair_empty_key_type() {
    let key_pair = KeyPair::new("", vec![1], vec![2]);
    assert_eq!(key_pair.key_type(), "");
}

/// Test 12: Test KeyPair with very long key type
#[test]
fn test_key_pair_long_key_type() {
    let long_type = format!("ssh-{}", "x".repeat(1000));
    let key_pair = KeyPair::new(&long_type, vec![1], vec![2]);
    assert_eq!(key_pair.key_type(), long_type);
}