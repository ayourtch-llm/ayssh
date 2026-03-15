//! Keys module - SSH key handling and formats

// Note: These modules will be implemented in later tasks
// pub mod formats;
// pub mod rsa;
// pub mod ecdsa;
// pub mod ed25519;

use std::fmt::Debug;

/// Placeholder for SSH key pair (to be implemented in Task 8)
#[derive(Debug)]
pub struct KeyPair {
    /// Key type
    pub key_type: String,
    /// Public key data
    pub public_key: Vec<u8>,
    /// Private key data (encrypted or unencrypted)
    pub private_key: Vec<u8>,
}

impl KeyPair {
    /// Create a new key pair placeholder
    pub fn new(key_type: &str, public_key: Vec<u8>, private_key: Vec<u8>) -> Self {
        Self {
            key_type: key_type.to_string(),
            public_key,
            private_key,
        }
    }

    /// Get the key type
    pub fn key_type(&self) -> &str {
        &self.key_type
    }
}

// Re-export commonly used items

