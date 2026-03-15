//! Ed25519 Key Operations for SSH
//!
//! Implements Ed25519 key signing and verification as defined in RFC 8332.

use ed25519_dalek::{Signature, Signer, Verifier, ed25519::Signer as DalekSigner};
use sha2::Digest;

/// Error type for Ed25519 operations
#[derive(Debug, thiserror::Error)]
pub enum Ed25519Error {
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    
    #[error("Ed25519 operation failed: {0}")]
    Ed25519Error(String),
}

/// Ed25519 key pair
#[derive(Debug)]
pub struct Ed25519KeyPair {
    /// Private key
    private_key: ed25519_dalek::SecretKey,
    /// Public key
    public_key: ed25519_dalek::PublicKey,
}

impl Ed25519KeyPair {
    /// Create a new Ed25519 key pair from a seed
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, Ed25519Error> {
        let sk = ed25519_dalek::SecretKey::from_bytes(seed)
            .map_err(|e| Ed25519Error::InvalidKeyFormat(e.to_string()))?;
        
        let vk = ed25519_dalek::PublicKey::from(&sk);
        
        Ok(Self {
            private_key: sk,
            public_key: vk,
        })
    }

    /// Generate a new random Ed25519 key pair
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        
        let sk = ed25519_dalek::SecretKey::generate(&mut csprng);
        let vk = ed25519_dalek::PublicKey::from(&sk);
        
        Self {
            private_key: sk,
            public_key: vk,
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(private: &[u8], public: &[u8]) -> Result<Self, Ed25519Error> {
        let private_key = ed25519_dalek::SecretKey::from_bytes(private)
            .map_err(|e| Ed25519Error::InvalidKeyFormat(e.to_string()))?;
        
        let public_key = ed25519_dalek::PublicKey::from_bytes(public)
            .map_err(|e| Ed25519Error::InvalidKeyFormat(e.to_string()))?;
        
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Sign data using Ed25519
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature = self.private_key.sign(data);
        signature.to_bytes().to_vec()
    }

    /// Verify signature
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Ed25519Error> {
        let sig = Signature::from_slice(signature)
            .map_err(|e| Ed25519Error::InvalidKeyFormat(e.to_string()))?;
        
        self.public_key
            .verify(data, &sig)
            .map(|_| true)
            .map_err(|e| Ed25519Error::Ed25519Error(e.to_string()))
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    /// Get private key bytes
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.private_key.to_bytes().to_vec()
    }
}

/// Ed25519 public key for SSH
#[derive(Debug)]
pub struct Ed25519PublicKey {
    /// Public key bytes (32 bytes)
    pub public_key: [u8; 32],
}

impl Ed25519PublicKey {
    /// Create Ed25519 public key from bytes
    pub fn new(public_key: [u8; 32]) -> Self {
        Self { public_key }
    }

    /// Verify signature
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Ed25519Error> {
        let sig = Signature::from_slice(signature)
            .map_err(|e| Ed25519Error::InvalidKeyFormat(e.to_string()))?;
        
        let public_key = ed25519_dalek::PublicKey::from_bytes(&self.public_key)
            .map_err(|e| Ed25519Error::InvalidKeyFormat(e.to_string()))?;
        
        public_key
            .verify(data, &sig)
            .map(|_| true)
            .map_err(|e| Ed25519Error::Ed25519Error(e.to_string()))
    }
}

/// Encode Ed25519 public key for SSH protocol
/// Format: string "ssh-ed25519" || string public_key
pub fn encode_ed25519_public_key(public_key: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    
    // Algorithm name
    result.extend_from_slice(&(u32::to_be_bytes(9))); // "ssh-ed25519".len()
    result.extend_from_slice(b"ssh-ed25519");
    
    // Public key (32 bytes)
    result.extend_from_slice(&(u32::to_be_bytes(32)));
    result.extend_from_slice(public_key);
    
    result
}

/// Decode Ed25519 public key from SSH protocol format
pub fn decode_ed25519_public_key(data: &[u8]) -> Result<[u8; 32], Ed25519Error> {
    if data.len() < 41 { // 9 (algo) + 4 (len) + 32 (key)
        return Err(Ed25519Error::InvalidKeyFormat("Data too short".to_string()));
    }
    
    // Skip algorithm name
    let algo_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if algo_len != 9 || &data[4..13] != b"ssh-ed25519" {
        return Err(Ed25519Error::InvalidKeyFormat("Invalid algorithm".to_string()));
    }
    
    // Read public key length
    let key_len = u32::from_be_bytes([data[13], data[14], data[15], data[16]]) as usize;
    if key_len != 32 {
        return Err(Ed25519Error::InvalidKeyFormat("Invalid key length".to_string()));
    }
    
    // Extract public key
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&data[17..49]);
    
    Ok(public_key)
}

/// Encode Ed25519 signature for SSH authentication
/// Format: string "ssh-ed25519" || string public_key || string signature
pub fn encode_ed25519_signature(public_key: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    
    // Algorithm name
    result.extend_from_slice(&(u32::to_be_bytes(9)));
    result.extend_from_slice(b"ssh-ed25519");
    
    // Public key
    result.extend_from_slice(&(u32::to_be_bytes(32)));
    result.extend_from_slice(public_key);
    
    // Signature (64 bytes)
    result.extend_from_slice(&(u32::to_be_bytes(64)));
    result.extend_from_slice(signature);
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_key_generation() {
        let key_pair = Ed25519KeyPair::generate();
        let public_bytes = key_pair.public_key_bytes();
        assert_eq!(public_bytes.len(), 32);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let key_pair = Ed25519KeyPair::generate();
        let data = b"Hello, Ed25519!";
        
        let signature = key_pair.sign(data);
        let result = key_pair.verify(data, &signature).unwrap();
        
        assert!(result);
    }

    #[test]
    fn test_ed25519_verify_wrong_data() {
        let key_pair = Ed25519KeyPair::generate();
        let data = b"Hello, Ed25519!";
        let wrong_data = b"Wrong data";
        
        let signature = key_pair.sign(data);
        let result = key_pair.verify(wrong_data, &signature).unwrap();
        
        assert!(!result);
    }

    #[test]
    fn test_ed25519_from_seed() {
        let seed = [0u8; 32];
        let key_pair = Ed25519KeyPair::from_seed(&seed).unwrap();
        assert_eq!(key_pair.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_ed25519_public_key_encoding() {
        let key_pair = Ed25519KeyPair::generate();
        let public_bytes = key_pair.public_key_bytes();
        
        let encoded = encode_ed25519_public_key(&public_bytes);
        
        assert!(encoded.len() >= 41);
    }

    #[test]
    fn test_ed25519_public_key_decoding() {
        let key_pair = Ed25519KeyPair::generate();
        let public_bytes = key_pair.public_key_bytes();
        
        let encoded = encode_ed25519_public_key(&public_bytes);
        let decoded = decode_ed25519_public_key(&encoded).unwrap();
        
        assert_eq!(decoded, public_bytes.as_slice());
    }
}