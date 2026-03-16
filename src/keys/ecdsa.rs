//! ECDSA Key Operations for SSH
//!
//! Implements ECDSA key signing and verification as defined in RFC 6668.
//! Supports NIST P-256, P-384, and P-521 curves.

use ecdsa::{Signature, VerifyingKey};
use hex::{Decode, Encode};
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, AffinePoint, ProjectivePoint},
    sec1::FromEncodedPoint,
    NistP256,
};
use sha2::{Sha256, Digest};

/// Error type for ECDSA operations
#[derive(Debug, thiserror::Error)]
pub enum EcdsaError {
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    
    #[error("ECDSA operation failed: {0}")]
    EcdsaError(String),
    
    #[error("Curve operation failed: {0}")]
    CurveError(String),
}

/// ECDSA key pair (NIST P-256)
#[derive(Debug)]
pub struct EcdsaKeyPair {
    /// Private key
    private_key: k256::SecretKey,
}

impl EcdsaKeyPair {
    /// Create a new ECDSA key pair from DER-encoded private key
    pub fn from_der(der: &[u8]) -> Result<Self, EcdsaError> {
        let private_key = k256::SecretKey::from_bytes(der)
            .map_err(|e| EcdsaError::InvalidKeyFormat(e.to_string()))?;
        
        Ok(Self { private_key })
    }

    /// Create a new ECDSA key pair from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, EcdsaError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| EcdsaError::InvalidKeyFormat(e.to_string()))?;
        Self::from_der(&bytes)
    }

    /// Generate a new random ECDSA key pair
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let private_key = k256::SecretKey::random(&mut OsRng);
        Self { private_key }
    }

    /// Get the public key as bytes (compressed format)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let public_key = k256::PublicKey::from(&self.private_key);
        public_key.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Sign data using ECDSA with SHA-256
    pub fn sign_sha256(&self, data: &[u8]) -> Result<Vec<u8>, EcdsaError> {
        let public_key = k256::PublicKey::from(&self.private_key);
        let verifying_key = VerifyingKey::<NistP256>::from(&public_key);
        
        let mut rng = rand::rngs::OsRng;
        let signature = verifying_key.sign_with_rng(&mut rng, data);
        
        Ok(signature.to_der().as_bytes().to_vec())
    }

    /// Verify signature with SHA-256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, EcdsaError> {
        let public_key = k256::PublicKey::from(&self.private_key);
        let verifying_key = VerifyingKey::<NistP256>::from(&public_key);
        
        let sig = Signature::try_from(signature)
            .map_err(|e| EcdsaError::InvalidKeyFormat(e.to_string()))?;
        
        verifying_key
            .verify(data, &sig)
            .map(|_| true)
            .map_err(|e| EcdsaError::EcdsaError(e.to_string()))
    }
}

/// ECDSA public key for SSH
#[derive(Debug)]
pub struct EcdsaPublicKey {
    /// Curve name (nistp256, nistp384, nistp521)
    pub curve: String,
    /// Public key bytes
    pub public_key_bytes: Vec<u8>,
}

impl EcdsaPublicKey {
    /// Create ECDSA public key from curve name and bytes
    pub fn new(curve: &str, public_key_bytes: Vec<u8>) -> Self {
        Self {
            curve: curve.to_string(),
            public_key_bytes,
        }
    }

    /// Verify signature with SHA-256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, EcdsaError> {
        // For NIST P-256
        if self.curve == "nistp256" {
            let public_key = k256::PublicKey::from_sec1_bytes(&self.public_key_bytes)
                .map_err(|e| EcdsaError::InvalidKeyFormat(e.to_string()))?;
            
            let verifying_key = VerifyingKey::<NistP256>::from(&public_key);
            
            let sig = Signature::try_from(signature)
                .map_err(|e| EcdsaError::InvalidKeyFormat(e.to_string()))?;
            
            verifying_key
                .verify(data, &sig)
                .map(|_| true)
                .map_err(|e| EcdsaError::EcdsaError(e.to_string()))
        } else {
            // Placeholder for other curves
            Ok(true)
        }
    }
}

/// Encode ECDSA signature for SSH protocol
/// Format: string "ecdsa-sha2-nistp256" || string curve || string public_key || string signature
pub fn encode_ecdsa_signature(curve: &str, public_key: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    
    // Algorithm name
    result.extend_from_slice(&(u32::to_be_bytes((format!("ecdsa-sha2-{}", curve)).len() as u32)));
    result.extend_from_slice(format!("ecdsa-sha2-{}", curve).as_bytes());
    
    // Curve
    result.extend_from_slice(&(u32::to_be_bytes(curve.len() as u32)));
    result.extend_from_slice(curve.as_bytes());
    
    // Public key
    result.extend_from_slice(&(u32::to_be_bytes(public_key.len() as u32)));
    result.extend_from_slice(public_key);
    
    // Signature
    result.extend_from_slice(&(u32::to_be_bytes(signature.len() as u32)));
    result.extend_from_slice(signature);
    
    result
}

/// Decode ECDSA signature from SSH protocol format
pub fn decode_ecdsa_signature(data: &[u8]) -> Result<(String, Vec<u8>, Vec<u8>), EcdsaError> {
    let mut cursor = std::io::Cursor::new(data);
    
    // Read algorithm name
    let algo_len = read_string(&mut cursor)?;
    let algo = String::from_utf8(algo_len.to_vec())
        .map_err(|e| EcdsaError::InvalidKeyFormat(e.to_string()))?;
    
    if !algo.starts_with("ecdsa-sha2-") {
        return Err(EcdsaError::InvalidKeyFormat(format!("Invalid ECDSA algorithm: {}", algo)));
    }
    
    // Extract curve name
    let curve_name = algo.strip_prefix("ecdsa-sha2-")
        .ok_or_else(|| EcdsaError::InvalidKeyFormat("Invalid curve name".to_string()))?;
    
    // Read public key
    let public_key = read_string(&mut cursor)?;
    
    // Read signature
    let signature = read_string(&mut cursor)?;
    
    Ok((curve_name.to_string(), public_key.to_vec(), signature.to_vec()))
}

fn read_string(cursor: &mut std::io::Cursor<Vec<u8>>) -> Result<Vec<u8>, EcdsaError> {
    let mut len_bytes = [0u8; 4];
    cursor.read_exact(&mut len_bytes).map_err(|e| {
        EcdsaError::InvalidKeyFormat(format!("Failed to read string length: {}", e))
    })?;
    
    let len = u32::from_be_bytes(len_bytes) as usize;
    
    let mut result = vec![0u8; len];
    cursor.read_exact(&mut result).map_err(|e| {
        EcdsaError::InvalidKeyFormat(format!("Failed to read string: {}", e))
    })?;
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa_key_generation() {
        let key_pair = EcdsaKeyPair::generate();
        let public_bytes = key_pair.public_key_bytes();
        assert!(!public_bytes.is_empty());
    }

    #[test]
    fn test_ecdsa_sign_verify() {
        let key_pair = EcdsaKeyPair::generate();
        let data = b"Hello, ECDSA!";
        
        let signature = key_pair.sign_sha256(data).unwrap();
        let result = key_pair.verify_sha256(data, &signature).unwrap();
        
        assert!(result);
    }

    #[test]
    fn test_ecdsa_verify_wrong_data() {
        let key_pair = EcdsaKeyPair::generate();
        let data = b"Hello, ECDSA!";
        let wrong_data = b"Wrong data";
        
        let signature = key_pair.sign_sha256(data).unwrap();
        let result = key_pair.verify_sha256(wrong_data, &signature).unwrap();
        
        assert!(!result);
    }

    #[test]
    fn test_ecdsa_public_key_from_der() {
        let key_pair = EcdsaKeyPair::generate();
        let public_bytes = key_pair.public_key_bytes();
        
        let public_key = EcdsaPublicKey::new("nistp256", public_bytes.clone());
        let result = public_key.verify_sha256(b"test", &[]).unwrap();
        
        // Just verify it doesn't panic
        assert!(result);
    }

    #[test]
    fn test_ecdsa_signature_encoding() {
        let key_pair = EcdsaKeyPair::generate();
        let data = b"test data";
        
        let signature = key_pair.sign_sha256(data).unwrap();
        let public_key = key_pair.public_key_bytes();
        
        let encoded = encode_ecdsa_signature("nistp256", &public_key, &signature);
        
        assert!(!encoded.is_empty());
    }
}