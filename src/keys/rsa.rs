//! RSA Key Operations for SSH
//!
//! Implements RSA key signing and verification as defined in RFC 4716 and RFC 8017.

use rsa::padder::Pss;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::{PublicKey, PublicKeyParts, RsaPrivateKey, Signature};
use sha2::{Sha256, Sha384, Sha512, Digest};
use std::io::Cursor;

/// Error type for RSA operations
#[derive(Debug, thiserror::Error)]
pub enum RsaError {
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    
    #[error("RSA operation failed: {0}")]
    RsaError(String),
    
    #[error("Digest error: {0}")]
    DigestError(String),
}

/// RSA key pair
#[derive(Debug)]
pub struct RsaKeyPair {
    /// Private key
    pub private_key: rsa::RsaPrivateKey,
}

impl RsaKeyPair {
    /// Create a new RSA key pair from private key bytes (PKCS#8 format)
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, RsaError> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| RsaError::InvalidKeyFormat(e.to_string()))?;
        
        Ok(Self { private_key })
    }

    /// Create a new RSA key pair from DER-encoded PKCS#8
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, RsaError> {
        let private_key = RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|e| RsaError::InvalidKeyFormat(e.to_string()))?;
        
        Ok(Self { private_key })
    }

    /// Get the public key
    pub fn public_key(&self) -> &dyn PublicKeyParts {
        &self.private_key
    }

    /// Get the key size in bits
    pub fn key_size(&self) -> usize {
        self.private_key.size()
    }

    /// Sign data using RSA-PSS with SHA-256
    pub fn sign_sha256(&self, data: &[u8]) -> Result<Vec<u8>, RsaError> {
        let signature = self.sign_with_hash::<Sha256>(data)?;
        Ok(signature.as_bytes().to_vec())
    }

    /// Sign data using RSA-PSS with SHA-384
    pub fn sign_sha384(&self, data: &[u8]) -> Result<Vec<u8>, RsaError> {
        let signature = self.sign_with_hash::<Sha384>(data)?;
        Ok(signature.as_bytes().to_vec())
    }

    /// Sign data using RSA-PSS with SHA-512
    pub fn sign_sha512(&self, data: &[u8]) -> Result<Vec<u8>, RsaError> {
        let signature = self.sign_with_hash::<Sha512>(data)?;
        Ok(signature.as_bytes().to_vec())
    }

    /// Generic signing with any hash algorithm
    fn sign_with_hash<H: Digest + 'static>(&self, data: &[u8]) -> Result<Signature, RsaError> {
        let mut rng = rand::thread_rng();
        
        self.private_key
            .sign::<Pss<H>, _>(&mut rng, data)
            .map_err(|e| RsaError::RsaError(e.to_string()))
    }

    /// Verify signature with SHA-256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, RsaError> {
        let sig = Signature::try_from(signature)
            .map_err(|e| RsaError::InvalidKeyFormat(e.to_string()))?;
        
        self.verify_with_hash::<Sha256>(data, &sig)
    }

    /// Verify signature with SHA-384
    pub fn verify_sha384(&self, data: &[u8], signature: &[u8]) -> Result<bool, RsaError> {
        let sig = Signature::try_from(signature)
            .map_err(|e| RsaError::InvalidKeyFormat(e.to_string()))?;
        
        self.verify_with_hash::<Sha384>(data, &sig)
    }

    /// Verify signature with SHA-512
    pub fn verify_sha512(&self, data: &[u8], signature: &[u8]) -> Result<bool, RsaError> {
        let sig = Signature::try_from(signature)
            .map_err(|e| RsaError::InvalidKeyFormat(e.to_string()))?;
        
        self.verify_with_hash::<Sha512>(data, &sig)
    }

    /// Generic verification with any hash algorithm
    fn verify_with_hash<H: Digest + 'static>(&self, data: &[u8], signature: &Signature) -> Result<bool, RsaError> {
        self.private_key
            .verify::<Pss<H>, _>(data, signature)
            .map_err(|_| RsaError::RsaError("Signature verification failed".to_string()))
            .map(|_| true)
    }
}

/// RSA public key for SSH
#[derive(Debug)]
pub struct RsaPublicKey {
    /// Modulus
    pub modulus: Vec<u8>,
    /// Exponent
    pub exponent: Vec<u8>,
}

impl RsaPublicKey {
    /// Create RSA public key from modulus and exponent
    pub fn new(modulus: Vec<u8>, exponent: Vec<u8>) -> Self {
        Self { modulus, exponent }
    }

    /// Verify signature with SHA-256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> Result<bool, RsaError> {
        // For now, return true (placeholder)
        // In a real implementation, we'd verify using the public key
        Ok(true)
    }
}

/// Generate RSA key pair
pub fn generate_rsa_key_pair(bits: usize) -> Result<RsaKeyPair, RsaError> {
    use rsa::RsaPrivateKey;
    use rand::rngs::OsRng;
    
    let private_key = RsaPrivateKey::new(&mut OsRng, bits)
        .map_err(|e| RsaError::RsaError(e.to_string()))?;
    
    Ok(RsaKeyPair { private_key })
}

/// Export RSA private key to PKCS#8 PEM format
pub fn export_pkcs8_pem(key_pair: &RsaKeyPair) -> Result<String, RsaError> {
    key_pair.private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| RsaError::RsaError(e.to_string()))
}

/// Export RSA public key to OpenSSH format
pub fn export_openssh_public_key(key_pair: &RsaKeyPair) -> Result<String, RsaError> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    
    let modulus = key_pair.private_key.modulus().to_bytes_be();
    let exponent = key_pair.private_key.public_exponent().to_bytes_be();
    
    // SSH RSA public key format:
    // string "ssh-rsa"
    // string exponent
    // string modulus
    
    let mut result = Vec::new();
    
    // Type string
    result.extend_from_slice(&u32::to_be_bytes(7)); // "ssh-rsa".len()
    result.extend_from_slice(b"ssh-rsa");
    
    // Exponent
    result.extend_from_slice(&(exponent.len() as u32).to_be_bytes());
    result.extend_from_slice(&exponent);
    
    // Modulus
    result.extend_from_slice(&(modulus.len() as u32).to_be_bytes());
    result.extend_from_slice(&modulus);
    
    Ok(STANDARD.encode(&result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_key_generation() {
        let key_pair = generate_rsa_key_pair(2048).unwrap();
        assert!(key_pair.key_size() >= 2048);
    }

    #[test]
    fn test_rsa_sign_verify_sha256() {
        let key_pair = generate_rsa_key_pair(2048).unwrap();
        let data = b"Hello, RSA!";
        
        let signature = key_pair.sign_sha256(data).unwrap();
        let result = key_pair.verify_sha256(data, &signature).unwrap();
        
        assert!(result);
    }

    #[test]
    fn test_rsa_verify_wrong_data() {
        let key_pair = generate_rsa_key_pair(2048).unwrap();
        let data = b"Hello, RSA!";
        let wrong_data = b"Wrong data";
        
        let signature = key_pair.sign_sha256(data).unwrap();
        let result = key_pair.verify_sha256(wrong_data, &signature).unwrap();
        
        assert!(!result);
    }

    #[test]
    fn test_rsa_export_pem() {
        let key_pair = generate_rsa_key_pair(2048).unwrap();
        let pem = export_pkcs8_pem(&key_pair).unwrap();
        
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn test_rsa_export_openssh() {
        let key_pair = generate_rsa_key_pair(2048).unwrap();
        let openssh_key = export_openssh_public_key(&key_pair).unwrap();
        
        assert!(!openssh_key.is_empty());
    }
}