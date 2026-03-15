//! AES-GCM Cipher for SSH
//!
//! This module implements AES-GCM (Galois/Counter Mode) authenticated encryption
//! as used in modern SSH implementations. AES-GCM provides both confidentiality
//! and integrity protection for encrypted data.
//!
//! # AES-GCM Overview
//!
//! AES-GCM is an authenticated encryption mode that combines:
//! - AES in Counter mode (CTR) for encryption
//! - Galois Counter Mode (GCM) for authentication
//!
//! It provides:
//! - **Confidentiality**: Encrypts data using AES-256
//! - **Integrity**: Authenticates data using a 128-bit authentication tag
//! - **Non-repudiation**: Prevents tampering detection
//!
//! # SSH Usage
//!
//! In SSH (RFC 4253), AES-GCM is used to protect the confidentiality and integrity
//! of data transferred over the secure channel. The cipher uses:
//! - 256-bit keys (32 bytes)
//! - 96-bit nonces (12 bytes)
//! - 128-bit authentication tags (16 bytes)
//!
//! # Security Considerations
//!
//! - Always use unique nonces for the same key
//! - Never reuse a (key, nonce) pair
//! - The authentication tag is appended to ciphertext
//! - Verify authentication before decrypting sensitive data

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use thiserror::Error;

/// Error type for cipher operations
#[derive(Debug, Error, PartialEq)]
pub enum CipherError {
    /// Invalid key size (expected 32 bytes for AES-256)
    #[error("Invalid key size: expected 32 bytes")]
    InvalidKeySize,
    
    /// Invalid nonce size (expected 12 bytes for AES-GCM)
    #[error("Invalid nonce size: expected 12 bytes")]
    InvalidNonceSize,
    
    /// Authentication failed (tampered or corrupted data)
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    /// Encryption/decryption error
    #[error("Encryption/decryption error: {0}")]
    CryptoError(String),
}

/// Encrypt data using AES-256-GCM
///
/// # Arguments
///
/// * `key` - 32-byte (256-bit) encryption key
/// * `nonce` - 12-byte (96-bit) nonce (must be unique per encryption)
/// * `plaintext` - Data to encrypt
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Ciphertext with authentication tag appended
/// * `Err(CipherError)` - Error if key/nonce size is invalid or encryption fails
///
/// # Example
///
/// ```
/// use ssh_client::crypto::cipher::{aes_gcm_encrypt, aes_gcm_decrypt};
///
/// let key = vec![0x00; 32];
/// let nonce = vec![0x00; 12];
/// let plaintext = b"Hello, SSH!";
///
/// let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
/// let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
///
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // Validate key size
    if key.len() != 32 {
        return Err(CipherError::InvalidKeySize);
    }
    
    // Validate nonce size
    if nonce.len() != 12 {
        return Err(CipherError::InvalidNonceSize);
    }
    
    // Create AES-256-GCM key
    let key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|e| CipherError::CryptoError(e.to_string()))?;
    let encrypting_key = LessSafeKey::new(key);
    
    // Create nonce
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|e| CipherError::CryptoError(e.to_string()))?;
    
    // Encrypt - we need to copy plaintext to a mutable buffer
    let mut buffer = plaintext.to_vec();
    let tag = encrypting_key
        .seal_in_place_separate_tag(nonce, Aad::empty(), &mut buffer)
        .map_err(|e| CipherError::CryptoError(e.to_string()))?;
    
    // Append tag to ciphertext
    buffer.extend_from_slice(tag.as_ref());
    Ok(buffer)
}

/// Decrypt data using AES-256-GCM
///
/// # Arguments
///
/// * `key` - 32-byte (256-bit) encryption key
/// * `nonce` - 12-byte (96-bit) nonce (must match encryption nonce)
/// * `ciphertext` - Ciphertext with authentication tag
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext
/// * `Err(CipherError)` - Error if key/nonce size is invalid or authentication fails
///
/// # Example
///
/// ```
/// use ssh_client::crypto::cipher::{aes_gcm_encrypt, aes_gcm_decrypt};
///
/// let key = vec![0x00; 32];
/// let nonce = vec![0x00; 12];
/// let plaintext = b"Hello, SSH!";
///
/// let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
/// let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
///
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
    // Validate key size
    if key.len() != 32 {
        return Err(CipherError::InvalidKeySize);
    }
    
    // Validate nonce size
    if nonce.len() != 12 {
        return Err(CipherError::InvalidNonceSize);
    }
    
    // Split ciphertext and tag (last 16 bytes is the tag)
    if ciphertext.len() < 16 {
        return Err(CipherError::AuthenticationFailed);
    }
    
    let (ciphertext_only, tag_bytes) = ciphertext.split_at(ciphertext.len() - 16);
    
    // Create AES-256-GCM key
    let key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|e| CipherError::CryptoError(e.to_string()))?;
    let decrypting_key = LessSafeKey::new(key);
    
    // Create nonce
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|e| CipherError::CryptoError(e.to_string()))?;
    
    // Decrypt using open_in_place_separate_tag
    let mut buffer = ciphertext_only.to_vec();
    
    // Convert tag_bytes to Tag
    use ring::aead::Tag;
    let tag = Tag::try_from(tag_bytes).map_err(|_| CipherError::AuthenticationFailed)?;
    
    match decrypting_key.open_in_place_separate_tag(
        nonce,
        Aad::empty(),
        tag,
        &mut buffer,
        0..,
    ) {
        Ok(_) => Ok(buffer),
        Err(_) => Err(CipherError::AuthenticationFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = vec![0x00; 32];
        let nonce = vec![0x00; 12];
        let plaintext = b"Hello, World!";
        
        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_keys() {
        let key1 = vec![0x00; 32];
        let key2 = vec![0xFF; 32];
        let nonce = vec![0x00; 12];
        let plaintext = b"test";
        
        let ct1 = aes_gcm_encrypt(&key1, &nonce, plaintext).unwrap();
        let ct2 = aes_gcm_encrypt(&key2, &nonce, plaintext).unwrap();
        
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_different_nonces() {
        let key = vec![0x00; 32];
        let nonce1 = vec![0x00; 12];
        let nonce2 = vec![0x01; 12];
        let plaintext = b"test";
        
        let ct1 = aes_gcm_encrypt(&key, &nonce1, plaintext).unwrap();
        let ct2 = aes_gcm_encrypt(&key, &nonce2, plaintext).unwrap();
        
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = vec![0x00; 32];
        let nonce = vec![0x00; 12];
        let plaintext = b"";
        
        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_auth_failure_tampered() {
        let key = vec![0x00; 32];
        let nonce = vec![0x00; 12];
        let plaintext = b"secret";
        
        let mut ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        ciphertext[0] ^= 0xFF;
        
        let result = aes_gcm_decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_failure_wrong_key() {
        let key1 = vec![0x00; 32];
        let key2 = vec![0xFF; 32];
        let nonce = vec![0x00; 12];
        let plaintext = b"secret";
        
        let ciphertext = aes_gcm_encrypt(&key1, &nonce, plaintext).unwrap();
        
        let result = aes_gcm_decrypt(&key2, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_size() {
        let key = vec![0x00; 16];
        let nonce = vec![0x00; 12];
        let plaintext = b"test";
        
        let result = aes_gcm_encrypt(&key, &nonce, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CipherError::InvalidKeySize);
    }

    #[test]
    fn test_invalid_nonce_size() {
        let key = vec![0x00; 32];
        let nonce = vec![0x00; 8];
        let plaintext = b"test";
        
        let result = aes_gcm_encrypt(&key, &nonce, plaintext);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CipherError::InvalidNonceSize);
    }
}