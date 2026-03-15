//! ChaCha20-Poly1305 AEAD Cipher Implementation
//!
//! Implements ChaCha20-Poly1305 AEAD cipher as defined in RFC 8439.
//! Supports the SSH extension chacha20-poly1305@openssh.com.

use ring::aead::{LessSafeKey, UnboundKey};
use ring::rand::SystemRandom;

use crate::error::SshError;

/// Key size for ChaCha20-Poly1305 (256 bits)
pub const KEY_SIZE: usize = 32;

/// Nonce size for ChaCha20-Poly1305 (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Tag size for Poly1305 (128 bits)
pub const TAG_SIZE: usize = 16;

/// ChaCha20-Poly1305 key
#[derive(Debug, Clone)]
pub struct Key {
    bytes: [u8; KEY_SIZE],
}

impl Key {
    /// Create a key from an array
    pub const fn from(bytes: [u8; KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Get the key bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the key length
    pub const fn len() -> usize {
        KEY_SIZE
    }

    /// Create a key from a slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, SshError> {
        if slice.len() != KEY_SIZE {
            return Err(SshError::CryptoError(format!(
                "Invalid key length: expected {}, got {}",
                KEY_SIZE,
                slice.len()
            )));
        }

        let mut bytes = [0u8; KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }
}

/// ChaCha20-Poly1305 nonce
#[derive(Debug, Clone)]
pub struct Nonce {
    bytes: [u8; NONCE_SIZE],
}

impl Nonce {
    /// Create a nonce from an array
    pub const fn from(bytes: [u8; NONCE_SIZE]) -> Self {
        Self { bytes }
    }

    /// Get the nonce bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the nonce length
    pub const fn len() -> usize {
        NONCE_SIZE
    }

    /// Create a nonce from a slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, SshError> {
        if slice.len() != NONCE_SIZE {
            return Err(SshError::CryptoError(format!(
                "Invalid nonce length: expected {}, got {}",
                NONCE_SIZE,
                slice.len()
            )));
        }

        let mut bytes = [0u8; NONCE_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }
}

/// ChaCha20-Poly1305 AEAD cipher
#[derive(Debug)]
pub struct ChaCha20Poly1305 {
    key: LessSafeKey,
    nonce: Nonce,
}

impl ChaCha20Poly1305 {
    /// Create a new ChaCha20-Poly1305 cipher
    pub fn new(key: &Key, nonce: &Nonce) -> Self {
        let unbound_key = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, key.as_slice())
            .expect("Invalid key length");
        let key = LessSafeKey::new(unbound_key);

        Self {
            key,
            nonce: nonce.clone(),
        }
    }

    /// Encrypt plaintext and return ciphertext + tag
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SshError> {
        let nonce = ring::aead::Nonce::assume_unique_for_key(self.nonce.bytes);

        let mut ciphertext = plaintext.to_vec();
        self.key
            .seal_in_place_separate_tag(
                nonce,
                ring::aead::Aad::empty(),
                &mut ciphertext,
            )
            .map(|tag| {
                ciphertext.extend_from_slice(tag.as_ref());
                ciphertext
            })
            .map_err(|_| SshError::CryptoError("Encryption failed".to_string()))
    }

    /// Decrypt ciphertext and return plaintext
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SshError> {
        if ciphertext.len() < TAG_SIZE {
            return Err(SshError::CryptoError(
                "Ciphertext too short".to_string(),
            ));
        }

        let nonce = ring::aead::Nonce::assume_unique_for_key(self.nonce.bytes);

        // Create a mutable copy for decryption
        let mut data = ciphertext.to_vec();
        
        // Use open_in_place - it expects the full ciphertext (data + tag)
        // and will verify the tag internally
        self.key
            .open_in_place(
                nonce,
                ring::aead::Aad::empty(),
                &mut data,
            )
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| SshError::CryptoError("Decryption failed or tag verification failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_size() {
        assert_eq!(Key::len(), 32);
    }

    #[test]
    fn test_nonce_size() {
        assert_eq!(Nonce::len(), 12);
    }

    #[test]
    fn test_tag_size() {
        assert_eq!(TAG_SIZE, 16);
    }

    #[test]
    fn test_key_from_slice() {
        let key_bytes = vec![0x00; 32];
        let key = Key::from_slice(&key_bytes).unwrap();
        assert_eq!(key.as_slice(), &key_bytes[..]);
    }

    #[test]
    fn test_nonce_from_slice() {
        let nonce_bytes = vec![0x00; 12];
        let nonce = Nonce::from_slice(&nonce_bytes).unwrap();
        assert_eq!(nonce.as_slice(), &nonce_bytes[..]);
    }

    #[test]
    fn test_invalid_key_length() {
        let key_bytes = vec![0x00; 16];
        let result = Key::from_slice(&key_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_nonce_length() {
        let nonce_bytes = vec![0x00; 8];
        let result = Nonce::from_slice(&nonce_bytes);
        assert!(result.is_err());
    }
}