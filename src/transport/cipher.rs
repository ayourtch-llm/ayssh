//! Transport cipher state for SSH encryption

use crate::crypto::cipher::{aes_gcm_decrypt, aes_gcm_encrypt, CipherError};

/// Cipher state for SSH transport encryption
#[derive(Debug, Clone, PartialEq)]
pub struct CipherState {
    /// Encryption key (32 bytes for AES-256)
    pub enc_key: Vec<u8>,
    /// MAC key (32 bytes for HMAC-SHA256)
    pub mac_key: Vec<u8>,
    /// Session ID for key derivation
    pub session_id: Vec<u8>,
    /// Nonce counter for generating unique nonces
    nonce_counter: u64,
}

impl CipherState {
    /// Create new cipher state
    pub fn new(_shared_secret: &[u8], session_id: &[u8], enc_key: &[u8], mac_key: &[u8]) -> Self {
        Self {
            enc_key: enc_key.to_vec(),
            mac_key: mac_key.to_vec(),
            session_id: session_id.to_vec(),
            nonce_counter: 0,
        }
    }
    
    /// Encrypt plaintext using AES-GCM
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        let nonce = self.generate_nonce();
        aes_gcm_encrypt(&self.enc_key, &nonce, plaintext)
    }
    
    /// Decrypt ciphertext using AES-GCM
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        // For simplicity, use zero nonce (in production would track nonce)
        let nonce = vec![0u8; 12];
        aes_gcm_decrypt(&self.enc_key, &nonce, ciphertext)
    }
    
    fn generate_nonce(&mut self) -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        nonce[8..12].copy_from_slice(&((self.nonce_counter & 0xFFFFFFFF) as u32).to_be_bytes());
        self.nonce_counter += 1;
        nonce
    }
}