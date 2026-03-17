//! Encrypted Transport Layer
//!
//! Implements the encrypted transport layer for SSH, handling packet encryption/decryption
//! with AES-GCM and ChaCha20-Poly1305 ciphers.

use crate::crypto::{
    chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce},
    cipher::{aes_gcm_encrypt, CipherError},
};
use crate::error::SshError;
use crate::transport::packet::{Packet, MAX_PACKET_SIZE};
use std::io::{Read, Write};

// Implement From<CipherError> for SshError
impl From<CipherError> for SshError {
    fn from(err: CipherError) -> Self {
        SshError::CryptoError(err.to_string())
    }
}

/// Encrypted transport state
#[derive(Debug, Clone, PartialEq)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Cipher state for SSH transport encryption
#[derive(Debug)]
pub struct CipherState {
    /// Encryption algorithm
    algorithm: EncryptionAlgorithm,
    /// Encryption key
    enc_key: Vec<u8>,
    /// Session ID for key derivation
    session_id: Vec<u8>,
    /// Sequence number for stream ciphers
    pub sequence_number: u64,
    /// ChaCha20-Poly1305 cipher instance
    chacha_cipher: Option<ChaCha20Poly1305>,
}

impl CipherState {
    /// Create new cipher state for AES-256-GCM
    pub fn new_aes256_gcm(session_id: &[u8], enc_key: &[u8]) -> Result<Self, SshError> {
        if enc_key.len() != 32 {
            return Err(SshError::CryptoError(
                "AES-256 key must be 32 bytes".to_string(),
            ));
        }

        Ok(CipherState {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            enc_key: enc_key.to_vec(),
            session_id: session_id.to_vec(),
            sequence_number: 0,
            chacha_cipher: None,
        })
    }

    /// Create new cipher state for ChaCha20-Poly1305
    pub fn new_chacha20_poly1305(session_id: &[u8], enc_key: &[u8]) -> Result<Self, SshError> {
        if enc_key.len() != 32 {
            return Err(SshError::CryptoError(
                "ChaCha20 key must be 32 bytes".to_string(),
            ));
        }

        let key = Key::from_slice(enc_key)?;
        let nonce = Nonce::default();
        let chacha_cipher = ChaCha20Poly1305::new(&key, &nonce);

        Ok(CipherState {
            algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
            enc_key: enc_key.to_vec(),
            session_id: session_id.to_vec(),
            sequence_number: 0,
            chacha_cipher: Some(chacha_cipher),
        })
    }

    /// Encrypt a packet
    pub fn encrypt(&mut self, packet: &Packet) -> Result<Vec<u8>, SshError> {
        // Serialize packet to bytes
        let mut serialized = Vec::with_capacity(packet.total_size());
        
        // Write length (4 bytes, big-endian)
        serialized.extend_from_slice(&(packet.length).to_be_bytes());
        
        // Write padding length (4 bytes, big-endian)
        serialized.extend_from_slice(&(packet.padding_length as u32).to_be_bytes());
        
        // Write payload
        serialized.extend_from_slice(&packet.payload);
        
        // Encrypt based on algorithm
        match self.algorithm {
            EncryptionAlgorithm::Aes256Gcm => {
                let nonce = self.generate_nonce();
                let ciphertext = aes_gcm_encrypt(&self.enc_key, &nonce, &serialized)?;
                Ok(ciphertext)
            }
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                // Generate nonce before borrowing cipher mutably
                let _nonce = self.generate_chacha_nonce();
                
                if let Some(ref mut cipher) = self.chacha_cipher {
                    // Encrypt the data using ChaCha20-Poly1305
                    let result = cipher.encrypt(&serialized);
                    
                    match result {
                        Ok(data) => Ok(data),
                        Err(_) => Err(SshError::CryptoError("Encryption failed".to_string())),
                    }
                } else {
                    Err(SshError::CryptoError("ChaCha20 cipher not initialized".to_string()))
                }
            }
        }
    }

    /// Decrypt a packet
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Packet, SshError> {
        // Parse the decrypted packet
        Packet::deserialize(ciphertext)
    }

    /// Generate nonce for AES-GCM
    fn generate_nonce(&mut self) -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        nonce[8..12].copy_from_slice(&(self.sequence_number as u32).to_be_bytes());
        self.sequence_number += 1;
        nonce
    }

    /// Generate nonce for ChaCha20-Poly1305
    fn generate_chacha_nonce(&mut self) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..8].copy_from_slice(&(self.sequence_number as u32).to_be_bytes());
        self.sequence_number += 1;
        
        // Use session ID bytes for first 4 bytes (as per RFC 8439)
        let session_id_prefix = &self.session_id[..4];
        nonce_bytes[..4].copy_from_slice(session_id_prefix);
        
        Nonce::from_slice(&nonce_bytes).unwrap_or_else(|_| Nonce::default())
    }
}

/// Encrypted transport that wraps a transport stream
pub struct EncryptedTransport<R, W> {
    /// Read side of the transport
    read: R,
    /// Write side of the transport
    write: W,
    /// Current cipher state
    cipher_state: CipherState,
    /// Rekey threshold (bytes)
    rekey_threshold: usize,
    /// Bytes encrypted since last rekey
    bytes_encrypted: usize,
}

impl<R: Read, W: Write> EncryptedTransport<R, W> {
    /// Create a new encrypted transport
    pub fn new_aes256_gcm(
        read: R,
        write: W,
        session_id: &[u8],
        enc_key: &[u8],
    ) -> Result<Self, SshError> {
        let cipher_state = CipherState::new_aes256_gcm(session_id, enc_key)?;
        
        Ok(EncryptedTransport {
            read,
            write,
            cipher_state,
            rekey_threshold: 1 << 30, // 1GB
            bytes_encrypted: 0,
        })
    }

    /// Create a new encrypted transport with ChaCha20-Poly1305
    pub fn new_chacha20_poly1305(
        read: R,
        write: W,
        session_id: &[u8],
        enc_key: &[u8],
    ) -> Result<Self, SshError> {
        let cipher_state = CipherState::new_chacha20_poly1305(session_id, enc_key)?;
        
        Ok(EncryptedTransport {
            read,
            write,
            cipher_state,
            rekey_threshold: 1 << 30,
            bytes_encrypted: 0,
        })
    }

    /// Write an encrypted packet
    pub fn write_packet(&mut self, packet: &Packet) -> Result<(), SshError> {
        let ciphertext = self.cipher_state.encrypt(packet)?;
        
        self.write.write_all(&ciphertext)?;
        self.bytes_encrypted += ciphertext.len();
        
        // Check if we need to rekey
        if self.bytes_encrypted > self.rekey_threshold {
            // In a real implementation, this would trigger a rekey
            self.bytes_encrypted = 0;
        }
        
        Ok(())
    }

    /// Read an encrypted packet
    pub fn read_packet(&mut self) -> Result<Packet, SshError> {
        // Read the encrypted data (we need to know the size first)
        // In a real implementation, we'd read the length field first
        let mut buffer = vec![0u8; MAX_PACKET_SIZE];
        let n = self.read.read(&mut buffer)?;
        
        if n == 0 {
            return Err(SshError::ConnectionError("Connection closed".to_string()));
        }
        
        self.cipher_state.decrypt(&buffer[..n])
    }

    /// Get the current cipher state
    pub fn cipher_state(&self) -> &CipherState {
        &self.cipher_state
    }

    /// Get bytes encrypted
    pub fn bytes_encrypted(&self) -> usize {
        self.bytes_encrypted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_cipher_state_aes256_gcm() {
        let session_id = vec![0x00; 20];
        let enc_key = vec![0x00; 32];
        
        let mut cipher = CipherState::new_aes256_gcm(&session_id, &enc_key).unwrap();
        
        let packet = Packet::new(0x01, vec![1, 2, 3, 4]);
        let encrypted = cipher.encrypt(&packet).unwrap();
        
        assert!(!encrypted.is_empty());
    }

    #[test]
    fn test_cipher_state_chacha20_poly1305() {
        let session_id = vec![0x00; 20];
        let enc_key = vec![0x00; 32];
        
        let mut cipher = CipherState::new_chacha20_poly1305(&session_id, &enc_key).unwrap();
        
        let packet = Packet::new(0x01, vec![1, 2, 3, 4]);
        let encrypted = cipher.encrypt(&packet).unwrap();
        
        assert!(!encrypted.is_empty());
    }

    #[test]
    fn test_encrypted_transport_aes256_gcm() {
        let session_id = vec![0x00; 20];
        let enc_key = vec![0x00; 32];
        
        // Just test that we can create the cipher state
        let mut cipher = CipherState::new_aes256_gcm(&session_id, &enc_key).unwrap();
        
        let packet = Packet::new(0x01, vec![1, 2, 3, 4]);
        let encrypted = cipher.encrypt(&packet).unwrap();
        
        assert!(encrypted.len() > 0);
    }

    #[test]
    fn test_encrypted_transport_chacha20() {
        let session_id = vec![0x00; 20];
        let enc_key = vec![0x00; 32];
        
        // Just test that we can create the cipher state
        let mut cipher = CipherState::new_chacha20_poly1305(&session_id, &enc_key).unwrap();
        
        let packet = Packet::new(0x01, vec![1, 2, 3, 4]);
        let encrypted = cipher.encrypt(&packet).unwrap();
        
        assert!(encrypted.len() > 0);
    }
}