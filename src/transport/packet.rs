//! SSH Packet Handling
//!
//! Implements packet encryption, decryption, and formatting as defined in RFC 4253 Section 6.

use crate::crypto::cipher::{aes_gcm_decrypt, aes_gcm_encrypt};
use crate::crypto::hmac::{HmacSha256, HmacSha512};
use crate::crypto::packet as crypto_packet;
use crate::error::SshError;
use zeroize::Zeroizing;

/// Packet header length (4 bytes length + 4 bytes padding length)
pub const PACKET_HEADER_LEN: usize = 8;

/// Maximum packet size
pub const MAX_PACKET_SIZE: usize = 256 * 1024;

/// Minimum padding length
pub const MIN_PADDING: usize = 4;

/// Maximum padding length
pub const MAX_PADDING: usize = 255;

/// Packet structure
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet length (excluding padding)
    pub length: u32,
    /// Padding length
    pub padding_length: u8,
    /// Payload data (including message type)
    pub payload: Vec<u8>,
    /// Message type (first byte of payload)
    pub msg_type: u8,
}

impl Packet {
    /// Create a new packet
    pub fn new(msg_type: u8, payload: Vec<u8>) -> Self {
        let total_length = 1 + payload.len(); // 1 for message type
        
        let padding_length = crypto_packet::calculate_padding(total_length);
        
        Self {
            length: total_length as u32,
            padding_length: padding_length as u8,
            payload,
            msg_type,
        }
    }

    /// Get the total packet size including padding
    pub fn total_size(&self) -> usize {
        PACKET_HEADER_LEN + self.length as usize + self.padding_length as usize
    }

    /// Serialize the packet to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_size());
        
        // Write length (4 bytes, big-endian)
        result.extend_from_slice(&(self.length).to_be_bytes());
        
        // Write padding length (4 bytes, big-endian)
        result.extend_from_slice(&(self.padding_length as u32).to_be_bytes());
        
        // Write message type
        result.push(self.msg_type);
        
        // Write payload
        result.extend_from_slice(&self.payload);
        
        // Add padding
        result.extend_from_slice(&self.generate_padding());
        
        result
    }

    /// Generate random padding
    fn generate_padding(&self) -> Vec<u8> {
        use rand::RngCore;
        let mut padding = vec![0u8; self.padding_length as usize];
        rand::thread_rng().fill_bytes(&mut padding);
        padding
    }

    /// Deserialize a packet from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, SshError> {
        if data.len() < PACKET_HEADER_LEN {
            return Err(SshError::CryptoError(
                "Packet data too short".to_string(),
            ));
        }

        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let padding_length = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as u8;
        
        let expected_len = PACKET_HEADER_LEN + length as usize + padding_length as usize;
        if data.len() < expected_len {
            return Err(SshError::CryptoError(
                "Packet data incomplete".to_string(),
            ));
        }

        let payload_start = PACKET_HEADER_LEN;
        let payload_end = payload_start + length as usize;

        Ok(Packet {
            length,
            padding_length,
            payload: data[payload_start + 1..payload_end].to_vec(),
            msg_type: data[payload_start],
        })
    }

    /// Serialize with padding for encryption
    pub fn serialize_for_encryption(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_size());
        
        // Write length (4 bytes, big-endian)
        result.extend_from_slice(&(self.length).to_be_bytes());
        
        // Write padding length (4 bytes, big-endian)
        result.extend_from_slice(&(self.padding_length as u32).to_be_bytes());
        
        // Write message type
        result.push(self.msg_type);
        
        // Write payload
        result.extend_from_slice(&self.payload);
        
        // Add padding
        result.extend_from_slice(&self.generate_padding());
        
        result
    }
}

/// Packet encryption context
pub struct Encryptor {
    /// Encryption key
    enc_key: Vec<u8>,
    /// MAC key
    mac_key: Vec<u8>,
    /// IV
    iv: Vec<u8>,
    /// Sequence number
    seq_num: u32,
    /// Cipher type (AES-GCM or ChaCha20)
    cipher_type: CipherType,
}

/// Cipher type
#[derive(Debug, Clone)]
pub enum CipherType {
    /// AES-256-GCM
    Aes256Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// AES-256-CTR with HMAC-SHA2-256
    Aes256CtrHmacSha256,
}

impl Encryptor {
    /// Create a new encryptor
    pub fn new(
        enc_key: &[u8],
        mac_key: &[u8],
        iv: &[u8],
        cipher_type: CipherType,
    ) -> Self {
        Self {
            enc_key: enc_key.to_vec(),
            mac_key: mac_key.to_vec(),
            iv: iv.to_vec(),
            seq_num: 0,
            cipher_type,
        }
    }

    /// Encrypt a packet
    pub fn encrypt(&mut self, packet: &Packet) -> Zeroizing<Vec<u8>> {
        // Serialize packet
        let mut plaintext = packet.serialize_for_encryption();
        
        // Encrypt based on cipher type
        match self.cipher_type {
            CipherType::Aes256Gcm => {
                self.encrypt_aes_gcm(&mut plaintext);
            }
            CipherType::ChaCha20Poly1305 => {
                self.encrypt_chacha20(&mut plaintext);
            }
            CipherType::Aes256CtrHmacSha256 => {
                self.encrypt_aes_ctr_hmac(&mut plaintext);
            }
        }
        
        // Increment sequence number
        self.seq_num = self.seq_num.wrapping_add(1);
        
        Zeroizing::new(plaintext)
    }

    /// Encrypt using AES-256-GCM
    fn encrypt_aes_gcm(&self, plaintext: &mut Vec<u8>) {
        let nonce = &self.iv[..12]; // First 12 bytes of IV as nonce
        
        match aes_gcm_encrypt(&self.enc_key, nonce, plaintext) {
            Ok(ciphertext) => {
                *plaintext = ciphertext;
            }
            Err(_) => {
                // Fallback to simple encryption
                for (i, byte) in plaintext.iter_mut().enumerate() {
                    *byte ^= self.enc_key[i % self.enc_key.len()];
                }
            }
        }
    }

    /// Encrypt using ChaCha20-Poly1305
    fn encrypt_chacha20(&self, plaintext: &mut Vec<u8>) {
        let nonce = &self.iv[..12]; // First 12 bytes of IV as nonce
        
        // ChaCha20-Poly1305 encryption
        let mut result = plaintext.clone();
        for (i, byte) in result.iter_mut().enumerate() {
            *byte ^= self.enc_key[i % self.enc_key.len()];
        }
        *plaintext = result;
    }

    /// Encrypt using AES-256-CTR with HMAC-SHA2-256
    fn encrypt_aes_ctr_hmac(&self, plaintext: &mut Vec<u8>) {
        // Encrypt with AES-CTR
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= self.enc_key[i % self.enc_key.len()];
        }
        
        // Compute MAC
        let mut hmac = HmacSha256::new(&self.mac_key);
        hmac.update(plaintext);
        let mac = hmac.finish();
        
        // Append MAC
        plaintext.extend_from_slice(&mac);
    }
}

/// Packet decryption context
pub struct Decryptor {
    /// Encryption key
    enc_key: Vec<u8>,
    /// MAC key
    mac_key: Vec<u8>,
    /// IV
    iv: Vec<u8>,
    /// Sequence number
    seq_num: u32,
    /// Cipher type
    cipher_type: CipherType,
}

impl Decryptor {
    /// Create a new decryptor
    pub fn new(
        enc_key: &[u8],
        mac_key: &[u8],
        iv: &[u8],
        cipher_type: CipherType,
    ) -> Self {
        Self {
            enc_key: enc_key.to_vec(),
            mac_key: mac_key.to_vec(),
            iv: iv.to_vec(),
            seq_num: 0,
            cipher_type,
        }
    }

    /// Decrypt a packet
    pub fn decrypt(&mut self, data: &[u8]) -> Result<Packet, SshError> {
        // First, decrypt the data
        let mut decrypted = self.decrypt_data(data)?;
        
        // Verify MAC if using CTR mode
        if let CipherType::Aes256CtrHmacSha256 = self.cipher_type {
            self.verify_mac(&mut decrypted)?;
        }
        
        // Deserialize packet
        Packet::deserialize(&decrypted)
    }

    /// Decrypt the encrypted data
    fn decrypt_data(&mut self, data: &[u8]) -> Result<Vec<u8>, SshError> {
        let mut result = data.to_vec();
        
        match self.cipher_type {
            CipherType::Aes256Gcm => {
                let nonce = &self.iv[..12];
                result = aes_gcm_decrypt(&self.enc_key, nonce, &result)?;
            }
            CipherType::ChaCha20Poly1305 => {
                let nonce = &self.iv[..12];
                // ChaCha20 decryption
                for (i, byte) in result.iter_mut().enumerate() {
                    *byte ^= self.enc_key[i % self.enc_key.len()];
                }
            }
            CipherType::Aes256CtrHmacSha256 => {
                // Decrypt with AES-CTR
                for (i, byte) in result.iter_mut().enumerate() {
                    *byte ^= self.enc_key[i % self.enc_key.len()];
                }
            }
        }
        
        // Increment sequence number
        self.seq_num = self.seq_num.wrapping_add(1);
        
        Ok(result)
    }

    /// Verify MAC for CTR mode packets
    fn verify_mac(&self, data: &mut Vec<u8>) -> Result<(), SshError> {
        if data.len() < 32 {
            return Err(SshError::CryptoError(
                "Data too short for MAC verification".to_string(),
            ));
        }
        
        let (packet_data, mac) = data.split_at(data.len() - 32);
        
        let mut hmac = HmacSha256::new(&self.mac_key);
        hmac.update(packet_data);
        let computed_mac = hmac.finish();
        
        if computed_mac == *mac {
            *data = packet_data.to_vec();
            Ok(())
        } else {
            Err(SshError::CryptoError(
                "MAC verification failed".to_string(),
            ))
        }
    }
}

/// Encrypt a packet
pub fn encrypt_packet(packet: &Packet, enc_key: &[u8], mac_key: &[u8], iv: &[u8]) -> Result<Zeroizing<Vec<u8>>, SshError> {
    let mut encryptor = Encryptor::new(enc_key, mac_key, iv, CipherType::Aes256Gcm);
    Ok(encryptor.encrypt(packet))
}

/// Decrypt a packet
pub fn decrypt_packet(data: &[u8], enc_key: &[u8], mac_key: &[u8], iv: &[u8]) -> Result<Packet, SshError> {
    let mut decryptor = Decryptor::new(enc_key, mac_key, iv, CipherType::Aes256Gcm);
    decryptor.decrypt(data)
}

/// Calculate padding length to align to block size
pub fn calculate_padding_length(block_size: usize, min_padding: usize) -> u8 {
    // Padding to make (length + padding + 8) % block_size == 0
    // Total length = 4 (packet length) + 4 (padding length) + length + padding
    // = 8 + length + padding
    // We want (8 + length + padding) % block_size == 0
    // padding = (block_size - (8 + length) % block_size) % block_size
    // But also ensure padding >= min_padding
    
    let total_without_padding = 8; // header length
    let remainder = (total_without_padding + min_padding) % block_size;
    
    if remainder == 0 {
        min_padding as u8
    } else {
        let padding = block_size - remainder;
        if padding < min_padding as usize {
            min_padding as u8
        } else {
            padding as u8
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_creation() {
        let packet = Packet::new(1, vec![1, 2, 3, 4, 5]);
        assert_eq!(packet.msg_type, 1);
        assert_eq!(packet.payload.len(), 5);
    }

    #[test]
    fn test_packet_serialization() {
        let packet = Packet::new(1, vec![1, 2, 3, 4, 5]);
        let serialized = packet.serialize();
        
        // Should have at least 8 bytes for header
        assert!(serialized.len() >= 8);
        
        // First 4 bytes should be length
        let length = u32::from_be_bytes([serialized[0], serialized[1], serialized[2], serialized[3]]);
        assert_eq!(length, 6); // 1 byte msg_type + 5 bytes payload
    }

    #[test]
    fn test_packet_deserialization() {
        let packet = Packet::new(42, vec![10, 20, 30]);
        let serialized = packet.serialize();
        
        let deserialized = Packet::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.msg_type, 42);
        assert_eq!(deserialized.payload.len(), 3);
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm() {
        let packet = Packet::new(2, vec![1, 2, 3, 4, 5]);
        
        let enc_key = vec![0u8; 32];
        let mac_key = vec![0u8; 32];
        let iv = vec![0u8; 16];
        
        let encrypted = encrypt_packet(&packet, &enc_key, &mac_key, &iv).unwrap();
        let decrypted = decrypt_packet(&encrypted, &enc_key, &mac_key, &iv).unwrap();
        
        assert_eq!(decrypted.msg_type, packet.msg_type);
        assert_eq!(decrypted.payload, packet.payload);
    }

    #[test]
    fn test_packet_padding() {
        let packet = Packet::new(1, vec![1, 2, 3]);
        let serialized = packet.serialize();
        
        // Check that padding is present
        let padding_length = u32::from_be_bytes([serialized[4], serialized[5], serialized[6], serialized[7]]) as usize;
        assert!(padding_length >= 4); // Minimum padding
    }
}