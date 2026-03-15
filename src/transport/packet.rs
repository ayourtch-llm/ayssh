//! SSH Packet Handling
//!
//! Implements packet encryption, decryption, and formatting.

use crate::crypto::packet as crypto_packet;
use crate::error::SshError;
use zeroize::Zeroizing;

/// Packet header length (4 bytes length + 4 bytes padding length)
pub const PACKET_HEADER_LEN: usize = 8;

/// Maximum packet size
pub const MAX_PACKET_SIZE: usize = 256 * 1024;

/// Packet structure
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet length (excluding padding)
    pub length: u32,
    /// Padding length
    pub padding_length: u8,
    /// Payload data
    pub payload: Vec<u8>,
    /// Message type (first byte of payload)
    pub msg_type: u8,
}

impl Packet {
    /// Create a new packet
    pub fn new(msg_type: u8, payload: Vec<u8>) -> Self {
        let mut packet = Self {
            length: (payload.len() + 1) as u32, // +1 for message type
            padding_length: 0,
            payload,
            msg_type,
        };
        
        // Calculate padding
        packet.padding_length = crypto_packet::calculate_padding(packet.length as usize) as u8;
        
        packet
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
        
        // Write payload
        result.extend_from_slice(&self.payload);
        
        // Note: In a real implementation, we'd add random padding here
        
        result
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
            payload: data[payload_start..payload_end].to_vec(),
            msg_type: if length > 0 { data[payload_start] } else { 0 },
        })
    }
}

/// Encrypt a packet
pub fn encrypt_packet(_packet: &Packet, _key: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    // Placeholder for actual encryption
    Ok(Zeroizing::new(Vec::new()))
}

/// Decrypt a packet
pub fn decrypt_packet(_data: &[u8], _key: &[u8]) -> anyhow::Result<Packet> {
    // Placeholder for actual decryption
    Ok(Packet::new(0, Vec::new()))
}

/// Calculate padding length to align to block size
pub fn calculate_padding_length(_block_size: usize, _min_padding: usize) -> u8 {
    // Placeholder for actual padding calculation
    8
}
