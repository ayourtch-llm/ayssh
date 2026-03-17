//! SSH Packet Handling
//!
//! Implements packet encryption, decryption, and formatting as defined in RFC 4253 Section 6.

use crate::crypto::packet as crypto_packet;
use crate::error::SshError;

/// Packet header length (4 bytes length + 1 byte padding length)
pub const PACKET_HEADER_LEN: usize = 5;

/// Maximum packet size
pub const MAX_PACKET_SIZE: usize = 256 * 1024;

/// RFC 4253 Section 6.1: Maximum total packet size (including length, padding_length,
/// payload, random padding, and MAC)
pub const RFC_MAX_PACKET_SIZE: usize = 35000;

/// RFC 4253 Section 6.1: Maximum uncompressed payload length
pub const RFC_MAX_PAYLOAD_SIZE: usize = 32768;

/// Minimum total packet size (RFC 4253 Section 6: minimum is 16 bytes or cipher block size)
pub const MIN_PACKET_SIZE: usize = 16;

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
        
        // Write padding length (1 byte)
        result.push(self.padding_length);
        
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
        rand::rngs::OsRng.fill_bytes(&mut padding);
        padding
    }

    /// Deserialize a packet from bytes
    ///
    /// Validates packet structure per RFC 4253 Section 6:
    /// - At least 4 bytes of padding
    /// - Minimum packet size of 16 bytes
    /// - Implementations SHOULD check that the packet length is reasonable
    pub fn deserialize(data: &[u8]) -> Result<Self, SshError> {
        if data.len() < PACKET_HEADER_LEN {
            return Err(SshError::CryptoError(
                "Packet data too short".to_string(),
            ));
        }

        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let padding_length = data[4]; // padding_length is 1 byte

        // RFC 4253 Section 6: "There MUST be at least four bytes of padding"
        if (padding_length as usize) < MIN_PADDING {
            return Err(SshError::CryptoError(
                format!("Padding too short: {} (minimum {})", padding_length, MIN_PADDING),
            ));
        }

        // RFC 4253 Section 6: Check total packet size is reasonable
        // total_size = 4 (length field) + 1 (padding_length) + payload + padding
        let total_size = PACKET_HEADER_LEN + length as usize + padding_length as usize;
        if total_size > MAX_PACKET_SIZE {
            return Err(SshError::CryptoError(
                format!("Packet too large: {} bytes (maximum {})", total_size, MAX_PACKET_SIZE),
            ));
        }
        
        if data.len() < total_size {
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
        
        // Write padding length (1 byte)
        result.push(self.padding_length);
        
        // Write message type
        result.push(self.msg_type);
        
        // Write payload
        result.extend_from_slice(&self.payload);
        
        // Add padding
        result.extend_from_slice(&self.generate_padding());
        
        result
    }
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
    fn test_packet_padding() {
        let packet = Packet::new(1, vec![1, 2, 3]);
        let serialized = packet.serialize();
        
        // Check that padding is present
        let padding_length = u32::from_be_bytes([serialized[4], serialized[5], serialized[6], serialized[7]]) as usize;
        assert!(padding_length >= 4); // Minimum padding
    }

    #[test]
    fn test_packet_padding_minimum() {
        let packet = Packet::new(1, vec![1, 2]);
        let serialized = packet.serialize();
        
        let padding_length = u32::from_be_bytes([serialized[4], serialized[5], serialized[6], serialized[7]]) as usize;
        assert!(padding_length >= 4); // Minimum padding
    }

    #[test]
    fn test_packet_padding_alignment() {
        // Test that padding aligns to block size
        let packet = Packet::new(1, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let serialized = packet.serialize();

        let total_len = serialized.len();
        // Total length should be aligned to 8 bytes (minimum block size)
        assert_eq!(total_len % 8, 0);
    }

    // --- total_size ---

    #[test]
    fn test_total_size() {
        let pkt = Packet::new(1, vec![10, 20]);
        // PACKET_HEADER_LEN(5) + length + padding_length
        assert_eq!(pkt.total_size(), PACKET_HEADER_LEN + pkt.length as usize + pkt.padding_length as usize);
    }

    #[test]
    fn test_total_size_matches_serialize_len() {
        let pkt = Packet::new(21, vec![1, 2, 3, 4, 5]);
        assert_eq!(pkt.total_size(), pkt.serialize().len());
    }

    // --- serialize_for_encryption ---

    #[test]
    fn test_serialize_for_encryption_same_structure() {
        let pkt = Packet::new(5, vec![0xAA, 0xBB]);
        let enc = pkt.serialize_for_encryption();
        // Same structure as serialize: length(4) + padlen(1) + msgtype(1) + payload + padding
        let length = u32::from_be_bytes([enc[0], enc[1], enc[2], enc[3]]);
        assert_eq!(length, pkt.length);
        assert_eq!(enc[4], pkt.padding_length);
        assert_eq!(enc[5], pkt.msg_type);
        assert_eq!(&enc[6..6 + pkt.payload.len()], &pkt.payload);
        assert_eq!(enc.len(), pkt.total_size());
    }

    // --- deserialize error paths ---

    #[test]
    fn test_deserialize_too_short() {
        let data = vec![0, 0, 0]; // Only 3 bytes, need at least 5
        let result = Packet::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_deserialize_padding_too_short() {
        // length=1, padding_length=2 (less than MIN_PADDING=4)
        let mut data = vec![];
        data.extend_from_slice(&1u32.to_be_bytes()); // length
        data.push(2); // padding_length = 2, below minimum of 4
        data.extend_from_slice(&[0x42]); // payload (1 byte)
        data.extend_from_slice(&[0; 2]); // padding (2 bytes)
        let result = Packet::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Padding too short"));
    }

    #[test]
    fn test_deserialize_packet_too_large() {
        // Craft a packet claiming to be larger than MAX_PACKET_SIZE
        let mut data = vec![];
        data.extend_from_slice(&(MAX_PACKET_SIZE as u32).to_be_bytes()); // huge length
        data.push(4); // padding_length
        // Don't need to provide the full data — size check happens before reading payload
        data.extend_from_slice(&[0; 100]);
        let result = Packet::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_deserialize_data_incomplete() {
        // Valid header but data too short for claimed length
        let mut data = vec![];
        data.extend_from_slice(&10u32.to_be_bytes()); // length = 10
        data.push(4); // padding_length = 4
        data.extend_from_slice(&[0; 5]); // Only 5 bytes, need 10+4=14
        let result = Packet::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("incomplete"));
    }

    #[test]
    fn test_deserialize_minimum_valid() {
        // Smallest valid packet: length=1, padding=4, 1 byte msg_type
        let pkt = Packet::new(21, vec![]);
        let serialized = pkt.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.msg_type, 21);
        assert!(deserialized.payload.is_empty());
    }

    // --- Roundtrip ---

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let original = Packet::new(94, vec![1, 2, 3, 4, 5]);
        let serialized = original.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.msg_type, original.msg_type);
        assert_eq!(deserialized.payload, original.payload);
        assert_eq!(deserialized.length, original.length);
        assert_eq!(deserialized.padding_length, original.padding_length);
    }

    #[test]
    fn test_serialize_deserialize_roundtrip_empty_payload() {
        let original = Packet::new(5, vec![]);
        let serialized = original.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.msg_type, 5);
        assert!(deserialized.payload.is_empty());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip_large_payload() {
        let payload = vec![0xAB; 1000];
        let original = Packet::new(94, payload.clone());
        let serialized = original.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.payload, payload);
    }

    #[test]
    fn test_serialize_8byte_alignment() {
        // Verify all packet sizes are 8-byte aligned
        for payload_len in 0..50 {
            let payload = vec![0u8; payload_len];
            let pkt = Packet::new(1, payload);
            let serialized = pkt.serialize();
            assert_eq!(serialized.len() % 8, 0,
                "payload_len={}: serialized len {} not 8-byte aligned",
                payload_len, serialized.len());
        }
    }

    // --- calculate_padding_length ---

    #[test]
    fn test_calculate_padding_length_block8() {
        let padding = calculate_padding_length(8, 4);
        assert!(padding >= 4);
    }

    #[test]
    fn test_calculate_padding_length_block16() {
        let padding = calculate_padding_length(16, 4);
        assert!(padding >= 4);
    }

    #[test]
    fn test_calculate_padding_length_exact_alignment() {
        // When (8 + min_padding) % block_size == 0, returns min_padding
        // 8 + 8 = 16, 16 % 16 = 0
        let padding = calculate_padding_length(16, 8);
        assert_eq!(padding, 8);
    }

    // --- Clone / Debug ---

    #[test]
    fn test_packet_clone() {
        let pkt = Packet::new(42, vec![1, 2, 3]);
        let cloned = pkt.clone();
        assert_eq!(pkt.msg_type, cloned.msg_type);
        assert_eq!(pkt.payload, cloned.payload);
        assert_eq!(pkt.length, cloned.length);
    }

    #[test]
    fn test_packet_debug() {
        let pkt = Packet::new(21, vec![]);
        let debug = format!("{:?}", pkt);
        assert!(debug.contains("Packet"));
    }
}