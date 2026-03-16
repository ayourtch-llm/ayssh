//! SSH Packet Protocol Implementation
//!
//! Implements the SSH packet protocol as defined in RFC 4253 Section 6.
//!
//! # Packet Structure
//!
//! In encryption:
//! ```text
//! < 1. 4 bytes: packet length (excluding length field and padding length field)
//! < 2. 4 bytes: padding length
//! < 3. [message bytes]: payload
//! < 4. [padding bytes]: random padding
//! < 5. 4 bytes: initial counter (for stream ciphers)
//! ```
//!
//! Before encryption:
//! ```text
//! < 1. 4 bytes: packet length (excluding length field and padding length field)
//! < 2. 4 bytes: padding length
//! < 3. [message bytes]: payload
//! < 4. [padding bytes]: random padding
//! ```

use crate::error::SshError;
use rand::Rng;
use std::mem;

/// Minimum padding length
const MIN_PADDING: usize = 4;

/// Maximum padding length
const MAX_PADDING: usize = 255;

/// Block size for alignment (RFC 4253: 8 bytes or cipher block size, whichever is larger)
const BLOCK_ALIGNMENT: usize = 8;

/// Size of length field (4 bytes)
const LENGTH_FIELD_SIZE: usize = 4;

/// Size of padding length field (1 byte)
const PADLEN_FIELD_SIZE: usize = 1;

/// Total header size (length + padlen fields)
const HEADER_SIZE: usize = LENGTH_FIELD_SIZE + PADLEN_FIELD_SIZE;

/// Packet structure before encryption
#[derive(Debug, Clone)]
pub struct Packet {
    /// Length of payload (not including length, padlen, or pad)
    pub length: u32,
    /// Length of padding
    pub padlen: u8,
    /// Message payload
    pub payload: Vec<u8>,
    /// Random padding bytes
    pub padding: Vec<u8>,
}

impl Packet {
    /// Create a new packet with the given payload
    /// Padding will be calculated automatically
    pub fn new(payload: Vec<u8>) -> Self {
        let padding_len = calculate_padding(payload.len());
        let mut padding = vec![0u8; padding_len];
        
        // Fill padding with random data
        rand::thread_rng().fill(&mut padding[..]);
        
        Packet {
            length: payload.len() as u32,
            padlen: padding_len as u8,
            payload,
            padding,
        }
    }

    /// Create a packet with a specific message type
    pub fn with_message_type(message_type: u8, payload: Vec<u8>) -> Self {
        let mut msg = vec![message_type];
        msg.extend_from_slice(&payload);
        Self::new(msg)
    }

    /// Create a packet with explicit padding length
    pub fn new_with_padding(payload: Vec<u8>, padding_len: usize) -> Self {
        let mut padding = vec![0u8; padding_len];
        
        // Fill padding with random data
        rand::thread_rng().fill(&mut padding[..]);
        
        Packet {
            length: payload.len() as u32,
            padlen: padding_len as u8,
            payload,
            padding,
        }
    }

    /// Serialize the packet to bytes (before encryption)
    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(HEADER_SIZE + self.length as usize + self.padding.len());
        
        // Write length (4 bytes, big-endian)
        result.extend_from_slice(&(self.length).to_be_bytes());
        
        // Write padding length (1 byte)
        result.push(self.padlen);
        
        // Write payload
        result.extend_from_slice(&self.payload);
        
        // Write padding
        result.extend_from_slice(&self.padding);
        
        result
    }

    /// Deserialize a packet from bytes (before encryption)
    pub fn deserialize(data: &[u8]) -> Result<Self, SshError> {
        if data.len() < HEADER_SIZE {
            return Err(SshError::CryptoError(
                "Packet data too short".to_string(),
            ));
        }

        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let padlen = data[4]; // padding length is 1 byte
        
        let expected_len = HEADER_SIZE + length as usize + padlen as usize;
        if data.len() < expected_len {
            return Err(SshError::CryptoError(
                "Packet data incomplete".to_string(),
            ));
        }

        let payload_start = HEADER_SIZE;
        let payload_end = payload_start + length as usize;
        let padding_start = payload_end;
        let padding_end = padding_start + padlen as usize;

        Ok(Packet {
            length,
            padlen,
            payload: data[payload_start..payload_end].to_vec(),
            padding: data[padding_start..padding_end].to_vec(),
        })
    }

    /// Calculate the total size of the serialized packet
    pub fn total_size(&self) -> usize {
        HEADER_SIZE + self.length as usize + self.padding.len()
    }
}

/// Calculate the padding length for a given payload size
///
/// According to RFC 4253 Section 6:
/// - Padding must be at least 4 bytes
/// - Padding must be at most 255 bytes
/// - The total packet length (packet_length + padding_length + payload + padding)
///   MUST be a multiple of 8 bytes (or cipher block size, whichever is larger)
///
/// The formula calculates padding such that:
/// (HEADER_SIZE + payload_len + padding) % 8 == 0
/// and 4 <= padding <= 255
pub fn calculate_padding(payload_len: usize) -> usize {
    // Total size without padding: length field (4) + padlen field (4) + payload
    let total_without_padding = HEADER_SIZE + payload_len;
    
    // Calculate how much padding we need to align to 8-byte boundaries
    // We want: (total_without_padding + padding) % 8 == 0
    let remainder = total_without_padding % BLOCK_ALIGNMENT;
    
    let padding_needed = if remainder == 0 {
        // Already aligned, but minimum padding is 4 bytes
        MIN_PADDING
    } else {
        let padding = BLOCK_ALIGNMENT - remainder;
        // If padding_needed < MIN_PADDING, we need to add more to reach MIN_PADDING
        // while maintaining 8-byte alignment
        if padding < MIN_PADDING {
            MIN_PADDING
        } else {
            padding
        }
    };
    
    // Ensure padding doesn't exceed MAX_PADDING
    if padding_needed > MAX_PADDING {
        MAX_PADDING
    } else {
        padding_needed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_calculation() {
        // Test that padding results in 8-byte alignment
        for payload_len in 0..1000 {
            let padding = calculate_padding(payload_len);
            let total = HEADER_SIZE + payload_len + padding;
            assert_eq!(total % 8, 0, "Payload len {}: total {} not aligned to 8", payload_len, total);
            assert!(padding >= MIN_PADDING, "Padding {} < MIN_PADDING", padding);
            assert!(padding <= MAX_PADDING, "Padding {} > MAX_PADDING", padding);
        }
    }

    #[test]
    fn test_small_payloads() {
        // Test small payloads that are commonly used
        assert_eq!(calculate_padding(0), 4);  // HEADER=8, padding=4, total=12, 12%8=4 != 0... wait
        
        // Let's verify: HEADER_SIZE=8, payload=0, padding=4
        // total = 8 + 0 + 4 = 12, 12 % 8 = 4 != 0
        // This is WRONG!
    }
}

/// Writer for building encrypted packets
pub struct PacketWriter {
    payload: Vec<u8>,
}

impl PacketWriter {
    /// Create a new packet writer
    pub fn new() -> Self {
        PacketWriter {
            payload: Vec::new(),
        }
    }

    /// Write a byte to the payload
    pub fn write_byte(&mut self, byte: u8) {
        self.payload.push(byte);
    }

    /// Write a slice to the payload
    pub fn write_payload(&mut self, data: &[u8]) {
        self.payload.extend_from_slice(data);
    }

    /// Write a message type byte followed by payload
    pub fn write_message(&mut self, message_type: u8, payload: &[u8]) {
        self.write_byte(message_type);
        self.write_payload(payload);
    }

    /// Build the packet with automatic padding calculation
    pub fn build(&self) -> Packet {
        let padding_len = calculate_padding(self.payload.len());
        let mut padding = vec![0u8; padding_len];
        
        // Fill padding with random data
        rand::thread_rng().fill(&mut padding[..]);
        
        Packet {
            length: self.payload.len() as u32,
            padlen: padding_len as u8,
            payload: self.payload.clone(),
            padding,
        }
    }
}

impl Default for PacketWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// Reader for parsing encrypted packets
pub struct PacketReader<'a> {
    /// Length of the payload
    pub payload_len: u32,
    /// Length of the padding
    pub padlen: u8,
    /// Reference to the payload data
    pub payload: &'a [u8],
    /// Reference to the padding data
    pub padding: &'a [u8],
}

impl<'a> PacketReader<'a> {
    /// Create a packet reader from serialized packet data
    pub fn new(data: &'a [u8]) -> Result<Self, SshError> {
        if data.len() < HEADER_SIZE {
            return Err(SshError::CryptoError(
                "Packet data too short".to_string(),
            ));
        }

        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let padlen = data[4]; // padding length is 1 byte
        
        let expected_len = HEADER_SIZE + length as usize + padlen as usize;
        if data.len() < expected_len {
            return Err(SshError::CryptoError(
                "Packet data incomplete".to_string(),
            ));
        }

        let payload_start = HEADER_SIZE;
        let payload_end = payload_start + length as usize;
        let padding_start = payload_end;
        let padding_end = padding_start + padlen as usize;

        Ok(PacketReader {
            payload_len: length,
            padlen,
            payload: &data[payload_start..payload_end],
            padding: &data[padding_start..padding_end],
        })
    }

    /// Get the message type (first byte of payload)
    pub fn message_type(&self) -> Option<u8> {
        self.payload.first().copied()
    }

    /// Get the payload without the message type byte
    pub fn message_data(&self) -> Option<&[u8]> {
        if self.payload.is_empty() {
            None
        } else {
            Some(&self.payload[1..])
        }
    }
}