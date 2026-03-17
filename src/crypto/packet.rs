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
        rand::rngs::OsRng.fill(&mut padding[..]);

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
        rand::rngs::OsRng.fill(&mut padding[..]);

        Packet {
            length: payload.len() as u32,
            padlen: padding_len as u8,
            payload,
            padding,
        }
    }

    /// Serialize the packet to bytes (before encryption)
    pub fn serialize(&self) -> Vec<u8> {
        let mut result =
            Vec::with_capacity(HEADER_SIZE + self.length as usize + self.padding.len());

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
            return Err(SshError::CryptoError("Packet data too short".to_string()));
        }

        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let padlen = data[4]; // padding length is 1 byte

        let expected_len = HEADER_SIZE + length as usize + padlen as usize;
        if data.len() < expected_len {
            return Err(SshError::CryptoError("Packet data incomplete".to_string()));
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

    // Start with minimum padding to align to block boundary
    let mut padding_needed = if remainder == 0 {
        0 // Already aligned
    } else {
        BLOCK_ALIGNMENT - remainder
    };

    // Ensure minimum padding of 4 bytes
    // If we need less than 4 bytes for alignment, add BLOCK_ALIGNMENT
    if padding_needed < MIN_PADDING {
        padding_needed += BLOCK_ALIGNMENT;
    }

    // With BLOCK_ALIGNMENT=8 and MIN_PADDING=4, the maximum padding_needed
    // is 15 (7 from alignment + 8 from min-padding bump), so this can never
    // exceed MAX_PADDING(255). Panic if our math is wrong rather than silently
    // clamping, since that would indicate a logic error.
    assert!(
        padding_needed <= MAX_PADDING,
        "BUG: calculate_padding produced {} bytes (max {}). \
         With block_align={} and min_pad={}, this should be impossible.",
        padding_needed, MAX_PADDING, BLOCK_ALIGNMENT, MIN_PADDING
    );
    padding_needed
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
            assert_eq!(
                total % 8,
                0,
                "Payload len {}: total {} not aligned to 8",
                payload_len,
                total
            );
            assert!(padding >= MIN_PADDING, "Padding {} < MIN_PADDING", padding);
            assert!(padding <= MAX_PADDING, "Padding {} > MAX_PADDING", padding);
        }
    }

    #[test]
    fn test_small_payloads() {
        // RFC 4253 Section 6: total of (packet_length || padding_length || payload || random padding)
        // must be a multiple of 8 (or cipher block size). HEADER_SIZE = 4 + 1 = 5.
        //
        // payload=0: total_without_pad=5, need 11 padding -> 5+11=16 (multiple of 8), 11>=4 OK
        assert_eq!(calculate_padding(0), 11);

        // payload=1: total_without_pad=6, need 10 padding -> 6+10=16, 10>=4 OK
        assert_eq!(calculate_padding(1), 10);

        // payload=2: total_without_pad=7, need 9 padding -> 7+9=16, 9>=4 OK
        assert_eq!(calculate_padding(2), 9);

        // payload=3: total_without_pad=8, need 8 padding -> 8+8=16, 8>=4 OK
        // (0 padding would align, but <4, so +8)
        assert_eq!(calculate_padding(3), 8);

        // payload=10: total_without_pad=15, need 1 to align -> 1<4, +8=9 -> 15+9=24 OK
        assert_eq!(calculate_padding(10), 9);

        // payload=11: total_without_pad=16, need 0 to align -> 0<4, +8=8 -> 16+8=24 OK
        assert_eq!(calculate_padding(11), 8);

        // Verify all small payloads satisfy constraints
        for payload_len in 0..32 {
            let padding = calculate_padding(payload_len);
            let total = HEADER_SIZE + payload_len + padding;
            assert_eq!(
                total % 8,
                0,
                "payload={}: total={} not aligned",
                payload_len,
                total
            );
            assert!(
                padding >= MIN_PADDING,
                "payload={}: padding={} < 4",
                payload_len,
                padding
            );
            assert!(
                padding <= MAX_PADDING,
                "payload={}: padding={} > 255",
                payload_len,
                padding
            );
        }
    }

    // --- Packet construction ---

    #[test]
    fn test_packet_new() {
        let pkt = Packet::new(vec![1, 2, 3]);
        assert_eq!(pkt.length, 3);
        assert_eq!(pkt.payload, vec![1, 2, 3]);
        assert!(pkt.padlen >= 4);
        assert_eq!(pkt.padding.len(), pkt.padlen as usize);
    }

    #[test]
    fn test_packet_new_empty_payload() {
        let pkt = Packet::new(vec![]);
        assert_eq!(pkt.length, 0);
        assert!(pkt.payload.is_empty());
        assert!(pkt.padlen >= 4);
    }

    #[test]
    fn test_packet_with_message_type() {
        let pkt = Packet::with_message_type(21, vec![0xAA, 0xBB]);
        // payload should be [msg_type, ...data]
        assert_eq!(pkt.payload[0], 21);
        assert_eq!(pkt.payload[1], 0xAA);
        assert_eq!(pkt.payload[2], 0xBB);
        assert_eq!(pkt.length, 3);
    }

    #[test]
    fn test_packet_with_message_type_no_extra_data() {
        let pkt = Packet::with_message_type(5, vec![]);
        assert_eq!(pkt.payload, vec![5]);
        assert_eq!(pkt.length, 1);
    }

    #[test]
    fn test_packet_new_with_padding() {
        let pkt = Packet::new_with_padding(vec![10, 20], 12);
        assert_eq!(pkt.length, 2);
        assert_eq!(pkt.padlen, 12);
        assert_eq!(pkt.padding.len(), 12);
        assert_eq!(pkt.payload, vec![10, 20]);
    }

    // --- Serialize ---

    #[test]
    fn test_serialize_structure() {
        let pkt = Packet::new_with_padding(vec![0xAA], 4);
        let data = pkt.serialize();
        // length field (4 bytes BE) = payload length = 1
        assert_eq!(&data[0..4], &[0, 0, 0, 1]);
        // padlen field (1 byte) = 4
        assert_eq!(data[4], 4);
        // payload
        assert_eq!(data[5], 0xAA);
        // padding (4 bytes)
        assert_eq!(data.len(), 4 + 1 + 1 + 4); // length + padlen + payload + padding
    }

    #[test]
    fn test_serialize_empty_payload() {
        let pkt = Packet::new_with_padding(vec![], 8);
        let data = pkt.serialize();
        assert_eq!(&data[0..4], &[0, 0, 0, 0]); // length = 0
        assert_eq!(data[4], 8); // padlen = 8
        assert_eq!(data.len(), 4 + 1 + 0 + 8);
    }

    // --- Deserialize ---

    #[test]
    fn test_deserialize_valid() {
        // Build: length=3, padlen=5, payload=[1,2,3], padding=[0;5]
        let mut data = vec![];
        data.extend_from_slice(&3u32.to_be_bytes()); // length
        data.push(5); // padlen
        data.extend_from_slice(&[1, 2, 3]); // payload
        data.extend_from_slice(&[0; 5]); // padding

        let pkt = Packet::deserialize(&data).unwrap();
        assert_eq!(pkt.length, 3);
        assert_eq!(pkt.padlen, 5);
        assert_eq!(pkt.payload, vec![1, 2, 3]);
        assert_eq!(pkt.padding, vec![0; 5]);
    }

    #[test]
    fn test_deserialize_too_short_for_header() {
        let data = vec![0, 0, 0]; // only 3 bytes, need at least 5
        let result = Packet::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_deserialize_incomplete_payload() {
        // Header says length=10 padlen=4, but only provide 2 bytes of payload
        let mut data = vec![];
        data.extend_from_slice(&10u32.to_be_bytes());
        data.push(4);
        data.extend_from_slice(&[0; 2]); // only 2 bytes, need 10+4=14
        let result = Packet::deserialize(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("incomplete"));
    }

    #[test]
    fn test_deserialize_exact_size() {
        // Exactly the right number of bytes, no extra
        let mut data = vec![];
        data.extend_from_slice(&2u32.to_be_bytes());
        data.push(4);
        data.extend_from_slice(&[0xAA, 0xBB]); // payload
        data.extend_from_slice(&[0xCC; 4]); // padding
        let pkt = Packet::deserialize(&data).unwrap();
        assert_eq!(pkt.payload, vec![0xAA, 0xBB]);
        assert_eq!(pkt.padding, vec![0xCC; 4]);
    }

    #[test]
    fn test_deserialize_extra_trailing_bytes_ignored() {
        let mut data = vec![];
        data.extend_from_slice(&1u32.to_be_bytes());
        data.push(4);
        data.extend_from_slice(&[0x42]); // payload
        data.extend_from_slice(&[0; 4]); // padding
        data.extend_from_slice(&[0xFF; 10]); // extra trailing bytes
        let pkt = Packet::deserialize(&data).unwrap();
        assert_eq!(pkt.payload, vec![0x42]);
        assert_eq!(pkt.padding.len(), 4);
    }

    #[test]
    fn test_deserialize_zero_length_zero_padding() {
        // Edge: length=0, padlen=0 — valid structure (empty packet)
        let mut data = vec![];
        data.extend_from_slice(&0u32.to_be_bytes());
        data.push(0);
        let pkt = Packet::deserialize(&data).unwrap();
        assert_eq!(pkt.length, 0);
        assert_eq!(pkt.padlen, 0);
        assert!(pkt.payload.is_empty());
        assert!(pkt.padding.is_empty());
    }

    // --- total_size ---

    #[test]
    fn test_total_size() {
        let pkt = Packet::new_with_padding(vec![1, 2, 3], 5);
        // HEADER_SIZE(5) + payload(3) + padding(5) = 13
        assert_eq!(pkt.total_size(), 5 + 3 + 5);
    }

    #[test]
    fn test_total_size_matches_serialize_len() {
        let pkt = Packet::new(vec![10, 20, 30, 40, 50]);
        assert_eq!(pkt.total_size(), pkt.serialize().len());
    }

    // --- Roundtrip ---

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let original = Packet::new(vec![1, 2, 3, 4, 5]);
        let serialized = original.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.length, original.length);
        assert_eq!(deserialized.padlen, original.padlen);
        assert_eq!(deserialized.payload, original.payload);
        assert_eq!(deserialized.padding, original.padding);
    }

    #[test]
    fn test_serialize_deserialize_roundtrip_empty() {
        let original = Packet::new(vec![]);
        let serialized = original.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.payload, original.payload);
        assert_eq!(deserialized.padding.len(), original.padding.len());
    }

    #[test]
    fn test_serialize_deserialize_roundtrip_large() {
        let payload = vec![0xAB; 500];
        let original = Packet::new(payload);
        let serialized = original.serialize();
        let deserialized = Packet::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.payload, original.payload);
    }

    // --- Clone / Debug ---

    #[test]
    fn test_packet_clone() {
        let pkt = Packet::new(vec![1, 2]);
        let cloned = pkt.clone();
        assert_eq!(pkt.payload, cloned.payload);
        assert_eq!(pkt.padlen, cloned.padlen);
    }

    #[test]
    fn test_packet_debug() {
        let pkt = Packet::new(vec![42]);
        let debug = format!("{:?}", pkt);
        assert!(debug.contains("Packet"));
        assert!(debug.contains("42"));
    }
}

