//! SSH Channel Data Transfer
//!
//! Implements channel data send/receive operations as defined in RFC 4254 Section 6.

use bytes::{BufMut, BytesMut};
use crate::protocol::MessageType;

/// Channel data message
#[derive(Debug, Clone)]
pub struct ChannelData {
    /// Channel number
    pub channel: u32,
    /// Data payload
    pub data: Vec<u8>,
}

/// Channel extended data message
#[derive(Debug, Clone)]
pub struct ChannelExtendedData {
    /// Channel number
    pub channel: u32,
    /// Extended data type (usually 1 for stderr)
    pub data_type: u32,
    /// Data payload
    pub data: Vec<u8>,
}

/// Channel EOF message
#[derive(Debug, Clone)]
pub struct ChannelEof {
    /// Channel number
    pub channel: u32,
}

/// Channel close message
#[derive(Debug, Clone)]
pub struct ChannelClose {
    /// Channel number
    pub channel: u32,
}

/// Channel window adjust message
#[derive(Debug, Clone)]
pub struct ChannelWindowAdjust {
    /// Channel number
    pub channel: u32,
    /// Additional window size to add
    pub bytes_to_add: u32,
}

impl ChannelData {
    /// Encode channel data message
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(16 + self.data.len());
        
        // Message type
        buf.put_u8(MessageType::ChannelData.value());
        
        // Channel
        buf.put_u32(self.channel);
        
        // Data
        buf.put_u32(self.data.len() as u32);
        buf.put_slice(&self.data);
        
        buf.to_vec()
    }

    /// Decode channel data message
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 9 {
            return Err("Data too short for channel data".to_string());
        }

        let msg_type = data[0];
        if msg_type != MessageType::ChannelData.value() {
            return Err(format!("Invalid message type: expected {}, got {}", 
                MessageType::ChannelData.value(), msg_type));
        }

        let mut cursor = &data[1..];
        
        let channel = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        
        let data_len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        
        if cursor.len() < data_len {
            return Err("Data too short for payload".to_string());
        }
        
        let data = cursor[..data_len].to_vec();

        Ok(ChannelData { channel, data })
    }
}

impl ChannelExtendedData {
    /// Encode channel extended data message
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(20 + self.data.len());
        
        // Message type
        buf.put_u8(MessageType::ChannelExtendedData.value());
        
        // Channel
        buf.put_u32(self.channel);
        
        // Data type
        buf.put_u32(self.data_type);
        
        // Data
        buf.put_u32(self.data.len() as u32);
        buf.put_slice(&self.data);
        
        buf.to_vec()
    }

    /// Decode channel extended data message
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 13 {
            return Err("Data too short for channel extended data".to_string());
        }

        let msg_type = data[0];
        if msg_type != MessageType::ChannelExtendedData.value() {
            return Err(format!("Invalid message type: expected {}, got {}", 
                MessageType::ChannelExtendedData.value(), msg_type));
        }

        let mut cursor = &data[1..];
        
        let channel = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        
        let data_type = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        
        let data_len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        
        if cursor.len() < data_len {
            return Err("Data too short for payload".to_string());
        }
        
        let data = cursor[..data_len].to_vec();

        Ok(ChannelExtendedData { channel, data_type, data })
    }
}

impl ChannelEof {
    /// Encode channel EOF message
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(5);
        
        // Message type
        buf.put_u8(MessageType::ChannelEof.value());
        
        // Channel
        buf.put_u32(self.channel);
        
        buf.to_vec()
    }

    /// Decode channel EOF message
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 5 {
            return Err("Data too short for channel EOF".to_string());
        }

        let msg_type = data[0];
        if msg_type != MessageType::ChannelEof.value() {
            return Err(format!("Invalid message type: expected {}, got {}", 
                MessageType::ChannelEof.value(), msg_type));
        }

        let channel = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

        Ok(ChannelEof { channel })
    }
}

impl ChannelClose {
    /// Encode channel close message
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(5);
        
        // Message type
        buf.put_u8(MessageType::ChannelClose.value());
        
        // Channel
        buf.put_u32(self.channel);
        
        buf.to_vec()
    }

    /// Decode channel close message
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 5 {
            return Err("Data too short for channel close".to_string());
        }

        let msg_type = data[0];
        if msg_type != MessageType::ChannelClose.value() {
            return Err(format!("Invalid message type: expected {}, got {}", 
                MessageType::ChannelClose.value(), msg_type));
        }

        let channel = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

        Ok(ChannelClose { channel })
    }
}

impl ChannelWindowAdjust {
    /// Encode channel window adjust message
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(9);
        
        // Message type
        buf.put_u8(MessageType::ChannelWindowAdjust.value());
        
        // Channel
        buf.put_u32(self.channel);
        
        // Bytes to add
        buf.put_u32(self.bytes_to_add);
        
        buf.to_vec()
    }

    /// Decode channel window adjust message
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 9 {
            return Err("Data too short for channel window adjust".to_string());
        }

        let msg_type = data[0];
        if msg_type != MessageType::ChannelWindowAdjust.value() {
            return Err(format!("Invalid message type: expected {}, got {}", 
                MessageType::ChannelWindowAdjust.value(), msg_type));
        }

        let channel = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let bytes_to_add = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);

        Ok(ChannelWindowAdjust { channel, bytes_to_add })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_data_encode_decode() {
        let data = ChannelData {
            channel: 1,
            data: b"Hello, SSH!".to_vec(),
        };

        let encoded = data.encode();
        let decoded = ChannelData::decode(&encoded).unwrap();

        assert_eq!(decoded.channel, 1);
        assert_eq!(decoded.data, b"Hello, SSH!".as_slice());
    }

    #[test]
    fn test_channel_extended_data() {
        let data = ChannelExtendedData {
            channel: 1,
            data_type: 1, // stderr
            data: b"Error message".to_vec(),
        };

        let encoded = data.encode();
        let decoded = ChannelExtendedData::decode(&encoded).unwrap();

        assert_eq!(decoded.channel, 1);
        assert_eq!(decoded.data_type, 1);
        assert_eq!(decoded.data, b"Error message".as_slice());
    }

    #[test]
    fn test_channel_eof() {
        let eof = ChannelEof { channel: 1 };

        let encoded = eof.encode();
        let decoded = ChannelEof::decode(&encoded).unwrap();

        assert_eq!(decoded.channel, 1);
    }

    #[test]
    fn test_channel_close() {
        let close = ChannelClose { channel: 1 };

        let encoded = close.encode();
        let decoded = ChannelClose::decode(&encoded).unwrap();

        assert_eq!(decoded.channel, 1);
    }

    #[test]
    fn test_channel_window_adjust() {
        let adjust = ChannelWindowAdjust {
            channel: 1,
            bytes_to_add: 65536,
        };

        let encoded = adjust.encode();
        let decoded = ChannelWindowAdjust::decode(&encoded).unwrap();

        assert_eq!(decoded.channel, 1);
        assert_eq!(decoded.bytes_to_add, 65536);
    }

    #[test]
    fn test_channel_data_empty_payload() {
        let data = ChannelData {
            channel: 1,
            data: vec![],
        };

        let encoded = data.encode();
        let decoded = ChannelData::decode(&encoded).unwrap();

        assert_eq!(decoded.channel, 1);
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn test_channel_data_large_payload() {
        let large_data = vec![0xAB; 65536]; // 64KB
        let data = ChannelData {
            channel: 1,
            data: large_data.clone(),
        };

        let encoded = data.encode();
        let decoded = ChannelData::decode(&encoded).unwrap();

        assert_eq!(decoded.channel, 1);
        assert_eq!(decoded.data, large_data);
    }

    #[test]
    fn test_channel_data_invalid_message_type() {
        let data = vec![0x5E, 0x00, 0x00, 0x00, 0x01]; // Invalid message type
        
        let result = ChannelData::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_channel_data_short_data() {
        let data = vec![0x5E, 0x00, 0x00, 0x00, 0x01]; // Too short
        
        let result = ChannelData::decode(&data);
        assert!(result.is_err());
    }
}