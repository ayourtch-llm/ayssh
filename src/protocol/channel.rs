//! SSH Channel Open Messages
//!
//! Implements channel open request and confirmation messages
//! as defined in RFC 4254 Section 5.1.

use bytes::{BufMut, BytesMut};
use crate::protocol::MessageType;

/// Channel open message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelType {
    /// Session channel (most common)
    Session,
    /// Direct TCP/IP forwarding
    DirectTcpip,
    /// TUNNEL forwarding
    Tun,
    /// UNIX socket forwarding
    StreamLocal,
}

/// Channel open request
#[derive(Debug, Clone)]
pub struct ChannelOpen {
    /// Channel type
    pub channel_type: ChannelType,
    /// Our channel number
    pub sender_channel: u32,
    /// Initial window size
    pub initial_window_size: u32,
    /// Maximum packet size
    pub maximum_packet_size: u32,
    /// Additional data (depends on channel type)
    pub additional_data: Vec<u8>,
}

/// Channel open confirmation
#[derive(Debug, Clone)]
pub struct ChannelOpenConfirmation {
    /// Peer's channel number
    pub recipient_channel: u32,
    /// Initial window size
    pub initial_window_size: u32,
    /// Maximum packet size
    pub maximum_packet_size: u32,
    /// Additional data
    pub additional_data: Vec<u8>,
}

/// Channel open failure
#[derive(Debug, Clone)]
pub struct ChannelOpenFailure {
    /// Recipient channel
    pub recipient_channel: u32,
    /// Error code
    pub error_code: RejectReason,
    /// Error message
    pub error_message: String,
    /// Language tag
    pub language_tag: String,
}

/// Reject reasons
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// administratively_prohibited
    AdministrativelyProhibited = 1,
    /// connect_failed
    ConnectFailed = 2,
    /// connection_refused_by_host
    ConnectionRefusedByHost = 3,
    /// host_unreachable
    HostUnreachable = 4,
}

impl ChannelType {
    /// Get the string representation of the channel type
    pub fn as_str(&self) -> &'static str {
        match self {
            ChannelType::Session => "session",
            ChannelType::DirectTcpip => "direct-tcpip",
            ChannelType::Tun => "tun",
            ChannelType::StreamLocal => "streamlocal",
        }
    }
}

impl ChannelOpen {
    /// Encode channel open message
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(128);
        
        // Message type
        buf.put_u8(MessageType::ChannelOpen.value());
        
        // Sender channel
        buf.put_u32(self.sender_channel);
        
        // Initial window size
        buf.put_u32(self.initial_window_size);
        
        // Maximum packet size
        buf.put_u32(self.maximum_packet_size);
        
        // Channel type
        let channel_type_bytes = self.channel_type.as_str().as_bytes();
        buf.put_u32(channel_type_bytes.len() as u32);
        buf.put_slice(channel_type_bytes);
        
        // Additional data
        buf.put_u32(self.additional_data.len() as u32);
        buf.put_slice(&self.additional_data);
        
        buf.to_vec()
    }

    /// Decode channel open message
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 20 {
            return Err("Data too short for channel open".to_string());
        }

        let mut cursor = &data[1..];
        
        let sender_channel = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        
        let initial_window_size = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        
        let maximum_packet_size = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        
        let channel_type_len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        
        if cursor.len() < channel_type_len {
            return Err("Data too short for channel type".to_string());
        }
        
        let channel_type_bytes = cursor[..channel_type_len].to_vec();
        let channel_type_str = String::from_utf8(channel_type_bytes)
            .map_err(|_| "Invalid UTF-8 in channel type".to_string())?;
        cursor = &cursor[channel_type_len..];
        
        let channel_type = match channel_type_str.as_str() {
            "session" => ChannelType::Session,
            "direct-tcpip" => ChannelType::DirectTcpip,
            "tun" => ChannelType::Tun,
            "streamlocal" => ChannelType::StreamLocal,
            _ => return Err(format!("Unknown channel type: {}", channel_type_str)),
        };
        
        let additional_data_len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        
        if cursor.len() < additional_data_len {
            return Err("Data too short for additional data".to_string());
        }
        
        let additional_data = cursor[..additional_data_len].to_vec();

        Ok(ChannelOpen {
            channel_type,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            additional_data,
        })
    }
}

impl ChannelOpenConfirmation {
    /// Encode channel open confirmation
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(64);
        
        // Message type
        buf.put_u8(MessageType::ChannelOpenConfirmation.value());
        
        // Recipient channel
        buf.put_u32(self.recipient_channel);
        
        // Initial window size
        buf.put_u32(self.initial_window_size);
        
        // Maximum packet size
        buf.put_u32(self.maximum_packet_size);
        
        // Additional data
        buf.put_u32(self.additional_data.len() as u32);
        buf.put_slice(&self.additional_data);
        
        buf.to_vec()
    }

    /// Decode channel open confirmation
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 13 {
            return Err("Data too short for channel open confirmation".to_string());
        }

        let mut cursor = &data[1..];
        
        let recipient_channel = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        
        let initial_window_size = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        
        let maximum_packet_size = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        
        let additional_data_len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        
        if cursor.len() < additional_data_len {
            return Err("Data too short for additional data".to_string());
        }
        
        let additional_data = cursor[..additional_data_len].to_vec();

        Ok(ChannelOpenConfirmation {
            recipient_channel,
            initial_window_size,
            maximum_packet_size,
            additional_data,
        })
    }
}

impl ChannelOpenFailure {
    /// Encode channel open failure
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(128);
        
        // Message type
        buf.put_u8(MessageType::ChannelOpenFailure.value());
        
        // Recipient channel
        buf.put_u32(self.recipient_channel);
        
        // Error code
        buf.put_u32(self.error_code as u32);
        
        // Error message
        let msg_bytes = self.error_message.as_bytes();
        buf.put_u32(msg_bytes.len() as u32);
        buf.put_slice(msg_bytes);
        
        // Language tag
        let lang_bytes = self.language_tag.as_bytes();
        buf.put_u32(lang_bytes.len() as u32);
        buf.put_slice(lang_bytes);
        
        buf.to_vec()
    }

    /// Decode channel open failure
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 17 {
            return Err("Data too short for channel open failure".to_string());
        }

        let mut cursor = &data[1..];
        
        let recipient_channel = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        
        let error_code = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        cursor = &cursor[4..];
        
        let error_msg_len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        
        if cursor.len() < error_msg_len {
            return Err("Data too short for error message".to_string());
        }
        
        let error_message = String::from_utf8(cursor[..error_msg_len].to_vec())
            .map_err(|_| "Invalid UTF-8 in error message".to_string())?;
        cursor = &cursor[error_msg_len..];
        
        let lang_tag_len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        
        if cursor.len() < lang_tag_len {
            return Err("Data too short for language tag".to_string());
        }
        
        let language_tag = String::from_utf8(cursor[..lang_tag_len].to_vec())
            .map_err(|_| "Invalid UTF-8 in language tag".to_string())?;

        Ok(ChannelOpenFailure {
            recipient_channel,
            error_code: match error_code {
                1 => RejectReason::AdministrativelyProhibited,
                2 => RejectReason::ConnectFailed,
                3 => RejectReason::ConnectionRefusedByHost,
                4 => RejectReason::HostUnreachable,
                _ => return Err(format!("Unknown reject reason: {}", error_code)),
            },
            error_message,
            language_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_type_as_str() {
        assert_eq!(ChannelType::Session.as_str(), "session");
        assert_eq!(ChannelType::DirectTcpip.as_str(), "direct-tcpip");
        assert_eq!(ChannelType::Tun.as_str(), "tun");
        assert_eq!(ChannelType::StreamLocal.as_str(), "streamlocal");
    }

    #[test]
    fn test_channel_open_encode_decode_session() {
        let open = ChannelOpen {
            channel_type: ChannelType::Session,
            sender_channel: 1,
            initial_window_size: 65536,
            maximum_packet_size: 32768,
            additional_data: vec![],
        };

        let encoded = open.encode();
        let decoded = ChannelOpen::decode(&encoded).unwrap();

        assert_eq!(decoded.channel_type, ChannelType::Session);
        assert_eq!(decoded.sender_channel, 1);
        assert_eq!(decoded.initial_window_size, 65536);
        assert_eq!(decoded.maximum_packet_size, 32768);
    }

    #[test]
    fn test_channel_open_confirmation() {
        let confirm = ChannelOpenConfirmation {
            recipient_channel: 1,
            initial_window_size: 65536,
            maximum_packet_size: 32768,
            additional_data: vec![],
        };

        let encoded = confirm.encode();
        let decoded = ChannelOpenConfirmation::decode(&encoded).unwrap();

        assert_eq!(decoded.recipient_channel, 1);
        assert_eq!(decoded.initial_window_size, 65536);
        assert_eq!(decoded.maximum_packet_size, 32768);
    }

    #[test]
    fn test_channel_open_failure() {
        let failure = ChannelOpenFailure {
            recipient_channel: 1,
            error_code: RejectReason::AdministrativelyProhibited,
            error_message: "Administratively prohibited".to_string(),
            language_tag: "en".to_string(),
        };

        let encoded = failure.encode();
        let decoded = ChannelOpenFailure::decode(&encoded).unwrap();

        assert_eq!(decoded.recipient_channel, 1);
        assert_eq!(decoded.error_code, RejectReason::AdministrativelyProhibited);
        assert_eq!(decoded.error_message, "Administratively prohibited");
        assert_eq!(decoded.language_tag, "en");
    }

    #[test]
    fn test_channel_open_with_direct_tcpip() {
        // Direct TCP/IP channel with additional data
        // Format: host_address (string), port (uint32), originator_address (string), originator_port (uint32)
        let host_addr: Vec<u8> = vec![127, 0, 0, 1]; // 127.0.0.1
        let port: u32 = 22;
        let originator_addr: Vec<u8> = vec![127, 0, 0, 1];
        let originator_port: u32 = 12345;
        
        let mut additional = BytesMut::new();
        additional.put_u32(host_addr.len() as u32);
        additional.put_slice(&host_addr);
        additional.put_u32(port);
        additional.put_u32(originator_addr.len() as u32);
        additional.put_slice(&originator_addr);
        additional.put_u32(originator_port);
        
        let open = ChannelOpen {
            channel_type: ChannelType::DirectTcpip,
            sender_channel: 1,
            initial_window_size: 65536,
            maximum_packet_size: 32768,
            additional_data: additional.to_vec(),
        };

        let encoded = open.encode();
        let decoded = ChannelOpen::decode(&encoded).unwrap();

        assert_eq!(decoded.channel_type, ChannelType::DirectTcpip);
        assert_eq!(decoded.sender_channel, 1);
    }

    #[test]
    fn test_channel_open_invalid_message_type() {
        let data = vec![0x5A, 0x00, 0x00, 0x00, 0x01]; // Invalid message type
        
        let result = ChannelOpen::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_channel_open_short_data() {
        let data = vec![0x5A, 0x00, 0x00, 0x00, 0x01]; // Too short
        
        let result = ChannelOpen::decode(&data);
        assert!(result.is_err());
    }
}