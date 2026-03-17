//! SSH Transport Layer Protocol Messages (RFC 4253 Section 11)
//!
//! Implements encoding/decoding for transport layer generic messages:
//! - SSH_MSG_DISCONNECT (1)
//! - SSH_MSG_IGNORE (2)  
//! - SSH_MSG_UNIMPLEMENTED (3)
//! - SSH_MSG_DEBUG (4)

use bytes::{Buf, BytesMut};
use crate::protocol::types::{SshString, SshUint32, SshBoolean};

/// SSH Disconnect Reason Codes (RFC 4253 Section 11.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectReason {
    HostNotAllowedToConnect = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    Reserved = 4,
    MacError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

impl DisconnectReason {
    /// Create from numeric value
    pub fn from_value(value: u32) -> Option<Self> {
        match value {
            1 => Some(DisconnectReason::HostNotAllowedToConnect),
            2 => Some(DisconnectReason::ProtocolError),
            3 => Some(DisconnectReason::KeyExchangeFailed),
            4 => Some(DisconnectReason::Reserved),
            5 => Some(DisconnectReason::MacError),
            6 => Some(DisconnectReason::CompressionError),
            7 => Some(DisconnectReason::ServiceNotAvailable),
            8 => Some(DisconnectReason::ProtocolVersionNotSupported),
            9 => Some(DisconnectReason::HostKeyNotVerifiable),
            10 => Some(DisconnectReason::ConnectionLost),
            11 => Some(DisconnectReason::ByApplication),
            12 => Some(DisconnectReason::TooManyConnections),
            13 => Some(DisconnectReason::AuthCancelledByUser),
            14 => Some(DisconnectReason::NoMoreAuthMethodsAvailable),
            15 => Some(DisconnectReason::IllegalUserName),
            _ => None,
        }
    }

    /// Get the numeric value
    pub fn value(&self) -> u32 {
        *self as u32
    }
}

/// SSH_MSG_DISCONNECT (RFC 4253 Section 11.1)
///
/// byte      SSH_MSG_DISCONNECT
/// uint32    reason code
/// string    description in ISO-10646 UTF-8 encoding
/// string    language tag [RFC3066]
///
/// This message causes immediate termination of the connection.
/// All implementations MUST be able to process this message.
#[derive(Debug, Clone, PartialEq)]
pub struct DisconnectMessage {
    pub reason_code: u32,
    pub description: String,
    pub language_tag: String,
}

impl DisconnectMessage {
    /// Create a new disconnect message
    pub fn new(reason: DisconnectReason, description: &str) -> Self {
        Self {
            reason_code: reason.value(),
            description: description.to_string(),
            language_tag: String::new(),
        }
    }

    /// Encode to bytes (excluding message type byte)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(100);
        SshUint32::new(self.reason_code).encode(&mut buf);
        SshString::from_str(&self.description).encode(&mut buf);
        SshString::from_str(&self.language_tag).encode(&mut buf);
        buf.to_vec()
    }

    /// Decode from bytes (excluding message type byte)
    pub fn decode(data: &[u8]) -> Result<Self, crate::error::SshError> {
        let mut buf = &data[..];
        if buf.remaining() < 4 {
            return Err(crate::error::SshError::ProtocolError(
                "Disconnect message too short".to_string(),
            ));
        }
        let reason_code = buf.get_u32();
        let description = if buf.remaining() >= 4 {
            let desc = SshString::decode(&mut buf)
                .map_err(|e| crate::error::SshError::ProtocolError(format!("Invalid disconnect description: {}", e)))?;
            desc.to_str().unwrap_or("").to_string()
        } else {
            String::new()
        };
        let language_tag = if buf.remaining() >= 4 {
            let lang = SshString::decode(&mut buf)
                .map_err(|e| crate::error::SshError::ProtocolError(format!("Invalid disconnect language: {}", e)))?;
            lang.to_str().unwrap_or("").to_string()
        } else {
            String::new()
        };
        Ok(Self {
            reason_code,
            description,
            language_tag,
        })
    }

    /// Get the disconnect reason as an enum (if recognized)
    pub fn reason(&self) -> Option<DisconnectReason> {
        DisconnectReason::from_value(self.reason_code)
    }
}

/// SSH_MSG_IGNORE (RFC 4253 Section 11.2)
///
/// byte      SSH_MSG_IGNORE
/// string    data
///
/// All implementations MUST understand (and ignore) this message at any time.
/// This is useful as an additional protection measure against traffic analysis.
#[derive(Debug, Clone, PartialEq)]
pub struct IgnoreMessage {
    pub data: Vec<u8>,
}

impl IgnoreMessage {
    /// Create a new ignore message
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create an empty ignore message
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    /// Encode to bytes (excluding message type byte)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(4 + self.data.len());
        SshString::new(bytes::Bytes::from(self.data.clone())).encode(&mut buf);
        buf.to_vec()
    }

    /// Decode from bytes (excluding message type byte)
    pub fn decode(data: &[u8]) -> Result<Self, crate::error::SshError> {
        let mut buf = &data[..];
        let s = SshString::decode(&mut buf)
            .map_err(|e| crate::error::SshError::ProtocolError(format!("Invalid ignore data: {}", e)))?;
        Ok(Self {
            data: s.as_bytes().to_vec(),
        })
    }
}

/// SSH_MSG_DEBUG (RFC 4253 Section 11.3)
///
/// byte      SSH_MSG_DEBUG
/// boolean   always_display
/// string    message in ISO-10646 UTF-8 encoding
/// string    language tag [RFC3066]
///
/// All implementations MUST understand this message, but are allowed to ignore it.
/// If 'always_display' is TRUE, the message SHOULD be displayed.
#[derive(Debug, Clone, PartialEq)]
pub struct DebugMessage {
    pub always_display: bool,
    pub message: String,
    pub language_tag: String,
}

impl DebugMessage {
    /// Create a new debug message
    pub fn new(always_display: bool, message: &str) -> Self {
        Self {
            always_display,
            message: message.to_string(),
            language_tag: String::new(),
        }
    }

    /// Encode to bytes (excluding message type byte)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(100);
        SshBoolean::new(self.always_display).encode(&mut buf);
        SshString::from_str(&self.message).encode(&mut buf);
        SshString::from_str(&self.language_tag).encode(&mut buf);
        buf.to_vec()
    }

    /// Decode from bytes (excluding message type byte)
    pub fn decode(data: &[u8]) -> Result<Self, crate::error::SshError> {
        let mut buf = &data[..];
        let always_display = SshBoolean::decode(&mut buf)
            .map_err(|e| crate::error::SshError::ProtocolError(format!("Invalid debug boolean: {}", e)))?;
        let message = SshString::decode(&mut buf)
            .map_err(|e| crate::error::SshError::ProtocolError(format!("Invalid debug message: {}", e)))?;
        let language_tag = if buf.remaining() >= 4 {
            SshString::decode(&mut buf)
                .map_err(|e| crate::error::SshError::ProtocolError(format!("Invalid debug language: {}", e)))?
                .to_str().unwrap_or("").to_string()
        } else {
            String::new()
        };
        Ok(Self {
            always_display: always_display.as_bool(),
            message: message.to_str().unwrap_or("").to_string(),
            language_tag,
        })
    }
}

/// SSH_MSG_UNIMPLEMENTED (RFC 4253 Section 11.4)
///
/// byte      SSH_MSG_UNIMPLEMENTED
/// uint32    packet sequence number of rejected message
///
/// An implementation MUST respond to all unrecognized messages with this.
#[derive(Debug, Clone, PartialEq)]
pub struct UnimplementedMessage {
    pub sequence_number: u32,
}

impl UnimplementedMessage {
    /// Create a new unimplemented message
    pub fn new(sequence_number: u32) -> Self {
        Self { sequence_number }
    }

    /// Encode to bytes (excluding message type byte)
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(4);
        SshUint32::new(self.sequence_number).encode(&mut buf);
        buf.to_vec()
    }

    /// Decode from bytes (excluding message type byte)
    pub fn decode(data: &[u8]) -> Result<Self, crate::error::SshError> {
        let mut buf = &data[..];
        let seq = SshUint32::decode(&mut buf)
            .map_err(|e| crate::error::SshError::ProtocolError(format!("Invalid unimplemented seq: {}", e)))?;
        Ok(Self {
            sequence_number: seq.as_u32(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disconnect_reason_values() {
        // RFC 4253 Section 11.1: All disconnect reason codes
        assert_eq!(DisconnectReason::HostNotAllowedToConnect.value(), 1);
        assert_eq!(DisconnectReason::ProtocolError.value(), 2);
        assert_eq!(DisconnectReason::KeyExchangeFailed.value(), 3);
        assert_eq!(DisconnectReason::Reserved.value(), 4);
        assert_eq!(DisconnectReason::MacError.value(), 5);
        assert_eq!(DisconnectReason::CompressionError.value(), 6);
        assert_eq!(DisconnectReason::ServiceNotAvailable.value(), 7);
        assert_eq!(DisconnectReason::ProtocolVersionNotSupported.value(), 8);
        assert_eq!(DisconnectReason::HostKeyNotVerifiable.value(), 9);
        assert_eq!(DisconnectReason::ConnectionLost.value(), 10);
        assert_eq!(DisconnectReason::ByApplication.value(), 11);
        assert_eq!(DisconnectReason::TooManyConnections.value(), 12);
        assert_eq!(DisconnectReason::AuthCancelledByUser.value(), 13);
        assert_eq!(DisconnectReason::NoMoreAuthMethodsAvailable.value(), 14);
        assert_eq!(DisconnectReason::IllegalUserName.value(), 15);
    }

    #[test]
    fn test_disconnect_reason_from_value() {
        for code in 1..=15 {
            assert!(DisconnectReason::from_value(code).is_some(),
                "Reason code {} should be recognized", code);
        }
        assert!(DisconnectReason::from_value(0).is_none());
        assert!(DisconnectReason::from_value(16).is_none());
    }

    #[test]
    fn test_disconnect_message_encode_decode() {
        let msg = DisconnectMessage::new(
            DisconnectReason::ByApplication,
            "Goodbye",
        );
        let encoded = msg.encode();
        let decoded = DisconnectMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.reason_code, 11);
        assert_eq!(decoded.description, "Goodbye");
        assert_eq!(decoded.language_tag, "");
        assert_eq!(decoded.reason(), Some(DisconnectReason::ByApplication));
    }

    #[test]
    fn test_disconnect_message_all_reasons() {
        // Test each disconnect reason code can be encoded and decoded
        let reasons = [
            DisconnectReason::HostNotAllowedToConnect,
            DisconnectReason::ProtocolError,
            DisconnectReason::KeyExchangeFailed,
            DisconnectReason::MacError,
            DisconnectReason::CompressionError,
            DisconnectReason::ServiceNotAvailable,
            DisconnectReason::ProtocolVersionNotSupported,
            DisconnectReason::HostKeyNotVerifiable,
            DisconnectReason::ConnectionLost,
            DisconnectReason::ByApplication,
            DisconnectReason::TooManyConnections,
            DisconnectReason::AuthCancelledByUser,
            DisconnectReason::NoMoreAuthMethodsAvailable,
            DisconnectReason::IllegalUserName,
        ];
        for reason in reasons {
            let msg = DisconnectMessage::new(reason, "test");
            let encoded = msg.encode();
            let decoded = DisconnectMessage::decode(&encoded).unwrap();
            assert_eq!(decoded.reason(), Some(reason));
        }
    }

    #[test]
    fn test_ignore_message_encode_decode() {
        // RFC 4253 Section 11.2: SSH_MSG_IGNORE
        let msg = IgnoreMessage::new(b"some padding data".to_vec());
        let encoded = msg.encode();
        let decoded = IgnoreMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.data, b"some padding data");
    }

    #[test]
    fn test_ignore_message_empty() {
        let msg = IgnoreMessage::empty();
        let encoded = msg.encode();
        let decoded = IgnoreMessage::decode(&encoded).unwrap();
        assert!(decoded.data.is_empty());
    }

    #[test]
    fn test_debug_message_encode_decode() {
        // RFC 4253 Section 11.3: SSH_MSG_DEBUG
        let msg = DebugMessage::new(true, "Debug info");
        let encoded = msg.encode();
        let decoded = DebugMessage::decode(&encoded).unwrap();
        assert!(decoded.always_display);
        assert_eq!(decoded.message, "Debug info");
        assert_eq!(decoded.language_tag, "");
    }

    #[test]
    fn test_debug_message_always_display_false() {
        let msg = DebugMessage::new(false, "Hidden debug");
        let encoded = msg.encode();
        let decoded = DebugMessage::decode(&encoded).unwrap();
        assert!(!decoded.always_display);
        assert_eq!(decoded.message, "Hidden debug");
    }

    #[test]
    fn test_unimplemented_message_encode_decode() {
        // RFC 4253 Section 11.4: SSH_MSG_UNIMPLEMENTED
        let msg = UnimplementedMessage::new(42);
        let encoded = msg.encode();
        let decoded = UnimplementedMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.sequence_number, 42);
    }

    #[test]
    fn test_unimplemented_message_max_seq() {
        // Sequence numbers can go up to 2^32-1
        let msg = UnimplementedMessage::new(u32::MAX);
        let encoded = msg.encode();
        let decoded = UnimplementedMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.sequence_number, u32::MAX);
    }

    #[test]
    fn test_disconnect_with_unknown_reason_code() {
        // Implementations should handle unknown reason codes gracefully
        let mut buf = BytesMut::new();
        SshUint32::new(999).encode(&mut buf);
        SshString::from_str("Unknown error").encode(&mut buf);
        SshString::from_str("").encode(&mut buf);

        let decoded = DisconnectMessage::decode(&buf).unwrap();
        assert_eq!(decoded.reason_code, 999);
        assert_eq!(decoded.reason(), None); // Unknown reason code
        assert_eq!(decoded.description, "Unknown error");
    }
}
