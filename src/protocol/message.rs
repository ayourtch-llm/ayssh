//! SSH Protocol Message Encoding/Decoding
//!
//! Implements SSH message encoding/decoding according to RFC 4251 Section 5.
//!
//! SSH messages are encoded as:
//! - 1 byte: message type
//! - Variable length: data fields (strings, uint32, uint64, boolean, mpint)

use bytes::{Buf, BufMut, BytesMut};
use crate::protocol::messages::MessageType;
use crate::protocol::types::{SshBoolean, SshMpint, SshString, SshUint32, SshUint64};
use crate::error::SshError;

/// SSH Protocol Message
///
/// Represents an SSH protocol message with its type and encoded payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    /// Raw message bytes (including message type)
    data: BytesMut,
}

impl Message {
    /// Create a new empty message
    pub fn new() -> Self {
        Self { data: BytesMut::new() }
    }

    /// Create a new message with the given type
    pub fn with_type(msg_type: MessageType) -> Self {
        let mut msg = Self::new();
        msg.data.put_u8(msg_type.value());
        msg
    }

    /// Set the message type
    pub fn set_message_type(&mut self, msg_type: MessageType) {
        if !self.data.is_empty() {
            self.data[0] = msg_type.value();
        } else {
            self.data.put_u8(msg_type.value());
        }
    }

    /// Get the message type
    pub fn msg_type(&self) -> Option<MessageType> {
        MessageType::from_value(self.data[0])
    }

    /// Get the raw data
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the message
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the message is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Write a byte to the message
    pub fn write_byte(&mut self, byte: u8) {
        self.data.put_u8(byte);
    }

    /// Write a bool to the message
    pub fn write_bool(&mut self, value: bool) {
        SshBoolean::new(value).encode(&mut self.data);
    }

    /// Write a string to the message
    pub fn write_string(&mut self, value: &[u8]) {
        let len = value.len();
        self.data.put_u32(len as u32);
        self.data.extend_from_slice(value);
    }

    /// Write a string slice to the message
    pub fn write_string_slice(&mut self, value: &str) {
        SshString::from_str(value).encode(&mut self.data);
    }

    /// Write a uint32 to the message
    pub fn write_uint32(&mut self, value: u32) {
        SshUint32::new(value).encode(&mut self.data);
    }

    /// Write a uint64 to the message
    pub fn write_uint64(&mut self, value: u64) {
        SshUint64::new(value).encode(&mut self.data);
    }

    /// Write an mpint to the message
    pub fn write_mpint(&mut self, value: u64) {
        SshMpint::from_u64(value).encode(&mut self.data);
    }

    /// Write bytes to the message
    pub fn write_bytes(&mut self, value: &[u8]) {
        self.data.extend_from_slice(value);
    }

    /// Encode the message to bytes
    pub fn encode(self) -> Vec<u8> {
        self.data.to_vec()
    }

    /// Read a byte from the message
    pub fn read_byte(&self, offset: usize) -> Option<u8> {
        if offset < self.data.len() {
            Some(self.data[offset])
        } else {
            None
        }
    }

    /// Read a string from the message
    pub fn read_string(&self, offset: usize) -> Option<Vec<u8>> {
        let mut buf = &self.data[offset..];
        if buf.remaining() < 4 {
            return None;
        }
        
        let len = buf.get_u32() as usize;
        if buf.remaining() < len {
            return None;
        }
        
        Some(buf.copy_to_bytes(len).to_vec())
    }

    /// Read a string slice from the message
    pub fn read_string_slice(&self, offset: usize) -> Option<String> {
        let bytes = self.read_string(offset)?;
        String::from_utf8(bytes).ok()
    }

    /// Read a bool from the message
    /// Per RFC 4251: All non-zero values MUST be interpreted as TRUE
    pub fn read_bool(&self, offset: usize) -> Option<bool> {
        if offset < self.data.len() {
            let byte = self.data[offset];
            Some(byte != 0)
        } else {
            None
        }
    }

    /// Read a uint32 from the message
    pub fn read_uint32(&self, offset: usize) -> Option<u32> {
        if offset + 4 <= self.data.len() {
            let mut buf = &self.data[offset..];
            Some(buf.get_u32())
        } else {
            None
        }
    }

    /// Read a uint64 from the message
    pub fn read_uint64(&self, offset: usize) -> Option<u64> {
        if offset + 8 <= self.data.len() {
            let mut buf = &self.data[offset..];
            Some(buf.get_u64())
        } else {
            None
        }
    }

    /// Parse the message according to SSH_USERAUTH_REQUEST format
    pub fn parse_userauth_request(&self) -> Option<(String, String, String, bool)> {
        let mut offset = 1; // Skip message type
        
        // Username
        let username = self.read_string_slice(offset)?;
        offset += 4 + username.len();
        
        // Service
        let service = self.read_string_slice(offset)?;
        offset += 4 + service.len();
        
        // Method
        let method = self.read_string_slice(offset)?;
        offset += 4 + method.len();
        
        // Boolean (first attempt)
        let first_attempt = self.read_bool(offset)?;
        
        Some((username.to_string(), service.to_string(), method.to_string(), first_attempt))
    }

    /// Parse the message according to SSH_USERAUTH_FAILURE format
    pub fn parse_userauth_failure(&self) -> Option<(Vec<String>, Vec<String>)> {
        let mut offset = 1; // Skip message type
        
        // Partial success list
        let partial_success_bytes = self.read_string(offset)?;
        let partial_success = String::from_utf8_lossy(&partial_success_bytes)
            .split(',')
            .map(|s| s.to_string())
            .collect();
        offset += 4 + partial_success_bytes.len();
        
        // Available methods list
        let available_bytes = self.read_string(offset)?;
        let available_methods = String::from_utf8_lossy(&available_bytes)
            .split(',')
            .map(|s| s.to_string())
            .collect();
        
        Some((partial_success, available_methods))
    }
}

impl Default for Message {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<u8>> for Message {
    fn from(data: Vec<u8>) -> Self {
        Self { data: BytesMut::from(data.as_slice()) }
    }
}

impl From<&[u8]> for Message {
    fn from(data: &[u8]) -> Self {
        Self { data: BytesMut::from(data) }
    }
}

impl From<BytesMut> for Message {
    fn from(data: BytesMut) -> Self {
        Self { data }
    }
}

impl Message {
    /// Create a message from raw bytes
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data: BytesMut::from(data.as_slice()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_new() {
        let msg = Message::new();
        assert!(msg.is_empty());
    }

    #[test]
    fn test_message_with_type() {
        let msg = Message::with_type(MessageType::UserauthRequest);
        assert_eq!(msg.msg_type(), Some(MessageType::UserauthRequest));
    }

    #[test]
    fn test_message_write_read_bool() {
        let mut msg = Message::new();
        msg.write_bool(true);
        msg.write_bool(false);
        
        assert_eq!(msg.read_bool(0), Some(true));
        assert_eq!(msg.read_bool(1), Some(false));
    }

    #[test]
    fn test_message_write_read_string() {
        let mut msg = Message::new();
        msg.write_string(b"hello");
        
        assert_eq!(msg.read_string(0), Some(b"hello".to_vec()));
    }

    #[test]
    fn test_message_write_read_uint32() {
        let mut msg = Message::new();
        msg.write_uint32(42);
        
        assert_eq!(msg.read_uint32(0), Some(42));
    }

    #[test]
    fn test_parse_userauth_request() {
        let mut msg = Message::with_type(MessageType::UserauthRequest);
        msg.write_string(b"alice");
        msg.write_string(b"ssh-connection");
        msg.write_string(b"password");
        msg.write_bool(false);
        
        let result = msg.parse_userauth_request();
        assert_eq!(result, Some((
            "alice".to_string(),
            "ssh-connection".to_string(),
            "password".to_string(),
            false
        )));
    }

    #[test]
    fn test_parse_userauth_failure() {
        let mut msg = Message::with_type(MessageType::UserauthFailure);
        msg.write_string(b"password");
        msg.write_string(b"password,publickey");
        
        let result = msg.parse_userauth_failure();
        assert_eq!(result, Some((
            vec!["password".to_string()],
            vec!["password".to_string(), "publickey".to_string()]
        )));
    }
}