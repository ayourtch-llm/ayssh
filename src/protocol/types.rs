//! SSH Data Type Representations (RFC 4251, Section 5)
//!
//! SSH defines several data types for encoding/decoding protocol messages:
//! - `string<N>` - Length-prefixed string
//! - `uint32` - 32-bit unsigned integer (big-endian)
//! - `uint64` - 64-bit unsigned integer (big-endian)
//! - `boolean` - Single byte (0 = false, 1 = true)
//! - `mpint` - Multiple-precision integer (signed, big-endian)

use bytes::Buf;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use thiserror::Error;

/// SSH serialization error
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SshError {
    #[error("Buffer too small: need {needed} bytes, have {have}")]
    BufferTooSmall { needed: usize, have: usize },

    #[error("Invalid boolean: {0} (expected 0 or 1)")]
    InvalidBoolean(u8),

    #[error("Invalid uint32: value too large")]
    InvalidUint32(u64),

    #[error("Invalid mpint: empty or all zeros")]
    InvalidMpint,

    #[error("Invalid string: null byte in string")]
    InvalidStringNullByte,

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Result type for SSH operations
pub type SshResult<T> = Result<T, SshError>;

/// SSH string type - length-prefixed string
///
/// In SSH protocol, strings are encoded as:
/// - 4 bytes: length (big-endian uint32)
/// - N bytes: string data (may contain arbitrary bytes including nulls)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SshString {
    data: Bytes,
}

impl SshString {
    /// Create a new SshString from bytes
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }

    /// Create a new SshString from a string
    pub fn from_str(s: &str) -> Self {
        Self {
            data: Bytes::from(s.as_bytes().to_vec()),
        }
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the string data (excluding length prefix)
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the string is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Convert to a UTF-8 string
    pub fn to_str(&self) -> SshResult<&str> {
        std::str::from_utf8(&self.data).map_err(|_| SshError::Serialization("invalid UTF-8".to_string()))
    }

    /// Encode this string into a buffer (with length prefix)
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.data.len() as u32);
        buf.put(&self.data[..]);
    }

    /// Decode a string from a buffer (expects length prefix)
    pub fn decode(buf: &mut impl Buf) -> SshResult<Self> {
        if buf.remaining() < 4 {
            return Err(SshError::BufferTooSmall {
                needed: 4,
                have: buf.remaining(),
            });
        }

        let len = buf.get_u32() as usize;
        if buf.remaining() < len {
            return Err(SshError::BufferTooSmall {
                needed: len,
                have: buf.remaining(),
            });
        }

        let data = buf.copy_to_bytes(len);
        Ok(Self { data })
    }
}

impl From<&str> for SshString {
    fn from(s: &str) -> Self {
        Self::from_str(s)
    }
}

impl From<String> for SshString {
    fn from(s: String) -> Self {
        Self {
            data: Bytes::from(s.into_bytes()),
        }
    }
}

/// SSH uint32 type - 32-bit unsigned integer (big-endian)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SshUint32(u32);

impl SshUint32 {
    /// Create a new SshUint32
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Get the value as u32
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Encode this value into a buffer
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.0);
    }

    /// Decode a uint32 from a buffer
    pub fn decode(buf: &mut impl Buf) -> SshResult<Self> {
        if buf.remaining() < 4 {
            return Err(SshError::BufferTooSmall {
                needed: 4,
                have: buf.remaining(),
            });
        }
        Ok(Self(buf.get_u32()))
    }
}

/// SSH uint64 type - 64-bit unsigned integer (big-endian)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SshUint64(u64);

impl SshUint64 {
    /// Create a new SshUint64
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Get the value as u64
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Encode this value into a buffer
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u64(self.0);
    }

    /// Decode a uint64 from a buffer
    pub fn decode(buf: &mut impl Buf) -> SshResult<Self> {
        if buf.remaining() < 8 {
            return Err(SshError::BufferTooSmall {
                needed: 8,
                have: buf.remaining(),
            });
        }
        Ok(Self(buf.get_u64()))
    }
}

/// SSH boolean type - single byte (0 = false, 1 = true)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SshBoolean(bool);

impl SshBoolean {
    /// Create a new SshBoolean from a bool
    pub fn new(value: bool) -> Self {
        Self(value)
    }

    /// Get the value as bool
    pub fn as_bool(&self) -> bool {
        self.0
    }

    /// Encode this value into a buffer
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(if self.0 { 1 } else { 0 });
    }

    /// Decode a boolean from a buffer
    pub fn decode(buf: &mut impl Buf) -> SshResult<Self> {
        if buf.remaining() < 1 {
            return Err(SshError::BufferTooSmall {
                needed: 1,
                have: buf.remaining(),
            });
        }
        let byte = buf.get_u8();
        match byte {
            0 => Ok(Self(false)),
            1 => Ok(Self(true)),
            _ => Err(SshError::InvalidBoolean(byte)),
        }
    }
}

/// SSH multiple-precision integer - signed, big-endian
///
/// mpint is encoded as:
/// - 4 bytes: length (big-endian uint32)
/// - N bytes: signed big-endian integer (two's complement)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SshMpint(Bytes);

impl SshMpint {
    /// Create a new SshMpint from bytes
    pub fn new(data: Bytes) -> Self {
        Self(data)
    }

    /// Create a new SshMpint from a u64 value
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = Vec::new();
        if value == 0 {
            bytes.push(0);
        } else {
            // Convert to big-endian bytes
            for i in (0..8).rev() {
                bytes.push((value >> (i * 8)) as u8);
            }
            // Remove leading zero bytes
            let mut start = 0;
            while start < bytes.len() - 1 && bytes[start] == 0 {
                start += 1;
            }
            bytes.drain(..start);
        }
        Self(Bytes::from(bytes))
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encode this value into a buffer (with length prefix)
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.0.len() as u32);
        buf.put(&self.0[..]);
    }

    /// Decode an mpint from a buffer (expects length prefix)
    pub fn decode(buf: &mut impl Buf) -> SshResult<Self> {
        if buf.remaining() < 4 {
            return Err(SshError::BufferTooSmall {
                needed: 4,
                have: buf.remaining(),
            });
        }

        let len = buf.get_u32() as usize;
        if buf.remaining() < len {
            return Err(SshError::BufferTooSmall {
                needed: len,
                have: buf.remaining(),
            });
        }

        let data = buf.copy_to_bytes(len);

        // mpint cannot be empty or all zeros
        if data.is_empty() || data.iter().all(|&b| b == 0) {
            return Err(SshError::InvalidMpint);
        }

        Ok(Self(data))
    }

    /// Get the value as u64 (if it fits)
    pub fn to_u64(&self) -> SshResult<u64> {
        if self.0.len() > 8 {
            return Err(SshError::InvalidUint32(self.0.len() as u64));
        }

        let mut bytes = [0u8; 8];
        let offset = 8 - self.0.len();
        bytes[offset..].copy_from_slice(&self.0);

        Ok(u64::from_be_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_string_new() {
        let s = SshString::from_str("hello");
        assert_eq!(s.len(), 5);
        assert_eq!(s.to_str().unwrap(), "hello");
    }

    #[test]
    fn test_ssh_string_encode_decode() {
        let original = SshString::from_str("hello world");
        let mut buf = BytesMut::with_capacity(20);
        original.encode(&mut buf);

        buf.advance(0);
        let decoded = SshString::decode(&mut buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_ssh_string_empty() {
        let empty = SshString::new(Bytes::new());
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn test_ssh_uint32() {
        let val = SshUint32::new(42);
        assert_eq!(val.as_u32(), 42);

        let mut buf = BytesMut::with_capacity(4);
        val.encode(&mut buf);
        buf.advance(0);

        let decoded = SshUint32::decode(&mut buf).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_ssh_uint64() {
        let val = SshUint64::new(123456789012345);
        assert_eq!(val.as_u64(), 123456789012345);

        let mut buf = BytesMut::with_capacity(8);
        val.encode(&mut buf);
        buf.advance(0);

        let decoded = SshUint64::decode(&mut buf).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn test_ssh_boolean() {
        let true_val = SshBoolean::new(true);
        let mut buf = BytesMut::with_capacity(1);
        true_val.encode(&mut buf);
        buf.advance(0);
        let decoded = SshBoolean::decode(&mut buf).unwrap();
        assert!(decoded.as_bool());

        let false_val = SshBoolean::new(false);
        let mut buf = BytesMut::with_capacity(1);
        false_val.encode(&mut buf);
        buf.advance(0);
        let decoded = SshBoolean::decode(&mut buf).unwrap();
        assert!(!decoded.as_bool());
    }

    #[test]
    fn test_ssh_boolean_invalid() {
        let mut buf = BytesMut::from(&[2u8][..]);
        assert!(SshBoolean::decode(&mut buf).is_err());
    }

    #[test]
    fn test_ssh_mpint() {
        let mpint = SshMpint::from_u64(42);
        assert_eq!(mpint.to_u64().unwrap(), 42);

        let mut buf = BytesMut::with_capacity(10);
        mpint.encode(&mut buf);
        buf.advance(0);

        let decoded = SshMpint::decode(&mut buf).unwrap();
        assert_eq!(mpint.as_bytes(), decoded.as_bytes());
    }

    #[test]
    fn test_ssh_mpint_zero() {
        let mpint = SshMpint::from_u64(0);
        assert_eq!(mpint.to_u64().unwrap(), 0);
    }

    #[test]
    fn test_buffer_too_small() {
        let mut empty = BytesMut::new();
        assert!(SshString::decode(&mut empty).is_err());
        assert!(SshUint32::decode(&mut empty).is_err());
        assert!(SshUint64::decode(&mut empty).is_err());
        assert!(SshBoolean::decode(&mut empty).is_err());
    }

    #[test]
    fn test_ssh_string_with_special_chars() {
        let s = SshString::from_str("hello\x00world");
        assert_eq!(s.len(), 11);
        // Should allow null bytes in the string data
        assert_eq!(s.as_bytes(), b"hello\x00world");
    }
}
