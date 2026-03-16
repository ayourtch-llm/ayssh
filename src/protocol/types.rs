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
    ///
    /// Per RFC 4251 Section 5: "All non-zero values MUST be interpreted as TRUE"
    /// Applications MUST NOT store values other than 0 and 1, but on decode
    /// any non-zero value is accepted as TRUE.
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
            _ => Ok(Self(true)),
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
    ///
    /// Per RFC 4251 Section 5: "The value zero MUST be stored as a string
    /// with zero bytes of data."
    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            // RFC 4251: zero is stored as empty data (length=0)
            return Self(Bytes::new());
        }
        let mut bytes = Vec::new();
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
        // RFC 4251: If the most significant bit would be set for a positive number,
        // the number MUST be preceded by a zero byte.
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0);
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
    ///
    /// Per RFC 4251 Section 5:
    /// - The value zero MUST be stored as a string with zero bytes of data
    /// - Unnecessary leading bytes with the value 0 or 255 MUST NOT be included
    /// - If the most significant bit would be set for a positive number,
    ///   the number MUST be preceded by a zero byte
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

        // Zero-length data represents the value 0 (RFC 4251)
        if data.is_empty() {
            return Ok(Self(data));
        }

        // Check for unnecessary leading zeros (RFC 4251 Section 5):
        // A leading 0x00 byte is only necessary when the next byte has its MSB set (bit 7),
        // because without it the number would be interpreted as negative in two's complement.
        // If the next byte does NOT have MSB set, the leading 0x00 is unnecessary padding.
        if data.len() > 1 && data[0] == 0x00 && (data[1] & 0x80) == 0 {
            return Err(SshError::InvalidMpint);
        }

        // Check for unnecessary leading 0xFF bytes (negative number, RFC 4251 Section 5):
        // A leading 0xFF byte is only necessary when the next byte does NOT have its MSB set,
        // because without it the number would be interpreted as positive.
        // If the next byte DOES have MSB set, the leading 0xFF is unnecessary padding.
        if data.len() > 1 && data[0] == 0xFF && (data[1] & 0x80) != 0 {
            return Err(SshError::InvalidMpint);
        }

        Ok(Self(data))
    }

    /// Get the value as u64 (if it fits)
    pub fn to_u64(&self) -> SshResult<u64> {
        // Empty data represents zero (RFC 4251)
        if self.0.is_empty() {
            return Ok(0);
        }

        let data = &self.0[..];

        // Skip leading zero byte used for sign extension (positive number with MSB set)
        let effective = if data.len() > 1 && data[0] == 0x00 {
            &data[1..]
        } else {
            data
        };

        if effective.len() > 8 {
            return Err(SshError::InvalidUint32(self.0.len() as u64));
        }

        let mut bytes = [0u8; 8];
        let offset = 8 - effective.len();
        bytes[offset..].copy_from_slice(effective);

        Ok(u64::from_be_bytes(bytes))
    }
}

/// SSH name-list type (RFC 4251 Section 5)
///
/// A name-list is a comma-separated list of names. Each name MUST have
/// a non-zero length and MUST NOT contain a comma. Names MUST be in US-ASCII.
/// Terminating null characters MUST NOT be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshNameList {
    names: Vec<String>,
}

impl SshNameList {
    /// Create a new SshNameList from a vector of names
    pub fn new(names: Vec<String>) -> SshResult<Self> {
        for name in &names {
            Self::validate_name(name)?;
        }
        Ok(Self { names })
    }

    /// Create an empty name-list
    pub fn empty() -> Self {
        Self { names: vec![] }
    }

    /// Validate a single algorithm/method name per RFC 4251 Section 6
    ///
    /// Names MUST be printable US-ASCII, non-empty, no longer than 64 characters,
    /// MUST NOT contain commas, whitespace, control characters, or null bytes.
    fn validate_name(name: &str) -> SshResult<()> {
        if name.is_empty() {
            return Err(SshError::Serialization("Name in name-list MUST have non-zero length".to_string()));
        }
        if name.len() > 64 {
            return Err(SshError::Serialization("Name MUST NOT be longer than 64 characters".to_string()));
        }
        for byte in name.bytes() {
            if byte == b',' {
                return Err(SshError::Serialization("Name MUST NOT contain comma".to_string()));
            }
            if byte == 0 {
                return Err(SshError::Serialization("Name MUST NOT contain null byte".to_string()));
            }
            if byte < 32 || byte == 127 {
                return Err(SshError::Serialization("Name MUST be printable US-ASCII".to_string()));
            }
        }
        Ok(())
    }

    /// Get the names as a slice
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Encode as a comma-separated SSH string
    pub fn encode(&self, buf: &mut BytesMut) {
        let joined = self.names.join(",");
        SshString::from_str(&joined).encode(buf);
    }

    /// Decode from an SSH string (comma-separated)
    pub fn decode(buf: &mut impl Buf) -> SshResult<Self> {
        let s = SshString::decode(buf)?;
        let text = s.to_str()?;
        if text.is_empty() {
            return Ok(Self::empty());
        }
        let names: Vec<String> = text.split(',').map(|s| s.to_string()).collect();
        for name in &names {
            Self::validate_name(name)?;
        }
        Ok(Self { names })
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
        // RFC 4251: All non-zero values MUST be interpreted as TRUE
        let mut buf = BytesMut::from(&[2u8][..]);
        let result = SshBoolean::decode(&mut buf).unwrap();
        assert!(result.as_bool()); // non-zero = true

        let mut buf = BytesMut::from(&[255u8][..]);
        let result = SshBoolean::decode(&mut buf).unwrap();
        assert!(result.as_bool()); // non-zero = true

        let mut buf = BytesMut::from(&[128u8][..]);
        let result = SshBoolean::decode(&mut buf).unwrap();
        assert!(result.as_bool()); // non-zero = true
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
        // RFC 4251: "The value zero MUST be stored as a string with zero bytes of data"
        let mpint = SshMpint::from_u64(0);
        assert_eq!(mpint.as_bytes().len(), 0); // zero-length data
        assert_eq!(mpint.to_u64().unwrap(), 0);

        // Verify encode produces length=0
        let mut buf = BytesMut::with_capacity(10);
        mpint.encode(&mut buf);
        assert_eq!(&buf[..], &[0x00, 0x00, 0x00, 0x00]); // 4-byte length prefix = 0
    }

    #[test]
    fn test_ssh_mpint_zero_decode() {
        // RFC 4251: Zero-length data decodes as zero
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x00, 0x00][..]);
        let mpint = SshMpint::decode(&mut buf).unwrap();
        assert_eq!(mpint.to_u64().unwrap(), 0);
    }

    #[test]
    fn test_ssh_mpint_roundtrip() {
        // Test roundtrip encode/decode for various values
        for value in [1u64, 42, 127, 128, 255, 256, 65535, 0x7FFFFFFF, 0x80000000, u64::MAX] {
            let mpint = SshMpint::from_u64(value);
            let mut buf = BytesMut::with_capacity(20);
            mpint.encode(&mut buf);
            let decoded = SshMpint::decode(&mut buf).unwrap();
            assert_eq!(mpint.as_bytes(), decoded.as_bytes(), "Roundtrip failed for {}", value);
        }
    }

    #[test]
    fn test_ssh_mpint_positive_msb_set() {
        // RFC 4251: If MSB would be set for positive number, MUST be preceded by zero byte
        let mpint = SshMpint::from_u64(0x80);  // 128 - MSB set
        assert_eq!(mpint.as_bytes(), &[0x00, 0x80]); // leading zero byte required

        let mpint = SshMpint::from_u64(0xFF);  // 255 - MSB set
        assert_eq!(mpint.as_bytes(), &[0x00, 0xFF]); // leading zero byte required

        let mpint = SshMpint::from_u64(0x7F);  // 127 - MSB not set
        assert_eq!(mpint.as_bytes(), &[0x7F]); // no leading zero needed
    }

    #[test]
    fn test_ssh_mpint_reject_unnecessary_leading_zeros() {
        // RFC 4251: "Unnecessary leading bytes with the value 0 or 255 MUST NOT be included"
        // 0x00 0x42 has unnecessary leading zero (0x42 doesn't have MSB set)
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x00, 0x02, 0x00, 0x42][..]);
        assert!(SshMpint::decode(&mut buf).is_err());
    }

    #[test]
    fn test_ssh_mpint_valid_leading_zero() {
        // 0x00 0x80 is valid - leading zero needed because 0x80 has MSB set (positive number)
        let mut buf = BytesMut::from(&[0x00, 0x00, 0x00, 0x02, 0x00, 0x80][..]);
        let mpint = SshMpint::decode(&mut buf).unwrap();
        assert_eq!(mpint.as_bytes(), &[0x00, 0x80]);
    }

    #[test]
    fn test_ssh_mpint_rfc4251_examples() {
        // RFC 4251 Section 5 examples:
        // value (hex)   representation (hex)
        // 0             00 00 00 00
        // 9a378f9b2e332a7 00 00 00 08 09 a3 78 f9 b2 e3 32 a7
        // 80             00 00 00 02 00 80

        // Zero
        let mpint = SshMpint::from_u64(0);
        let mut buf = BytesMut::with_capacity(20);
        mpint.encode(&mut buf);
        assert_eq!(&buf[..], &[0x00, 0x00, 0x00, 0x00]);

        // 0x80 (needs leading zero)
        let mpint = SshMpint::from_u64(0x80);
        let mut buf = BytesMut::with_capacity(20);
        mpint.encode(&mut buf);
        assert_eq!(&buf[..], &[0x00, 0x00, 0x00, 0x02, 0x00, 0x80]);

        // 0x9a378f9b2e332a7
        let mpint = SshMpint::from_u64(0x09a378f9b2e332a7);
        let mut buf = BytesMut::with_capacity(20);
        mpint.encode(&mut buf);
        assert_eq!(&buf[..], &[0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]);
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

    // SshNameList tests (RFC 4251 Section 5)

    #[test]
    fn test_ssh_name_list_valid() {
        let nl = SshNameList::new(vec!["aes128-cbc".to_string(), "3des-cbc".to_string()]).unwrap();
        assert_eq!(nl.names().len(), 2);
        assert_eq!(nl.names()[0], "aes128-cbc");
        assert_eq!(nl.names()[1], "3des-cbc");
    }

    #[test]
    fn test_ssh_name_list_empty() {
        let nl = SshNameList::empty();
        assert_eq!(nl.names().len(), 0);
    }

    #[test]
    fn test_ssh_name_list_encode_decode() {
        let nl = SshNameList::new(vec!["hmac-sha2-256".to_string(), "hmac-sha1".to_string()]).unwrap();
        let mut buf = BytesMut::with_capacity(100);
        nl.encode(&mut buf);
        let decoded = SshNameList::decode(&mut buf).unwrap();
        assert_eq!(nl, decoded);
    }

    #[test]
    fn test_ssh_name_list_reject_empty_name() {
        // RFC 4251: "A name MUST have a non-zero length"
        assert!(SshNameList::new(vec!["".to_string()]).is_err());
    }

    #[test]
    fn test_ssh_name_list_reject_comma() {
        // RFC 4251: Name "MUST NOT contain a comma"
        assert!(SshNameList::new(vec!["aes,cbc".to_string()]).is_err());
    }

    #[test]
    fn test_ssh_name_list_reject_null_byte() {
        // RFC 4251: "Terminating null characters MUST NOT be used"
        assert!(SshNameList::new(vec!["aes\x00cbc".to_string()]).is_err());
    }

    #[test]
    fn test_ssh_name_list_reject_control_chars() {
        // RFC 4251: Names MUST be printable US-ASCII
        assert!(SshNameList::new(vec!["aes\x01cbc".to_string()]).is_err());
    }

    #[test]
    fn test_ssh_name_list_reject_too_long_name() {
        // RFC 4251: Names MUST NOT be longer than 64 characters
        let long_name = "a".repeat(65);
        assert!(SshNameList::new(vec![long_name]).is_err());

        // 64 chars is OK
        let name_64 = "a".repeat(64);
        assert!(SshNameList::new(vec![name_64]).is_ok());
    }

    #[test]
    fn test_ssh_name_list_domain_name_format() {
        // RFC 4251 Section 6: Domain-specific names with @ sign are valid
        let nl = SshNameList::new(vec!["aes256-gcm@openssh.com".to_string()]).unwrap();
        assert_eq!(nl.names()[0], "aes256-gcm@openssh.com");
    }

    // Boolean encoding tests (RFC 4251 Section 5)

    #[test]
    fn test_ssh_boolean_encode_stores_only_0_or_1() {
        // RFC 4251: "applications MUST NOT store values other than 0 and 1"
        let t = SshBoolean::new(true);
        let mut buf = BytesMut::with_capacity(1);
        t.encode(&mut buf);
        assert_eq!(buf[0], 1);

        let f = SshBoolean::new(false);
        let mut buf = BytesMut::with_capacity(1);
        f.encode(&mut buf);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_ssh_boolean_nonzero_is_true() {
        // RFC 4251: "All non-zero values MUST be interpreted as TRUE"
        for v in [1u8, 2, 42, 127, 128, 255] {
            let mut buf = BytesMut::from(&[v][..]);
            let b = SshBoolean::decode(&mut buf).unwrap();
            assert!(b.as_bool(), "value {} should decode as true", v);
        }
    }
}
