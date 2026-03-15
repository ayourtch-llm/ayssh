//! SSH String encoding utilities
//!
//! This module implements SSH string encoding/decoding as specified in RFC 4251.
//! SSH strings are length-prefixed, where the length is a 32-bit unsigned integer
//! in network byte order (big-endian).

use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;

/// SSH string encoding error
#[derive(Error, Debug)]
pub enum StringError {
    #[error("Invalid string length: {0}")]
    InvalidLength(u32),

    #[error("Buffer too short for string length")]
    BufferTooShort,

    #[error("Invalid UTF-8: {0}")]
    InvalidUtf8(String),
}

/// Result type for string operations
pub type Result<T> = std::result::Result<T, StringError>;

/// Read a length-prefixed string from a buffer
///
/// The string length is encoded as a 32-bit unsigned integer (big-endian).
/// This function reads the length, then reads that many bytes from the buffer.
pub fn read_string(buf: &mut &[u8]) -> Result<String> {
    let len = buf.get_u32() as usize;

    if buf.len() < len {
        return Err(StringError::BufferTooShort);
    }

    let string_bytes = &buf[..len];
    buf.advance(len);

    String::from_utf8(string_bytes.to_vec()).map_err(|_| StringError::InvalidUtf8("Invalid UTF-8".to_string()))
}

/// Write a string to a buffer as a length-prefixed string
pub fn write_string(buf: &mut BytesMut, s: &str) {
    buf.put_u32(s.len() as u32);
    buf.put_slice(s.as_bytes());
}

/// Read a string slice (without ownership transfer)
pub fn read_string_slice<'a>(buf: &mut &'a [u8]) -> Result<&'a str> {
    let len = buf.get_u32() as usize;

    if buf.len() < len {
        return Err(StringError::BufferTooShort);
    }

    let string_bytes = &buf[..len];
    buf.advance(len);

    std::str::from_utf8(string_bytes).map_err(|_| StringError::InvalidUtf8("Invalid UTF-8".to_string()))
}

/// Write a string slice to a buffer
pub fn write_string_slice(buf: &mut BytesMut, s: &str) {
    write_string(buf, s);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write_string() {
        let input = "hello world";
        let mut buf = BytesMut::new();
        write_string(&mut buf, input);

        let mut read_buf = &buf[..];
        let output = read_string(&mut read_buf).unwrap();

        assert_eq!(input, output);
        assert_eq!(read_buf.len(), 0);
    }

    #[test]
    fn test_read_string_slice() {
        let input = "test string";
        let mut buf = BytesMut::new();
        write_string(&mut buf, input);

        let mut read_buf = &buf[..];
        let output = read_string_slice(&mut read_buf).unwrap();

        assert_eq!(input, output);
    }

    #[test]
    fn test_empty_string() {
        let input = "";
        let mut buf = BytesMut::new();
        write_string(&mut buf, input);

        let mut read_buf = &buf[..];
        let output = read_string(&mut read_buf).unwrap();

        assert_eq!(input, output);
    }

    #[test]
    fn test_buffer_too_short() {
        // Create a buffer with a length prefix that exceeds actual data
        let mut buf = BytesMut::new();
        buf.put_u32(100); // Claim 100 bytes
        buf.put_slice(b"short"); // Only 5 bytes

        let mut read_buf = &buf[..];
        let result = read_string(&mut read_buf);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StringError::BufferTooShort));
    }

    #[test]
    fn test_invalid_utf8() {
        let mut buf = BytesMut::new();
        buf.put_u32(5);
        buf.put_slice(&[0xFF, 0xFE, 0xFD, 0xFC, 0xFB]); // Invalid UTF-8

        let mut read_buf = &buf[..];
        let result = read_string(&mut read_buf);

        assert!(result.is_err());
    }
}
