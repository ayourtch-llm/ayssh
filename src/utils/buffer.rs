//! SSH Buffer types
//!
//! This module provides buffer types for reading and writing SSH data.

use std::io::{self, Read, Write};

/// Buffer for reading SSH data
pub struct SshReader<R: Read> {
    inner: R,
}

impl<R: Read> SshReader<R> {
    /// Create a new SSH reader
    pub fn new(reader: R) -> Self {
        Self { inner: reader }
    }

    /// Get a reference to the inner reader
    pub fn inner(&self) -> &R {
        &self.inner
    }

    /// Get a mutable reference to the inner reader
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Read a byte
    pub fn read_u8(&mut self) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        self.inner.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    /// Read a big-endian u32
    pub fn read_u32(&mut self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.inner.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    /// Read a big-endian u64
    pub fn read_u64(&mut self) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.inner.read_exact(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }
}

/// Buffer for writing SSH data
pub struct SshWriter<W: Write> {
    inner: W,
}

impl<W: Write> SshWriter<W> {
    /// Create a new SSH writer
    pub fn new(writer: W) -> Self {
        Self { inner: writer }
    }

    /// Get a reference to the inner writer
    pub fn inner(&self) -> &W {
        &self.inner
    }

    /// Get a mutable reference to the inner writer
    pub fn inner_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// Write a byte
    pub fn write_u8(&mut self, value: u8) -> io::Result<()> {
        self.inner.write_all(&[value])
    }

    /// Write a big-endian u32
    pub fn write_u32(&mut self, value: u32) -> io::Result<()> {
        self.inner.write_all(&value.to_be_bytes())
    }

    /// Write a big-endian u64
    pub fn write_u64(&mut self, value: u64) -> io::Result<()> {
        self.inner.write_all(&value.to_be_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_u8() {
        let mut reader = SshReader::new(Cursor::new(vec![0x42]));
        assert_eq!(reader.read_u8().unwrap(), 0x42);
    }

    #[test]
    fn test_read_u32() {
        let mut reader = SshReader::new(Cursor::new(vec![0x01, 0x02, 0x03, 0x04]));
        assert_eq!(reader.read_u32().unwrap(), 0x01020304);
    }

    #[test]
    fn test_write_u8() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u8(0x42).unwrap();
        assert_eq!(writer.inner(), &vec![0x42]);
    }

    #[test]
    fn test_write_u32() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u32(0x01020304).unwrap();
        assert_eq!(writer.inner(), &vec![0x01, 0x02, 0x03, 0x04]);
    }
}
