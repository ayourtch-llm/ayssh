//! SSH Buffer types
//!
//! This module provides buffer types for reading and writing SSH data.

use std::io::{self, Read, Write};

/// Buffer for reading SSH data
pub struct SshReader<R: Read> {
    inner: R,
}

impl<R: Read> std::fmt::Debug for SshReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshReader").finish_non_exhaustive()
    }
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

impl<W: Write> std::fmt::Debug for SshWriter<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshWriter").finish_non_exhaustive()
    }
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

    // --- SshReader ---

    #[test]
    fn test_read_u8() {
        let mut reader = SshReader::new(Cursor::new(vec![0x42]));
        assert_eq!(reader.read_u8().unwrap(), 0x42);
    }

    #[test]
    fn test_read_u8_zero() {
        let mut reader = SshReader::new(Cursor::new(vec![0x00]));
        assert_eq!(reader.read_u8().unwrap(), 0);
    }

    #[test]
    fn test_read_u8_max() {
        let mut reader = SshReader::new(Cursor::new(vec![0xFF]));
        assert_eq!(reader.read_u8().unwrap(), 255);
    }

    #[test]
    fn test_read_u8_empty_buffer_fails() {
        let mut reader = SshReader::new(Cursor::new(vec![]));
        assert!(reader.read_u8().is_err());
    }

    #[test]
    fn test_read_u32() {
        let mut reader = SshReader::new(Cursor::new(vec![0x01, 0x02, 0x03, 0x04]));
        assert_eq!(reader.read_u32().unwrap(), 0x01020304);
    }

    #[test]
    fn test_read_u32_zero() {
        let mut reader = SshReader::new(Cursor::new(vec![0, 0, 0, 0]));
        assert_eq!(reader.read_u32().unwrap(), 0);
    }

    #[test]
    fn test_read_u32_max() {
        let mut reader = SshReader::new(Cursor::new(vec![0xFF, 0xFF, 0xFF, 0xFF]));
        assert_eq!(reader.read_u32().unwrap(), u32::MAX);
    }

    #[test]
    fn test_read_u32_too_short_fails() {
        let mut reader = SshReader::new(Cursor::new(vec![0x01, 0x02]));
        assert!(reader.read_u32().is_err());
    }

    #[test]
    fn test_read_u64() {
        let mut reader = SshReader::new(Cursor::new(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]));
        assert_eq!(reader.read_u64().unwrap(), 0x0102030405060708);
    }

    #[test]
    fn test_read_u64_zero() {
        let mut reader = SshReader::new(Cursor::new(vec![0; 8]));
        assert_eq!(reader.read_u64().unwrap(), 0);
    }

    #[test]
    fn test_read_u64_max() {
        let mut reader = SshReader::new(Cursor::new(vec![0xFF; 8]));
        assert_eq!(reader.read_u64().unwrap(), u64::MAX);
    }

    #[test]
    fn test_read_u64_too_short_fails() {
        let mut reader = SshReader::new(Cursor::new(vec![0x01; 5]));
        assert!(reader.read_u64().is_err());
    }

    #[test]
    fn test_reader_sequential_reads() {
        let data = vec![0x42, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07];
        let mut reader = SshReader::new(Cursor::new(data));
        assert_eq!(reader.read_u8().unwrap(), 0x42);
        assert_eq!(reader.read_u32().unwrap(), 10);
        assert_eq!(reader.read_u64().unwrap(), 7);
    }

    #[test]
    fn test_reader_inner() {
        let cursor = Cursor::new(vec![1, 2, 3]);
        let reader = SshReader::new(cursor);
        assert_eq!(reader.inner().get_ref(), &vec![1, 2, 3]);
    }

    #[test]
    fn test_reader_inner_mut() {
        let cursor = Cursor::new(vec![1, 2, 3]);
        let mut reader = SshReader::new(cursor);
        reader.inner_mut().set_position(2);
        assert_eq!(reader.read_u8().unwrap(), 3);
    }

    // --- SshWriter ---

    #[test]
    fn test_write_u8() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u8(0x42).unwrap();
        assert_eq!(writer.inner(), &vec![0x42]);
    }

    #[test]
    fn test_write_u8_zero() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u8(0).unwrap();
        assert_eq!(writer.inner(), &vec![0x00]);
    }

    #[test]
    fn test_write_u32() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u32(0x01020304).unwrap();
        assert_eq!(writer.inner(), &vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_write_u32_zero() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u32(0).unwrap();
        assert_eq!(writer.inner(), &vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_write_u32_max() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u32(u32::MAX).unwrap();
        assert_eq!(writer.inner(), &vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_write_u64() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u64(0x0102030405060708).unwrap();
        assert_eq!(writer.inner(), &vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_write_u64_zero() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u64(0).unwrap();
        assert_eq!(writer.inner(), &vec![0; 8]);
    }

    #[test]
    fn test_write_u64_max() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u64(u64::MAX).unwrap();
        assert_eq!(writer.inner(), &vec![0xFF; 8]);
    }

    #[test]
    fn test_writer_sequential_writes() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u8(0x42).unwrap();
        writer.write_u32(10).unwrap();
        writer.write_u64(7).unwrap();
        assert_eq!(writer.inner(), &vec![0x42, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07]);
    }

    #[test]
    fn test_writer_inner_mut() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u8(1).unwrap();
        writer.inner_mut().push(99); // directly mutate underlying vec
        assert_eq!(writer.inner(), &vec![1, 99]);
    }

    // --- Roundtrip ---

    #[test]
    fn test_roundtrip_u8() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u8(0xAB).unwrap();
        let mut reader = SshReader::new(Cursor::new(writer.inner().clone()));
        assert_eq!(reader.read_u8().unwrap(), 0xAB);
    }

    #[test]
    fn test_roundtrip_u32() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u32(123456789).unwrap();
        let mut reader = SshReader::new(Cursor::new(writer.inner().clone()));
        assert_eq!(reader.read_u32().unwrap(), 123456789);
    }

    #[test]
    fn test_roundtrip_u64() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u64(9876543210).unwrap();
        let mut reader = SshReader::new(Cursor::new(writer.inner().clone()));
        assert_eq!(reader.read_u64().unwrap(), 9876543210);
    }

    #[test]
    fn test_roundtrip_mixed() {
        let mut writer = SshWriter::new(Vec::new());
        writer.write_u8(1).unwrap();
        writer.write_u32(2).unwrap();
        writer.write_u64(3).unwrap();
        writer.write_u8(4).unwrap();

        let mut reader = SshReader::new(Cursor::new(writer.inner().clone()));
        assert_eq!(reader.read_u8().unwrap(), 1);
        assert_eq!(reader.read_u32().unwrap(), 2);
        assert_eq!(reader.read_u64().unwrap(), 3);
        assert_eq!(reader.read_u8().unwrap(), 4);
    }
}
