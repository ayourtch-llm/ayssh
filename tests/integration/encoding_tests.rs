use bytes::BytesMut;
use ayssh::protocol::{SshString, SshUint32};

#[test]
fn test_ssh_string_encode_decode() {
    let original = SshString::from_str("hello world");
    let mut buf = BytesMut::with_capacity(20);
    original.encode(&mut buf);
    
    let mut read_buf = &buf[..];
    let decoded = SshString::decode(&mut read_buf).unwrap();
    
    assert_eq!(original, decoded);
}

#[test]
fn test_ssh_string_with_null_bytes() {
    // SSH strings can contain null bytes
    let original = SshString::new(bytes::Bytes::from_static(b"hello\x00world"));
    let mut buf = BytesMut::new();
    original.encode(&mut buf);
    
    let mut read_buf = &buf[..];
    let decoded = SshString::decode(&mut read_buf).unwrap();
    
    assert_eq!(original.as_bytes(), decoded.as_bytes());
}

#[test]
fn test_ssh_string_empty() {
    let empty = SshString::new(bytes::Bytes::new());
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
}

#[test]
fn test_ssh_uint32_encode_decode() {
    let val = SshUint32::new(42);
    let mut buf = BytesMut::with_capacity(4);
    val.encode(&mut buf);
    
    let mut read_buf = &buf[..];
    let decoded = SshUint32::decode(&mut read_buf).unwrap();
    
    assert_eq!(val, decoded);
}