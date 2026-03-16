//! Channel Data Transfer Integration Tests

use ssh_client::channel::{ChannelTransferManager, ChannelId};
use ssh_client::protocol::messages::MessageType;
use std::io::{Cursor, Read, Write};

#[test]
fn test_channel_transfer_manager_create_session() {
    let mut manager = ChannelTransferManager::new();
    
    let channel_id = manager.create_session_channel("127.0.0.100", 12345);
    
    assert_eq!(channel_id.to_u32(), 0);
    
    let channel = manager.get_channel(channel_id).expect("Channel should exist");
    assert_eq!(channel.channel_type_str(), "session");
}

#[test]
fn test_channel_transfer_manager_send_data() {
    let mut manager = ChannelTransferManager::new();
    let channel_id = manager.create_session_channel("127.0.0.100", 12345);
    
    let data = b"Hello, SSH!";
    let encoded = manager.send_data(channel_id, data).expect("Should encode data");
    
    // Verify the message structure
    assert!(!encoded.is_empty());
    assert_eq!(encoded[0], MessageType::ChannelData as u8);
    
    // Parse back to verify using manual parsing
    let mut cursor = Cursor::new(&encoded);
    let mut msg_type_buf = [0u8; 1];
    cursor.read_exact(&mut msg_type_buf).expect("Read msg type");
    assert_eq!(msg_type_buf[0], MessageType::ChannelData as u8);
    
    let mut channel_id_buf = [0u8; 4];
    cursor.read_exact(&mut channel_id_buf).expect("Read channel id");
    let channel_id_read = u32::from_be_bytes(channel_id_buf);
    assert_eq!(channel_id_read, channel_id.to_u32());
    
    let mut data_len_buf = [0u8; 4];
    cursor.read_exact(&mut data_len_buf).expect("Read data len");
    let data_len = u32::from_be_bytes(data_len_buf);
    assert_eq!(data_len as usize, data.len());
    
    let mut data_read = vec![0u8; data.len()];
    cursor.read_exact(&mut data_read).expect("Read data");
    assert_eq!(data_read, data);
}

#[test]
fn test_channel_transfer_manager_send_eof() {
    let mut manager = ChannelTransferManager::new();
    let channel_id = manager.create_session_channel("127.0.0.100", 12345);
    
    let encoded = manager.send_eof(channel_id).expect("Should encode EOF");
    
    assert!(!encoded.is_empty());
    assert_eq!(encoded[0], MessageType::ChannelEof as u8);
    
    let mut cursor = Cursor::new(&encoded);
    let mut msg_type_buf = [0u8; 1];
    cursor.read_exact(&mut msg_type_buf).expect("Read msg type");
    assert_eq!(msg_type_buf[0], MessageType::ChannelEof as u8);
    
    let mut channel_id_buf = [0u8; 4];
    cursor.read_exact(&mut channel_id_buf).expect("Read channel id");
    let channel_id_read = u32::from_be_bytes(channel_id_buf);
    assert_eq!(channel_id_read, channel_id.to_u32());
}

#[test]
fn test_channel_transfer_manager_send_close() {
    let mut manager = ChannelTransferManager::new();
    let channel_id = manager.create_session_channel("127.0.0.100", 12345);
    
    let encoded = manager.send_close(channel_id).expect("Should encode close");
    
    assert!(!encoded.is_empty());
    assert_eq!(encoded[0], MessageType::ChannelClose as u8);
    
    let mut cursor = Cursor::new(&encoded);
    let mut msg_type_buf = [0u8; 1];
    cursor.read_exact(&mut msg_type_buf).expect("Read msg type");
    assert_eq!(msg_type_buf[0], MessageType::ChannelClose as u8);
    
    let mut channel_id_buf = [0u8; 4];
    cursor.read_exact(&mut channel_id_buf).expect("Read channel id");
    let channel_id_read = u32::from_be_bytes(channel_id_buf);
    assert_eq!(channel_id_read, channel_id.to_u32());
}

#[test]
fn test_channel_transfer_manager_window_enforcement() {
    let mut manager = ChannelTransferManager::new();
    let channel_id = manager.create_session_channel("127.0.0.100", 12345);
    
    // Get the channel to check its window size
    let channel = manager.get_channel(channel_id).expect("Channel should exist");
    let window_size = channel.window_size;
    
    // Try to send data larger than window size
    let large_data = vec![0u8; (window_size + 1) as usize];
    let result = manager.send_data(channel_id, &large_data);
    
    // Should fail due to window size
    assert!(result.is_none(), "Should fail when data exceeds window size");
}

#[test]
fn test_channel_transfer_manager_invalid_channel() {
    let mut manager = ChannelTransferManager::new();
    let invalid_channel_id = ChannelId::new(999);
    
    // Try to send data on non-existent channel
    let result = manager.send_data(invalid_channel_id, b"test");
    assert!(result.is_none(), "Should fail for invalid channel");
    
    let result = manager.send_eof(invalid_channel_id);
    assert!(result.is_none(), "Should fail for invalid channel");
    
    let result = manager.send_close(invalid_channel_id);
    assert!(result.is_none(), "Should fail for invalid channel");
}