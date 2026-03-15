use ssh_client::crypto::packet::{Packet, PacketWriter, PacketReader, calculate_padding};

#[test]
fn test_packet_construction() {
    let packet = Packet::new(vec![1, 2, 3, 4]);
    assert_eq!(packet.length, 4);
    assert!(packet.padlen >= 4); // Padding is calculated automatically
    assert_eq!(packet.payload, vec![1, 2, 3, 4]);
}

#[test]
fn test_packet_with_padding() {
    let packet = Packet::new_with_padding(vec![1, 2, 3, 4], 10);
    assert_eq!(packet.length, 4);
    assert_eq!(packet.padlen, 10);
    assert_eq!(packet.payload, vec![1, 2, 3, 4]);
    assert_eq!(packet.padding.len(), 10);
}

#[test]
fn test_calculate_padding_minimum() {
    // For a 4-byte payload, we need at least 4 bytes of padding
    let padding = calculate_padding(4);
    assert!(padding >= 4);
    assert!(padding <= 255);
}

#[test]
fn test_calculate_padding_alignment() {
    // Padding should align to 64-bit blocks
    // The formula is: (HEADER_SIZE + payload_len + padding) % 64 == 0
    // where HEADER_SIZE = 8 (4 bytes length + 4 bytes padlen)
    for payload_len in 0..100 {
        let padding = calculate_padding(payload_len);
        let total = 8 + payload_len + padding; // 8 = HEADER_SIZE
        assert_eq!(total % 64, 0, "Payload {} with padding {} doesn't align to 64 bits", payload_len, padding);
    }
}

#[test]
fn test_calculate_padding_zero_payload() {
    let padding = calculate_padding(0);
    assert!(padding >= 4);
    assert!(padding <= 255);
}

#[test]
fn test_calculate_padding_large_payload() {
    let padding = calculate_padding(1000);
    assert!(padding >= 4);
    assert!(padding <= 255);
}

#[test]
fn test_packet_writer() {
    let mut writer = PacketWriter::new();
    writer.write_payload(&[1, 2, 3, 4]);
    
    let packet = writer.build();
    assert_eq!(packet.length, 4);
    assert!(packet.padding.len() >= 4);
}

#[test]
fn test_packet_writer_empty_payload() {
    let mut writer = PacketWriter::new();
    writer.write_payload(&[]);
    
    let packet = writer.build();
    assert_eq!(packet.length, 0);
    assert!(packet.padding.len() >= 4);
}

#[test]
fn test_packet_writer_large_payload() {
    let mut writer = PacketWriter::new();
    let large_payload = vec![0xAA; 1000];
    writer.write_payload(&large_payload);
    
    let packet = writer.build();
    assert_eq!(packet.length, 1000);
    assert!(packet.padding.len() >= 4);
}

#[test]
fn test_packet_reader() {
    let packet = Packet::new_with_padding(vec![1, 2, 3, 4], 10);
    let serialized = packet.serialize();
    
    let reader = PacketReader::new(&serialized).unwrap();
    assert_eq!(reader.payload_len, 4);
    assert_eq!(reader.padlen, 10);
}

#[test]
fn test_packet_reader_empty_payload() {
    let packet = Packet::new_with_padding(vec![], 4);
    let serialized = packet.serialize();
    
    let reader = PacketReader::new(&serialized).unwrap();
    assert_eq!(reader.payload_len, 0);
    assert_eq!(reader.padlen, 4);
}

#[test]
fn test_packet_round_trip() {
    let original_payload = vec![0x01, 0x02, 0x03, 0x04];
    let mut writer = PacketWriter::new();
    writer.write_payload(&original_payload);
    let packet = writer.build();
    let serialized = packet.serialize();
    
    let reader = PacketReader::new(&serialized).unwrap();
    assert_eq!(reader.payload_len, original_payload.len() as u32);
}

#[test]
fn test_packet_padding_randomness() {
    let mut writer = PacketWriter::new();
    writer.write_payload(&[1, 2, 3]);
    let packet1 = writer.build();
    
    let mut writer2 = PacketWriter::new();
    writer2.write_payload(&[1, 2, 3]);
    let packet2 = writer2.build();
    
    // Padding should be random, so different packets should have different padding
    assert_ne!(packet1.padding, packet2.padding);
}

#[test]
fn test_packet_max_padding() {
    // Test that padding doesn't exceed 255 bytes
    let mut writer = PacketWriter::new();
    writer.write_payload(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    let packet = writer.build();
    
    assert!(packet.padding.len() <= 255);
}

#[test]
fn test_packet_alignment_all_sizes() {
    // Test alignment for various payload sizes
    for payload_size in 0..200 {
        let mut writer = PacketWriter::new();
        writer.write_payload(&vec![0x00; payload_size]);
        let packet = writer.build();
        
        // Total size should be: HEADER_SIZE (8) + payload_size + padding
        let total = 8 + payload_size + packet.padding.len();
        assert_eq!(total % 64, 0, "Payload size {} failed alignment", payload_size);
    }
}

#[test]
fn test_packet_struct_size() {
    let packet = Packet::new(vec![1, 2, 3]);
    
    assert_eq!(packet.length, 3);
    assert!(packet.padlen <= 255);
    assert!(packet.padding.len() <= 255);
}

#[test]
fn test_packet_with_message_type() {
    // SSH messages start with a message type byte
    let message_type = vec![0x01]; // SSH_MSG_DISCONNECT
    let mut writer = PacketWriter::new();
    writer.write_payload(&message_type);
    
    let packet = writer.build();
    assert_eq!(packet.length, 1);
    assert_eq!(packet.payload[0], 0x01);
}

#[test]
fn test_packet_padding_bounds() {
    for _ in 0..100 {
        let mut writer = PacketWriter::new();
        writer.write_payload(&[1, 2, 3, 4]);
        let packet = writer.build();
        
        assert!(packet.padding.len() >= 4, "Padding too small");
        assert!(packet.padding.len() <= 255, "Padding too large");
    }
}