use ayssh::crypto::packet::{calculate_padding, Packet, PacketWriter};

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
    // RFC 4253 Section 6: Padding MUST align to 8-byte blocks (64 bits)
    // The formula is: (packet_length || padding_length || payload || random padding) % 8 == 0
    // packet_length = 4 bytes, padding_length = 1 byte, so HEADER_SIZE = 5
    // We need: (5 + payload_len + padding) % 8 == 0 with padding >= 4
    for payload_len in 0..100 {
        let padding = calculate_padding(payload_len);
        let total = 5 + payload_len + padding; // 5 = 4 (length) + 1 (padlen)
        assert_eq!(
            total % 8,
            0,
            "Payload {} with padding {} doesn't align to 8 bytes",
            payload_len,
            padding
        );
        assert!(padding >= 4, "Padding {} is less than minimum 4", padding);
        assert!(padding <= 255, "Padding {} exceeds maximum 255", padding);
    }
}

#[test]
fn test_packet_struct_size() {
    let packet = Packet::new(vec![1, 2, 3]);

    assert_eq!(packet.length, 3);
    #[allow(unused_comparisons)]
    { assert!(packet.padlen <= 255); }
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
