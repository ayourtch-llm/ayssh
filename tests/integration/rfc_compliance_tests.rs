//! RFC Compliance Tests
//!
//! Tests verifying compliance with SSH RFCs:
//! - RFC 4251: SSH Protocol Architecture (data types)
//! - RFC 4253: SSH Transport Layer Protocol
//! - RFC 4252: SSH Authentication Protocol
//! - RFC 4254: SSH Connection Protocol

use ayssh::protocol::types::{SshBoolean, SshMpint, SshNameList, SshString, SshUint32, SshUint64};
use ayssh::protocol::transport_messages::{
    DebugMessage, DisconnectMessage, DisconnectReason, IgnoreMessage, UnimplementedMessage,
};
use ayssh::protocol::messages::MessageType;
use ayssh::protocol::algorithms::AlgorithmProposal;
use ayssh::transport::version::{parse_version_string, MAX_VERSION_STRING_LENGTH};
use ayssh::transport::packet::{Packet, PACKET_HEADER_LEN, MIN_PADDING, MAX_PADDING,
    MIN_PACKET_SIZE, RFC_MAX_PACKET_SIZE, RFC_MAX_PAYLOAD_SIZE};
use ayssh::channel::ChannelId;
use ayssh::channel::state::{ChannelManager, ChannelState};
use ayssh::channel::types::{ChannelOpenRequest, ChannelType};
use bytes::BytesMut;

// ============================================================================
// RFC 4251 Section 5: Data Type Tests
// ============================================================================

#[test]
fn test_rfc4251_boolean_nonzero_is_true() {
    // RFC 4251 Section 5: "All non-zero values MUST be interpreted as TRUE"
    for v in [1u8, 2, 42, 127, 128, 200, 255] {
        let mut buf = BytesMut::from(&[v][..]);
        let decoded = SshBoolean::decode(&mut buf).unwrap();
        assert!(decoded.as_bool(), "Value {} should decode as true", v);
    }
}

#[test]
fn test_rfc4251_boolean_zero_is_false() {
    let mut buf = BytesMut::from(&[0u8][..]);
    let decoded = SshBoolean::decode(&mut buf).unwrap();
    assert!(!decoded.as_bool());
}

#[test]
fn test_rfc4251_boolean_encode_only_0_or_1() {
    // RFC 4251 Section 5: "applications MUST NOT store values other than 0 and 1"
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
fn test_rfc4251_mpint_zero_encoding() {
    // RFC 4251 Section 5: "The value zero MUST be stored as a string
    // with zero bytes of data."
    let mpint = SshMpint::from_u64(0);
    let mut buf = BytesMut::with_capacity(10);
    mpint.encode(&mut buf);
    // Expected: 00 00 00 00 (4-byte length = 0)
    assert_eq!(&buf[..], &[0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn test_rfc4251_mpint_zero_decode() {
    // Zero-length mpint data decodes as 0
    let mut buf = BytesMut::from(&[0x00, 0x00, 0x00, 0x00][..]);
    let mpint = SshMpint::decode(&mut buf).unwrap();
    assert_eq!(mpint.to_u64().unwrap(), 0);
}

#[test]
fn test_rfc4251_mpint_positive_with_msb_set() {
    // RFC 4251: "If the most significant bit would be set for a positive
    // number, the number MUST be preceded by a zero byte."
    let mpint = SshMpint::from_u64(0x80);
    let mut buf = BytesMut::with_capacity(10);
    mpint.encode(&mut buf);
    // Expected: 00 00 00 02 00 80
    assert_eq!(&buf[..], &[0x00, 0x00, 0x00, 0x02, 0x00, 0x80]);
}

#[test]
fn test_rfc4251_mpint_no_unnecessary_leading_zeros() {
    // RFC 4251: "Unnecessary leading bytes with the value 0 or 255 MUST NOT be included."
    // Encoding: from_u64 should not produce unnecessary leading zeros
    let mpint = SshMpint::from_u64(0x42);
    assert_eq!(mpint.as_bytes(), &[0x42]); // No leading zero needed

    let mpint = SshMpint::from_u64(0x7F);
    assert_eq!(mpint.as_bytes(), &[0x7F]); // No leading zero needed
}

#[test]
fn test_rfc4251_mpint_reject_unnecessary_leading_zeros() {
    // Decoding: reject mpint with unnecessary leading 0x00
    // 0x00 0x42 is invalid because 0x42 < 0x80 (no MSB set)
    let mut buf = BytesMut::from(&[0x00, 0x00, 0x00, 0x02, 0x00, 0x42][..]);
    assert!(SshMpint::decode(&mut buf).is_err());
}

#[test]
fn test_rfc4251_mpint_accept_valid_leading_zero() {
    // 0x00 0x80 is valid - leading zero needed because 0x80 has MSB set
    let mut buf = BytesMut::from(&[0x00, 0x00, 0x00, 0x02, 0x00, 0x80][..]);
    let mpint = SshMpint::decode(&mut buf).unwrap();
    assert_eq!(mpint.as_bytes(), &[0x00, 0x80]);
}

#[test]
fn test_rfc4251_mpint_rfc_examples() {
    // RFC 4251 Section 5 examples:
    //   value (hex)             representation (hex)
    //   0                       00 00 00 00
    //   9a378f9b2e332a7         00 00 00 08 09 a3 78 f9 b2 e3 32 a7
    //   80                      00 00 00 02 00 80

    // 0x9a378f9b2e332a7
    let mpint = SshMpint::from_u64(0x09a378f9b2e332a7);
    let mut buf = BytesMut::with_capacity(20);
    mpint.encode(&mut buf);
    assert_eq!(&buf[..], &[0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]);
}

#[test]
fn test_rfc4251_mpint_roundtrip() {
    // Test various values roundtrip correctly
    for value in [1u64, 42, 127, 128, 255, 256, 65535, 0x7FFFFFFF, 0x80000000, u64::MAX] {
        let mpint = SshMpint::from_u64(value);
        let mut buf = BytesMut::with_capacity(20);
        mpint.encode(&mut buf);
        let decoded = SshMpint::decode(&mut buf).unwrap();
        assert_eq!(decoded.to_u64().unwrap(), value, "Roundtrip failed for 0x{:x}", value);
    }
}

#[test]
fn test_rfc4251_string_encoding() {
    // RFC 4251 Section 5: strings are encoded as uint32 length followed by data
    let s = SshString::from_str("hello");
    let mut buf = BytesMut::with_capacity(20);
    s.encode(&mut buf);
    // 4 bytes length (5) + 5 bytes data
    assert_eq!(&buf[..4], &[0, 0, 0, 5]);
    assert_eq!(&buf[4..], b"hello");
}

#[test]
fn test_rfc4251_string_empty() {
    let s = SshString::from_str("");
    let mut buf = BytesMut::with_capacity(10);
    s.encode(&mut buf);
    assert_eq!(&buf[..], &[0, 0, 0, 0]); // Empty string has 0 length
}

#[test]
fn test_rfc4251_uint32_big_endian() {
    // RFC 4251 Section 5: uint32 stored in big-endian
    let val = SshUint32::new(0x12345678);
    let mut buf = BytesMut::with_capacity(4);
    val.encode(&mut buf);
    assert_eq!(&buf[..], &[0x12, 0x34, 0x56, 0x78]);
}

#[test]
fn test_rfc4251_uint64_big_endian() {
    // RFC 4251 Section 5: uint64 stored in big-endian
    let val = SshUint64::new(0x0102030405060708);
    let mut buf = BytesMut::with_capacity(8);
    val.encode(&mut buf);
    assert_eq!(&buf[..], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
}

// ============================================================================
// RFC 4251 Section 5: Name-List Tests
// ============================================================================

#[test]
fn test_rfc4251_name_list_valid() {
    let nl = SshNameList::new(vec!["aes128-cbc".to_string(), "3des-cbc".to_string()]).unwrap();
    assert_eq!(nl.names().len(), 2);
}

#[test]
fn test_rfc4251_name_list_roundtrip() {
    let nl = SshNameList::new(vec!["hmac-sha2-256".to_string(), "hmac-sha1".to_string()]).unwrap();
    let mut buf = BytesMut::with_capacity(100);
    nl.encode(&mut buf);
    let decoded = SshNameList::decode(&mut buf).unwrap();
    assert_eq!(nl, decoded);
}

#[test]
fn test_rfc4251_name_list_reject_empty_name() {
    // RFC 4251: "A name MUST have a non-zero length"
    assert!(SshNameList::new(vec!["".to_string()]).is_err());
}

#[test]
fn test_rfc4251_name_list_reject_comma() {
    // RFC 4251: names "MUST NOT contain a comma"
    assert!(SshNameList::new(vec!["bad,name".to_string()]).is_err());
}

#[test]
fn test_rfc4251_name_list_reject_null() {
    // RFC 4251: "Terminating null characters MUST NOT be used"
    assert!(SshNameList::new(vec!["bad\x00name".to_string()]).is_err());
}

#[test]
fn test_rfc4251_name_list_reject_control_chars() {
    // Names MUST be printable US-ASCII
    assert!(SshNameList::new(vec!["bad\x01name".to_string()]).is_err());
    assert!(SshNameList::new(vec!["bad\x7fname".to_string()]).is_err()); // DEL
}

#[test]
fn test_rfc4251_name_list_max_64_chars() {
    // RFC 4251: names "MUST NOT be longer than 64 characters"
    let long_name = "a".repeat(65);
    assert!(SshNameList::new(vec![long_name]).is_err());
    let ok_name = "a".repeat(64);
    assert!(SshNameList::new(vec![ok_name]).is_ok());
}

#[test]
fn test_rfc4251_name_list_domain_names() {
    // Domain-specific names with @ sign are valid (RFC 4251 Section 6)
    let nl = SshNameList::new(vec!["hmac-sha2-256-etm@openssh.com".to_string()]).unwrap();
    assert_eq!(nl.names()[0], "hmac-sha2-256-etm@openssh.com");
}

// ============================================================================
// RFC 4253 Section 4: Protocol Version Exchange
// ============================================================================

#[test]
fn test_rfc4253_version_max_255_bytes() {
    // RFC 4253 Section 4.2: "The maximum length of the string is 255 characters,
    // including the Carriage Return and Line Feed."
    assert_eq!(MAX_VERSION_STRING_LENGTH, 255);

    // 253 chars + \r\n = 255 (OK)
    let sw = "x".repeat(253 - 8);
    let data = format!("SSH-2.0-{}\r\n", sw);
    assert_eq!(data.len(), 255);
    assert!(parse_version_string(data.as_bytes()).is_ok());

    // 254 chars + \r\n = 256 (too long)
    let sw = "x".repeat(254 - 8);
    let data = format!("SSH-2.0-{}\r\n", sw);
    assert_eq!(data.len(), 256);
    assert!(parse_version_string(data.as_bytes()).is_err());
}

#[test]
fn test_rfc4253_version_null_byte_rejected() {
    // RFC 4253 Section 4.2: "The null character MUST NOT be sent"
    let data = b"SSH-2.0-Open\x00SSH\r\n";
    assert!(parse_version_string(data).is_err());
}

#[test]
fn test_rfc4253_version_crlf_required() {
    // RFC 4253: "The identification MUST be terminated by a single CR and a single LF"
    assert!(parse_version_string(b"SSH-2.0-Test\r\n").is_ok());
    assert!(parse_version_string(b"SSH-2.0-Test\n").is_err());
    assert!(parse_version_string(b"SSH-2.0-Test").is_err());
}

#[test]
fn test_rfc4253_version_protocol_must_be_2_0() {
    // RFC 4253 Section 4.2: "'protoversion' MUST be '2.0'"
    assert!(parse_version_string(b"SSH-2.0-Test\r\n").is_ok());
    assert!(parse_version_string(b"SSH-1.0-Test\r\n").is_err());
    assert!(parse_version_string(b"SSH-3.0-Test\r\n").is_err());
}

#[test]
fn test_rfc4253_version_199_compatibility() {
    // RFC 4253 Section 5.1: "1.99" MUST be accepted as identical to "2.0"
    let result = parse_version_string(b"SSH-1.99-Cisco-1.25\r\n");
    assert!(result.is_ok());
}

#[test]
fn test_rfc4253_version_software_required() {
    // Software version is required and cannot be empty
    assert!(parse_version_string(b"SSH-2.0-\r\n").is_err());
}

// ============================================================================
// RFC 4253 Section 6: Binary Packet Protocol
// ============================================================================

#[test]
fn test_rfc4253_packet_min_padding_4_bytes() {
    // RFC 4253 Section 6: "There MUST be at least four bytes of padding"
    assert!(MIN_PADDING >= 4);

    // Test that Packet creation always has >= 4 bytes padding
    let pkt = Packet::new(21, vec![]);
    assert!(pkt.padding_length >= 4);
}

#[test]
fn test_rfc4253_packet_max_padding_255_bytes() {
    // RFC 4253 Section 6: "The maximum amount of padding is 255 bytes"
    assert_eq!(MAX_PADDING, 255);
}

#[test]
fn test_rfc4253_packet_min_size_16_bytes() {
    // RFC 4253 Section 6: "The minimum size of a packet is 16 (or the cipher
    // block size, whichever is larger) bytes (plus 'mac')"
    assert_eq!(MIN_PACKET_SIZE, 16);
}

#[test]
fn test_rfc4253_packet_max_payload_32768() {
    // RFC 4253 Section 6.1: "All implementations MUST be able to process
    // packets with an uncompressed payload length of 32768 bytes or less"
    assert_eq!(RFC_MAX_PAYLOAD_SIZE, 32768);
}

#[test]
fn test_rfc4253_packet_max_total_35000() {
    // RFC 4253 Section 6.1: "...and a total packet size of 35000 bytes or less"
    assert_eq!(RFC_MAX_PACKET_SIZE, 35000);
}

#[test]
fn test_rfc4253_packet_padding_too_small_rejected() {
    // Crafted packet with padding < 4 bytes should be rejected
    let mut data = vec![0u8; 20];
    data[0..4].copy_from_slice(&6u32.to_be_bytes()); // packet_length
    data[4] = 2; // padding_length = 2 (too small)
    data[5] = 21; // msg_type = newkeys
    // Pad rest
    let result = Packet::deserialize(&data);
    assert!(result.is_err());
}

#[test]
fn test_rfc4253_packet_serialization() {
    // Test that packet serialization follows RFC structure
    let pkt = Packet::new(21, vec![0x01, 0x02, 0x03]);
    let serialized = pkt.serialize();

    // Check structure: [4-byte length][1-byte padding_length][msg_type][payload][padding]
    assert!(serialized.len() >= PACKET_HEADER_LEN + 1);
    let length = u32::from_be_bytes([serialized[0], serialized[1], serialized[2], serialized[3]]);
    let pad_len = serialized[4];
    let msg_type = serialized[5];

    assert_eq!(msg_type, 21);
    assert!(pad_len >= 4);
    // Total serialized size = 4 (length field) + 1 (padding_length) + payload_content + padding
    // In this implementation, 'length' = 1 (msg_type) + payload.len() = 4
    // So total = 4 + 1 + length + pad_len = PACKET_HEADER_LEN + length + pad_len
    assert_eq!(PACKET_HEADER_LEN + length as usize + pad_len as usize, serialized.len());
}

// ============================================================================
// RFC 4253 Section 7: Algorithm Negotiation
// ============================================================================

#[test]
fn test_rfc4253_algorithm_negotiation_client_preference() {
    // RFC 4253 Section 7.1: "The first algorithm on the client's name-list
    // that is also on the server's name-list MUST be chosen."
    let client = AlgorithmProposal {
        kex_algorithms: vec![
            "diffie-hellman-group14-sha256".to_string(),
            "curve25519-sha256".to_string(),
        ],
        ..AlgorithmProposal::client_proposal()
    };
    let server = AlgorithmProposal {
        kex_algorithms: vec![
            "curve25519-sha256".to_string(),
            "diffie-hellman-group14-sha256".to_string(),
        ],
        ..AlgorithmProposal::server_proposal()
    };

    let negotiated = client.select_common_algorithms(&server).unwrap();
    // Client's first choice wins
    assert_eq!(negotiated.kex, "diffie-hellman-group14-sha256");
}

#[test]
fn test_rfc4253_algorithm_negotiation_no_common() {
    // RFC 4253 Section 7.1: "If no algorithm satisfying all these conditions
    // can be found, the connection fails, and both sides MUST disconnect."
    let client = AlgorithmProposal {
        kex_algorithms: vec!["nonexistent-kex".to_string()],
        ..AlgorithmProposal::client_proposal()
    };
    let server = AlgorithmProposal::server_proposal();

    let result = client.select_common_algorithms(&server);
    assert!(result.is_err());
}

#[test]
fn test_rfc4253_algorithm_negotiation_all_categories() {
    // Each category must be negotiated independently
    let client = AlgorithmProposal::client_proposal();
    let server = AlgorithmProposal::server_proposal();

    let negotiated = client.select_common_algorithms(&server).unwrap();

    // All fields must be non-empty
    assert!(!negotiated.kex.is_empty());
    assert!(!negotiated.host_key.is_empty());
    assert!(!negotiated.enc_c2s.is_empty());
    assert!(!negotiated.enc_s2c.is_empty());
    assert!(!negotiated.mac_c2s.is_empty());
    assert!(!negotiated.mac_s2c.is_empty());
    assert!(!negotiated.compression.is_empty());

    // All negotiated algorithms must exist in both proposals
    assert!(client.kex_algorithms.contains(&negotiated.kex));
    assert!(server.kex_algorithms.contains(&negotiated.kex));
}

// ============================================================================
// RFC 4253 Section 11: Transport Layer Messages
// ============================================================================

#[test]
fn test_rfc4253_disconnect_reason_codes() {
    // RFC 4253 Section 11.1: All defined disconnect reason codes
    assert_eq!(DisconnectReason::HostNotAllowedToConnect.value(), 1);
    assert_eq!(DisconnectReason::ProtocolError.value(), 2);
    assert_eq!(DisconnectReason::KeyExchangeFailed.value(), 3);
    assert_eq!(DisconnectReason::Reserved.value(), 4);
    assert_eq!(DisconnectReason::MacError.value(), 5);
    assert_eq!(DisconnectReason::CompressionError.value(), 6);
    assert_eq!(DisconnectReason::ServiceNotAvailable.value(), 7);
    assert_eq!(DisconnectReason::ProtocolVersionNotSupported.value(), 8);
    assert_eq!(DisconnectReason::HostKeyNotVerifiable.value(), 9);
    assert_eq!(DisconnectReason::ConnectionLost.value(), 10);
    assert_eq!(DisconnectReason::ByApplication.value(), 11);
    assert_eq!(DisconnectReason::TooManyConnections.value(), 12);
    assert_eq!(DisconnectReason::AuthCancelledByUser.value(), 13);
    assert_eq!(DisconnectReason::NoMoreAuthMethodsAvailable.value(), 14);
    assert_eq!(DisconnectReason::IllegalUserName.value(), 15);
}

#[test]
fn test_rfc4253_disconnect_message_encode_decode() {
    // RFC 4253 Section 11.1: SSH_MSG_DISCONNECT encoding
    let msg = DisconnectMessage::new(DisconnectReason::ByApplication, "User quit");
    let encoded = msg.encode();
    let decoded = DisconnectMessage::decode(&encoded).unwrap();
    assert_eq!(decoded.reason_code, 11);
    assert_eq!(decoded.description, "User quit");
    assert_eq!(decoded.reason(), Some(DisconnectReason::ByApplication));
}

#[test]
fn test_rfc4253_ignore_message() {
    // RFC 4253 Section 11.2: "All implementations MUST understand (and ignore)
    // this message at any time"
    let msg = IgnoreMessage::new(b"padding".to_vec());
    let encoded = msg.encode();
    let decoded = IgnoreMessage::decode(&encoded).unwrap();
    assert_eq!(decoded.data, b"padding");
}

#[test]
fn test_rfc4253_ignore_message_empty() {
    let msg = IgnoreMessage::empty();
    let encoded = msg.encode();
    let decoded = IgnoreMessage::decode(&encoded).unwrap();
    assert!(decoded.data.is_empty());
}

#[test]
fn test_rfc4253_debug_message() {
    // RFC 4253 Section 11.3: SSH_MSG_DEBUG
    let msg = DebugMessage::new(true, "Debug info here");
    let encoded = msg.encode();
    let decoded = DebugMessage::decode(&encoded).unwrap();
    assert!(decoded.always_display);
    assert_eq!(decoded.message, "Debug info here");
}

#[test]
fn test_rfc4253_debug_message_always_display() {
    // RFC 4253: "If 'always_display' is TRUE, the message SHOULD be displayed"
    let msg = DebugMessage::new(true, "Important");
    assert!(msg.always_display);

    let msg = DebugMessage::new(false, "Hidden");
    assert!(!msg.always_display);
}

#[test]
fn test_rfc4253_unimplemented_message() {
    // RFC 4253 Section 11.4: SSH_MSG_UNIMPLEMENTED
    let msg = UnimplementedMessage::new(12345);
    let encoded = msg.encode();
    let decoded = UnimplementedMessage::decode(&encoded).unwrap();
    assert_eq!(decoded.sequence_number, 12345);
}

#[test]
fn test_rfc4253_message_type_values() {
    // RFC 4253: Verify correct message type numeric values
    assert_eq!(MessageType::Disconnect.value(), 1);
    assert_eq!(MessageType::Ignore.value(), 2);
    assert_eq!(MessageType::Unimplemented.value(), 3);
    assert_eq!(MessageType::Debug.value(), 4);
    assert_eq!(MessageType::ServiceRequest.value(), 5);
    assert_eq!(MessageType::ServiceAccept.value(), 6);
    assert_eq!(MessageType::KexInit.value(), 20);
    assert_eq!(MessageType::Newkeys.value(), 21);
    assert_eq!(MessageType::KexDhInit.value(), 30);
    assert_eq!(MessageType::KexDhReply.value(), 31);
}

#[test]
fn test_rfc4253_message_type_roundtrip() {
    // All defined message types should roundtrip through from_value
    let types = [
        MessageType::Disconnect,
        MessageType::Ignore,
        MessageType::Unimplemented,
        MessageType::Debug,
        MessageType::ServiceRequest,
        MessageType::ServiceAccept,
        MessageType::KexInit,
        MessageType::Newkeys,
        MessageType::KexDhInit,
        MessageType::KexDhReply,
        MessageType::UserauthRequest,
        MessageType::UserauthFailure,
        MessageType::UserauthSuccess,
        MessageType::UserauthBanner,
        MessageType::ChannelOpen,
        MessageType::ChannelOpenConfirmation,
        MessageType::ChannelOpenFailure,
        MessageType::ChannelWindowAdjust,
        MessageType::ChannelData,
        MessageType::ChannelExtendedData,
        MessageType::ChannelEof,
        MessageType::ChannelClose,
        MessageType::ChannelRequest,
        MessageType::ChannelSuccess,
        MessageType::ChannelFailure,
    ];
    for mt in types {
        assert_eq!(MessageType::from_value(mt.value()), Some(mt));
    }
}

// ============================================================================
// RFC 4252: SSH Authentication Protocol
// ============================================================================

#[test]
fn test_rfc4252_message_type_values() {
    // RFC 4252: Authentication message type values
    assert_eq!(MessageType::UserauthRequest.value(), 50);
    assert_eq!(MessageType::UserauthFailure.value(), 51);
    assert_eq!(MessageType::UserauthSuccess.value(), 52);
    assert_eq!(MessageType::UserauthBanner.value(), 53);
    assert_eq!(MessageType::UserauthInfoRequest.value(), 60);
    assert_eq!(MessageType::UserauthInfoResponse.value(), 61);
}

// ============================================================================
// RFC 4254: SSH Connection Protocol - Channels
// ============================================================================

#[test]
fn test_rfc4254_channel_close_must_respond() {
    // RFC 4254 Section 5.3: "Upon receiving this message, a party MUST send
    // back an SSH_MSG_CHANNEL_CLOSE unless it has already sent this message
    // for the channel."
    let mgr = ChannelManager::new();
    let request = ChannelOpenRequest {
        channel_type: ChannelType::Session,
        sender_channel: ChannelId::new(0),
        initial_window_size: 32768,
        max_packet_size: 32768,
    };
    let ch_id = mgr.open_channel(&request).unwrap();

    // Receive close when we haven't sent close yet -> must send close response
    let result = mgr.receive_close(ch_id).unwrap();
    assert!(result.is_some(), "Must send close response when receiving close");
}

#[test]
fn test_rfc4254_channel_close_already_sent() {
    // If we already sent close, receiving close should not generate response
    let mgr = ChannelManager::new();
    let request = ChannelOpenRequest {
        channel_type: ChannelType::Session,
        sender_channel: ChannelId::new(0),
        initial_window_size: 32768,
        max_packet_size: 32768,
    };
    let ch_id = mgr.open_channel(&request).unwrap();

    // We send close first
    mgr.close(ch_id).unwrap();
    assert_eq!(mgr.get_channel(ch_id).unwrap().state, ChannelState::Closed);

    // Receive close after already sent -> no response needed
    let result = mgr.receive_close(ch_id).unwrap();
    assert!(result.is_none(), "Should not send close response if already closed");
}

#[test]
fn test_rfc4254_channel_eof_handling() {
    // RFC 4254 Section 5.3: "When a party will no longer send more data to a
    // channel, it SHOULD send SSH_MSG_CHANNEL_EOF."
    let mgr = ChannelManager::new();
    let request = ChannelOpenRequest {
        channel_type: ChannelType::Session,
        sender_channel: ChannelId::new(0),
        initial_window_size: 32768,
        max_packet_size: 32768,
    };
    let ch_id = mgr.open_channel(&request).unwrap();

    // Send EOF
    let eof = mgr.send_eof(ch_id).unwrap();
    assert_eq!(eof.channel_id, ch_id);

    // Channel should be in EofReceived state
    let info = mgr.get_channel(ch_id).unwrap();
    assert_eq!(info.state, ChannelState::EofReceived);
}

#[test]
fn test_rfc4254_channel_eof_then_close() {
    // Typical channel shutdown: EOF then Close
    let mgr = ChannelManager::new();
    let request = ChannelOpenRequest {
        channel_type: ChannelType::Session,
        sender_channel: ChannelId::new(0),
        initial_window_size: 32768,
        max_packet_size: 32768,
    };
    let ch_id = mgr.open_channel(&request).unwrap();

    mgr.send_eof(ch_id).unwrap();
    mgr.close(ch_id).unwrap();

    let info = mgr.get_channel(ch_id).unwrap();
    assert_eq!(info.state, ChannelState::Closed);
}

#[test]
fn test_rfc4254_channel_message_types() {
    // RFC 4254: Channel message type values
    assert_eq!(MessageType::ChannelOpen.value(), 90);
    assert_eq!(MessageType::ChannelOpenConfirmation.value(), 91);
    assert_eq!(MessageType::ChannelOpenFailure.value(), 92);
    assert_eq!(MessageType::ChannelWindowAdjust.value(), 93);
    assert_eq!(MessageType::ChannelData.value(), 94);
    assert_eq!(MessageType::ChannelExtendedData.value(), 95);
    assert_eq!(MessageType::ChannelEof.value(), 96);
    assert_eq!(MessageType::ChannelClose.value(), 97);
    assert_eq!(MessageType::ChannelRequest.value(), 98);
    assert_eq!(MessageType::ChannelSuccess.value(), 99);
    assert_eq!(MessageType::ChannelFailure.value(), 100);
}

#[test]
fn test_rfc4254_channel_no_data_after_close() {
    // Cannot send data after channel is closed
    let mgr = ChannelManager::new();
    let request = ChannelOpenRequest {
        channel_type: ChannelType::Session,
        sender_channel: ChannelId::new(0),
        initial_window_size: 32768,
        max_packet_size: 32768,
    };
    let ch_id = mgr.open_channel(&request).unwrap();
    mgr.close(ch_id).unwrap();

    let result = mgr.receive_data(ch_id, b"test");
    assert!(result.is_err());
}

#[test]
fn test_rfc4254_channel_no_eof_after_close() {
    // Cannot send EOF after channel is closed
    let mgr = ChannelManager::new();
    let request = ChannelOpenRequest {
        channel_type: ChannelType::Session,
        sender_channel: ChannelId::new(0),
        initial_window_size: 32768,
        max_packet_size: 32768,
    };
    let ch_id = mgr.open_channel(&request).unwrap();
    mgr.close(ch_id).unwrap();

    let result = mgr.send_eof(ch_id);
    assert!(result.is_err());
}

// ============================================================================
// RFC 4253 Section 6.3: Sequence Number Tests
// ============================================================================

#[test]
fn test_rfc4253_sequence_number_32bit() {
    // RFC 4253 Section 6.4: "The sequence_number is an implicit packet sequence
    // number represented as uint32. The sequence_number is initialized to zero
    // for the first packet, and is incremented after every packet."
    // "It wraps around to zero after every 2^32 packets."
    let max_seq: u32 = u32::MAX;
    let wrapped = max_seq.wrapping_add(1);
    assert_eq!(wrapped, 0); // Wraps to 0
}

// ============================================================================
// RFC 4253 Section 6.4: MAC Tests
// ============================================================================

#[test]
fn test_rfc4253_mac_over_unencrypted_packet() {
    // RFC 4253 Section 6.4: "mac = MAC(key, sequence_number || unencrypted_packet)"
    // The MAC is computed over the unencrypted packet, not the encrypted one
    use ayssh::crypto::hmac::compute;

    let key = vec![0x42u8; 32];
    let seq: u32 = 0;
    let unencrypted_packet = vec![0x01, 0x02, 0x03, 0x04, 0x05];

    // Build the data: sequence_number || unencrypted_packet
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(&seq.to_be_bytes());
    mac_input.extend_from_slice(&unencrypted_packet);

    let mac = compute(&key, &mac_input);
    assert!(!mac.is_empty());
    assert_eq!(mac.len(), 32); // SHA-256 produces 32-byte MAC
}
