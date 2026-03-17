//! Channel Management Integration Tests (RFC 4254)

use ayssh::channel::types::{
    Channel, ChannelClose, ChannelData, ChannelEof, ChannelId, ChannelOpenConfirmation,
    ChannelOpenFailure, ChannelOpenRequest, ChannelRequest, ChannelSuccessOrFailure, ChannelType,
    ReasonCode,
};
use ayssh::protocol::messages::MessageType;

#[test]
fn test_channel_open_request_encoding() {
    // Test encoding of channel open request for session
    let request = ChannelOpenRequest {
        sender_channel: ChannelId::new(1),
        initial_window_size: 65536,
        max_packet_size: 32768,
        channel_type: ChannelType::Session,
    };

    let msg = request.encode();
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelOpen));

    // Verify message can be parsed back
    let parsed = ChannelOpenRequest::parse(&msg).unwrap();
    assert_eq!(parsed.sender_channel, request.sender_channel);
    assert_eq!(parsed.initial_window_size, request.initial_window_size);
    assert_eq!(parsed.max_packet_size, request.max_packet_size);
    assert_eq!(parsed.channel_type, request.channel_type);
}

#[test]
fn test_channel_open_request_with_direct_tcpip() {
    // Test encoding of channel open request for direct-tcpip
    let request = ChannelOpenRequest {
        sender_channel: ChannelId::new(1),
        initial_window_size: 65536,
        max_packet_size: 32768,
        channel_type: ChannelType::DirectTcpIp {
            originator_address: "127.0.0.100".to_string(),
            originator_port: 12345,
            host_to_connect: "10.0.0.1".to_string(),
            port_to_connect: 22,
        },
    };

    let msg = request.encode();
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelOpen));

    // Verify message can be parsed back
    let parsed = ChannelOpenRequest::parse(&msg).unwrap();
    assert_eq!(parsed.sender_channel, request.sender_channel);
    assert_eq!(parsed.initial_window_size, request.initial_window_size);
    assert_eq!(parsed.max_packet_size, request.max_packet_size);

    if let ChannelType::DirectTcpIp {
        ref originator_address,
        ref originator_port,
        ref host_to_connect,
        ref port_to_connect,
    } = parsed.channel_type
    {
        assert_eq!(originator_address, "127.0.0.100");
        assert_eq!(originator_port, &12345);
        assert_eq!(host_to_connect, "10.0.0.1");
        assert_eq!(port_to_connect, &22);
    } else {
        panic!("Expected DirectTcpIp channel type");
    }
}

#[test]
fn test_channel_open_request_with_forwarded_tcpip() {
    // Test encoding of channel open request for forwarded-tcpip
    let request = ChannelOpenRequest {
        sender_channel: ChannelId::new(1),
        initial_window_size: 65536,
        max_packet_size: 32768,
        channel_type: ChannelType::ForwardedTcpIp {
            address_to_bind: "0.0.0.0".to_string(),
            port_to_bind: 8080,
            originator_address: "127.0.0.100".to_string(),
            originator_port: 12345,
        },
    };

    let msg = request.encode();
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelOpen));

    // Verify message can be parsed back
    let parsed = ChannelOpenRequest::parse(&msg).unwrap();
    assert_eq!(parsed.sender_channel, request.sender_channel);

    if let ChannelType::ForwardedTcpIp {
        ref address_to_bind,
        ref port_to_bind,
        ref originator_address,
        ref originator_port,
    } = parsed.channel_type
    {
        assert_eq!(address_to_bind, "0.0.0.0");
        assert_eq!(port_to_bind, &8080);
        assert_eq!(originator_address, "127.0.0.100");
        assert_eq!(originator_port, &12345);
    } else {
        panic!("Expected ForwardedTcpIp channel type");
    }
}

#[test]
fn test_channel_open_confirmation() {
    // Test encoding/decoding of channel open confirmation
    let confirmation = ChannelOpenConfirmation {
        recipient_channel: ChannelId::new(1),
        sender_channel: ChannelId::new(100),
        initial_window_size: 65536,
        max_packet_size: 32768,
    };

    let msg = confirmation.encode();
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelOpenConfirmation));

    // Verify message can be parsed back
    let parsed = ChannelOpenConfirmation::parse(&msg).unwrap();
    assert_eq!(parsed.recipient_channel, confirmation.recipient_channel);
    assert_eq!(parsed.sender_channel, confirmation.sender_channel);
    assert_eq!(parsed.initial_window_size, confirmation.initial_window_size);
    assert_eq!(parsed.max_packet_size, confirmation.max_packet_size);
}

#[test]
fn test_channel_open_failure() {
    // Test encoding/decoding of channel open failure
    let failure = ChannelOpenFailure {
        recipient_channel: ChannelId::new(1),
        reason_code: ReasonCode::ConnectionRefused,
        description: "Connection refused".to_string(),
        language_tag: "en".to_string(),
    };

    let msg = failure.encode();
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelOpenFailure));

    // Verify message can be parsed back
    let parsed = ChannelOpenFailure::parse(&msg).unwrap();
    assert_eq!(parsed.recipient_channel, failure.recipient_channel);
    assert_eq!(parsed.reason_code, failure.reason_code);
    assert_eq!(parsed.description, failure.description);
    assert_eq!(parsed.language_tag, failure.language_tag);
}

#[test]
fn test_channel_data() {
    // Test encoding/decoding of channel data
    let data = ChannelData {
        channel_id: ChannelId::new(1),
        data: b"Hello, SSH!".to_vec(),
    };

    let msg = data.encode();
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelData));

    // Verify message can be parsed back
    let parsed = ChannelData::parse(&msg).unwrap();
    assert_eq!(parsed.channel_id, data.channel_id);
    assert_eq!(parsed.data, data.data);
}

#[test]
fn test_channel_close() {
    // Test encoding/decoding of channel close
    let close = ChannelClose {
        channel_id: ChannelId::new(1),
    };

    let msg = close.encode();
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelClose));

    // Verify message can be parsed back
    let parsed = ChannelClose::parse(&msg).unwrap();
    assert_eq!(parsed.channel_id, close.channel_id);
}

#[test]
fn test_channel_eof() {
    // Test encoding/decoding of channel EOF
    let eof = ChannelEof {
        channel_id: ChannelId::new(1),
    };

    let msg = eof.encode();
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelEof));

    // Verify message can be parsed back
    let parsed = ChannelEof::parse(&msg).unwrap();
    assert_eq!(parsed.channel_id, eof.channel_id);
}

#[test]
fn test_channel_success_failure() {
    // Test encoding/decoding of channel success
    let success_msg = ChannelSuccessOrFailure::Success.encode(ChannelId::new(1));
    assert_eq!(success_msg.msg_type(), Some(MessageType::ChannelSuccess));

    let parsed = ChannelSuccessOrFailure::parse(&success_msg).unwrap();
    assert!(matches!(parsed, ChannelSuccessOrFailure::Success));

    // Test encoding/decoding of channel failure
    let failure_msg = ChannelSuccessOrFailure::Failure.encode(ChannelId::new(1));
    assert_eq!(failure_msg.msg_type(), Some(MessageType::ChannelFailure));

    let parsed = ChannelSuccessOrFailure::parse(&failure_msg).unwrap();
    assert!(matches!(parsed, ChannelSuccessOrFailure::Failure));
}

#[test]
fn test_channel_request_shell() {
    // Test encoding/decoding of shell request
    let request = ChannelRequest::Shell;
    let msg = request.encode(ChannelId::new(1), false);
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify message can be parsed back
    let (parsed, want_reply) = ChannelRequest::parse(&msg).unwrap();
    assert!(matches!(parsed, ChannelRequest::Shell));
    assert!(!want_reply);
}

#[test]
fn test_channel_request_exec() {
    // Test encoding/decoding of exec request
    let request = ChannelRequest::Exec {
        command: "ls -la".to_string(),
    };
    let msg = request.encode(ChannelId::new(1), false);
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify message can be parsed back
    let (parsed, want_reply) = ChannelRequest::parse(&msg).unwrap();
    if let ChannelRequest::Exec { ref command } = parsed {
        assert_eq!(command, "ls -la");
    } else {
        panic!("Expected Exec request");
    }
    assert!(!want_reply);
}

#[test]
fn test_channel_request_pty_req() {
    // Test encoding/decoding of pty-req request
    let request = ChannelRequest::PseudoTerminal {
        term: "xterm-256color".to_string(),
        width: 80,
        height: 24,
        pixel_width: 640,
        pixel_height: 480,
        modes: "0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
    };
    let msg = request.encode(ChannelId::new(1), false);
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify message can be parsed back
    let (parsed, want_reply) = ChannelRequest::parse(&msg).unwrap();
    if let ChannelRequest::PseudoTerminal {
        ref term,
        width,
        height,
        pixel_width,
        pixel_height,
        ref modes,
    } = parsed
    {
        assert_eq!(term, "xterm-256color");
        assert_eq!(width, 80);
        assert_eq!(height, 24);
        assert_eq!(pixel_width, 640);
        assert_eq!(pixel_height, 480);
        assert_eq!(modes, "0000000000000000000000000000000000000000000000000000000000000000");
    } else {
        panic!("Expected PseudoTerminal request");
    }
    assert!(!want_reply);
}

#[test]
fn test_channel_request_window_change() {
    // Test encoding/decoding of window-change request
    let request = ChannelRequest::WindowChange {
        width: 120,
        height: 40,
        pixel_width: 960,
        pixel_height: 800,
    };
    let msg = request.encode(ChannelId::new(1), false);
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify message can be parsed back
    let (parsed, want_reply) = ChannelRequest::parse(&msg).unwrap();
    if let ChannelRequest::WindowChange {
        width,
        height,
        pixel_width,
        pixel_height,
    } = parsed
    {
        assert_eq!(width, 120);
        assert_eq!(height, 40);
        assert_eq!(pixel_width, 960);
        assert_eq!(pixel_height, 800);
    } else {
        panic!("Expected WindowChange request");
    }
    assert!(!want_reply);
}

#[test]
fn test_channel_request_signal() {
    // Test encoding/decoding of signal request
    let request = ChannelRequest::Signal {
        signal: "SIGINT".to_string(),
    };
    let msg = request.encode(ChannelId::new(1), false);
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify message can be parsed back
    let (parsed, want_reply) = ChannelRequest::parse(&msg).unwrap();
    if let ChannelRequest::Signal { ref signal } = parsed {
        assert_eq!(signal, "SIGINT");
    } else {
        panic!("Expected Signal request");
    }
    assert!(!want_reply);
}

#[test]
fn test_channel_request_exit_status() {
    // Test encoding/decoding of exit-status request
    let request = ChannelRequest::ExitStatus { exit_status: 0 };
    let msg = request.encode(ChannelId::new(1), false);
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify message can be parsed back
    let (parsed, want_reply) = ChannelRequest::parse(&msg).unwrap();
    if let ChannelRequest::ExitStatus { exit_status } = parsed {
        assert_eq!(exit_status, 0);
    } else {
        panic!("Expected ExitStatus request");
    }
    assert!(!want_reply);
}

#[test]
fn test_channel_request_env() {
    // Test encoding/decoding of env request
    let request = ChannelRequest::Environment {
        name: "PATH".to_string(),
        value: "/usr/bin:/bin".to_string(),
    };
    let msg = request.encode(ChannelId::new(1), false);
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify message can be parsed back
    let (parsed, want_reply) = ChannelRequest::parse(&msg).unwrap();
    if let ChannelRequest::Environment { ref name, ref value } = parsed {
        assert_eq!(name, "PATH");
        assert_eq!(value, "/usr/bin:/bin");
    } else {
        panic!("Expected Environment request");
    }
    assert!(!want_reply);
}

#[test]
fn test_channel_request_keepalive() {
    // Test encoding/decoding of keepalive request
    let request = ChannelRequest::KeepAlive(true);
    let msg = request.encode(ChannelId::new(1), true);
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify message can be parsed back
    let (parsed, want_reply) = ChannelRequest::parse(&msg).unwrap();
    assert!(matches!(parsed, ChannelRequest::KeepAlive(_)));
    assert!(want_reply);
}

#[test]
fn test_channel_request_unknown() {
    // Test encoding/decoding of unknown request
    let request = ChannelRequest::Unknown {
        request: "unknown-request".to_string(),
        want_reply: false,
    };
    let msg = request.encode(ChannelId::new(1), false);
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify message can be parsed back
    let (parsed, _want_reply) = ChannelRequest::parse(&msg).unwrap();
    if let ChannelRequest::Unknown { ref request, want_reply: wr } = parsed {
        assert_eq!(request, "unknown-request");
        assert!(!wr);
    } else {
        panic!("Expected Unknown request");
    }
}

#[test]
fn test_channel_struct() {
    // Test Channel struct
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    assert_eq!(channel.local_id.to_u32(), 1);
    assert_eq!(channel.remote_id.to_u32(), 100);
    assert_eq!(channel.channel_type_str(), "session");
    assert_eq!(channel.window_size, 65536);
    assert_eq!(channel.max_packet_size, 32768);

    // Test send_data
    let data = channel.send_data(b"test data");
    assert_eq!(data.channel_id, channel.local_id);
    assert_eq!(data.data, b"test data");

    // Test close
    let close = channel.close();
    assert_eq!(close.channel_id, channel.local_id);

    // Test send_eof
    let eof = channel.send_eof();
    assert_eq!(eof.channel_id, channel.local_id);
}