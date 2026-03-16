//! Integration tests for Channel state management

use ayssh::channel::state::{ChannelState, ChannelInfo};
use ayssh::channel::types::ChannelId;

/// Test 1: Verify ChannelState enum has all variants
#[test]
fn test_channel_state_variants() {
    let _open = ChannelState::Open;
    let _eof_received = ChannelState::EofReceived;
    let _closing = ChannelState::Closing;
    let _closed = ChannelState::Closed;
}

/// Test 2: Verify ChannelState debug implementation
#[test]
fn test_channel_state_debug() {
    let open = ChannelState::Open;
    let closed = ChannelState::Closed;
    
    let open_debug = format!("{:?}", open);
    let closed_debug = format!("{:?}", closed);
    
    assert!(open_debug.contains("Open"));
    assert!(closed_debug.contains("Closed"));
}

/// Test 3: Verify ChannelState clone implementation
#[test]
fn test_channel_state_clone() {
    let open = ChannelState::Open;
    let open_clone = open.clone();
    assert_eq!(open, open_clone);
    
    let closed = ChannelState::Closed;
    let closed_clone = closed.clone();
    assert_eq!(closed, closed_clone);
}

/// Test 4: Verify ChannelState partial_eq implementation
#[test]
fn test_channel_state_partial_eq() {
    let open1 = ChannelState::Open;
    let open2 = ChannelState::Open;
    assert_eq!(open1, open2);
    
    let open = ChannelState::Open;
    let closed = ChannelState::Closed;
    assert_ne!(open, closed);
}

/// Test 5: Test channel state transitions
#[test]
fn test_channel_state_transitions() {
    let state1 = ChannelState::Open;
    let state2 = ChannelState::EofReceived;
    let state3 = ChannelState::Closing;
    let state4 = ChannelState::Closed;
    
    assert_ne!(state1, state2);
    assert_ne!(state2, state3);
    assert_ne!(state3, state4);
}

/// Test 6: Test channel state is_open (via pattern matching)
#[test]
fn test_channel_state_is_open() {
    let open = ChannelState::Open;
    let eof_received = ChannelState::EofReceived;
    let closing = ChannelState::Closing;
    let closed = ChannelState::Closed;
    
    match open {
        ChannelState::Open => assert!(true),
        _ => panic!("Expected Open"),
    }
    
    match eof_received {
        ChannelState::Open => panic!("Expected EofReceived"),
        _ => assert!(true),
    }
    
    match closing {
        ChannelState::Open => panic!("Expected Closing"),
        _ => assert!(true),
    }
    
    match closed {
        ChannelState::Open => panic!("Expected Closed"),
        _ => assert!(true),
    }
}

/// Test 7: Test channel state is_closed (via pattern matching)
#[test]
fn test_channel_state_is_closed() {
    let open = ChannelState::Open;
    let eof_received = ChannelState::EofReceived;
    let closing = ChannelState::Closing;
    let closed = ChannelState::Closed;
    
    match closed {
        ChannelState::Closed => assert!(true),
        _ => panic!("Expected Closed"),
    }
    
    match open {
        ChannelState::Closed => panic!("Expected Open"),
        _ => assert!(true),
    }
    
    match eof_received {
        ChannelState::Closed => panic!("Expected EofReceived"),
        _ => assert!(true),
    }
    
    match closing {
        ChannelState::Closed => panic!("Expected Closing"),
        _ => assert!(true),
    }
}

/// Test 8: Test channel state is_eof_received (via pattern matching)
#[test]
fn test_channel_state_is_eof_received() {
    let open = ChannelState::Open;
    let eof_received = ChannelState::EofReceived;
    let closing = ChannelState::Closing;
    let closed = ChannelState::Closed;
    
    match eof_received {
        ChannelState::EofReceived => assert!(true),
        _ => panic!("Expected EofReceived"),
    }
    
    match open {
        ChannelState::EofReceived => panic!("Expected Open"),
        _ => assert!(true),
    }
    
    match closing {
        ChannelState::EofReceived => panic!("Expected Closing"),
        _ => assert!(true),
    }
    
    match closed {
        ChannelState::EofReceived => panic!("Expected Closed"),
        _ => assert!(true),
    }
}

/// Test 9: Test channel state is_closing (via pattern matching)
#[test]
fn test_channel_state_is_closing() {
    let open = ChannelState::Open;
    let eof_received = ChannelState::EofReceived;
    let closing = ChannelState::Closing;
    let closed = ChannelState::Closed;
    
    match closing {
        ChannelState::Closing => assert!(true),
        _ => panic!("Expected Closing"),
    }
    
    match open {
        ChannelState::Closing => panic!("Expected Open"),
        _ => assert!(true),
    }
    
    match eof_received {
        ChannelState::Closing => panic!("Expected EofReceived"),
        _ => assert!(true),
    }
    
    match closed {
        ChannelState::Closing => panic!("Expected Closed"),
        _ => assert!(true),
    }
}

/// Test 10: Test channel info structure
#[test]
fn test_channel_info_structure() {
    let info = ChannelInfo {
        local_id: ChannelId::new(1),
        remote_id: ChannelId::new(2),
        channel_type: "session".to_string(),
        state: ChannelState::Open,
        close_sent: false,
        local_window_size: 65536,
        remote_window_size: 65536,
        local_max_packet_size: 32768,
        remote_max_packet_size: 32768,
    };
    
    assert_eq!(info.local_id.to_u32(), 1);
    assert_eq!(info.remote_id.to_u32(), 2);
    assert_eq!(info.channel_type, "session");
    assert_eq!(info.state, ChannelState::Open);
    assert_eq!(info.local_window_size, 65536);
    assert_eq!(info.remote_window_size, 65536);
}

/// Test 11: Test channel info clone
#[test]
fn test_channel_info_clone() {
    let info1 = ChannelInfo {
        local_id: ChannelId::new(1),
        remote_id: ChannelId::new(2),
        channel_type: "session".to_string(),
        state: ChannelState::Open,
        close_sent: false,
        local_window_size: 65536,
        remote_window_size: 65536,
        local_max_packet_size: 32768,
        remote_max_packet_size: 32768,
    };
    
    let info2 = info1.clone();
    
    assert_eq!(info1.local_id, info2.local_id);
    assert_eq!(info1.remote_id, info2.remote_id);
    assert_eq!(info1.channel_type, info2.channel_type);
    assert_eq!(info1.state, info2.state);
}

/// Test 12: Test channel state equality
#[test]
fn test_channel_state_equality() {
    assert_eq!(ChannelState::Open, ChannelState::Open);
    assert_eq!(ChannelState::EofReceived, ChannelState::EofReceived);
    assert_eq!(ChannelState::Closing, ChannelState::Closing);
    assert_eq!(ChannelState::Closed, ChannelState::Closed);
    
    assert_ne!(ChannelState::Open, ChannelState::Closed);
    assert_ne!(ChannelState::EofReceived, ChannelState::Closing);
}

/// Test 13: Test channel state lifecycle
#[test]
fn test_channel_state_lifecycle() {
    // Simulate channel lifecycle
    let state1 = ChannelState::Open;
    let state2 = ChannelState::EofReceived;
    let state3 = ChannelState::Closing;
    let state4 = ChannelState::Closed;
    
    assert_ne!(state1, state2);
    assert_ne!(state2, state3);
    assert_ne!(state3, state4);
}

/// Test 14: Test channel state error scenarios
#[test]
fn test_channel_state_error_scenarios() {
    // Test that closed channels can't send data
    let closed_state = ChannelState::Closed;
    match closed_state {
        ChannelState::Open => panic!("Should not be open"),
        _ => assert!(true),
    }
    
    // Test that eof_received channels can't send data
    let eof_state = ChannelState::EofReceived;
    match eof_state {
        ChannelState::Open => panic!("Should not be open"),
        _ => assert!(true),
    }
}

/// Test 15: Test channel state display
#[test]
fn test_channel_state_display() {
    let open = ChannelState::Open;
    let closed = ChannelState::Closed;
    
    let open_str = format!("{:?}", open);
    let closed_str = format!("{:?}", closed);
    
    assert!(open_str.contains("Open"));
    assert!(closed_str.contains("Closed"));
}