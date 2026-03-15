//! Transport State Machine Integration Tests (TDD)

use ssh_client::transport::state::{State, TransportStateMachine};
use ssh_client::protocol::MessageType;

#[tokio::test]
async fn test_new_state_machine_starts_in_handshake() {
    let sm = TransportStateMachine::new();
    assert_eq!(sm.current_state(), State::Handshake);
    assert!(sm.is_handshake());
    assert!(!sm.is_key_exchange());
    assert!(!sm.is_established());
    assert!(!sm.is_disconnected());
}

#[tokio::test]
async fn test_handshake_to_keyexchange_on_kexinit() {
    let mut sm = TransportStateMachine::new();
    assert_eq!(sm.current_state(), State::Handshake);
    
    let result = sm.process_message(MessageType::KexInit).unwrap();
    assert_eq!(result, ssh_client::transport::state::MessageResult::Transitioned(State::KeyExchange));
    assert_eq!(sm.current_state(), State::KeyExchange);
}

#[tokio::test]
async fn test_keyexchange_to_established_on_newkeys() {
    let mut sm = TransportStateMachine::new();
    
    // First transition to KeyExchange
    sm.process_message(MessageType::KexInit).unwrap();
    assert_eq!(sm.current_state(), State::KeyExchange);
    
    // Then transition to Established
    let result = sm.process_message(MessageType::Newkeys).unwrap();
    assert_eq!(result, ssh_client::transport::state::MessageResult::Transitioned(State::Established));
    assert_eq!(sm.current_state(), State::Established);
}

#[tokio::test]
async fn test_complete_handshake_flow() {
    let mut sm = TransportStateMachine::new();
    
    // Start in Handshake
    assert_eq!(sm.current_state(), State::Handshake);
    
    // Receive server KEXINIT
    sm.process_message(MessageType::KexInit).unwrap();
    assert_eq!(sm.current_state(), State::KeyExchange);
    
    // Key exchange messages - stay in KeyExchange
    sm.process_message(MessageType::KexInit).unwrap();
    assert_eq!(sm.current_state(), State::KeyExchange);
    
    // Receive NEWKEYS
    sm.process_message(MessageType::Newkeys).unwrap();
    assert_eq!(sm.current_state(), State::Established);
    
    // Now can process channel messages
    sm.process_message(MessageType::ChannelOpen).unwrap();
    assert_eq!(sm.current_state(), State::Established);
}

#[tokio::test]
async fn test_invalid_state_transitions() {
    let mut sm = TransportStateMachine::new();
    
    // Cannot skip KeyExchange - NEWKEYS in Handshake should fail
    let result = sm.process_message(MessageType::Newkeys);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_disconnect_from_any_state() {
    // From Handshake
    let mut sm = TransportStateMachine::new();
    sm.disconnect();
    assert_eq!(sm.current_state(), State::Disconnected);
    
    // From KeyExchange
    let mut sm = TransportStateMachine::new();
    sm.process_message(MessageType::KexInit).unwrap();
    sm.disconnect();
    assert_eq!(sm.current_state(), State::Disconnected);
    
    // From Established
    let mut sm = TransportStateMachine::new();
    sm.process_message(MessageType::KexInit).unwrap();
    sm.process_message(MessageType::Newkeys).unwrap();
    sm.disconnect();
    assert_eq!(sm.current_state(), State::Disconnected);
}