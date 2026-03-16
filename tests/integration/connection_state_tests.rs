//! Integration tests for Connection state management

use ayssh::connection::state::{ConnectionState, ConnectionStateMachine};
use ayssh::error::SshError;

/// Test 1: Verify ConnectionState enum has all variants
#[test]
fn test_connection_state_variants() {
    let _disconnected = ConnectionState::Disconnected;
    let _connected = ConnectionState::Connected;
    let _version_exchange = ConnectionState::VersionExchange;
    let _algorithm_negotiation = ConnectionState::AlgorithmNegotiation;
    let _key_exchange = ConnectionState::KeyExchange;
    let _authentication = ConnectionState::Authentication;
    let _established = ConnectionState::Established;
    let _closed = ConnectionState::Closed;
}

/// Test 2: Verify ConnectionStateMachine::new() creates machine in Disconnected state
#[test]
fn test_connection_state_machine_new() {
    let machine = ConnectionStateMachine::new();
    assert_eq!(machine.current_state(), ConnectionState::Disconnected);
}

/// Test 3: Verify ConnectionStateMachine implements Default
#[test]
fn test_connection_state_machine_default() {
    let machine: ConnectionStateMachine = Default::default();
    assert_eq!(machine.current_state(), ConnectionState::Disconnected);
}

/// Test 4: Verify state transition from Disconnected to Connected
#[test]
fn test_connection_state_connect() {
    let mut machine = ConnectionStateMachine::new();
    assert!(machine.transition_to_connected().is_ok());
    assert_eq!(machine.current_state(), ConnectionState::Connected);
}

/// Test 5: Verify state transition from Connected to VersionExchange
#[test]
fn test_connection_state_version_exchange() {
    let mut machine = ConnectionStateMachine::new();
    machine.transition_to_connected().unwrap();
    machine.transition_to_version_exchange().unwrap();
    assert_eq!(machine.current_state(), ConnectionState::VersionExchange);
}

/// Test 6: Verify state transition from VersionExchange to AlgorithmNegotiation
#[test]
fn test_connection_state_algorithm_negotiation() {
    let mut machine = ConnectionStateMachine::new();
    machine.transition_to_connected().unwrap();
    machine.transition_to_version_exchange().unwrap();
    machine.transition_to_algorithm_negotiation().unwrap();
    assert_eq!(machine.current_state(), ConnectionState::AlgorithmNegotiation);
}

/// Test 7: Verify state transition from AlgorithmNegotiation to KeyExchange
#[test]
fn test_connection_state_key_exchange() {
    let mut machine = ConnectionStateMachine::new();
    machine.transition_to_connected().unwrap();
    machine.transition_to_version_exchange().unwrap();
    machine.transition_to_algorithm_negotiation().unwrap();
    machine.transition_to_key_exchange().unwrap();
    assert_eq!(machine.current_state(), ConnectionState::KeyExchange);
}

/// Test 8: Verify state transition from KeyExchange to Authentication
#[test]
fn test_connection_state_authentication() {
    let mut machine = ConnectionStateMachine::new();
    machine.transition_to_connected().unwrap();
    machine.transition_to_version_exchange().unwrap();
    machine.transition_to_algorithm_negotiation().unwrap();
    machine.transition_to_key_exchange().unwrap();
    machine.transition_to_authentication().unwrap();
    assert_eq!(machine.current_state(), ConnectionState::Authentication);
}

/// Test 9: Verify state transition from Authentication to Established
#[test]
fn test_connection_state_established() {
    let mut machine = ConnectionStateMachine::new();
    machine.transition_to_connected().unwrap();
    machine.transition_to_version_exchange().unwrap();
    machine.transition_to_algorithm_negotiation().unwrap();
    machine.transition_to_key_exchange().unwrap();
    machine.transition_to_authentication().unwrap();
    machine.transition_to_service_negotiation().unwrap();
    machine.mark_service_requested();
    machine.mark_service_accepted();
    machine.transition_to_established().unwrap();
    assert!(machine.is_established());
}

/// Test 10: Verify state transition to Closed
#[test]
fn test_connection_state_close() {
    let mut machine = ConnectionStateMachine::new();
    machine.transition_to_connected().unwrap();
    machine.transition_to_version_exchange().unwrap();
    machine.transition_to_algorithm_negotiation().unwrap();
    machine.transition_to_key_exchange().unwrap();
    machine.transition_to_authentication().unwrap();
    machine.transition_to_service_negotiation().unwrap();
    machine.mark_service_requested();
    machine.mark_service_accepted();
    machine.transition_to_established().unwrap();
    machine.transition_to_closed();
    assert_eq!(machine.current_state(), ConnectionState::Closed);
}

/// Test 11: Test invalid state transition (connect from non-disconnected)
#[test]
fn test_connection_state_invalid_connect() {
    let mut machine = ConnectionStateMachine::new();
    machine.transition_to_connected().unwrap();
    
    // Try to connect again - should fail
    let result = machine.transition_to_connected();
    assert!(result.is_err());
    assert_eq!(machine.current_state(), ConnectionState::Connected);
}

/// Test 12: Test connection state display implementation
#[test]
fn test_connection_state_display() {
    use std::fmt::Display;
    
    let disconnected = ConnectionState::Disconnected;
    let connected = ConnectionState::Connected;
    let established = ConnectionState::Established;
    let closed = ConnectionState::Closed;
    
    assert_eq!(format!("{}", disconnected), "DISCONNECTED");
    assert_eq!(format!("{}", connected), "CONNECTED");
    assert_eq!(format!("{}", established), "ESTABLISHED");
    assert_eq!(format!("{}", closed), "CLOSED");
}

/// Test 13: Test connection state machine full lifecycle
#[test]
fn test_connection_state_full_lifecycle() {
    let mut machine = ConnectionStateMachine::new();
    
    // Start
    assert_eq!(machine.current_state(), ConnectionState::Disconnected);
    
    // Connect
    machine.transition_to_connected().unwrap();
    assert_eq!(machine.current_state(), ConnectionState::Connected);
    
    // Version exchange
    machine.transition_to_version_exchange().unwrap();
    assert_eq!(machine.current_state(), ConnectionState::VersionExchange);
    
    // Algorithm negotiation
    machine.transition_to_algorithm_negotiation().unwrap();
    assert_eq!(machine.current_state(), ConnectionState::AlgorithmNegotiation);
    
    // Key exchange
    machine.transition_to_key_exchange().unwrap();
    assert_eq!(machine.current_state(), ConnectionState::KeyExchange);
    
    // Authentication
    machine.transition_to_authentication().unwrap();
    assert_eq!(machine.current_state(), ConnectionState::Authentication);
    
    // Service negotiation
    machine.transition_to_service_negotiation().unwrap();
    assert_eq!(machine.current_state(), ConnectionState::ServiceNegotiation);
    machine.mark_service_requested();
    machine.mark_service_accepted();
    
    // Established
    machine.transition_to_established().unwrap();
    assert!(machine.is_established());
    
    // Close
    machine.transition_to_closed();
    assert_eq!(machine.current_state(), ConnectionState::Closed);
}

/// Test 14: Test connection state with server version
#[test]
fn test_connection_state_server_version() {
    let mut machine = ConnectionStateMachine::new();
    
    assert!(machine.server_version().is_none());
    
    machine.set_server_version("SSH-2.0-OpenSSH_8.0".to_string());
    
    assert_eq!(machine.server_version(), Some("SSH-2.0-OpenSSH_8.0"));
}

/// Test 15: Test connection state with client version
#[test]
fn test_connection_state_client_version() {
    let machine = ConnectionStateMachine::new();
    // Client version is set internally, can't directly test but can verify machine works
    assert_eq!(machine.current_state(), ConnectionState::Disconnected);
}

/// Test 16: Test connection state after close
#[test]
fn test_connection_state_after_close() {
    let mut machine = ConnectionStateMachine::new();
    
    machine.transition_to_connected().unwrap();
    machine.transition_to_version_exchange().unwrap();
    machine.transition_to_algorithm_negotiation().unwrap();
    machine.transition_to_key_exchange().unwrap();
    machine.transition_to_authentication().unwrap();
    machine.transition_to_service_negotiation().unwrap();
    machine.mark_service_requested();
    machine.mark_service_accepted();
    machine.transition_to_established().unwrap();
    machine.transition_to_closed();
    
    // Should be closed
    assert_eq!(machine.current_state(), ConnectionState::Closed);
    
    // Try to transition again - should fail
    let result = machine.transition_to_connected();
    assert!(result.is_err());
}

/// Test 17: Test connection state is_established
#[test]
fn test_connection_state_is_established() {
    let mut machine = ConnectionStateMachine::new();
    
    assert!(!machine.is_established());
    
    machine.transition_to_connected().unwrap();
    assert!(!machine.is_established());
    
    machine.transition_to_version_exchange().unwrap();
    assert!(!machine.is_established());
    
    machine.transition_to_algorithm_negotiation().unwrap();
    assert!(!machine.is_established());
    
    machine.transition_to_key_exchange().unwrap();
    assert!(!machine.is_established());
    
    machine.transition_to_authentication().unwrap();
    assert!(!machine.is_established());
    
    machine.transition_to_service_negotiation().unwrap();
    assert!(!machine.is_established());
    
    machine.mark_service_requested();
    machine.mark_service_accepted();
    
    machine.transition_to_established().unwrap();
    assert!(machine.is_established());
    
    machine.transition_to_closed();
    assert!(!machine.is_established());
}

/// Test 18: Test connection state error handling
#[test]
fn test_connection_state_error_handling() {
    let mut machine = ConnectionStateMachine::new();
    
    // Try to go to version exchange without connecting first
    let result = machine.transition_to_version_exchange();
    assert!(result.is_err());
    
    // Just verify it's an error, don't compare error types
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(err_msg.contains("Cannot transition"));
}