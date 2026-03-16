use ayssh::connection::state::{ConnectionState, ConnectionStateMachine};

#[test]
fn test_connection_state_machine() {
    let mut machine = ConnectionStateMachine::new();
    
    // Initial state
    assert_eq!(machine.current_state(), ConnectionState::Disconnected);
    
    // Valid transitions
    assert!(machine.transition_to_connected().is_ok());
    assert_eq!(machine.current_state(), ConnectionState::Connected);
    
    assert!(machine.transition_to_version_exchange().is_ok());
    assert_eq!(machine.current_state(), ConnectionState::VersionExchange);
    
    assert!(machine.transition_to_algorithm_negotiation().is_ok());
    assert_eq!(machine.current_state(), ConnectionState::AlgorithmNegotiation);
    
    assert!(machine.transition_to_key_exchange().is_ok());
    assert_eq!(machine.current_state(), ConnectionState::KeyExchange);
    
    assert!(machine.transition_to_authentication().is_ok());
    assert_eq!(machine.current_state(), ConnectionState::Authentication);
    
    assert!(machine.transition_to_service_negotiation().is_ok());
    assert_eq!(machine.current_state(), ConnectionState::ServiceNegotiation);
    machine.mark_service_requested();
    machine.mark_service_accepted();
    
    assert!(machine.transition_to_established().is_ok());
    assert_eq!(machine.current_state(), ConnectionState::Established);
}

#[test]
fn test_closed_state() {
    let mut machine = ConnectionStateMachine::new();
    machine.transition_to_connected().unwrap();
    machine.transition_to_closed();
    assert_eq!(machine.current_state(), ConnectionState::Closed);
}

#[test]
fn test_server_version() {
    let mut machine = ConnectionStateMachine::new();
    machine.set_server_version("SSH-2.0-OpenSSH_8.0".to_string());
    
    assert_eq!(machine.server_version(), Some("SSH-2.0-OpenSSH_8.0"));
}

#[test]
fn test_algorithms() {
    let mut machine = ConnectionStateMachine::new();
    let algo = ayssh::protocol::algorithms::NegotiatedAlgorithms::default();
    
    machine.set_algorithms(algo.clone());
    
    assert!(machine.algorithms().is_some());
    assert_eq!(machine.algorithms(), Some(&algo));
}

#[test]
fn test_client_version() {
    let machine = ConnectionStateMachine::new();
    assert_eq!(machine.client_version(), "SSH-2.0-rustssh");
}

#[test]
fn test_is_established() {
    let mut machine = ConnectionStateMachine::new();
    
    assert!(!machine.is_established());
    
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

#[test]
fn test_invalid_transition() {
    let mut machine = ConnectionStateMachine::new();
    
    // Try to go from Disconnected to VersionExchange (should fail)
    assert!(machine.transition_to_version_exchange().is_err());
}