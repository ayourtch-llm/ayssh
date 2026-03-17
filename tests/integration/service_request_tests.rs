//! Service Request Integration Tests

use ayssh::protocol::messages::MessageType;
use ayssh::transport::state::{State, TransportStateMachine};
use std::io::{Cursor, Read};

#[test]
fn test_service_request_message_encoding() {
    // Test encoding of SERVICE_REQUEST message
    let service = "ssh-connection";
    
    // Manually encode as per RFC 4250
    let mut msg = Vec::new();
    msg.push(MessageType::ServiceRequest as u8);
    
    // Encode service name as SSH string (4-byte length + string)
    let service_bytes = service.as_bytes();
    msg.extend_from_slice(&(service_bytes.len() as u32).to_be_bytes());
    msg.extend_from_slice(service_bytes);
    
    assert_eq!(msg[0], MessageType::ServiceRequest as u8);
    
    // Verify structure - cursor starts at position 0
    let mut cursor = Cursor::new(&msg);
    
    // Read message type
    let mut msg_type_buf = [0u8; 1];
    cursor.read_exact(&mut msg_type_buf).expect("Read msg type");
    assert_eq!(msg_type_buf[0], MessageType::ServiceRequest as u8);
    
    // Read length
    let mut len_buf = [0u8; 4];
    cursor.read_exact(&mut len_buf).expect("Read length");
    let len = u32::from_be_bytes(len_buf);
    assert_eq!(len as usize, service_bytes.len());
    
    // Read service
    let mut service_read = vec![0u8; service_bytes.len()];
    cursor.read_exact(&mut service_read).expect("Read service");
    assert_eq!(String::from_utf8(service_read).unwrap(), service);
}

#[test]
fn test_service_accept_message_encoding() {
    // Test encoding of SERVICE_ACCEPT message
    let service = "ssh-connection";
    
    let mut msg = Vec::new();
    msg.push(MessageType::ServiceAccept as u8);
    
    // Encode service name as SSH string
    let service_bytes = service.as_bytes();
    msg.extend_from_slice(&(service_bytes.len() as u32).to_be_bytes());
    msg.extend_from_slice(service_bytes);
    
    assert_eq!(msg[0], MessageType::ServiceAccept as u8);
    
    // Verify structure - cursor starts at position 0
    let mut cursor = Cursor::new(&msg);
    
    // Read message type
    let mut msg_type_buf = [0u8; 1];
    cursor.read_exact(&mut msg_type_buf).expect("Read msg type");
    assert_eq!(msg_type_buf[0], MessageType::ServiceAccept as u8);
    
    // Read length
    let mut len_buf = [0u8; 4];
    cursor.read_exact(&mut len_buf).expect("Read length");
    let len = u32::from_be_bytes(len_buf);
    assert_eq!(len as usize, service_bytes.len());
    
    // Read service
    let mut service_read = vec![0u8; service_bytes.len()];
    cursor.read_exact(&mut service_read).expect("Read service");
    assert_eq!(String::from_utf8(service_read).unwrap(), service);
}

#[test]
fn test_service_request_state_transition() {
    let mut state_machine = TransportStateMachine::new();
    
    // Initial state should be Handshake
    assert_eq!(state_machine.current_state(), State::Handshake);
    
    // After receiving KEXINIT, should be KeyExchange
    state_machine.process_message(MessageType::KexInit).unwrap();
    assert_eq!(state_machine.current_state(), State::KeyExchange);
    
    // After NEWKEYS, should be Established
    state_machine.process_message(MessageType::Newkeys).unwrap();
    assert_eq!(state_machine.current_state(), State::Established);
}

#[test]
fn test_service_request_in_established_state() {
    let mut state_machine = TransportStateMachine::new();
    
    // Transition to established state
    state_machine.process_message(MessageType::KexInit).unwrap();
    state_machine.process_message(MessageType::Newkeys).unwrap();
    
    assert_eq!(state_machine.current_state(), State::Established);
    
    // In established state, we should be able to send service requests
    // This test verifies the state machine allows service requests
    let result = state_machine.process_message(MessageType::ServiceRequest);
    assert!(result.is_ok());
}

#[test]
fn test_service_request_message_parsing() {
    // Test parsing of SERVICE_REQUEST message
    let service = "ssh-connection";
    
    let mut msg = Vec::new();
    msg.push(MessageType::ServiceRequest as u8);
    
    let service_bytes = service.as_bytes();
    msg.extend_from_slice(&(service_bytes.len() as u32).to_be_bytes());
    msg.extend_from_slice(service_bytes);
    
    // Parse the message - cursor starts at position 0
    let mut cursor = Cursor::new(&msg);
    
    // Read message type
    let mut msg_type_buf = [0u8; 1];
    cursor.read_exact(&mut msg_type_buf).expect("Read msg type");
    assert_eq!(msg_type_buf[0], MessageType::ServiceRequest as u8);
    
    // Read length
    let mut len_buf = [0u8; 4];
    cursor.read_exact(&mut len_buf).expect("Read length");
    let len = u32::from_be_bytes(len_buf);
    
    // Read service
    let mut service_read = vec![0u8; len as usize];
    cursor.read_exact(&mut service_read).expect("Read service");
    
    assert_eq!(String::from_utf8(service_read).unwrap(), service);
}

#[test]
fn test_service_request_with_different_services() {
    // Test SERVICE_REQUEST with different service names
    let services = vec![
        "ssh-userauth",
        "ssh-connection",
        "sftp-subsystem",
    ];
    
    for service in services {
        let mut msg = Vec::new();
        msg.push(MessageType::ServiceRequest as u8);
        
        let service_bytes = service.as_bytes();
        msg.extend_from_slice(&(service_bytes.len() as u32).to_be_bytes());
        msg.extend_from_slice(service_bytes);
        
        // Parse back - cursor starts at position 0
        let mut cursor = Cursor::new(&msg);
        
        // Read message type
        let mut msg_type_buf = [0u8; 1];
        cursor.read_exact(&mut msg_type_buf).expect("Read msg type");
        assert_eq!(msg_type_buf[0], MessageType::ServiceRequest as u8);
        
        // Read length
        let mut len_buf = [0u8; 4];
        cursor.read_exact(&mut len_buf).expect("Read length");
        let len = u32::from_be_bytes(len_buf);
        
        // Read service
        let mut service_read = vec![0u8; len as usize];
        cursor.read_exact(&mut service_read).expect("Read service");
        
        assert_eq!(String::from_utf8(service_read).unwrap(), service);
    }
}