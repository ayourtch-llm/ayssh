//! Algorithm negotiation tests for SSH protocol

use ayssh::protocol::AlgorithmProposal;

#[test]
fn test_client_proposal_has_default_algorithms() {
    let client = AlgorithmProposal::client_proposal();
    
    assert!(!client.kex_algorithms.is_empty());
    assert!(!client.server_host_key_algorithms.is_empty());
    assert!(!client.encryption_algorithms_c2s.is_empty());
    assert!(!client.encryption_algorithms_s2c.is_empty());
    assert!(!client.mac_algorithms_c2s.is_empty());
    assert!(!client.mac_algorithms_s2c.is_empty());
    assert!(!client.compression_algorithms.is_empty());
}

#[test]
fn test_server_proposal_has_default_algorithms() {
    let server = AlgorithmProposal::server_proposal();
    
    assert!(!server.kex_algorithms.is_empty());
    assert!(!server.server_host_key_algorithms.is_empty());
}

#[test]
fn test_algorithm_selection_common_kex() {
    let client = AlgorithmProposal::client_proposal();
    let server = AlgorithmProposal::server_proposal();
    
    let negotiated = client.select_common_algorithms(&server).unwrap();
    
    assert!(!negotiated.kex.is_empty());
}

#[test]
fn test_algorithm_selection_no_common() {
    let mut client = AlgorithmProposal::client_proposal();
    let server = AlgorithmProposal::server_proposal();
    
    // Remove all common kex algorithms
    client.kex_algorithms = vec!["nonexistent-algo".to_string()];
    
    let result = client.select_common_algorithms(&server);
    assert!(result.is_err());
}

#[test]
fn test_kex_algorithms_preference() {
    let client = AlgorithmProposal::client_proposal();
    
    // Check that preferred algorithms are in the list
    assert!(client.kex_algorithms.contains(&"curve25519-sha256".to_string()));
}

#[test]
fn test_encryption_algorithms() {
    let client = AlgorithmProposal::client_proposal();
    
    // Check for modern encryption algorithms
    assert!(client.encryption_algorithms_c2s.contains(&"aes256-gcm@openssh.com".to_string()));
    assert!(client.encryption_algorithms_s2c.contains(&"aes256-gcm@openssh.com".to_string()));
}

#[test]
fn test_mac_algorithms() {
    let client = AlgorithmProposal::client_proposal();
    
    // Check for secure MAC algorithms
    assert!(client.mac_algorithms_c2s.contains(&"hmac-sha2-256-etm@openssh.com".to_string()));
}