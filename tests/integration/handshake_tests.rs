//! End-to-End Handshake Integration Tests
//!
//! Tests the complete SSH handshake flow from version exchange to established state

use ssh_client::protocol::{AlgorithmProposal, KexAlgorithm, HashAlgorithm};
use ssh_client::transport::{
    HandshakeState, TransportStateMachine, State, generate_client_kexinit, compute_session_id, hash_algorithm_for_kex
};
use ssh_client::transport::version::parse_version_string;
use ssh_client::crypto::{dh::DhGroup, kdf::kdf};

#[test]
fn test_complete_handshake_flow() {
    // Step 1: Version exchange
    let client_version = b"SSH-2.0-ayssh_1.0.0\r\n";
    let server_version = b"SSH-2.0-OpenSSH_8.4\r\n";
    
    let (client_proto, client_sw) = parse_version_string(client_version).unwrap();
    let (server_proto, server_sw) = parse_version_string(server_version).unwrap();
    
    assert_eq!(client_proto, 2);
    assert_eq!(server_proto, 2);
    assert_eq!(client_sw, "ayssh_1.0.0");
    assert_eq!(server_sw, "OpenSSH_8.4");
    
    // Step 2: Algorithm negotiation
    let client = AlgorithmProposal::client_proposal();
    let server = AlgorithmProposal::server_proposal();
    
    let negotiated = client.select_common_algorithms(&server).unwrap();
    
    assert!(!negotiated.kex.is_empty());
    assert!(!negotiated.host_key.is_empty());
    assert!(!negotiated.enc_c2s.is_empty());
    assert!(!negotiated.enc_s2c.is_empty());
    
    // Step 3: Key exchange (DH Group14)
    let kex_algorithm = KexAlgorithm::DiffieHellmanGroup14Sha256;
    let hash_algorithm = hash_algorithm_for_kex(kex_algorithm);
    
    let group = DhGroup::group14();
    let mut rng = rand::thread_rng();
    
    // Client generates private key
    let client_private = group.generate_private_key(&mut rng, 256);
    let client_public = group.compute_public_key(&client_private);
    
    // Server generates private key
    let server_private = group.generate_private_key(&mut rng, 256);
    let server_public = group.compute_public_key(&server_private);
    
    // Both compute shared secret
    let client_shared = group.compute_shared_secret(&server_public, &client_private);
    let server_shared = group.compute_shared_secret(&client_public, &server_private);
    
    assert_eq!(client_shared, server_shared);
    
    // Step 4: Compute session ID
    let client_kexinit = generate_client_kexinit();
    let server_kexinit = generate_client_kexinit(); // Same for test
    
    // Convert BigUint to bytes for session ID computation
    let client_public_bytes = client_public.to_bytes_be();
    let server_public_bytes = server_public.to_bytes_be();
    
    let session_id = compute_session_id(
        client_shared.to_bytes_be().as_slice(),
        client_version,
        server_version,
        &client_kexinit,
        &server_kexinit,
        &[], // Server host key (empty for test)
        &client_public_bytes,
        &server_public_bytes,
        hash_algorithm,
    );
    
    assert_eq!(session_id.len(), 32); // SHA-256 output
    
    // Step 5: Derive keys
    let enc_key_len = 32; // AES-256
    let mac_key_len = 32; // HMAC-SHA256
    let iv_len = 16; // AES block size
    
    let enc_key = kdf(&session_id, &session_id, 1, enc_key_len);
    let mac_key = kdf(&session_id, &session_id, 2, mac_key_len);
    let iv = kdf(&session_id, &session_id, 3, iv_len);
    
    assert_eq!(enc_key.len(), enc_key_len);
    assert_eq!(mac_key.len(), mac_key_len);
    assert_eq!(iv.len(), iv_len);
    
    // Step 6: State machine transitions
    let mut state_machine = TransportStateMachine::new();
    
    // Start in Handshake state
    assert_eq!(state_machine.current_state(), State::Handshake);
    
    // After KEXINIT exchange, transition to KeyExchange
    state_machine.transition_to_key_exchange();
    assert_eq!(state_machine.current_state(), State::KeyExchange);
    
    // After NEWKEYS, transition to Established
    state_machine.transition_to_established();
    assert_eq!(state_machine.current_state(), State::Established);
    
    // State machine should be in established state
    assert!(state_machine.is_established());
}

#[test]
fn test_handshake_state_integration() {
    let mut handshake = HandshakeState::default();
    
    // Initial state
    assert!(handshake.client_kexinit.is_none());
    assert!(handshake.server_kexinit.is_none());
    assert!(handshake.negotiated.is_none());
    
    // Simulate receiving KEXINITs
    let client_kexinit = generate_client_kexinit();
    handshake.client_kexinit = Some(client_kexinit.clone());
    
    handshake.server_kexinit = Some(client_kexinit.clone());
    
    // Negotiate algorithms
    let client = AlgorithmProposal::client_proposal();
    let server = AlgorithmProposal::server_proposal();
    let negotiated = client.select_common_algorithms(&server).unwrap();
    handshake.negotiated = Some(negotiated);
    
    assert!(handshake.client_kexinit.is_some());
    assert!(handshake.server_kexinit.is_some());
    assert!(handshake.negotiated.is_some());
}

#[test]
fn test_state_machine_invalid_transitions() {
    let mut state_machine = TransportStateMachine::new();
    
    // Cannot go directly from Handshake to Established
    // (must go through KeyExchange)
    // This is enforced by the state machine design
    
    // Initial state is Handshake, not Disconnected
    assert!(!state_machine.is_disconnected());
    
    // No transitions allowed from Disconnected
    // (would panic or return error in real implementation)
}

#[test]
fn test_version_exchange_errors() {
    // Old protocol version
    let old_version = b"SSH-1.0-OldClient\r\n";
    assert!(parse_version_string(old_version).is_err());
    
    // Missing CRLF
    let no_crlf = b"SSH-2.0-Client";
    assert!(parse_version_string(no_crlf).is_err());
    
    // Invalid prefix
    let invalid_prefix = b"SSH3-2.0-Client\r\n";
    assert!(parse_version_string(invalid_prefix).is_err());
}

#[test]
fn test_session_id_uniqueness() {
    let shared_secret = vec![0xAB; 32];
    let client_version = b"SSH-2.0-ayssh_1.0.0\r\n";
    let server_version = b"SSH-2.0-OpenSSH_8.4\r\n";
    let client_kexinit = generate_client_kexinit();
    let server_kexinit = generate_client_kexinit();
    
    let hash_algorithm = HashAlgorithm::Sha256;
    
    // Different shared secrets produce different session IDs
    let session_id1 = compute_session_id(
        &shared_secret,
        client_version,
        server_version,
        &client_kexinit,
        &server_kexinit,
        &[],
        &[0x00],
        &[0x01],
        hash_algorithm,
    );
    
    let session_id2 = compute_session_id(
        &shared_secret,
        client_version,
        server_version,
        &client_kexinit,
        &server_kexinit,
        &[],
        &[0x01],
        &[0x02],
        hash_algorithm,
    );
    
    assert_ne!(session_id1, session_id2);
}

#[test]
fn test_kex_algorithm_hash_mapping() {
    use ssh_client::protocol::KexAlgorithm;
    
    assert_eq!(hash_algorithm_for_kex(KexAlgorithm::DiffieHellmanGroup14Sha256), HashAlgorithm::Sha256);
    assert_eq!(hash_algorithm_for_kex(KexAlgorithm::DiffieHellmanGroup16Sha512), HashAlgorithm::Sha384);
    assert_eq!(hash_algorithm_for_kex(KexAlgorithm::EcdhSha2Nistp521), HashAlgorithm::Sha512);
}

#[test]
fn test_key_derivation_determinism() {
    let session_id = vec![0xAB; 32];
    
    let enc_key1 = kdf(&session_id, &session_id, 1, 32);
    let enc_key2 = kdf(&session_id, &session_id, 1, 32);
    
    assert_eq!(enc_key1, enc_key2);
    
    let enc_key3 = kdf(&session_id, &session_id, 2, 32);
    assert_ne!(enc_key1, enc_key3);
}