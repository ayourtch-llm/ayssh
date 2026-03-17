//! Transport Session Manager
//!
//! Coordinates the key exchange and encrypted transport layer,
//! providing a unified interface for encrypted communication.

use crate::error::SshError;
use crate::protocol;
use crate::transport::cipher::CipherState;
use crate::transport::{KexContext, SessionKeys};

/// Transport session state
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// Key exchange not started
    Initial,
    /// KEX in progress
    KexInProgress,
    /// KEX complete, encrypted transport ready
    Encrypted,
    /// Service requested
    ServiceRequested,
    /// Authenticated
    Authenticated,
    /// Session closed
    Closed,
}

/// Transport session manager
pub struct TransportSession<S> {
    /// Underlying stream (wrapped)
    stream: S,
    /// KEX context
    kex_context: KexContext,
    /// Current session state
    state: SessionState,
    /// Session ID
    session_id: Option<Vec<u8>>,
    /// Derived session keys (after KEX)
    session_keys: Option<SessionKeys>,
    /// Cipher state for encryption (after KEX)
    cipher_state: Option<CipherState>,
    /// Negotiated encryption algorithm
    encryption_algorithm: Option<String>,
}

impl<S> TransportSession<S> {
    /// Create a new transport session
    pub fn new(stream: S, algorithm: protocol::KexAlgorithm) -> Self {
        Self {
            stream,
            kex_context: KexContext::new(algorithm),
            state: SessionState::Initial,
            session_id: None,
            session_keys: None,
            cipher_state: None,
            encryption_algorithm: None,
        }
    }

    /// Initialize KEX with client's ephemeral key
    pub fn init_kex(&mut self) -> Result<(), SshError> {
        let mut rng = rand::rngs::OsRng;
        self.kex_context.generate_client_key(&mut rng)?;
        self.state = SessionState::KexInProgress;
        
        Ok(())
    }

    /// Get KEX context reference
    pub fn kex_context(&self) -> &KexContext {
        &self.kex_context
    }

    /// Get KEX context mutable reference
    pub fn kex_context_mut(&mut self) -> &mut KexContext {
        &mut self.kex_context
    }

    /// Get current session state
    pub fn state(&self) -> SessionState {
        self.state.clone()
    }

    /// Get session ID
    pub fn session_id(&self) -> Option<&Vec<u8>> {
        self.session_id.as_ref()
    }

    /// Get negotiated encryption algorithm
    pub fn encryption_algorithm(&self) -> Option<&str> {
        self.encryption_algorithm.as_deref()
    }

    /// Get cipher state reference
    pub fn cipher_state(&self) -> Option<&CipherState> {
        self.cipher_state.as_ref()
    }

    /// Get session keys reference
    pub fn session_keys(&self) -> Option<&SessionKeys> {
        self.session_keys.as_ref()
    }

    /// Get mutable reference to stream
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Transition to encrypted state after receiving NEWKEYS
    pub fn transition_to_encrypted(&mut self) -> Result<(), SshError> {
        // Set session ID from KEX context
        let session_id = self.kex_context.session_id.clone()
            .ok_or(SshError::ProtocolError("Session ID not computed".to_string()))?;
        
        // Derive session keys from shared secret
        let session_keys = self.kex_context.derive_session_keys(&session_id)
            .map_err(|e| SshError::ProtocolError(e.to_string()))?;
        
        // Initialize cipher state
        let cipher_state = CipherState::new(
            &session_keys.enc_key_c2s,
            &session_id,
            &session_keys.enc_key_s2c,
            &session_keys.mac_key_c2s,
        );
        
        self.session_id = Some(session_id);
        self.session_keys = Some(session_keys);
        self.cipher_state = Some(cipher_state);
        self.state = SessionState::Encrypted;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> TransportSession<Vec<u8>> {
        TransportSession::new(vec![], protocol::KexAlgorithm::DiffieHellmanGroup14Sha256)
    }

    fn make_session_with_algorithm(algo: protocol::KexAlgorithm) -> TransportSession<Vec<u8>> {
        TransportSession::new(vec![1, 2, 3], algo)
    }

    #[test]
    fn test_initial_state() {
        let session = make_session();
        assert_eq!(session.state(), SessionState::Initial);
    }

    #[test]
    fn test_initial_state_accessors_return_none() {
        let session = make_session();
        assert!(session.session_id().is_none());
        assert!(session.encryption_algorithm().is_none());
        assert!(session.cipher_state().is_none());
        assert!(session.session_keys().is_none());
    }

    #[test]
    fn test_kex_context_accessible() {
        let session = make_session();
        let ctx = session.kex_context();
        assert_eq!(ctx.algorithm, protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
    }

    #[test]
    fn test_kex_context_mut_accessible() {
        let mut session = make_session();
        let ctx = session.kex_context_mut();
        // Can mutate through the reference
        ctx.session_id = Some(vec![42]);
        assert_eq!(session.kex_context().session_id, Some(vec![42]));
    }

    #[test]
    fn test_stream_mut_accessible() {
        let mut session = make_session_with_algorithm(protocol::KexAlgorithm::Curve25519Sha256);
        let stream = session.stream_mut();
        stream.push(99);
        assert_eq!(session.stream_mut(), &vec![1, 2, 3, 99]);
    }

    #[test]
    fn test_init_kex_transitions_to_kex_in_progress() {
        let mut session = make_session();
        assert_eq!(session.state(), SessionState::Initial);
        session.init_kex().unwrap();
        assert_eq!(session.state(), SessionState::KexInProgress);
    }

    #[test]
    fn test_init_kex_generates_client_ephemeral() {
        let mut session = make_session();
        session.init_kex().unwrap();
        assert!(session.kex_context().client_ephemeral.is_some());
    }

    #[test]
    fn test_init_kex_works_for_all_algorithms() {
        let algos = [
            protocol::KexAlgorithm::DiffieHellmanGroup1Sha1,
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha1,
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha256,
            protocol::KexAlgorithm::Curve25519Sha256,
            protocol::KexAlgorithm::EcdhSha2Nistp256,
            protocol::KexAlgorithm::EcdhSha2Nistp384,
            protocol::KexAlgorithm::EcdhSha2Nistp521,
        ];
        for algo in algos {
            let mut session = make_session_with_algorithm(algo);
            session.init_kex().unwrap();
            assert_eq!(session.state(), SessionState::KexInProgress);
            assert!(session.kex_context().client_ephemeral.is_some());
        }
    }

    #[test]
    fn test_transition_to_encrypted_fails_without_session_id() {
        let mut session = make_session();
        let result = session.transition_to_encrypted();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Session ID not computed"), "Got: {}", err);
        // State should remain unchanged on failure
        assert_eq!(session.state(), SessionState::Initial);
    }

    #[test]
    fn test_transition_to_encrypted_fails_without_shared_secret() {
        let mut session = make_session();
        // Set session_id but not shared_secret
        session.kex_context_mut().session_id = Some(vec![1, 2, 3, 4]);
        let result = session.transition_to_encrypted();
        assert!(result.is_err());
    }

    #[test]
    fn test_transition_to_encrypted_succeeds() {
        let mut session = make_session();
        let ctx = session.kex_context_mut();
        ctx.session_id = Some(vec![0u8; 32]);
        ctx.shared_secret = Some(vec![0u8; 32]);

        let result = session.transition_to_encrypted();
        assert!(result.is_ok());
        assert_eq!(session.state(), SessionState::Encrypted);
        assert!(session.session_id().is_some());
        assert_eq!(session.session_id().unwrap().len(), 32);
        assert!(session.session_keys().is_some());
        assert!(session.cipher_state().is_some());
    }

    #[test]
    fn test_transition_to_encrypted_sets_session_keys() {
        let mut session = make_session();
        let ctx = session.kex_context_mut();
        ctx.session_id = Some(vec![0xAA; 32]);
        ctx.shared_secret = Some(vec![0xBB; 32]);
        session.transition_to_encrypted().unwrap();

        let keys = session.session_keys().unwrap();
        assert!(!keys.enc_key_c2s.is_empty());
        assert!(!keys.enc_key_s2c.is_empty());
        assert!(!keys.mac_key_c2s.is_empty());
        assert!(!keys.mac_key_s2c.is_empty());
        assert!(!keys.client_iv.is_empty());
        assert!(!keys.server_iv.is_empty());
    }

    #[test]
    fn test_transition_to_encrypted_cipher_state_usable() {
        let mut session = make_session();
        let ctx = session.kex_context_mut();
        ctx.session_id = Some(vec![0u8; 32]);
        ctx.shared_secret = Some(vec![0u8; 32]);
        session.transition_to_encrypted().unwrap();

        let cs = session.cipher_state().unwrap();
        assert!(!cs.enc_key.is_empty());
        assert!(!cs.session_id.is_empty());
    }

    #[test]
    fn test_session_state_enum_equality() {
        assert_eq!(SessionState::Initial, SessionState::Initial);
        assert_ne!(SessionState::Initial, SessionState::KexInProgress);
        assert_ne!(SessionState::Encrypted, SessionState::Authenticated);
        assert_ne!(SessionState::ServiceRequested, SessionState::Closed);
    }

    #[test]
    fn test_session_state_clone() {
        let state = SessionState::Encrypted;
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_session_state_debug() {
        let state = SessionState::KexInProgress;
        let debug = format!("{:?}", state);
        assert!(debug.contains("KexInProgress"));
    }

    #[test]
    fn test_encryption_algorithm_initially_none() {
        let session = make_session();
        assert_eq!(session.encryption_algorithm(), None);
    }
}