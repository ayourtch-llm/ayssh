//! Transport Session Manager
//!
//! Coordinates the key exchange and encrypted transport layer,
//! providing a unified interface for encrypted communication.

use crate::error::SshError;
use crate::protocol::{self, Message, MessageType};
use crate::transport::cipher::CipherState;
use crate::transport::{KexContext, SessionKeys};
use bytes::{BufMut, BytesMut};

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
        use rand::RngCore;
        
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

    #[test]
    fn test_transport_session_initial_state() {
        let stream: Vec<u8> = vec![];
        let session = TransportSession::new(stream, protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        assert_eq!(session.state(), SessionState::Initial);
    }

    #[test]
    fn test_transport_session_kex_init() {
        let stream: Vec<u8> = vec![];
        let mut session = TransportSession::new(stream, protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        
        let result = session.init_kex();
        assert!(result.is_ok());
        assert_eq!(session.state(), SessionState::KexInProgress);
    }
}