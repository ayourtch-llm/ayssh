//! Transport Layer State Machine for SSH Client
//!
//! Implements RFC 4253 transport layer state machine with three states:
//! - Handshake: Initial state, waiting for version exchange and server KEXINIT
//! - KeyExchange: Key exchange in progress
//! - Established: Secure channel established, encrypted communication

use crate::crypto::cipher::CipherError;
use crate::protocol::MessageType;
use crate::error::SshError;
use crate::transport::cipher::CipherState;

/// Transport session states as defined in RFC 4253
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum State {
    /// Initial state, waiting for version exchange and server KEXINIT
    Handshake,
    /// Key exchange in progress
    KeyExchange,
    /// Secure channel established, encrypted communication
    Established,
    /// Session disconnected (terminal state)
    Disconnected,
}

impl Default for State {
    fn default() -> Self {
        State::Handshake
    }
}

/// Result of processing a message in the current state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageResult {
    /// Message processed successfully, state transitioned
    Transitioned(State),
    /// Message processed successfully, same state
    SameState,
    /// Message not allowed in current state
    InvalidMessage,
}

/// Transport state machine implementation
#[derive(Debug, Clone, PartialEq)]
pub struct TransportStateMachine {
    /// Current state of the transport session
    state: State,
    /// Encryption cipher (optional, initialized after key exchange)
    cipher: Option<CipherState>,
    /// Encryption key
    encryption_key: Vec<u8>,
    /// MAC key
    mac_key: Vec<u8>,
}

impl TransportStateMachine {
    /// Create a new transport state machine starting in Handshake state
    pub fn new() -> Self {
        Self {
            state: State::default(),
            cipher: None,
            encryption_key: Vec::new(),
            mac_key: Vec::new(),
        }
    }

    /// Get the current state
    pub fn current_state(&self) -> State {
        self.state
    }

    /// Check if the state machine is in the Handshake state
    pub fn is_handshake(&self) -> bool {
        self.state == State::Handshake
    }

    /// Check if the state machine is in the KeyExchange state
    pub fn is_key_exchange(&self) -> bool {
        self.state == State::KeyExchange
    }

    /// Check if the state machine is in the Established state
    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    /// Check if the state machine is in the Disconnected state
    pub fn is_disconnected(&self) -> bool {
        self.state == State::Disconnected
    }

    /// Initialize the cipher after key exchange
    pub fn initialize_cipher(
        &mut self,
        shared_secret: &[u8],
        session_id: &[u8],
        enc_key: &[u8],
        mac_key: &[u8],
    ) {
        self.cipher = Some(CipherState::new(shared_secret, session_id, enc_key, mac_key));
        self.encryption_key = enc_key.to_vec();
        self.mac_key = mac_key.to_vec();
    }

    /// Transition to KeyExchange state
    pub fn transition_to_key_exchange(&mut self) {
        self.state = State::KeyExchange;
    }

    /// Transition to Established state
    pub fn transition_to_established(&mut self) {
        self.state = State::Established;
    }

    /// Transition to Disconnected state
    pub fn transition_to_disconnected(&mut self) {
        self.state = State::Disconnected;
    }

    /// Get reference to cipher if initialized
    pub fn cipher(&self) -> Option<&CipherState> {
        self.cipher.as_ref()
    }

    /// Encrypt a packet using the current cipher
    pub fn encrypt_packet(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if let Some(ref mut cipher) = self.cipher {
            cipher.encrypt(plaintext)
        } else {
            Err(CipherError::CryptoError("Cipher not initialized".to_string()))
        }
    }

    /// Decrypt a packet using the current cipher
    pub fn decrypt_packet(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherError> {
        if let Some(ref cipher) = self.cipher {
            cipher.decrypt(ciphertext)
        } else {
            Err(CipherError::CryptoError("Cipher not initialized".to_string()))
        }
    }

    /// Process a message and return the result
    ///
    /// # Arguments
    /// * `msg_type` - The type of message received
    ///
    /// # Returns
    /// * `Ok(MessageResult)` - Result of processing the message
    /// * `Err(SshError)` - Error if an invalid transition occurs
    pub fn process_message(&mut self, msg_type: MessageType) -> Result<MessageResult, SshError> {
        match self.state {
            State::Handshake => self.handle_handshake(msg_type),
            State::KeyExchange => self.handle_key_exchange(msg_type),
            State::Established => self.handle_established(msg_type),
            State::Disconnected => {
                // Already disconnected, any message results in error
                Err(SshError::ProtocolError(
                    "Cannot process message in Disconnected state".to_string(),
                ))
            }
        }
    }

    /// Handle messages in Handshake state
    ///
    /// In Handshake state, we can receive:
    /// - SSH_MSG_KEXINIT from server
    /// - SSH_MSG_KEX_ECDH_INIT (client initiates key exchange)
    /// - SSH_MSG_KEX_DH_GEX_REQUEST (client initiates DH GEX key exchange)
    fn handle_handshake(&mut self, msg_type: MessageType) -> Result<MessageResult, SshError> {
        match msg_type {
            MessageType::KexInit => {
                // Server sent KEXINIT, transition to KeyExchange
                self.state = State::KeyExchange;
                Ok(MessageResult::Transitioned(State::KeyExchange))
            }
            _ => {
                // Any other message is invalid in Handshake state
                Err(SshError::ProtocolError(format!(
                    "Invalid message {:?} in Handshake state",
                    msg_type
                )))
            }
        }
    }

    /// Handle messages in KeyExchange state
    ///
    /// In KeyExchange state, we can receive:
    /// - SSH_MSG_KEX_ECDH_REPLY (ECDH key exchange reply)
    /// - SSH_MSG_KEX_DH_GEX_GROUP (DH GEX group reply)
    /// - SSH_MSG_KEX_DH_GEX_REPLY (DH GEX reply)
    /// - SSH_MSG_NEWKEYS (key exchange complete)
    fn handle_key_exchange(&mut self, msg_type: MessageType) -> Result<MessageResult, SshError> {
        match msg_type {
            MessageType::Newkeys => {
                // Key exchange complete, transition to Established
                self.state = State::Established;
                Ok(MessageResult::Transitioned(State::Established))
            }
            // Key exchange algorithm-specific messages (allowed but don't change state)
            MessageType::KexInit => {
                // Re-keying initiated, stay in KeyExchange
                Ok(MessageResult::SameState)
            }
            _ => {
                // Other key exchange messages are allowed but don't change state
                // (ECDH_REPLY, DH_GEX_GROUP, etc.)
                Ok(MessageResult::SameState)
            }
        }
    }

    /// Handle messages in Established state
    ///
    /// In Established state, we can receive:
    /// - All encrypted messages
    /// - SSH_MSG_KEXINIT (trigger re-keying)
    fn handle_established(&mut self, msg_type: MessageType) -> Result<MessageResult, SshError> {
        match msg_type {
            MessageType::KexInit => {
                // Re-keying triggered, transition back to KeyExchange
                self.state = State::KeyExchange;
                Ok(MessageResult::Transitioned(State::KeyExchange))
            }
            // All other messages are allowed in Established state
            _ => Ok(MessageResult::SameState),
        }
    }

    /// Trigger a disconnect (terminal state)
    ///
    /// Can be called from any state to transition to Disconnected
    pub fn disconnect(&mut self) {
        self.state = State::Disconnected;
    }

    /// Trigger re-keying from any state (except Disconnected)
    ///
    /// From Handshake or Established, transitions to KeyExchange
    /// From KeyExchange, stays in KeyExchange
    pub fn trigger_rekey(&mut self) -> Result<(), SshError> {
        match self.state {
            State::Handshake | State::Established => {
                self.state = State::KeyExchange;
                Ok(())
            }
            State::KeyExchange => {
                // Already in key exchange, just stay there
                Ok(())
            }
            State::Disconnected => {
                Err(SshError::ProtocolError(
                    "Cannot trigger re-key in Disconnected state".to_string(),
                ))
            }
        }
    }

    /// Check if a message is valid in the current state (without modifying state)
    pub fn is_valid_message(&self, msg_type: MessageType) -> bool {
        match self.state {
            State::Handshake => matches!(msg_type, MessageType::KexInit),
            State::KeyExchange => matches!(
                msg_type,
                MessageType::Newkeys | MessageType::KexInit
            ),
            State::Established => true, // All messages valid in established state
            State::Disconnected => false, // No messages valid in disconnected state
        }
    }

    /// Validate a state transition
    ///
    /// # Arguments
    /// * `from` - Current state
    /// * `to` - Target state
    ///
    /// # Returns
    /// * `Ok(())` - Transition is valid
    /// * `Err(SshError)` - Transition is invalid
    pub fn validate_transition(from: State, to: State) -> Result<(), SshError> {
        match (from, to) {
            // Valid transitions
            (State::Handshake, State::KeyExchange) => Ok(()),
            (State::KeyExchange, State::Established) => Ok(()),
            (State::Established, State::KeyExchange) => Ok(()), // Re-keying
            (_, State::Disconnected) => Ok(()), // Disconnect from any state
            // Invalid transitions
            (State::Handshake, State::Handshake) => Ok(()), // Stay in same state is OK
            (State::KeyExchange, State::KeyExchange) => Ok(()), // Stay in same state is OK
            (State::Established, State::Established) => Ok(()), // Stay in same state is OK
            (State::Handshake, State::Established) => Err(SshError::ProtocolError(
                "Cannot skip KeyExchange state".to_string(),
            )),
            (State::Established, State::Handshake) => Err(SshError::ProtocolError(
                "Cannot go back to Handshake from Established".to_string(),
            )),
            (State::KeyExchange, State::Handshake) => Err(SshError::ProtocolError(
                "Cannot go back to Handshake from KeyExchange".to_string(),
            )),
            (State::Disconnected, _) => Err(SshError::ProtocolError(
                "Cannot transition from Disconnected state".to_string(),
            )),
        }
    }
}

impl Default for TransportStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state_machine_starts_in_handshake() {
        let sm = TransportStateMachine::new();
        assert_eq!(sm.current_state(), State::Handshake);
        assert!(sm.is_handshake());
        assert!(!sm.is_key_exchange());
        assert!(!sm.is_established());
        assert!(!sm.is_disconnected());
    }

    #[test]
    fn test_handshake_to_keyexchange_on_kexinit() {
        let mut sm = TransportStateMachine::new();
        assert_eq!(sm.current_state(), State::Handshake);

        let result = sm.process_message(MessageType::KexInit).unwrap();
        assert_eq!(result, MessageResult::Transitioned(State::KeyExchange));
        assert_eq!(sm.current_state(), State::KeyExchange);
    }

    #[test]
    fn test_keyexchange_to_established_on_newkeys() {
        let mut sm = TransportStateMachine::new();
        
        // First transition to KeyExchange
        sm.process_message(MessageType::KexInit).unwrap();
        assert_eq!(sm.current_state(), State::KeyExchange);

        // Then transition to Established
        let result = sm.process_message(MessageType::Newkeys).unwrap();
        assert_eq!(result, MessageResult::Transitioned(State::Established));
        assert_eq!(sm.current_state(), State::Established);
    }

    #[test]
    fn test_established_to_keyexchange_on_rekey() {
        let mut sm = TransportStateMachine::new();
        
        // Complete handshake
        sm.process_message(MessageType::KexInit).unwrap();
        sm.process_message(MessageType::Newkeys).unwrap();
        assert_eq!(sm.current_state(), State::Established);

        // Trigger re-keying
        let result = sm.process_message(MessageType::KexInit).unwrap();
        assert_eq!(result, MessageResult::Transitioned(State::KeyExchange));
        assert_eq!(sm.current_state(), State::KeyExchange);
    }

    #[test]
    fn test_disconnect_from_any_state() {
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

    #[test]
    fn test_invalid_transition_handshake_to_established() {
        let result = TransportStateMachine::validate_transition(
            State::Handshake,
            State::Established,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transition_established_to_handshake() {
        let result = TransportStateMachine::validate_transition(
            State::Established,
            State::Handshake,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_transition_from_disconnected() {
        let result = TransportStateMachine::validate_transition(
            State::Disconnected,
            State::Handshake,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_message_in_handshake_state() {
        let mut sm = TransportStateMachine::new();
        
        // Try to process a non-KEXINIT message in Handshake state
        let result = sm.process_message(MessageType::Newkeys);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_in_disconnected_state_fails() {
        let mut sm = TransportStateMachine::new();
        sm.disconnect();
        
        // Any message should fail in Disconnected state
        let result = sm.process_message(MessageType::KexInit);
        assert!(result.is_err());
    }

    #[test]
    fn test_rekey_trigger_from_handshake() {
        let mut sm = TransportStateMachine::new();
        assert_eq!(sm.current_state(), State::Handshake);

        sm.trigger_rekey().unwrap();
        assert_eq!(sm.current_state(), State::KeyExchange);
    }

    #[test]
    fn test_rekey_trigger_from_established() {
        let mut sm = TransportStateMachine::new();
        sm.process_message(MessageType::KexInit).unwrap();
        sm.process_message(MessageType::Newkeys).unwrap();
        assert_eq!(sm.current_state(), State::Established);

        sm.trigger_rekey().unwrap();
        assert_eq!(sm.current_state(), State::KeyExchange);
    }

    #[test]
    fn test_rekey_trigger_from_keyexchange() {
        let mut sm = TransportStateMachine::new();
        sm.process_message(MessageType::KexInit).unwrap();
        assert_eq!(sm.current_state(), State::KeyExchange);

        // Re-triggering rekey while already in KeyExchange should be OK
        sm.trigger_rekey().unwrap();
        assert_eq!(sm.current_state(), State::KeyExchange);
    }

    #[test]
    fn test_rekey_trigger_from_disconnected_fails() {
        let mut sm = TransportStateMachine::new();
        sm.disconnect();

        let result = sm.trigger_rekey();
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_message_in_handshake() {
        let sm = TransportStateMachine::new();
        assert!(sm.is_valid_message(MessageType::KexInit));
        assert!(!sm.is_valid_message(MessageType::Newkeys));
        assert!(!sm.is_valid_message(MessageType::Disconnect));
    }

    #[test]
    fn test_is_valid_message_in_key_exchange() {
        let mut sm = TransportStateMachine::new();
        sm.process_message(MessageType::KexInit).unwrap();

        assert!(sm.is_valid_message(MessageType::Newkeys));
        assert!(sm.is_valid_message(MessageType::KexInit));
        assert!(!sm.is_valid_message(MessageType::Disconnect));
    }

    #[test]
    fn test_is_valid_message_in_established() {
        let mut sm = TransportStateMachine::new();
        sm.process_message(MessageType::KexInit).unwrap();
        sm.process_message(MessageType::Newkeys).unwrap();

        // All messages valid in established state
        assert!(sm.is_valid_message(MessageType::KexInit));
        assert!(sm.is_valid_message(MessageType::Newkeys));
        assert!(sm.is_valid_message(MessageType::Disconnect));
        assert!(sm.is_valid_message(MessageType::ChannelOpen));
    }

    #[test]
    fn test_is_valid_message_in_disconnected() {
        let mut sm = TransportStateMachine::new();
        sm.disconnect();

        // No messages valid in disconnected state
        assert!(!sm.is_valid_message(MessageType::KexInit));
        assert!(!sm.is_valid_message(MessageType::Newkeys));
    }

    #[test]
    fn test_complete_handshake_flow() {
        let mut sm = TransportStateMachine::new();

        // 1. Start in Handshake
        assert_eq!(sm.current_state(), State::Handshake);

        // 2. Receive server KEXINIT
        let result = sm.process_message(MessageType::KexInit).unwrap();
        assert_eq!(result, MessageResult::Transitioned(State::KeyExchange));

        // 3. Key exchange messages (ECDH_INIT, etc.) - stay in KeyExchange
        let result = sm.process_message(MessageType::KexInit).unwrap();
        assert_eq!(result, MessageResult::SameState);

        // 4. Receive NEWKEYS
        let result = sm.process_message(MessageType::Newkeys).unwrap();
        assert_eq!(result, MessageResult::Transitioned(State::Established));

        // 5. Now in Established state
        assert_eq!(sm.current_state(), State::Established);

        // 6. Process encrypted messages
        let result = sm.process_message(MessageType::ChannelOpen).unwrap();
        assert_eq!(result, MessageResult::SameState);

        // 7. Trigger re-keying
        let result = sm.process_message(MessageType::KexInit).unwrap();
        assert_eq!(result, MessageResult::Transitioned(State::KeyExchange));

        // 8. Complete re-keying
        let result = sm.process_message(MessageType::Newkeys).unwrap();
        assert_eq!(result, MessageResult::Transitioned(State::Established));

        assert_eq!(sm.current_state(), State::Established);
    }

    #[test]
    fn test_default_impl() {
        let sm: TransportStateMachine = Default::default();
        assert_eq!(sm.current_state(), State::Handshake);
    }

    #[test]
    fn test_state_clone_and_equality() {
        let sm1 = TransportStateMachine::new();
        let sm2 = sm1.clone();
        
        assert_eq!(sm1.current_state(), sm2.current_state());
        assert_eq!(sm1, sm2);
    }
}
