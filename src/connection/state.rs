//! Connection State Machine for SSH
//!
//! Implements the connection state machine as defined in RFC 4253.

use std::fmt;

/// SSH Connection States
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state - no connection
    Disconnected,
    /// TCP connection established
    Connected,
    /// Exchanging version strings
    VersionExchange,
    /// Negotiating algorithms
    AlgorithmNegotiation,
    /// Performing key exchange
    KeyExchange,
    /// Authenticating user
    Authentication,
    /// Connection established and ready for use
    Established,
    /// Connection closed or error
    Closed,
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionState::Disconnected => write!(f, "DISCONNECTED"),
            ConnectionState::Connected => write!(f, "CONNECTED"),
            ConnectionState::VersionExchange => write!(f, "VERSION_EXCHANGE"),
            ConnectionState::AlgorithmNegotiation => write!(f, "ALGORITHM_NEGOTIATION"),
            ConnectionState::KeyExchange => write!(f, "KEY_EXCHANGE"),
            ConnectionState::Authentication => write!(f, "AUTHENTICATION"),
            ConnectionState::Established => write!(f, "ESTABLISHED"),
            ConnectionState::Closed => write!(f, "CLOSED"),
        }
    }
}

/// Connection State Machine
pub struct ConnectionStateMachine {
    current_state: ConnectionState,
    server_version: Option<String>,
    client_version: String,
    algorithms: Option<crate::protocol::algorithms::NegotiatedAlgorithms>,
}

impl Default for ConnectionStateMachine {
    fn default() -> Self {
        Self {
            current_state: ConnectionState::Disconnected,
            server_version: None,
            client_version: "SSH-2.0-rustssh".to_string(),
            algorithms: None,
        }
    }
}

impl ConnectionStateMachine {
    /// Create a new connection state machine
    pub fn new() -> Self {
        Self::default()
    }

    /// Get current state
    pub fn current_state(&self) -> ConnectionState {
        self.current_state.clone()
    }

    /// Transition to Connected state
    pub fn transition_to_connected(&mut self) -> Result<(), crate::error::SshError> {
        if self.current_state != ConnectionState::Disconnected {
            return Err(crate::error::SshError::ProtocolError(
                "Cannot transition to Connected from current state".to_string(),
            ));
        }
        self.current_state = ConnectionState::Connected;
        Ok(())
    }

    /// Transition to VersionExchange state
    pub fn transition_to_version_exchange(&mut self) -> Result<(), crate::error::SshError> {
        if self.current_state != ConnectionState::Connected {
            return Err(crate::error::SshError::ProtocolError(
                "Cannot transition to VersionExchange from current state".to_string(),
            ));
        }
        self.current_state = ConnectionState::VersionExchange;
        Ok(())
    }

    /// Set server version string
    pub fn set_server_version(&mut self, version: String) {
        self.server_version = Some(version);
    }

    /// Get server version
    pub fn server_version(&self) -> Option<&str> {
        self.server_version.as_deref()
    }

    /// Transition to AlgorithmNegotiation state
    pub fn transition_to_algorithm_negotiation(&mut self) -> Result<(), crate::error::SshError> {
        if self.current_state != ConnectionState::VersionExchange {
            return Err(crate::error::SshError::ProtocolError(
                "Cannot transition to AlgorithmNegotiation from current state".to_string(),
            ));
        }
        self.current_state = ConnectionState::AlgorithmNegotiation;
        Ok(())
    }

    /// Set negotiated algorithms
    pub fn set_algorithms(&mut self, algorithms: crate::protocol::algorithms::NegotiatedAlgorithms) {
        self.algorithms = Some(algorithms);
    }

    /// Get negotiated algorithms
    pub fn algorithms(&self) -> Option<&crate::protocol::algorithms::NegotiatedAlgorithms> {
        self.algorithms.as_ref()
    }

    /// Transition to KeyExchange state
    pub fn transition_to_key_exchange(&mut self) -> Result<(), crate::error::SshError> {
        if self.current_state != ConnectionState::AlgorithmNegotiation {
            return Err(crate::error::SshError::ProtocolError(
                "Cannot transition to KeyExchange from current state".to_string(),
            ));
        }
        self.current_state = ConnectionState::KeyExchange;
        Ok(())
    }

    /// Transition to Authentication state
    pub fn transition_to_authentication(&mut self) -> Result<(), crate::error::SshError> {
        if self.current_state != ConnectionState::KeyExchange {
            return Err(crate::error::SshError::ProtocolError(
                "Cannot transition to Authentication from current state".to_string(),
            ));
        }
        self.current_state = ConnectionState::Authentication;
        Ok(())
    }

    /// Transition to Established state
    pub fn transition_to_established(&mut self) -> Result<(), crate::error::SshError> {
        if self.current_state != ConnectionState::Authentication {
            return Err(crate::error::SshError::ProtocolError(
                "Cannot transition to Established from current state".to_string(),
            ));
        }
        self.current_state = ConnectionState::Established;
        Ok(())
    }

    /// Transition to Closed state
    pub fn transition_to_closed(&mut self) {
        self.current_state = ConnectionState::Closed;
    }

    /// Check if connection is established
    pub fn is_established(&self) -> bool {
        self.current_state == ConnectionState::Established
    }

    /// Get client version
    pub fn client_version(&self) -> &str {
        &self.client_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_machine_initial() {
        let machine = ConnectionStateMachine::new();
        assert_eq!(machine.current_state(), ConnectionState::Disconnected);
    }

    #[test]
    fn test_state_machine_transitions() {
        let mut machine = ConnectionStateMachine::new();
        
        // Disconnected -> Connected
        assert!(machine.transition_to_connected().is_ok());
        assert_eq!(machine.current_state(), ConnectionState::Connected);
        
        // Connected -> VersionExchange
        assert!(machine.transition_to_version_exchange().is_ok());
        assert_eq!(machine.current_state(), ConnectionState::VersionExchange);
        
        // VersionExchange -> AlgorithmNegotiation
        assert!(machine.transition_to_algorithm_negotiation().is_ok());
        assert_eq!(machine.current_state(), ConnectionState::AlgorithmNegotiation);
        
        // AlgorithmNegotiation -> KeyExchange
        assert!(machine.transition_to_key_exchange().is_ok());
        assert_eq!(machine.current_state(), ConnectionState::KeyExchange);
        
        // KeyExchange -> Authentication
        assert!(machine.transition_to_authentication().is_ok());
        assert_eq!(machine.current_state(), ConnectionState::Authentication);
        
        // Authentication -> Established
        assert!(machine.transition_to_established().is_ok());
        assert_eq!(machine.current_state(), ConnectionState::Established);
    }

    #[test]
    fn test_invalid_transition() {
        let mut machine = ConnectionStateMachine::new();
        
        // Try to go from Disconnected to VersionExchange (should fail)
        assert!(machine.transition_to_version_exchange().is_err());
    }

    #[test]
    fn test_closed_state() {
        let mut machine = ConnectionStateMachine::new();
        machine.transition_to_connected().unwrap();
        machine.transition_to_closed();
        assert_eq!(machine.current_state(), ConnectionState::Closed);
    }
}