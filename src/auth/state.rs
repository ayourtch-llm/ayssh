//! Authentication state machine

use crate::error::SshError;

/// Authentication state
#[derive(Debug, Clone, PartialEq)]
pub enum AuthenticationState {
    /// Initial state, no authentication started
    Initial,
    /// Authentication in progress
    InProgress,
    /// Authentication successful
    Success,
    /// Authentication failed
    Failed,
}

/// Authentication state machine
#[derive(Debug)]
pub struct AuthenticationStateMachine {
    state: AuthenticationState,
}

impl AuthenticationStateMachine {
    /// Creates a new authentication state machine
    pub fn new() -> Self {
        Self {
            state: AuthenticationState::Initial,
        }
    }

    /// Returns current state
    pub fn state(&self) -> &AuthenticationState {
        &self.state
    }

    /// Transitions to InProgress state
    pub fn transition_to_authentication(&mut self) -> Result<(), SshError> {
        match self.state {
            AuthenticationState::Initial => {
                self.state = AuthenticationState::InProgress;
                Ok(())
            }
            _ => Err(SshError::ProtocolError(format!(
                "Invalid state transition: {:?} -> InProgress",
                self.state
            ))),
        }
    }

    /// Transitions to Success state
    pub fn transition_to_success(&mut self) -> Result<(), SshError> {
        match self.state {
            AuthenticationState::InProgress => {
                self.state = AuthenticationState::Success;
                Ok(())
            }
            _ => Err(SshError::ProtocolError(format!(
                "Invalid state transition: {:?} -> Success",
                self.state
            ))),
        }
    }

    /// Transitions to Failed state
    pub fn transition_to_failed(&mut self) -> Result<(), SshError> {
        match self.state {
            AuthenticationState::InProgress => {
                self.state = AuthenticationState::Failed;
                Ok(())
            }
            _ => Err(SshError::ProtocolError(format!(
                "Invalid state transition: {:?} -> Failed",
                self.state
            ))),
        }
    }

    /// Resets state machine
    pub fn reset(&mut self) {
        self.state = AuthenticationState::Initial;
    }

    /// Checks if authentication is successful
    pub fn is_success(&self) -> bool {
        self.state == AuthenticationState::Success
    }

    /// Checks if authentication is in progress
    pub fn is_in_progress(&self) -> bool {
        self.state == AuthenticationState::InProgress
    }

    /// Checks if authentication has failed
    pub fn is_failed(&self) -> bool {
        self.state == AuthenticationState::Failed
    }
}

impl Default for AuthenticationStateMachine {
    fn default() -> Self {
        Self::new()
    }
}