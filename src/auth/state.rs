//! Authentication state machine

use crate::error::SshError;

/// Authentication status
#[derive(Debug, Clone, PartialEq)]
pub enum AuthStatus {
    /// Initial state, not authenticating
    NotAuthenticating,
    /// Currently authenticating
    Authenticating,
    /// Successfully authenticated
    Authenticated,
    /// Authentication failed
    Failed,
}

/// Authentication state machine
#[derive(Debug)]
pub struct AuthState {
    status: AuthStatus,
}

impl AuthState {
    /// Creates a new authentication state with initial status `NotAuthenticating`
    pub fn new() -> Self {
        Self {
            status: AuthStatus::NotAuthenticating,
        }
    }

    /// Returns current status
    pub fn status(&self) -> &AuthStatus {
        &self.status
    }

    /// Starts authentication process, transitioning to `Authenticating`
    /// 
    /// # Errors
    /// Returns `SshError::ProtocolError` if already in `Authenticating`, `Authenticated`, or `Failed` state
    pub fn start_auth(&mut self) -> Result<(), SshError> {
        match self.status {
            AuthStatus::NotAuthenticating => {
                self.status = AuthStatus::Authenticating;
                Ok(())
            }
            _ => Err(SshError::ProtocolError(format!(
                "Invalid state transition: {:?} -> Authenticating",
                self.status
            ))),
        }
    }

    /// Completes authentication successfully, transitioning to `Authenticated`
    /// 
    /// # Errors
    /// Returns `SshError::ProtocolError` if not in `Authenticating` state
    pub fn complete_auth(&mut self) -> Result<(), SshError> {
        match self.status {
            AuthStatus::Authenticating => {
                self.status = AuthStatus::Authenticated;
                Ok(())
            }
            _ => Err(SshError::ProtocolError(format!(
                "Invalid state transition: {:?} -> Authenticated",
                self.status
            ))),
        }
    }

    /// Marks authentication as failed, transitioning to `Failed`
    /// 
    /// # Errors
    /// Returns `SshError::ProtocolError` if not in `Authenticating` state
    pub fn fail_auth(&mut self) -> Result<(), SshError> {
        match self.status {
            AuthStatus::Authenticating => {
                self.status = AuthStatus::Failed;
                Ok(())
            }
            _ => Err(SshError::ProtocolError(format!(
                "Invalid state transition: {:?} -> Failed",
                self.status
            ))),
        }
    }

    /// Resets state to `NotAuthenticating`
    pub fn reset(&mut self) {
        self.status = AuthStatus::NotAuthenticating;
    }

    /// Checks if currently authenticating
    pub fn is_authenticating(&self) -> bool {
        self.status == AuthStatus::Authenticating
    }

    /// Checks if authentication is successful
    pub fn is_authenticated(&self) -> bool {
        self.status == AuthStatus::Authenticated
    }

    /// Checks if authentication has failed
    pub fn is_failed(&self) -> bool {
        self.status == AuthStatus::Failed
    }

    /// Checks if not authenticating (initial state)
    pub fn is_not_authenticating(&self) -> bool {
        self.status == AuthStatus::NotAuthenticating
    }
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}