//! Authentication State Management
//!
//! Tracks the state of the authentication process.

use crate::protocol;

/// Authentication state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthState {
    /// Initial state, no authentication attempted
    None,
    /// Authentication in progress
    InProgress,
    /// Authentication succeeded
    Success,
    /// Authentication failed
    Failed,
}

impl AuthState {
    /// Check if authentication is complete
    pub fn is_complete(&self) -> bool {
        matches!(self, AuthState::Success | AuthState::Failed)
    }
}

impl Default for AuthState {
    fn default() -> Self {
        AuthState::None
    }
}

/// Authentication context
#[derive(Debug, Default)]
pub struct AuthContext {
    /// Current state
    pub state: AuthState,
    /// Methods tried
    pub tried_methods: Vec<protocol::AuthMethod>,
    /// Methods available
    pub available_methods: Vec<protocol::AuthMethod>,
}

impl AuthContext {
    /// Create a new auth context
    pub fn new() -> Self {
        Self {
            state: AuthState::None,
            tried_methods: Vec::new(),
            available_methods: Vec::new(),
        }
    }

    /// Record a tried method
    pub fn record_tried(&mut self, method: protocol::AuthMethod) {
        if !self.tried_methods.contains(&method) {
            self.tried_methods.push(method);
        }
    }
}
