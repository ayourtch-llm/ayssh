//! SSH Session management

use crate::protocol::AuthMethod;

/// Represents an SSH session
pub struct Session {
    host: String,
    port: u16,
    authenticated: bool,
}

impl Session {
    /// Create a new session
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            authenticated: false,
        }
    }

    /// Get the host
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if authenticated
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Mark session as authenticated
    pub fn authenticate(&mut self, _method: &AuthMethod) {
        self.authenticated = true;
    }
}
