//! Authentication methods for SSH

use crate::protocol::AuthMethod as ProtocolAuthMethod;

/// Authentication method manager
#[derive(Debug, Clone)]
pub struct AuthMethodManager {
    /// Supported authentication methods
    pub supported_methods: Vec<ProtocolAuthMethod>,
    /// Allowed authentication methods
    pub allowed_methods: Vec<ProtocolAuthMethod>,
}

impl AuthMethodManager {
    /// Create a new auth method manager
    pub fn new() -> Self {
        Self {
            supported_methods: Vec::new(),
            allowed_methods: Vec::new(),
        }
    }

    /// Add a supported method
    pub fn add_supported(&mut self, method: ProtocolAuthMethod) {
        if !self.supported_methods.contains(&method) {
            self.supported_methods.push(method);
        }
    }

    /// Add an allowed method
    pub fn add_allowed(&mut self, method: ProtocolAuthMethod) {
        if !self.allowed_methods.contains(&method) {
            self.allowed_methods.push(method);
        }
    }

    /// Get usable methods (intersection of supported and allowed)
    pub fn usable_methods(&self) -> Vec<ProtocolAuthMethod> {
        self.supported_methods
            .iter()
            .filter(|m| self.allowed_methods.contains(m))
            .cloned()
            .collect()
    }

    /// Check if a method is supported
    pub fn is_supported(&self, method: ProtocolAuthMethod) -> bool {
        self.supported_methods.contains(&method)
    }

    /// Check if a method is allowed
    pub fn is_allowed(&self, method: ProtocolAuthMethod) -> bool {
        self.allowed_methods.contains(&method)
    }
}

impl Default for AuthMethodManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Authentication methods supported by the SSH client
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// Password-based authentication
    Password {
        username: String,
        password: String,
    },
    /// Public key authentication
    PublicKey {
        username: String,
        private_key: Vec<u8>,
    },
}

impl AuthMethod {
    /// Create a password authentication method
    pub fn password(username: String, password: String) -> Self {
        Self::Password { username, password }
    }

    /// Create a public key authentication method
    pub fn public_key(username: String, private_key: Vec<u8>) -> Self {
        Self::PublicKey {
            username,
            private_key,
        }
    }
}