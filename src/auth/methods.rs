//! Authentication Methods
//!
//! Manages available and attempted authentication methods.

use crate::protocol;

/// Authentication method manager
#[derive(Debug, Default)]
pub struct AuthMethodManager {
    /// Methods we can try
    pub supported_methods: Vec<protocol::AuthMethod>,
    /// Methods server allows
    pub allowed_methods: Vec<protocol::AuthMethod>,
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
    pub fn add_supported(&mut self, method: protocol::AuthMethod) {
        if !self.supported_methods.contains(&method) {
            self.supported_methods.push(method);
        }
    }

    /// Add an allowed method
    pub fn add_allowed(&mut self, method: protocol::AuthMethod) {
        if !self.allowed_methods.contains(&method) {
            self.allowed_methods.push(method);
        }
    }

    /// Get methods that are both supported and allowed
    pub fn usable_methods(&self) -> Vec<protocol::AuthMethod> {
        self.supported_methods
            .iter()
            .filter(|m| self.allowed_methods.contains(m))
            .copied()
            .collect()
    }

    /// Check if a method is supported
    pub fn is_supported(&self, method: protocol::AuthMethod) -> bool {
        self.supported_methods.contains(&method)
    }

    /// Check if a method is allowed
    pub fn is_allowed(&self, method: protocol::AuthMethod) -> bool {
        self.allowed_methods.contains(&method)
    }
}
