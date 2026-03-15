//! Authentication methods for SSH

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
        private_key: String,
    },
}

impl AuthMethod {
    /// Create a password authentication method
    pub fn password(username: String, password: String) -> Self {
        Self::Password { username, password }
    }

    /// Create a public key authentication method
    pub fn public_key(username: String, private_key: String) -> Self {
        Self::PublicKey {
            username,
            private_key,
        }
    }
}
