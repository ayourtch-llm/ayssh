//! SSH Client implementation

use crate::auth::{Authenticator, AuthMethodManager, AuthMethod as AuthMethodConfig};
use crate::protocol::AuthMethod as ProtocolAuthMethod;
use crate::session::Session;
use crate::error::SshError;
use crate::transport::Transport;

/// SSH Client for connecting to remote servers
pub struct SshClient {
    host: String,
    port: u16,
    /// Username for authentication
    username: Option<String>,
    /// Password for authentication
    password: Option<String>,
    /// Private key for authentication
    private_key: Option<Vec<u8>>,
    /// Allowed authentication methods
    allowed_methods: Vec<ProtocolAuthMethod>,
}

impl SshClient {
    /// Create a new SSH client
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            username: None,
            password: None,
            private_key: None,
            allowed_methods: vec![
                ProtocolAuthMethod::Password,
                ProtocolAuthMethod::PublicKey,
                ProtocolAuthMethod::None,
            ],
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

    /// Set the username for authentication
    pub fn with_username(mut self, username: String) -> Self {
        self.username = Some(username);
        self
    }

    /// Set the password for authentication
    pub fn with_password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }

    /// Set the private key for authentication
    pub fn with_private_key(mut self, private_key: Vec<u8>) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Set allowed authentication methods
    pub fn with_allowed_methods(mut self, methods: Vec<ProtocolAuthMethod>) -> Self {
        self.allowed_methods = methods;
        self
    }

    /// Add a password authentication method
    pub fn with_password_auth(mut self, username: String, password: String) -> Self {
        self.username = Some(username);
        self.password = Some(password);
        self
    }

    /// Add a public key authentication method
    pub fn with_publickey_auth(mut self, username: String, private_key: Vec<u8>) -> Self {
        self.username = Some(username);
        self.private_key = Some(private_key);
        self
    }

    /// Connect to the server without authentication
    ///
    /// This establishes a TCP connection and performs the SSH handshake
    /// but does not authenticate. Returns a Transport for further operations.
    pub async fn connect(&self) -> Result<Transport, SshError> {
        // In a real implementation, this would:
        // 1. Establish TCP connection
        // 2. Perform version exchange
        // 3. Perform key exchange
        // 4. Return Transport
        
        // For now, return an error indicating this needs implementation
        Err(SshError::SessionError(
            "Connection requires TCP implementation".into()
        ))
    }

    /// Connect with authentication
    ///
    /// This performs the complete SSH connection flow:
    /// 1. Establish TCP connection
    /// 2. Perform version exchange
    /// 3. Perform key exchange
    /// 4. Authenticate with provided method
    /// 5. Open session channel
    /// 6. Return Session
    pub async fn connect_with_auth(&self, _auth_method: AuthMethodConfig) -> Result<Session, SshError> {
        // Validate credentials
        let username = match &self.username {
            Some(u) => u.clone(),
            None => return Err(SshError::AuthenticationFailed("No username provided".into())),
        };

        // In a real implementation, this would:
        // 1. Connect to TCP socket
        // 2. Perform version exchange
        // 3. Perform key exchange
        // 4. Send SERVICE_REQUEST for "ssh-connection"
        // 5. Authenticate using the Authenticator
        // 6. Open session channel
        // 7. Create Session
        
        // For now, return an error indicating this needs implementation
        Err(SshError::SessionError(
            "Full connection flow requires TCP and handshake implementation".into()
        ))
    }

    /// Connect with password authentication
    pub async fn connect_with_password(&self, username: String, password: String) -> Result<Session, SshError> {
        self.connect_with_auth(AuthMethodConfig::Password { username, password }).await
    }

    /// Connect with public key authentication
    pub async fn connect_with_publickey(&self, username: String, private_key: Vec<u8>) -> Result<Session, SshError> {
        self.connect_with_auth(AuthMethodConfig::PublicKey { username, private_key }).await
    }

    /// Create an authenticator for manual authentication flow
    pub fn create_authenticator(&self) -> Result<Authenticator, SshError> {
        let username = match &self.username {
            Some(u) => u.clone(),
            None => return Err(SshError::AuthenticationFailed("No username provided".into())),
        };

        let mut auth_manager = AuthMethodManager::new();
        for method in &self.allowed_methods {
            auth_manager.add_allowed(*method);
        }

        // Note: We can't create a real Authenticator without a Transport
        // This is a placeholder for when Transport is available
        Err(SshError::ProtocolError(
            "Authenticator requires established Transport".into()
        ))
    }

    /// Get the username
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    /// Get the password
    pub fn password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    /// Check if password authentication is configured
    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Check if public key authentication is configured
    pub fn has_publickey(&self) -> bool {
        self.private_key.is_some()
    }
}

impl Default for SshClient {
    fn default() -> Self {
        Self::new("localhost".to_string(), 22)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = SshClient::new("example.com".to_string(), 22);
        assert_eq!(client.host(), "example.com");
        assert_eq!(client.port(), 22);
    }

    #[test]
    fn test_client_with_username() {
        let client = SshClient::new("example.com".to_string(), 22)
            .with_username("alice".to_string());
        assert_eq!(client.username(), Some("alice"));
    }

    #[test]
    fn test_client_with_password() {
        let client = SshClient::new("example.com".to_string(), 22)
            .with_password("secret".to_string());
        assert!(client.has_password());
        assert_eq!(client.password(), Some("secret"));
    }

    #[test]
    fn test_client_with_publickey() {
        let key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake_key\n-----END OPENSSH PRIVATE KEY-----".to_vec();
        let client = SshClient::new("example.com".to_string(), 22)
            .with_private_key(key.clone());
        assert!(client.has_publickey());
    }

    #[test]
    fn test_client_with_password_auth() {
        let client = SshClient::new("example.com".to_string(), 22)
            .with_password_auth("alice".to_string(), "secret".to_string());
        assert_eq!(client.username(), Some("alice"));
        assert!(client.has_password());
    }

    #[test]
    fn test_client_with_publickey_auth() {
        let key = b"fake_key".to_vec();
        let client = SshClient::new("example.com".to_string(), 22)
            .with_publickey_auth("alice".to_string(), key.clone());
        assert_eq!(client.username(), Some("alice"));
        assert!(client.has_publickey());
    }

    #[test]
    fn test_client_allowed_methods() {
        let client = SshClient::new("example.com".to_string(), 22);
        // Default client should have password and publickey methods
        assert!(client.allowed_methods.contains(&ProtocolAuthMethod::Password));
        assert!(client.allowed_methods.contains(&ProtocolAuthMethod::PublicKey));
    }

    #[test]
    fn test_client_default() {
        let client = SshClient::default();
        assert_eq!(client.host(), "localhost");
        assert_eq!(client.port(), 22);
    }

    #[test]
    fn test_client_connect_fails_without_implementation() {
        let client = SshClient::new("example.com".to_string(), 22);
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { client.connect().await });
        assert!(result.is_err());
    }

    #[test]
    fn test_client_connect_with_auth_fails_without_implementation() {
        let client = SshClient::new("example.com".to_string(), 22)
            .with_password_auth("alice".to_string(), "secret".to_string());
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { client.connect_with_auth(AuthMethodConfig::Password { username: "alice".to_string(), password: "secret".to_string() }).await });
        assert!(result.is_err());
    }

    #[test]
    fn test_client_create_authenticator_fails_without_transport() {
        let client = SshClient::new("example.com".to_string(), 22)
            .with_username("alice".to_string());
        let result = client.create_authenticator();
        assert!(result.is_err());
    }
}