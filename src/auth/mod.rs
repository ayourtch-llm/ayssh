//! Authentication module - SSH user authentication (RFC 4252)
//!
//! This module implements SSH authentication protocols including:
//! - Password authentication
//! - Public key authentication
//! - Authentication state machine

pub mod methods;
pub mod password;
pub mod publickey;
pub mod state;

pub use methods::{AuthMethodManager, AuthMethod};
pub use password::PasswordAuthenticator;
pub use publickey::PublicKeyAuthenticator;
pub use state::AuthenticationStateMachine;

use crate::error::SshError;
use crate::protocol::message::Message;
use crate::protocol::messages::MessageType;
use crate::transport::Transport;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Represents an authentication attempt
#[derive(Debug, Clone)]
pub struct AuthenticationRequest {
    /// Username to authenticate as
    pub username: String,
    /// Service being requested (usually "ssh-connection")
    pub service: String,
    /// Authentication method
    pub method: String,
}

/// Authentication result
#[derive(Debug, Clone, PartialEq)]
pub enum AuthenticationResult {
    /// Authentication successful
    Success,
    /// Authentication failed
    Failure {
        /// Partially successful methods
        partial_success: Vec<String>,
        /// Available authentication methods
        available_methods: Vec<String>,
    },
}

/// SSH authentication handler
pub struct Authenticator {
    /// Transport layer for sending messages
    transport: Transport,
    /// Authentication state machine
    state: AuthenticationStateMachine,
    /// User credentials (for password auth)
    username: String,
    /// Password (for password auth)
    password: Option<String>,
    /// Private key (for public key auth)
    private_key: Option<Vec<u8>>,
    /// List of available authentication methods
    available_methods: HashSet<String>,
}

impl Authenticator {
    /// Creates a new authenticator
    pub fn new(transport: Transport, username: String) -> Self {
        Self {
            transport,
            state: AuthenticationStateMachine::new(),
            username,
            password: None,
            private_key: None,
            available_methods: HashSet::new(),
        }
    }

    /// Sets the password for authentication
    pub fn with_password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }

    /// Sets the private key for authentication
    pub fn with_private_key(mut self, key: Vec<u8>) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Sets available authentication methods
    pub fn with_available_methods(mut self, methods: Vec<String>) -> Self {
        self.available_methods = methods.into_iter().collect();
        self
    }

    /// Starts authentication process
    pub async fn authenticate(&mut self) -> Result<AuthenticationResult, SshError> {
        self.state.transition_to_authentication()?;
        
        // Try available methods
        for method in self.available_methods.iter() {
            match method.as_str() {
                SSH_AUTH_METHOD_PASSWORD => {
                    if let Some(ref pwd) = self.password.clone() {
                        return self.try_password_auth(&pwd).await;
                    }
                }
                SSH_AUTH_METHOD_PUBLICKEY => {
                    if let Some(ref key) = self.private_key.clone() {
                        return self.try_publickey_auth(&key).await;
                    }
                }
                _ => {}
            }
        }

        Ok(AuthenticationResult::Failure {
            partial_success: Vec::new(),
            available_methods: self.available_methods.iter().cloned().collect(),
        })
    }

    /// Tries password authentication
    async fn try_password_auth(&mut self, password: &str) -> Result<AuthenticationResult, SshError> {
        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"password");
        msg.write_bool(false); // first attempt
        msg.write_string(password.as_bytes());

        self.transport.send_message(&msg.as_bytes()).await?;

        let response = self.transport.recv_message().await?;
        let msg = Message::from(response);
        self.process_auth_response(msg)
    }

    /// Tries public key authentication
    async fn try_publickey_auth(&mut self, private_key: &[u8]) -> Result<AuthenticationResult, SshError> {
        // Compute public key hash (simplified)
        let mut hasher = Sha256::new();
        hasher.update(private_key);
        let public_key_hash = hasher.finalize();

        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(false); // no signature yet
        msg.write_string(b"ssh-rsa"); // algorithm
        msg.write_bytes(&public_key_hash);

        self.transport.send_message(&msg.as_bytes()).await?;

        let response = self.transport.recv_message().await?;
        let msg = Message::from(response);

        match msg.msg_type() {
            Some(MessageType::UserauthSuccess) => Ok(AuthenticationResult::Success),
            Some(MessageType::UserauthFailure) => self.process_auth_response(msg),
            Some(MessageType::UserauthRequest) => {
                // Server wants signature
                self.send_signature(private_key).await
            }
            _ => Ok(AuthenticationResult::Failure {
                partial_success: Vec::new(),
                available_methods: Vec::new(),
            }),
        }
    }

    /// Sends signature for public key authentication
    async fn send_signature(&mut self, private_key: &[u8]) -> Result<AuthenticationResult, SshError> {
        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(true); // has signature
        msg.write_string(b"ssh-rsa"); // algorithm
        msg.write_bytes(&[]); // public key blob
        msg.write_string(b""); // signature (placeholder)

        self.transport.send_message(&msg.as_bytes()).await?;

        let response = self.transport.recv_message().await?;
        let msg = Message::from(response);
        self.process_auth_response(msg)
    }

    /// Processes authentication response
    fn process_auth_response(&self, response: Message) -> Result<AuthenticationResult, SshError> {
        match response.msg_type() {
            Some(MessageType::UserauthSuccess) => Ok(AuthenticationResult::Success),
            Some(MessageType::UserauthFailure) => {
                let (partial_success, available_methods) = response.parse_userauth_failure()
                    .unwrap_or((Vec::new(), Vec::new()));
                
                Ok(AuthenticationResult::Failure {
                    partial_success,
                    available_methods,
                })
            }
            _ => Err(SshError::ProtocolError(format!(
                "Unexpected authentication response: {:?}",
                response.msg_type()
            ))),
        }
    }
}