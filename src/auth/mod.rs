//! Authentication module - SSH user authentication (RFC 4252)
//!
//! This module implements SSH authentication protocols including:
//! - Password authentication
//! - Public key authentication
//! - Authentication state machine

pub mod key;
pub mod keyboard;
pub mod methods;
pub mod password;
pub mod publickey;
pub mod signature;
pub mod state;

pub use key::PrivateKey;
pub use keyboard::KeyboardInteractiveAuthenticator;
pub use methods::{AuthMethod, AuthMethodManager};
pub use password::PasswordAuthenticator;
pub use publickey::PublicKeyAuthenticator;
pub use signature::{
    create_signature_data, Ed25519SignatureEncoder, EcdsaSignatureEncoder,
    RsaSignatureEncoder, SshSignature, SSH_SIG_ALGORITHM_ED25519,
    SSH_SIG_ALGORITHM_ECDSA_NISTP256, SSH_SIG_ALGORITHM_ECDSA_NISTP384,
    SSH_SIG_ALGORITHM_ECDSA_NISTP521, SSH_SIG_ALGORITHM_RSA,
};
pub use state::AuthState;

use crate::error::SshError;
use crate::protocol::message::Message;
use crate::protocol::messages::MessageType;
use crate::transport::Transport;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

// Constants for authentication methods
const SSH_AUTH_METHOD_PASSWORD: &str = "password";
const SSH_AUTH_METHOD_PUBLICKEY: &str = "publickey";
const SSH_AUTH_METHOD_KEYBOARD_INTERACTIVE: &str = "keyboard-interactive";

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
pub struct Authenticator<'a> {
    /// Transport layer for sending messages
    transport: &'a mut Transport,
    /// Authentication state machine
    state: AuthState,
    /// User credentials (for password auth)
    username: String,
    /// Password (for password auth)
    password: Option<String>,
    /// Private key (for public key auth)
    private_key: Option<Vec<u8>>,
    /// List of available authentication methods
    pub available_methods: HashSet<String>,
    /// Keyboard-interactive responses handler
    keyboard_interactive_handler: Option<Box<dyn Fn(&keyboard::Challenge) -> Result<Vec<String>, SshError> + Send>>,
}

impl<'a> Authenticator<'a> {
    /// Creates a new authenticator
    pub fn new(transport: &'a mut Transport, username: String) -> Self {
        Self {
            transport,
            state: AuthState::new(),
            username,
            password: None,
            private_key: None,
            available_methods: HashSet::new(),
            keyboard_interactive_handler: None,
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

    /// Sets the keyboard-interactive response handler
    pub fn with_keyboard_interactive_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&keyboard::Challenge) -> Result<Vec<String>, SshError> + Send + 'static,
    {
        self.keyboard_interactive_handler = Some(Box::new(handler));
        self
    }

    /// Starts authentication process
    pub async fn authenticate(&mut self) -> Result<AuthenticationResult, SshError> {
        self.state.start_auth()?;
        
        // Try available methods
        for method in self.available_methods.iter() {
            match method.as_str() {
                SSH_AUTH_METHOD_PASSWORD => {
                    if let Some(ref pwd) = self.password.clone() {
                        return self.try_password_auth(pwd).await;
                    }
                }
                SSH_AUTH_METHOD_PUBLICKEY => {
                    if let Some(ref key) = self.private_key.clone() {
                        return self.try_publickey_auth(key).await;
                    }
                }
                SSH_AUTH_METHOD_KEYBOARD_INTERACTIVE => {
                    if let Some(ref handler) = self.keyboard_interactive_handler {
                        let mut ki_auth = keyboard::KeyboardInteractiveAuthenticator::new(
                            self.transport,
                            self.username.clone(),
                        );
                        
                        match ki_auth.authenticate(handler).await {
                            Ok(()) => return Ok(AuthenticationResult::Success),
                            Err(e) => {
                                // Continue to next method on failure
                                eprintln!("Keyboard-interactive authentication failed: {:?}", e);
                                continue;
                            }
                        }
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
    async fn try_publickey_auth(&mut self, private_key_pem: &[u8]) -> Result<AuthenticationResult, SshError> {
        // Parse the OpenSSH private key to get the RSA key
        let private_key = self.parse_private_key(private_key_pem)?;
        
        // Extract public key blob from the RSA private key
        let public_key_blob = self.extract_public_key_blob(&private_key)?;

        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(false); // no signature yet (initial request)
        msg.write_string(b"ssh-rsa"); // algorithm
        msg.write_bytes(&public_key_blob);

        self.transport.send_message(&msg.as_bytes()).await?;

        let response = self.transport.recv_message().await?;
        let msg = Message::from(response);

        match msg.msg_type() {
            Some(MessageType::UserauthSuccess) => Ok(AuthenticationResult::Success),
            Some(MessageType::UserauthFailure) => self.process_auth_response(msg),
            Some(MessageType::UserauthRequest) => {
                // Server wants signature - use real signature encoding
                self.send_signature(private_key).await
            }
            _ => Ok(AuthenticationResult::Failure {
                partial_success: Vec::new(),
                available_methods: Vec::new(),
            }),
        }
    }

    /// Parses OpenSSH private key to extract RSA private key
    fn parse_private_key(&self, private_key_pem: &[u8]) -> Result<rsa::RsaPrivateKey, SshError> {
        use crate::auth::key::PrivateKey;
        
        // Convert private key bytes to string for parsing
        let pem_content = String::from_utf8_lossy(private_key_pem);
        
        // Try to parse as OpenSSH format
        match PrivateKey::parse_pem(&pem_content.to_string()) {
            Ok(key) => {
                // Extract RSA private key from the parsed key
                if let PrivateKey::Rsa(rsa_key) = key {
                    Ok(rsa_key)
                } else {
                    Err(SshError::CryptoError(
                        "Parsed key is not an RSA key".to_string()
                    ))
                }
            }
            Err(e) => {
                eprintln!("Failed to parse OpenSSH private key: {:?}", e);
                Err(SshError::CryptoError(
                    format!("Failed to parse private key: {:?}", e)
                ))
            }
        }
    }

    /// Extracts public key blob from RSA private key
    fn extract_public_key_blob(&self, private_key: &rsa::RsaPrivateKey) -> Result<Vec<u8>, SshError> {
        use rsa::traits::PublicKeyParts;
        use bytes::{BufMut, BytesMut};
        
        let mut buf = BytesMut::new();
        
        // Public key algorithm string
        buf.put_u32(b"ssh-rsa".len() as u32);
        buf.put_slice(b"ssh-rsa");
        
        // Public exponent e
        let e = private_key.e().to_bytes_be();
        buf.put_u32(e.len() as u32);
        buf.put_slice(&e);
        
        // Modulus n
        let n = private_key.n().to_bytes_be();
        buf.put_u32(n.len() as u32);
        buf.put_slice(&n);
        
        Ok(buf.to_vec())
    }

    /// Sends signature for public key authentication using real RSA signing
    async fn send_signature(&mut self, private_key: rsa::RsaPrivateKey) -> Result<AuthenticationResult, SshError> {
        // Note: We need to reconstruct the message data to create the signature
        // For now, we'll use a simplified approach - in production, we'd need to
        // track the exact message that was sent to construct the signature data
        
        // For testing purposes, create dummy signature data
        // In production, this would be constructed from the actual auth request
        let session_id = vec![0x01; 20]; // Placeholder - should come from key exchange
        let signature_data = create_signature_data(
            &session_id,
            &self.username,
            "ssh-connection",
            "publickey",
            true,
            "ssh-rsa",
            &[], // public key blob would be needed here
        );
        
        eprintln!("Creating RSA signature with {} bytes of data", signature_data.len());
        
        // Encode the signature using RSA signature encoder
        let signature = RsaSignatureEncoder::encode(&private_key, &signature_data)?;
        
        eprintln!("✓ Signature encoded successfully ({} bytes)", signature.data.len());
        
        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(true); // has signature
        msg.write_string(b"ssh-rsa"); // algorithm
        msg.write_bytes(&[]); // public key blob (simplified)
        msg.write_bytes(&signature.encode()); // SSH-encoded signature

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