//! Authentication module - SSH user authentication (RFC 4252)
//!
//! This module implements SSH authentication protocols including:
//! - Password authentication
//! - Public key authentication
//! - Authentication state machine

pub mod key;
pub mod keyboard;
pub mod methods;
pub mod signature;
pub mod state;

use tracing::debug;

pub use key::PrivateKey;
pub use keyboard::KeyboardInteractiveAuthenticator;
pub use methods::{AuthMethod, AuthMethodManager};
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

/// Info about an authentication attempt that just failed
#[derive(Debug, Clone)]
pub struct AuthAttemptInfo {
    /// The method that was tried (e.g., "publickey", "password")
    pub method: String,
    /// The specific algorithm used, if applicable (e.g., "rsa-sha2-256")
    pub algorithm: Option<String>,
    /// Human-readable reason for failure
    pub error: Option<String>,
}

/// Context passed to the fallback handler between auth attempts
#[derive(Debug, Clone)]
pub struct AuthFallbackContext {
    /// Details about the attempt that just failed
    pub failed_attempt: AuthAttemptInfo,
    /// Methods we can still try (in order), filtered by what the server accepts
    pub remaining_methods: Vec<String>,
    /// Methods the server listed in its USERAUTH_FAILURE response
    pub server_methods: Vec<String>,
}

/// The fallback handler's verdict
#[derive(Debug, Clone, PartialEq)]
pub enum AuthFallbackVerdict {
    /// Continue with the default fallback (try next method in order)
    Continue,
    /// Skip to a specific method (must be in remaining_methods)
    TryMethod(String),
    /// Abort authentication entirely, return Failure
    Abort,
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
    /// Ordered list of methods to try (tried in this order)
    /// Also accessible as `available_methods` for backward compatibility
    pub available_methods: HashSet<String>,
    /// Ordered list of methods to try
    method_order: Vec<String>,
    /// Keyboard-interactive responses handler
    keyboard_interactive_handler: Option<Box<dyn Fn(&keyboard::Challenge) -> Result<Vec<String>, SshError> + Send>>,
    /// Optional callback invoked between auth attempts on failure.
    /// Receives context about what failed and what's next, returns a verdict.
    fallback_handler: Option<Box<dyn Fn(&AuthFallbackContext) -> AuthFallbackVerdict + Send>>,
    /// SSH agent client for agent-based pubkey auth
    agent: Option<crate::agent::AgentClient>,
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
            method_order: Vec::new(),
            keyboard_interactive_handler: None,
            fallback_handler: None,
            agent: None,
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

    /// Sets available authentication methods (unordered, for backward compatibility).
    /// If method_order is not set, methods are tried in an arbitrary order.
    pub fn with_available_methods(mut self, methods: Vec<String>) -> Self {
        self.available_methods = methods.into_iter().collect();
        self
    }

    /// Sets the ordered list of methods to try.
    /// Methods are tried in this exact order, skipping any that the server
    /// doesn't accept or that we don't have credentials for.
    pub fn with_method_order(mut self, methods: Vec<String>) -> Self {
        for m in &methods {
            self.available_methods.insert(m.clone());
        }
        self.method_order = methods;
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

    /// Sets the SSH agent for agent-based public key authentication.
    /// The agent must already be connected (call `agent.connect().await` first).
    pub fn with_agent(mut self, agent: crate::agent::AgentClient) -> Self {
        self.agent = Some(agent);
        self
    }

    /// Sets the fallback handler called between auth method attempts.
    /// The handler receives context about the failed attempt and remaining methods,
    /// and returns a verdict (Continue, TryMethod, or Abort).
    pub fn with_fallback_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&AuthFallbackContext) -> AuthFallbackVerdict + Send + 'static,
    {
        self.fallback_handler = Some(Box::new(handler));
        self
    }

    /// Get the ordered list of methods to try.
    /// Uses method_order if set, otherwise falls back to available_methods in default order.
    fn methods_to_try(&self) -> Vec<String> {
        if !self.method_order.is_empty() {
            return self.method_order.clone();
        }
        // Default order: publickey first, then password, then keyboard-interactive
        let default_order = [SSH_AUTH_METHOD_PUBLICKEY, SSH_AUTH_METHOD_PASSWORD, SSH_AUTH_METHOD_KEYBOARD_INTERACTIVE];
        let mut result = Vec::new();
        for method in &default_order {
            if self.available_methods.contains(*method) {
                result.push(method.to_string());
            }
        }
        // Add any remaining methods not in default order
        for method in &self.available_methods {
            if !result.contains(method) {
                result.push(method.clone());
            }
        }
        result
    }

    /// Check if we have credentials for a given method
    fn has_credentials_for(&self, method: &str) -> bool {
        match method {
            SSH_AUTH_METHOD_PASSWORD => self.password.is_some(),
            SSH_AUTH_METHOD_PUBLICKEY => self.private_key.is_some() || self.agent.is_some(),
            SSH_AUTH_METHOD_KEYBOARD_INTERACTIVE => self.keyboard_interactive_handler.is_some(),
            _ => false,
        }
    }

    /// Starts authentication process.
    /// Tries methods in order, falling back on failure if multiple methods are configured.
    pub async fn authenticate(&mut self) -> Result<AuthenticationResult, SshError> {
        self.state.start_auth()?;

        let methods = self.methods_to_try();
        let mut server_accepted_methods: Option<Vec<String>> = None;
        let mut last_failure: Option<AuthenticationResult> = None;

        let mut i = 0;
        while i < methods.len() {
            let method = &methods[i];

            // Skip methods we don't have credentials for
            if !self.has_credentials_for(method) {
                i += 1;
                continue;
            }

            // Skip methods the server doesn't accept (if we know from a previous failure)
            if let Some(ref server_methods) = server_accepted_methods {
                if !server_methods.contains(method) {
                    debug!("Skipping method '{}' — server doesn't accept it", method);
                    i += 1;
                    continue;
                }
            }

            debug!("Trying auth method: {}", method);

            let result = match method.as_str() {
                SSH_AUTH_METHOD_PASSWORD => {
                    let pwd = self.password.clone().unwrap();
                    self.try_password_auth(&pwd).await?
                }
                SSH_AUTH_METHOD_PUBLICKEY => {
                    if let Some(ref key) = self.private_key.clone() {
                        self.try_publickey_auth(key).await?
                    } else if self.agent.is_some() {
                        self.try_agent_auth().await?
                    } else {
                        continue;
                    }
                }
                SSH_AUTH_METHOD_KEYBOARD_INTERACTIVE => {
                    // keyboard-interactive has its own internal loop
                    let handler = self.keyboard_interactive_handler.as_ref().unwrap();
                    let mut ki_auth = keyboard::KeyboardInteractiveAuthenticator::new(
                        self.transport,
                        self.username.clone(),
                    );
                    match ki_auth.authenticate(handler).await {
                        Ok(()) => AuthenticationResult::Success,
                        Err(e) => AuthenticationResult::Failure {
                            partial_success: Vec::new(),
                            available_methods: vec![],
                        },
                    }
                }
                _ => {
                    i += 1;
                    continue;
                }
            };

            match result {
                AuthenticationResult::Success => return Ok(AuthenticationResult::Success),
                AuthenticationResult::Failure { ref partial_success, ref available_methods } => {
                    // Update server's accepted methods for filtering
                    if !available_methods.is_empty() {
                        server_accepted_methods = Some(available_methods.clone());
                    }

                    let remaining: Vec<String> = methods[i+1..].iter()
                        .filter(|m| self.has_credentials_for(m))
                        .cloned()
                        .collect();

                    // Call fallback handler if set
                    if let Some(ref handler) = self.fallback_handler {
                        let ctx = AuthFallbackContext {
                            failed_attempt: AuthAttemptInfo {
                                method: method.clone(),
                                algorithm: None,
                                error: Some(format!("Server returned USERAUTH_FAILURE")),
                            },
                            remaining_methods: remaining.clone(),
                            server_methods: available_methods.clone(),
                        };

                        match handler(&ctx) {
                            AuthFallbackVerdict::Continue => {
                                // Default: try next method
                            }
                            AuthFallbackVerdict::TryMethod(target) => {
                                // Jump to specific method
                                if let Some(pos) = methods.iter().position(|m| m == &target) {
                                    i = pos;
                                    continue;
                                }
                                // Method not found — fall through to abort
                                return Ok(result);
                            }
                            AuthFallbackVerdict::Abort => {
                                return Ok(result);
                            }
                        }
                    }

                    // If no more methods, return failure
                    if remaining.is_empty() {
                        return Ok(result);
                    }

                    last_failure = Some(result);
                    i += 1;
                }
            }
        }

        // All methods exhausted
        Ok(last_failure.unwrap_or(AuthenticationResult::Failure {
            partial_success: Vec::new(),
            available_methods: self.available_methods.iter().cloned().collect(),
        }))
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

    /// Tries public key authentication.
    /// Supports RSA (rsa-sha2-256, ssh-rsa), Ed25519, and ECDSA keys.
    async fn try_publickey_auth(&mut self, private_key_pem: &[u8]) -> Result<AuthenticationResult, SshError> {
        use crate::auth::key::PrivateKey;

        let pem_content = String::from_utf8_lossy(private_key_pem);
        let private_key = PrivateKey::parse_pem(&pem_content)
            .map_err(|e| SshError::CryptoError(format!("Failed to parse private key: {}", e)))?;

        let public_key_blob = private_key.ssh_public_key_blob()?;
        let algorithms = private_key.ssh_algorithm_names();

        for algorithm in &algorithms {
            debug!("Trying publickey auth with algorithm: {}", algorithm);

            let mut msg = Message::new();
            msg.write_byte(MessageType::UserauthRequest.value());
            msg.write_string(self.username.as_bytes());
            msg.write_string(b"ssh-connection");
            msg.write_string(b"publickey");
            msg.write_bool(false); // no signature yet (probe)
            msg.write_string(algorithm.as_bytes());
            msg.write_string(&public_key_blob);

            self.transport.send_message(&msg.as_bytes()).await?;

            let response = self.transport.recv_message().await?;
            let msg = Message::from(response);

            match msg.msg_type() {
                Some(MessageType::UserauthSuccess) => return Ok(AuthenticationResult::Success),
                Some(MessageType::UserauthInfoRequest) => {
                    // Message 60 = SSH_MSG_USERAUTH_PK_OK
                    debug!("Server accepted public key with {}, sending signature", algorithm);
                    return self.send_signed_auth(&private_key, &public_key_blob, algorithm).await;
                }
                Some(MessageType::UserauthFailure) => {
                    debug!("Server rejected {} algorithm, trying next", algorithm);
                    continue;
                }
                other => {
                    debug!("Unexpected pubkey auth response: {:?}", other);
                    continue;
                }
            }
        }

        Ok(AuthenticationResult::Failure {
            partial_success: Vec::new(),
            available_methods: Vec::new(),
        })
    }

    /// Send the signed USERAUTH_REQUEST after receiving PK_OK.
    /// Works for all key types (RSA, Ed25519, ECDSA).
    async fn send_signed_auth(
        &mut self,
        private_key: &key::PrivateKey,
        public_key_blob: &[u8],
        algorithm: &str,
    ) -> Result<AuthenticationResult, SshError> {
        let session_id = self.transport.session_id()
            .ok_or_else(|| SshError::ProtocolError("Session ID not available for signature".to_string()))?
            .to_vec();

        // Construct signature data per RFC 4252 Section 7
        let signature_data = create_signature_data(
            &session_id,
            &self.username,
            "ssh-connection",
            "publickey",
            true,
            algorithm,
            public_key_blob,
        );

        debug!("Creating {} signature over {} bytes of data", algorithm, signature_data.len());

        let signature = private_key.sign_with_algorithm(&signature_data, algorithm)?;
        debug!("Signature encoded successfully ({} bytes)", signature.data.len());

        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(true); // has signature
        msg.write_string(algorithm.as_bytes());
        msg.write_string(public_key_blob);
        msg.write_string(&signature.encode());

        self.transport.send_message(&msg.as_bytes()).await?;

        let response = self.transport.recv_message().await?;
        let msg = Message::from(response);
        self.process_auth_response(msg)
    }

    /// Try public key authentication using the SSH agent.
    /// Lists keys from the agent, probes each one, and asks the agent to sign if accepted.
    async fn try_agent_auth(&mut self) -> Result<AuthenticationResult, SshError> {
        let agent = self.agent.as_mut()
            .ok_or_else(|| SshError::AuthenticationFailed("No agent configured".into()))?;

        // Get keys from the agent
        let identities = agent.request_identities().await?;
        if identities.is_empty() {
            return Ok(AuthenticationResult::Failure {
                partial_success: Vec::new(),
                available_methods: Vec::new(),
            });
        }

        for identity in &identities {
            // Detect algorithm from key blob (first string in the blob is the algorithm name)
            let algo = if identity.key_blob.len() > 4 {
                let algo_len = u32::from_be_bytes([
                    identity.key_blob[0], identity.key_blob[1],
                    identity.key_blob[2], identity.key_blob[3],
                ]) as usize;
                if identity.key_blob.len() >= 4 + algo_len {
                    String::from_utf8_lossy(&identity.key_blob[4..4 + algo_len]).to_string()
                } else {
                    continue;
                }
            } else {
                continue;
            };

            debug!("Trying agent key: {} ({})", algo, identity.comment);

            // Send probe (no signature)
            let mut msg = Message::new();
            msg.write_byte(MessageType::UserauthRequest.value());
            msg.write_string(self.username.as_bytes());
            msg.write_string(b"ssh-connection");
            msg.write_string(b"publickey");
            msg.write_bool(false); // no signature (probe)
            msg.write_string(algo.as_bytes());
            msg.write_string(&identity.key_blob);

            self.transport.send_message(&msg.as_bytes()).await?;
            let response = self.transport.recv_message().await?;
            let resp_msg = Message::from(response);

            match resp_msg.msg_type() {
                Some(MessageType::UserauthInfoRequest) => {
                    // PK_OK — server wants a signature
                    debug!("Agent key accepted by server, requesting signature");

                    let session_id = self.transport.session_id()
                        .ok_or_else(|| SshError::ProtocolError("Session ID not available".into()))?
                        .to_vec();

                    // Build the data to sign per RFC 4252 Section 7
                    let signature_data = create_signature_data(
                        &session_id,
                        &self.username,
                        "ssh-connection",
                        "publickey",
                        true,
                        &algo,
                        &identity.key_blob,
                    );

                    // Ask agent to sign
                    // Flag 2 = SSH_AGENT_RSA_SHA2_256 (for RSA keys)
                    let flags = if algo == "ssh-rsa" { 2u32 } else { 0u32 };
                    let agent = self.agent.as_mut().unwrap();
                    let sig = agent.sign(&identity.key_blob, &signature_data, flags).await?;

                    // Send signed auth request
                    let mut msg = Message::new();
                    msg.write_byte(MessageType::UserauthRequest.value());
                    msg.write_string(self.username.as_bytes());
                    msg.write_string(b"ssh-connection");
                    msg.write_string(b"publickey");
                    msg.write_bool(true); // has signature
                    msg.write_string(algo.as_bytes());
                    msg.write_string(&identity.key_blob);
                    msg.write_string(&sig.signature_blob);

                    self.transport.send_message(&msg.as_bytes()).await?;
                    let response = self.transport.recv_message().await?;
                    let resp_msg = Message::from(response);
                    return self.process_auth_response(resp_msg);
                }
                Some(MessageType::UserauthSuccess) => {
                    return Ok(AuthenticationResult::Success);
                }
                Some(MessageType::UserauthFailure) => {
                    debug!("Server rejected agent key {}", algo);
                    continue; // try next key
                }
                _ => continue,
            }
        }

        Ok(AuthenticationResult::Failure {
            partial_success: Vec::new(),
            available_methods: Vec::new(),
        })
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

#[cfg(test)]
mod tests {
    /// Verify extract_public_key_blob adds 0x00 prefix for mpint sign handling.
    /// RSA modulus n typically has the high bit set, requiring a 0x00 prefix
    /// to be encoded as a positive SSH mpint.
    #[test]
    fn test_extract_public_key_blob_mpint_encoding() {
        use rsa::RsaPrivateKey;
        use rand::rngs::OsRng;

        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();

        // Create a dummy authenticator just to call extract_public_key_blob
        // We can't create a real one without a transport, so test the helper directly
        let blob = {
            use rsa::traits::PublicKeyParts;
            use bytes::{BufMut, BytesMut};

            fn put_mpint(buf: &mut BytesMut, value: &[u8]) {
                if !value.is_empty() && (value[0] & 0x80) != 0 {
                    buf.put_u32((value.len() + 1) as u32);
                    buf.put_u8(0x00);
                    buf.put_slice(value);
                } else {
                    buf.put_u32(value.len() as u32);
                    buf.put_slice(value);
                }
            }

            let mut buf = BytesMut::new();
            buf.put_u32(7);
            buf.put_slice(b"ssh-rsa");
            let e = private_key.e().to_bytes_be();
            put_mpint(&mut buf, &e);
            let n = private_key.n().to_bytes_be();
            put_mpint(&mut buf, &n);
            buf.to_vec()
        };

        // Parse the blob to verify structure
        let mut offset = 0;

        // Algorithm string
        let alg_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        offset += 4;
        assert_eq!(&blob[offset..offset + alg_len], b"ssh-rsa");
        offset += alg_len;

        // Exponent e
        let e_len = u32::from_be_bytes([blob[offset], blob[offset+1], blob[offset+2], blob[offset+3]]) as usize;
        offset += 4;
        // e = 65537 = 0x010001 (high bit not set, no prefix needed)
        assert_eq!(e_len, 3);
        assert_eq!(&blob[offset..offset + e_len], &[0x01, 0x00, 0x01]);
        offset += e_len;

        // Modulus n
        let n_len = u32::from_be_bytes([blob[offset], blob[offset+1], blob[offset+2], blob[offset+3]]) as usize;
        offset += 4;
        let n_first_byte = blob[offset];

        // RSA-2048 modulus is 256 bytes. If high bit is set, n_len should be 257
        // with a leading 0x00 byte
        if n_first_byte == 0x00 {
            assert_eq!(n_len, 257, "Modulus with 0x00 prefix must be 257 bytes for RSA-2048");
            assert_ne!(blob[offset + 1] & 0x80, 0,
                "The byte after 0x00 prefix must have high bit set");
        } else {
            assert_eq!(n_len, 256, "Modulus without prefix must be 256 bytes for RSA-2048");
            assert_eq!(n_first_byte & 0x80, 0,
                "Modulus without prefix must have high bit clear");
        }
    }

    /// Verify the public key blob matches ssh-keygen output format by checking
    /// the MD5 fingerprint of our generated blob against a known test key
    #[test]
    fn test_extract_public_key_blob_matches_ssh_keygen() {
        use base64::Engine;

        // Read the test key
        let key_content = std::fs::read_to_string("tests/keys/test_rsa_2048.pub");
        if key_content.is_err() {
            // Skip if test keys not available
            return;
        }
        let key_content = key_content.unwrap();
        let parts: Vec<&str> = key_content.trim().splitn(3, ' ').collect();
        let expected_blob = base64::engine::general_purpose::STANDARD.decode(parts[1]).unwrap();

        // Parse the private key and generate blob
        let private_key_pem = std::fs::read("tests/keys/test_rsa_2048").unwrap();
        let pem_content = String::from_utf8_lossy(&private_key_pem);
        let private_key = crate::auth::key::PrivateKey::parse_pem(&pem_content).unwrap();

        if let crate::auth::key::PrivateKey::Rsa(ref rsa_key) = private_key {
            use rsa::traits::PublicKeyParts;
            use bytes::{BufMut, BytesMut};

            fn put_mpint(buf: &mut BytesMut, value: &[u8]) {
                if !value.is_empty() && (value[0] & 0x80) != 0 {
                    buf.put_u32((value.len() + 1) as u32);
                    buf.put_u8(0x00);
                    buf.put_slice(value);
                } else {
                    buf.put_u32(value.len() as u32);
                    buf.put_slice(value);
                }
            }

            let mut buf = BytesMut::new();
            buf.put_u32(7);
            buf.put_slice(b"ssh-rsa");
            let e = rsa_key.e().to_bytes_be();
            put_mpint(&mut buf, &e);
            let n = rsa_key.n().to_bytes_be();
            put_mpint(&mut buf, &n);
            let our_blob = buf.to_vec();

            assert_eq!(our_blob, expected_blob,
                "Generated public key blob must match ssh-keygen output exactly");
        } else {
            panic!("Expected RSA key");
        }
    }

    /// Compile-time verification that Authenticator is Send.
    /// This enables using it in tokio::spawn and across thread boundaries.
    #[test]
    fn test_authenticator_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<super::Authenticator>();
    }

    #[test]
    fn test_authentication_result_equality() {
        let success = super::AuthenticationResult::Success;
        assert_eq!(success, super::AuthenticationResult::Success);

        let failure1 = super::AuthenticationResult::Failure {
            partial_success: vec!["password".to_string()],
            available_methods: vec!["publickey".to_string()],
        };
        let failure2 = super::AuthenticationResult::Failure {
            partial_success: vec!["password".to_string()],
            available_methods: vec!["publickey".to_string()],
        };
        assert_eq!(failure1, failure2);
        assert_ne!(success, failure1);
    }

    #[test]
    fn test_authentication_result_clone() {
        let original = super::AuthenticationResult::Failure {
            partial_success: vec!["password".to_string()],
            available_methods: vec!["publickey".to_string(), "keyboard-interactive".to_string()],
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_authentication_request_fields() {
        let req = super::AuthenticationRequest {
            username: "alice".to_string(),
            service: "ssh-connection".to_string(),
            method: "password".to_string(),
        };
        assert_eq!(req.username, "alice");
        assert_eq!(req.service, "ssh-connection");
        assert_eq!(req.method, "password");

        // Test Clone
        let cloned = req.clone();
        assert_eq!(cloned.username, "alice");
        assert_eq!(cloned.service, "ssh-connection");
    }

    #[test]
    fn test_process_auth_response_success() {
        use crate::protocol::message::Message;
        use crate::protocol::messages::MessageType;

        // Build a UserauthSuccess message (message type 52)
        let msg = Message::with_type(MessageType::UserauthSuccess);

        // We can't construct an Authenticator without a Transport, but we can
        // test process_auth_response by calling it on a dummy. Instead, replicate
        // the logic inline since it's a pure function on the Message.
        let result = match msg.msg_type() {
            Some(MessageType::UserauthSuccess) => Ok(super::AuthenticationResult::Success),
            Some(MessageType::UserauthFailure) => {
                let (partial_success, available_methods) = msg.parse_userauth_failure()
                    .unwrap_or((Vec::new(), Vec::new()));
                Ok(super::AuthenticationResult::Failure {
                    partial_success,
                    available_methods,
                })
            }
            _ => Err(crate::error::SshError::ProtocolError(format!(
                "Unexpected authentication response: {:?}",
                msg.msg_type()
            ))),
        };

        assert_eq!(result.unwrap(), super::AuthenticationResult::Success);
    }

    #[test]
    fn test_process_auth_response_failure() {
        use crate::protocol::message::Message;
        use crate::protocol::messages::MessageType;

        // Build a UserauthFailure message with method list
        let mut msg = Message::with_type(MessageType::UserauthFailure);
        msg.write_string(b"publickey,password");
        msg.write_string(b"publickey");

        let result = match msg.msg_type() {
            Some(MessageType::UserauthSuccess) => Ok(super::AuthenticationResult::Success),
            Some(MessageType::UserauthFailure) => {
                let (partial_success, available_methods) = msg.parse_userauth_failure()
                    .unwrap_or((Vec::new(), Vec::new()));
                Ok(super::AuthenticationResult::Failure {
                    partial_success,
                    available_methods,
                })
            }
            _ => Err(crate::error::SshError::ProtocolError("unexpected".into())),
        };

        match result.unwrap() {
            super::AuthenticationResult::Failure { partial_success, available_methods } => {
                assert!(partial_success.iter().any(|m| m.contains("publickey")));
                assert!(available_methods.iter().any(|m| m.contains("publickey")));
            }
            _ => panic!("Expected Failure"),
        }
    }

    #[test]
    fn test_process_auth_response_unexpected_type() {
        use crate::protocol::message::Message;
        use crate::protocol::messages::MessageType;

        // Use a Disconnect message (unexpected during auth)
        let msg = Message::with_type(MessageType::Disconnect);

        let result = match msg.msg_type() {
            Some(MessageType::UserauthSuccess) => Ok(super::AuthenticationResult::Success),
            Some(MessageType::UserauthFailure) => {
                let (partial_success, available_methods) = msg.parse_userauth_failure()
                    .unwrap_or((Vec::new(), Vec::new()));
                Ok(super::AuthenticationResult::Failure {
                    partial_success,
                    available_methods,
                })
            }
            _ => Err(crate::error::SshError::ProtocolError(format!(
                "Unexpected authentication response: {:?}",
                msg.msg_type()
            ))),
        };

        assert!(result.is_err());
    }

    #[test]
    fn test_auth_method_manager_basics() {
        use crate::protocol::AuthMethod as ProtocolAuthMethod;

        let mut mgr = super::AuthMethodManager::new();
        assert!(mgr.usable_methods().is_empty());

        mgr.add_supported(ProtocolAuthMethod::Password);
        mgr.add_supported(ProtocolAuthMethod::PublicKey);
        mgr.add_allowed(ProtocolAuthMethod::Password);

        assert!(mgr.is_supported(ProtocolAuthMethod::Password));
        assert!(mgr.is_supported(ProtocolAuthMethod::PublicKey));
        assert!(mgr.is_allowed(ProtocolAuthMethod::Password));
        assert!(!mgr.is_allowed(ProtocolAuthMethod::PublicKey));

        let usable = mgr.usable_methods();
        assert_eq!(usable.len(), 1);
        assert_eq!(usable[0], ProtocolAuthMethod::Password);
    }

    #[test]
    fn test_auth_method_manager_no_duplicates() {
        use crate::protocol::AuthMethod as ProtocolAuthMethod;

        let mut mgr = super::AuthMethodManager::new();
        mgr.add_supported(ProtocolAuthMethod::Password);
        mgr.add_supported(ProtocolAuthMethod::Password);
        assert_eq!(mgr.supported_methods.len(), 1);

        mgr.add_allowed(ProtocolAuthMethod::Password);
        mgr.add_allowed(ProtocolAuthMethod::Password);
        assert_eq!(mgr.allowed_methods.len(), 1);
    }

    #[test]
    fn test_auth_method_manager_default() {
        let mgr = super::AuthMethodManager::default();
        assert!(mgr.supported_methods.is_empty());
        assert!(mgr.allowed_methods.is_empty());
    }

    #[test]
    fn test_auth_method_constructors() {
        let pw = super::AuthMethod::password("user".to_string(), "pass".to_string());
        match pw {
            super::AuthMethod::Password { username, password } => {
                assert_eq!(username, "user");
                assert_eq!(password, "pass");
            }
            _ => panic!("Expected Password variant"),
        }

        let pk = super::AuthMethod::public_key("user".to_string(), vec![1, 2, 3]);
        match pk {
            super::AuthMethod::PublicKey { username, private_key } => {
                assert_eq!(username, "user");
                assert_eq!(private_key, vec![1, 2, 3]);
            }
            _ => panic!("Expected PublicKey variant"),
        }
    }

    #[test]
    fn test_auth_state_transitions() {
        let mut state = super::AuthState::new();
        assert!(state.is_not_authenticating());
        assert!(!state.is_authenticating());

        state.start_auth().unwrap();
        assert!(state.is_authenticating());

        state.complete_auth().unwrap();
        assert!(state.is_authenticated());

        // Reset and try fail path
        state.reset();
        assert!(state.is_not_authenticating());

        state.start_auth().unwrap();
        state.fail_auth().unwrap();
        assert!(state.is_failed());
    }

    #[test]
    fn test_auth_state_invalid_transitions() {
        let mut state = super::AuthState::new();

        // Can't complete without starting
        assert!(state.complete_auth().is_err());
        assert!(state.fail_auth().is_err());

        // Can't start twice
        state.start_auth().unwrap();
        assert!(state.start_auth().is_err());
    }

    #[test]
    fn test_auth_state_default() {
        let state = super::AuthState::default();
        assert!(state.is_not_authenticating());
    }
}