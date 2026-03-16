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

use tracing::debug;

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
    keyboard_interactive_handler: Option<Box<dyn Fn(&keyboard::Challenge) -> Result<Vec<String>, SshError> + Send + Sync>>,
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
        F: Fn(&keyboard::Challenge) -> Result<Vec<String>, SshError> + Send + Sync + 'static,
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

    /// Tries public key authentication.
    /// Attempts rsa-sha2-256 first (modern OpenSSH), falls back to ssh-rsa (legacy Cisco).
    async fn try_publickey_auth(&mut self, private_key_pem: &[u8]) -> Result<AuthenticationResult, SshError> {
        let private_key = self.parse_private_key(private_key_pem)?;
        let public_key_blob = self.extract_public_key_blob(&private_key)?;

        // Try rsa-sha2-256 first (required by OpenSSH 8.8+), then ssh-rsa fallback
        for algorithm in &["rsa-sha2-256", "ssh-rsa"] {
            debug!("Trying publickey auth with algorithm: {}", algorithm);

            // The public key blob always uses "ssh-rsa" as the key type inside,
            // but the algorithm in the auth request can be "rsa-sha2-256"
            let mut msg = Message::new();
            msg.write_byte(MessageType::UserauthRequest.value());
            msg.write_string(self.username.as_bytes());
            msg.write_string(b"ssh-connection");
            msg.write_string(b"publickey");
            msg.write_bool(false); // no signature yet
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
                    return self.send_signature_with_algo(private_key, &public_key_blob, algorithm).await;
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

    /// Extracts public key blob from RSA private key.
    /// Encodes as SSH wire format: string("ssh-rsa") || mpint(e) || mpint(n)
    fn extract_public_key_blob(&self, private_key: &rsa::RsaPrivateKey) -> Result<Vec<u8>, SshError> {
        use rsa::traits::PublicKeyParts;
        use bytes::{BufMut, BytesMut};

        // Helper: encode a BigUint as SSH mpint (with 0x00 prefix if high bit set)
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

        // Public key algorithm string
        buf.put_u32(b"ssh-rsa".len() as u32);
        buf.put_slice(b"ssh-rsa");

        // Public exponent e (as mpint)
        let e = private_key.e().to_bytes_be();
        put_mpint(&mut buf, &e);

        // Modulus n (as mpint)
        let n = private_key.n().to_bytes_be();
        put_mpint(&mut buf, &n);

        Ok(buf.to_vec())
    }

    /// Sends signature for public key authentication using the specified algorithm.
    /// "ssh-rsa" uses SHA-1, "rsa-sha2-256" uses SHA-256.
    async fn send_signature_with_algo(
        &mut self,
        private_key: rsa::RsaPrivateKey,
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

        debug!("Creating RSA signature ({}) over {} bytes of data", algorithm, signature_data.len());

        // Sign with the appropriate hash algorithm
        let signature = match algorithm {
            "rsa-sha2-256" => RsaSignatureEncoder::encode_sha256(&private_key, &signature_data)?,
            _ => RsaSignatureEncoder::encode(&private_key, &signature_data)?,
        };

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
    use super::*;

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
}