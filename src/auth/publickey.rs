//! Public Key Authentication implementation
//!
//! Implements RFC 4252 Section 7 for public key authentication.
//! This module handles the two-step authentication flow:
//! 1. Initial request with public key (no signature)
//! 2. Signature request from server, then signature response

use crate::auth::signature::{create_signature_data, RsaSignatureEncoder, SSH_SIG_ALGORITHM_RSA};
use crate::error::SshError;
use crate::protocol::message::Message;
use crate::protocol::messages::MessageType;
use crate::transport::Transport;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

/// Public key authenticator for SSH authentication
pub struct PublicKeyAuthenticator {
    /// Transport layer
    transport: Transport,
    /// Username
    username: String,
    /// Private key (OpenSSH format)
    private_key_pem: Vec<u8>,
    /// Algorithm (e.g., "ssh-rsa")
    algorithm: String,
    /// Session ID from key exchange (needed for signature)
    session_id: Vec<u8>,
}

impl PublicKeyAuthenticator {
    /// Create a new public key authenticator
    pub fn new(
        transport: Transport,
        username: String,
        private_key_pem: Vec<u8>,
        algorithm: String,
        session_id: Vec<u8>,
    ) -> Self {
        Self {
            transport,
            username,
            private_key_pem,
            algorithm,
            session_id,
        }
    }

    /// Request public key authentication
    ///
    /// This implements the two-step SSH public key authentication flow:
    /// 1. Send initial request with public key (no signature)
    /// 2. If server responds with UserauthRequest, send signature
    pub async fn request_publickey_auth(&mut self) -> Result<bool, SshError> {
        // Parse the OpenSSH private key to get the RSA key
        let private_key = self.parse_private_key()?;
        
        // Extract public key blob from the private key
        let public_key_blob = self.extract_public_key_blob(&private_key)?;

        // Build SSH_MSG_USERAUTH_REQUEST message (first attempt, no signature)
        // Format (RFC 4252 Section 7):
        // byte      SSH_MSG_USERAUTH_REQUEST
        // string    username
        // string    service
        // string    method
        // boolean   has_signature (false for initial request)
        // string    public_key_algorithm
        // string    public_key_blob
        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(false); // no signature yet (initial request)
        msg.write_string(self.algorithm.as_bytes());
        msg.write_bytes(&public_key_blob);

        // Send the request
        self.transport.send_message(&msg.as_bytes()).await?;

        // Receive response
        let response_bytes = self.transport.recv_message().await?;
        let response = Message::from(response_bytes);

        match response.msg_type() {
            Some(MessageType::UserauthSuccess) => {
                eprintln!("✓ Public key authentication successful (no signature required)");
                Ok(true)
            }
            Some(MessageType::UserauthFailure) => {
                let (partial_success, available_methods) = response.parse_userauth_failure()
                    .unwrap_or((Vec::new(), Vec::new()));
                
                eprintln!("Public key authentication failed");
                eprintln!("Partial success: {:?}", partial_success);
                eprintln!("Available methods: {:?}", available_methods);
                Ok(false)
            }
            Some(MessageType::UserauthRequest) => {
                // Server wants signature - this is the normal flow
                // Construct signature data and sign it
                self.send_signature(&private_key, &public_key_blob).await
            }
            _ => Err(SshError::ProtocolError(format!(
                "Unexpected authentication response: {:?}",
                response.msg_type()
            ))),
        }
    }

    /// Parse OpenSSH private key to extract RSA private key
    fn parse_private_key(&self) -> Result<RsaPrivateKey, SshError> {
        use crate::auth::key::PrivateKey;
        
        // Convert private key bytes to string for parsing
        let pem_content = String::from_utf8_lossy(&self.private_key_pem);
        
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

    /// Extract public key blob from RSA private key
    fn extract_public_key_blob(&self, private_key: &RsaPrivateKey) -> Result<Vec<u8>, SshError> {
        use rsa::traits::PublicKeyParts;
        use bytes::{BufMut, BytesMut};
        
        let mut buf = BytesMut::new();
        
        // Public key algorithm string
        buf.put_u32(self.algorithm.len() as u32);
        buf.put_slice(self.algorithm.as_bytes());
        
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

    /// Send signature for public key authentication
    ///
    /// This constructs the signature data according to RFC 4252 Section 7,
    /// signs it with the private key, and sends the signature.
    async fn send_signature(
        &mut self,
        private_key: &RsaPrivateKey,
        public_key_blob: &[u8],
    ) -> Result<bool, SshError> {
        // Construct signature data according to RFC 4252 Section 7
        let signature_data = create_signature_data(
            &self.session_id,
            &self.username,
            "ssh-connection",
            "publickey",
            true, // has_signature
            &self.algorithm,
            public_key_blob,
        );
        
        eprintln!("Signature data length: {} bytes", signature_data.len());
        eprintln!("Signature data (hex): {:02x?}", &signature_data[..20.min(signature_data.len())]);
        
        // Encode the signature using RSA signature encoder
        let signature = RsaSignatureEncoder::encode(private_key, &signature_data)?;
        
        eprintln!("✓ Signature encoded successfully ({} bytes)", signature.data.len());
        
        // Build SSH_MSG_USERAUTH_REQUEST message with signature
        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(true); // has signature
        msg.write_string(self.algorithm.as_bytes());
        msg.write_bytes(public_key_blob);
        msg.write_bytes(&signature.encode()); // SSH-encoded signature

        // Send the message with signature
        self.transport.send_message(&msg.as_bytes()).await?;

        // Receive response
        let response_bytes = self.transport.recv_message().await?;
        let response = Message::from(response_bytes);

        match response.msg_type() {
            Some(MessageType::UserauthSuccess) => {
                eprintln!("✓ Public key signature verification successful!");
                Ok(true)
            }
            Some(MessageType::UserauthFailure) => {
                let (partial_success, available_methods) = response.parse_userauth_failure()
                    .unwrap_or((Vec::new(), Vec::new()));
                
                eprintln!("Public key signature verification failed");
                eprintln!("Partial success: {:?}", partial_success);
                eprintln!("Available methods: {:?}", available_methods);
                Ok(false)
            }
            _ => Err(SshError::ProtocolError(format!(
                "Unexpected authentication response: {:?}",
                response.msg_type()
            ))),
        }
    }
}