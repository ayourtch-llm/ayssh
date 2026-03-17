//! Public Key Authentication implementation
//!
//! Implements RFC 4252 Section 7 for public key authentication.
//! This module handles the two-step authentication flow:
//! 1. Initial request with public key (no signature)
//! 2. Signature request from server, then signature response

use crate::auth::key::PrivateKey;
use crate::auth::signature::{create_signature_data, Ed25519SignatureEncoder, EcdsaSignatureEncoder, RsaSignatureEncoder};
use crate::error::SshError;
use crate::protocol::message::Message;
use crate::protocol::messages::MessageType;
use crate::transport::Transport;
use bytes::{BufMut, BytesMut};

/// Public key authenticator for SSH authentication
pub struct PublicKeyAuthenticator {
    /// Transport layer
    transport: Transport,
    /// Username
    username: String,
    /// Private key (parsed)
    private_key: PrivateKey,
    /// Algorithm (e.g., "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519")
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
    ) -> Result<Self, SshError> {
        // Parse the private key immediately to validate it
        let private_key = Self::parse_private_key(&private_key_pem)?;
        
        Ok(Self {
            transport,
            username,
            private_key,
            algorithm,
            session_id,
        })
    }

    /// Request public key authentication
    ///
    /// This implements the two-step SSH public key authentication flow:
    /// 1. Send initial request with public key (no signature)
    /// 2. If server responds with UserauthRequest, send signature
    pub async fn request_publickey_auth(&mut self) -> Result<bool, SshError> {
        // Extract public key blob from the private key
        let public_key_blob = self.extract_public_key_blob()?;

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
                self.send_signature(&public_key_blob).await
            }
            _ => Err(SshError::ProtocolError(format!(
                "Unexpected authentication response: {:?}",
                response.msg_type()
            ))),
        }
    }

    /// Parse OpenSSH private key to extract the appropriate key type
    fn parse_private_key(private_key_pem: &[u8]) -> Result<PrivateKey, SshError> {
        // Convert private key bytes to string for parsing
        let pem_content = String::from_utf8_lossy(private_key_pem);
        
        // Parse using the key module
        PrivateKey::parse_pem(&pem_content.to_string())
    }

    /// Extract public key blob from the private key
    fn extract_public_key_blob(&self) -> Result<Vec<u8>, SshError> {
        match &self.private_key {
            PrivateKey::Rsa(rsa_key) => {
                self.extract_rsa_public_key_blob(rsa_key)
            }
            PrivateKey::Ecdsa(curve, scalar) => {
                self.extract_ecdsa_public_key_blob(curve, scalar)
            }
            PrivateKey::Ed25519(ed25519_key) => {
                self.extract_ed25519_public_key_blob(ed25519_key)
            }
        }
    }

    /// Extract RSA public key blob
    fn extract_rsa_public_key_blob(&self, private_key: &rsa::RsaPrivateKey) -> Result<Vec<u8>, SshError> {
        use rsa::traits::PublicKeyParts;
        
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

    /// Extract ECDSA public key blob
    fn extract_ecdsa_public_key_blob(&self, curve: &crate::auth::key::EcdsaCurve, scalar: &[u8]) -> Result<Vec<u8>, SshError> {
        let mut buf = BytesMut::new();
        
        // Public key algorithm string
        buf.put_u32(self.algorithm.len() as u32);
        buf.put_slice(self.algorithm.as_bytes());
        
        // Curve name
        let (curve_name, public_key_bytes) = match curve {
            crate::auth::key::EcdsaCurve::Nistp256 => {
                use k256::SecretKey;
                use k256::ecdsa::SigningKey;
                
                let secret_key = SecretKey::from_slice(scalar)
                    .map_err(|_| SshError::CryptoError("Invalid ECDSA P-256 key".into()))?;
                let signing_key = SigningKey::from(secret_key);
                let public_key = k256::ecdsa::VerifyingKey::from(&signing_key);
                let encoded_point = public_key.to_encoded_point(false);
                (b"nistp256", encoded_point.as_bytes().to_vec())
            }
            crate::auth::key::EcdsaCurve::Nistp384 => {
                use p384::SecretKey;
                use p384::ecdsa::SigningKey;
                
                let secret_key = SecretKey::from_slice(scalar)
                    .map_err(|_| SshError::CryptoError("Invalid ECDSA P-384 key".into()))?;
                let signing_key = SigningKey::from(secret_key);
                let public_key = p384::ecdsa::VerifyingKey::from(&signing_key);
                let encoded_point = public_key.to_encoded_point(false);
                (b"nistp384", encoded_point.as_bytes().to_vec())
            }
            crate::auth::key::EcdsaCurve::Nistp521 => {
                use p521::ecdsa::SigningKey;
                
                // For P-521, the scalar is 66 bytes
                let signing_key = SigningKey::from_slice(scalar)
                    .map_err(|_| SshError::CryptoError("Invalid ECDSA P-521 key".into()))?;
                let public_key = p521::ecdsa::VerifyingKey::from(&signing_key);
                let encoded_point = public_key.to_encoded_point(false);
                (b"nistp521", encoded_point.as_bytes().to_vec())
            }
        };
        
        buf.put_u32(curve_name.len() as u32);
        buf.put_slice(curve_name);
        buf.put_u32(public_key_bytes.len() as u32);
        buf.put_slice(&public_key_bytes);
        
        Ok(buf.to_vec())
    }

    /// Extract Ed25519 public key blob
    fn extract_ed25519_public_key_blob(&self, private_key: &ed25519_dalek::SigningKey) -> Result<Vec<u8>, SshError> {
        let mut buf = BytesMut::new();
        
        // Public key algorithm string
        buf.put_u32(self.algorithm.len() as u32);
        buf.put_slice(self.algorithm.as_bytes());
        
        // Public key (32 bytes)
        let public_key = private_key.verifying_key();
        let public_key_bytes = public_key.to_bytes();
        buf.put_u32(public_key_bytes.len() as u32);
        buf.put_slice(&public_key_bytes);
        
        Ok(buf.to_vec())
    }

    /// Send signature for public key authentication
    ///
    /// This constructs the signature data according to RFC 4252 Section 7,
    /// signs it with the private key, and sends the signature.
    async fn send_signature(
        &mut self,
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
        
        // Encode the signature using the appropriate encoder based on key type
        let signature = match &self.private_key {
            PrivateKey::Rsa(rsa_key) => {
                RsaSignatureEncoder::encode(rsa_key, &signature_data)?
            }
            PrivateKey::Ecdsa(curve, scalar) => {
                match curve {
                    crate::auth::key::EcdsaCurve::Nistp256 => {
                        use k256::SecretKey;
                        use k256::ecdsa::SigningKey;
                        let secret_key = SecretKey::from_slice(scalar)
                            .map_err(|_| SshError::CryptoError("Invalid ECDSA P-256 key".into()))?;
                        let signing_key = SigningKey::from(secret_key);
                        EcdsaSignatureEncoder::encode_nistp256(&signing_key, &signature_data)?
                    }
                    crate::auth::key::EcdsaCurve::Nistp384 => {
                        use p384::SecretKey;
                        use p384::ecdsa::SigningKey;
                        let secret_key = SecretKey::from_slice(scalar)
                            .map_err(|_| SshError::CryptoError("Invalid ECDSA P-384 key".into()))?;
                        let signing_key = SigningKey::from(secret_key);
                        EcdsaSignatureEncoder::encode_nistp384(&signing_key, &signature_data)?
                    }
                    crate::auth::key::EcdsaCurve::Nistp521 => {
                        use p521::ecdsa::SigningKey;
                        let signing_key = SigningKey::from_slice(scalar)
                            .map_err(|_| SshError::CryptoError("Invalid ECDSA P-521 key".into()))?;
                        EcdsaSignatureEncoder::encode_nistp521(&signing_key, &signature_data)?
                    }
                }
            }
            PrivateKey::Ed25519(ed25519_key) => {
                Ed25519SignatureEncoder::encode(ed25519_key, &signature_data)?
            }
        };
        
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