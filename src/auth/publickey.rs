//! Public Key Authentication implementation

use crate::error::SshError;
use crate::protocol::message::Message;
use crate::protocol::messages::MessageType;
use crate::transport::Transport;

/// Public key authenticator for SSH authentication
pub struct PublicKeyAuthenticator {
    /// Transport layer
    transport: Transport,
    /// Username
    username: String,
    /// Private key
    private_key: Vec<u8>,
    /// Algorithm (e.g., "ssh-rsa")
    algorithm: String,
}

impl PublicKeyAuthenticator {
    /// Create a new public key authenticator
    pub fn new(transport: Transport, username: String, private_key: Vec<u8>, algorithm: String) -> Self {
        Self {
            transport,
            username,
            private_key,
            algorithm,
        }
    }

    /// Request public key authentication
    pub async fn request_publickey_auth(&mut self) -> Result<bool, SshError> {
        // Compute public key hash (simplified - in real implementation, would extract public key from private key)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.private_key);
        let public_key_hash = hasher.finalize();

        // Build SSH_MSG_USERAUTH_REQUEST message
        // Format (RFC 4252 Section 7):
        // byte      SSH_MSG_USERAUTH_REQUEST
        // string    username
        // string    service
        // string    method
        // boolean   has_signature
        // string    public_key_algorithm
        // string    public_key_blob
        // string    signature
        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(false); // no signature yet (initial request)
        msg.write_string(self.algorithm.as_bytes());
        msg.write_bytes(&public_key_hash.to_vec());

        // Send the request
        self.transport.send_message(&msg.as_bytes()).await?;

        // Receive response
        let response_bytes = self.transport.recv_message().await?;
        let response = Message::from(response_bytes);

        match response.msg_type() {
            Some(MessageType::UserauthSuccess) => Ok(true),
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
                // In a real implementation, we would:
                // 1. Construct the signature data (session ID + auth request)
                // 2. Sign it with the private key
                // 3. Send the signature in a new request
                
                // For now, send a dummy signature
                self.send_signature().await
            }
            _ => Err(SshError::ProtocolError(format!(
                "Unexpected authentication response: {:?}",
                response.msg_type()
            ))),
        }
    }

    /// Send signature for public key authentication
    async fn send_signature(&mut self) -> Result<bool, SshError> {
        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(true); // has signature
        msg.write_string(self.algorithm.as_bytes());
        msg.write_bytes(&[]); // public key blob (empty, we already sent hash)
        msg.write_string(b""); // dummy signature

        self.transport.send_message(&msg.as_bytes()).await?;

        let response_bytes = self.transport.recv_message().await?;
        let response = Message::from(response_bytes);

        match response.msg_type() {
            Some(MessageType::UserauthSuccess) => Ok(true),
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