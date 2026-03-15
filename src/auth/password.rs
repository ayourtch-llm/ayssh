//! Password Authentication implementation

use crate::error::SshError;
use crate::protocol::message::Message;
use crate::protocol::messages::MessageType;
use crate::transport::Transport;

/// Password authenticator for SSH authentication
pub struct PasswordAuthenticator {
    /// Transport layer
    transport: Transport,
    /// Username
    username: String,
    /// Password
    password: String,
}

impl PasswordAuthenticator {
    /// Create a new password authenticator
    pub fn new(transport: Transport, username: String, password: String) -> Self {
        Self {
            transport,
            username,
            password,
        }
    }

    /// Request password authentication
    pub async fn request_password_auth(&mut self) -> Result<bool, SshError> {
        // Build SSH_MSG_USERAUTH_REQUEST message
        // Format (RFC 4252 Section 5.2):
        // byte      SSH_MSG_USERAUTH_REQUEST
        // string    username
        // string    service
        // string    method
        // boolean   first_attempt
        // string    password
        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"password");
        msg.write_bool(false); // first attempt
        msg.write_string(self.password.as_bytes());

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
                
                eprintln!("Password authentication failed");
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