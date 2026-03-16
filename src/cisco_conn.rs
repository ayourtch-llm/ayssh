//! CiscoConn - High-level Cisco device command executor
//!
//! This module provides a simple interface for executing single commands
//! on Cisco devices via SSH.

#![deny(unused_must_use)]

use std::time::Duration;

use crate::error::SshError;
use tracing::{debug, info};

/// Connection type for Cisco devices
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionType {
    /// SSH connection with password authentication
    CiscoSsh,
    /// SSH connection with RSA public key authentication
    CiscoSshKey,
    /// SSH connection with keyboard-interactive authentication
    CiscoSshKbdInteractive,
}

/// Configuration for CiscoConn command execution
#[derive(Debug, Clone)]
pub struct CiscoConnConfig {
    /// Target device address (IPv4/IPv6)
    pub target: String,
    /// Connection type (SSH, etc.)
    pub conntype: ConnectionType,
    /// Authentication username
    pub username: String,
    /// Authentication password
    pub password: String,
    /// Connection timeout
    pub timeout: Duration,
    /// Read timeout for command output
    pub read_timeout: Duration,
    /// Custom prompts to detect command completion
    pub prompts: Vec<String>,
}

impl Default for CiscoConnConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            conntype: ConnectionType::CiscoSsh,
            username: String::new(),
            password: String::new(),
            timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(30),
            prompts: vec![
                "Router#".to_string(),
                "Switch#".to_string(),
                "config#".to_string(),
                "cli#".to_string(),
            ],
        }
    }
}

/// High-level Cisco device command executor
///
/// This struct provides a simple interface for executing commands
/// on a Cisco device and returning the output. It handles connection,
/// authentication, and command execution automatically.
///
/// # Example
///
/// ```no_run
/// use ayssh::cisco_conn::{CiscoConn, ConnectionType};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut conn = CiscoConn::new(
///         "127.0.0.1",
///         ConnectionType::CiscoSsh,
///         "admin",
///         "password"
///     ).await?;
///
///     let output = conn.run_cmd("show version").await?;
///     println!("Command output: {}", output);
///     Ok(())
/// }
/// ```
pub struct CiscoConn {
    config: CiscoConnConfig,
    transport: crate::transport::Transport,
    channel_id: u32,
}

impl CiscoConn {
    /// Create a new CiscoConn with password authentication and default timeouts
    pub async fn new(
        target: &str,
        conntype: ConnectionType,
        username: &str,
        password: &str,
    ) -> Result<Self, SshError> {
        Self::connect_internal(
            target,
            conntype,
            username,
            password,
            None,
            Duration::from_secs(30),
            Duration::from_secs(30),
        ).await
    }

    /// Create a new CiscoConn with password authentication and custom timeouts
    pub async fn with_timeouts(
        target: &str,
        conntype: ConnectionType,
        username: &str,
        password: &str,
        timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, SshError> {
        Self::connect_internal(target, conntype, username, password, None, timeout, read_timeout).await
    }

    /// Create a new CiscoConn with RSA key authentication
    pub async fn new_with_key(
        target: &str,
        username: &str,
        private_key: &[u8],
    ) -> Result<Self, SshError> {
        Self::connect_internal(
            target,
            ConnectionType::CiscoSshKey,
            username,
            "",
            Some(private_key.to_vec()),
            Duration::from_secs(30),
            Duration::from_secs(30),
        ).await
    }

    /// Internal connection method that handles both password and key auth
    async fn connect_internal(
        target: &str,
        conntype: ConnectionType,
        username: &str,
        password: &str,
        private_key: Option<Vec<u8>>,
        timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, SshError> {
        let prompts: Vec<String> = vec![
            "Router#".to_string(),
            "Switch#".to_string(),
            "config#".to_string(),
            "cli#".to_string(),
        ];

        // Create SSH client and connect
        let mut transport = {
            let client = crate::client::SshClient::new(target.to_string(), 22)
                .with_username(username.to_string())
                .with_password(password.to_string());

            info!("Connecting to {}...", target);
            let mut transport = client.connect().await?;
            transport.handshake().await?;

            // Request ssh-userauth service
            transport.send_service_request("ssh-userauth").await?;
            let _service = transport.recv_service_accept().await?;

            // Authenticate based on connection type
            match conntype {
                ConnectionType::CiscoSsh => {
                    let mut authenticator = crate::auth::Authenticator::new(&mut transport, username.to_string())
                        .with_password(password.to_string());
                    authenticator.available_methods.insert("password".to_string());
                    let auth_result = authenticator.authenticate().await?;

                    match auth_result {
                        crate::auth::AuthenticationResult::Success => {
                            info!("Password authentication successful");
                        }
                        crate::auth::AuthenticationResult::Failure { .. } => {
                            return Err(SshError::AuthenticationFailed(
                                "Password authentication failed".to_string()
                            ));
                        }
                    }
                }
                ConnectionType::CiscoSshKey => {
                    let key_data = private_key.as_ref().ok_or_else(|| {
                        SshError::AuthenticationFailed("Private key required for CiscoSshKey".to_string())
                    })?;

                    let mut authenticator = crate::auth::Authenticator::new(&mut transport, username.to_string())
                        .with_private_key(key_data.clone());
                    authenticator.available_methods.insert("publickey".to_string());
                    let auth_result = authenticator.authenticate().await?;

                    match auth_result {
                        crate::auth::AuthenticationResult::Success => {
                            info!("Public key authentication successful");
                        }
                        crate::auth::AuthenticationResult::Failure { .. } => {
                            return Err(SshError::AuthenticationFailed(
                                "Public key authentication failed".to_string()
                            ));
                        }
                    }
                }
                ConnectionType::CiscoSshKbdInteractive => {
                    let password = password.to_string();
                    let mut kbd_auth = crate::auth::KeyboardInteractiveAuthenticator::new(
                        &mut transport,
                        username.to_string(),
                    );

                    kbd_auth.authenticate(|challenge| {
                        debug!("Keyboard-interactive challenge: name={:?}, instruction={:?}, {} prompts",
                               challenge.name, challenge.instruction, challenge.num_prompts);
                        for prompt in &challenge.prompts {
                            debug!("  Prompt: {:?} (echo={})", prompt.prompt, prompt.echo);
                        }
                        // Respond to each prompt with the password
                        Ok(challenge.prompts.iter().map(|_| password.clone()).collect())
                    }).await.map_err(|e| {
                        SshError::AuthenticationFailed(format!("Keyboard-interactive auth failed: {}", e))
                    })?;

                    info!("Keyboard-interactive authentication successful");
                }
            }

            transport
        };

        // Open session channel
        let session = crate::session::Session::open(&mut transport).await?;
        let channel_id = session.remote_channel_id();
        info!("Session channel opened (local={}, remote={})", session.channel_id(), channel_id);

        // Request PTY (required by Cisco IOS before shell)
        {
            use bytes::BufMut;
            let mut pty_msg = bytes::BytesMut::new();
            pty_msg.put_u8(crate::protocol::MessageType::ChannelRequest as u8);
            pty_msg.put_u32(channel_id);
            let req_type = b"pty-req";
            pty_msg.put_u32(req_type.len() as u32);
            pty_msg.put_slice(req_type);
            pty_msg.put_u8(1); // want reply
            // Terminal type
            let term = b"vt100";
            pty_msg.put_u32(term.len() as u32);
            pty_msg.put_slice(term);
            pty_msg.put_u32(80);  // width chars
            pty_msg.put_u32(24);  // height chars
            pty_msg.put_u32(0);   // width pixels
            pty_msg.put_u32(0);   // height pixels
            // Terminal modes (empty string)
            pty_msg.put_u32(0);
            transport.send_message(&pty_msg).await?;
            let pty_response = transport.recv_message().await?;
            debug!("PTY request response: msg_type={}", pty_response[0]);
        }

        // Request shell
        transport.send_channel_request(channel_id, "shell", true).await?;
        let shell_response = transport.recv_message().await?;
        debug!("Shell request response: msg_type={}", shell_response[0]);

        let mut conn = Self {
            config: CiscoConnConfig {
                target: target.to_string(),
                conntype,
                username: username.to_string(),
                password: password.to_string(),
                timeout,
                read_timeout,
                prompts,
            },
            transport,
            channel_id,
        };

        // Wait for initial shell prompt
        let _ = conn.receive_until(b"#", read_timeout).await;

        // Issue term len 0 to disable pagination
        conn.send(b"term len 0\n").await?;
        // Wait for response (echo + prompt)
        let _ = conn.receive_until(b"#", read_timeout).await;

        Ok(conn)
    }

    /// Send raw bytes to the device over the SSH channel
    async fn send(&mut self, data: &[u8]) -> Result<(), SshError> {
        self.transport.send_channel_data(self.channel_id, data).await
    }

    /// Receive data from the device until a delimiter is found or timeout
    async fn receive_until(&mut self, delimiter: &[u8], timeout: Duration) -> Result<String, SshError> {
        let mut output = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            match tokio::time::timeout_at(deadline, self.transport.recv_message()).await {
                Ok(Ok(msg)) => {
                    // Check if it's channel data (type 94 = SSH_MSG_CHANNEL_DATA)
                    if !msg.is_empty() && msg[0] == crate::protocol::MessageType::ChannelData as u8 {
                        // Channel data format: type(1) + channel(4) + length(4) + data
                        if msg.len() > 9 {
                            let data_len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
                            if msg.len() >= 9 + data_len {
                                output.extend_from_slice(&msg[9..9 + data_len]);
                            }
                        }
                    } else if !msg.is_empty() && msg[0] == crate::protocol::MessageType::ChannelWindowAdjust as u8 {
                        // Window adjust - ignore and continue
                        continue;
                    } else {
                        debug!("Received non-data message type: {}", if msg.is_empty() { 0 } else { msg[0] });
                    }

                    // Check if delimiter found
                    if output.windows(delimiter.len()).any(|w| w == delimiter) {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    debug!("Error receiving: {}", e);
                    if !output.is_empty() {
                        break;
                    }
                    return Err(e);
                }
                Err(_) => {
                    debug!("Receive timeout");
                    break;
                }
            }
        }

        String::from_utf8(output)
            .map_err(|e| SshError::ProtocolError(format!("Invalid UTF-8 in output: {}", e)))
    }

    /// Execute a command on the connected device
    ///
    /// This method sends the command to the device and returns the output
    /// until the prompt is detected.
    ///
    /// # Arguments
    ///
    /// * `cmd` - Command to execute on the device
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Command output
    /// * `Err(SshError)` - Connection or execution error
    pub async fn run_cmd(&mut self, cmd: &str) -> Result<String, SshError> {
        debug!("Starting CiscoConn::run_cmd for target: {}", self.config.target);
        debug!("Command: {}", cmd);

        // Send the command with newline
        let command_with_newline = format!("{}\n", cmd);
        debug!("Sending command: {}", command_with_newline);
        self.send(command_with_newline.as_bytes()).await?;
        debug!("Command sent successfully");

        // Wait for command output until prompt is detected
        info!("Waiting for command output until prompt detected (timeout: {:?})", self.config.read_timeout);
        let output = self.receive_until(b"#", self.config.read_timeout).await?;
        debug!("Received output ({} bytes)", output.len());

        debug!("Command execution completed successfully");
        Ok(output)
    }

    /// Disconnect from the device
    pub async fn disconnect(&mut self) -> Result<(), SshError> {
        info!("Disconnecting from device...");
        self.transport.send_channel_close(self.channel_id).await?;
        info!("Disconnected successfully");
        Ok(())
    }

    /// Get the configured target address
    pub fn target(&self) -> &str {
        &self.config.target
    }

    /// Get the configured username
    pub fn username(&self) -> &str {
        &self.config.username
    }

    /// Get the connection type
    pub fn conntype(&self) -> &ConnectionType {
        &self.config.conntype
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_type_variants() {
        assert_ne!(ConnectionType::CiscoSsh, ConnectionType::CiscoSshKey);
    }

    #[test]
    fn test_config_defaults() {
        let config = CiscoConnConfig::default();
        assert_eq!(config.conntype, ConnectionType::CiscoSsh);
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.read_timeout, Duration::from_secs(30));
        assert!(!config.prompts.is_empty());
    }
}
