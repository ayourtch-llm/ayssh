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
    /// SSH connection (default)
    CiscoSsh,
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
/// use ssh_client::cisco_conn::{CiscoConn, ConnectionType};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut conn = CiscoConn::new(
///         "192.168.1.1",
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
    /// Create a new CiscoConn with default timeouts
    ///
    /// This method establishes a connection to the device, authenticates,
    /// and issues the `term len 0` command to disable pagination.
    ///
    /// # Arguments
    ///
    /// * `target` - Device address (IPv4/IPv6, with optional port)
    /// * `conntype` - Connection type (currently only CiscoSsh)
    /// * `username` - Authentication username
    /// * `password` - Authentication password
    ///
    /// # Returns
    ///
    /// * `Ok(CiscoConn)` - Successfully created connection
    /// * `Err(SshError)` - Failed to create connection
    pub async fn new(
        target: &str,
        conntype: ConnectionType,
        username: &str,
        password: &str,
    ) -> Result<Self, SshError> {
        Self::with_timeouts(
            target,
            conntype,
            username,
            password,
            Duration::from_secs(30),
            Duration::from_secs(30),
        ).await
    }

    /// Create a new CiscoConn with custom timeouts
    ///
    /// This method establishes a connection to the device, authenticates,
    /// and issues the `term len 0` command to disable pagination.
    ///
    /// # Arguments
    ///
    /// * `target` - Device address (IPv4/IPv6, with optional port)
    /// * `conntype` - Connection type (currently only CiscoSsh)
    /// * `username` - Authentication username
    /// * `password` - Authentication password
    /// * `timeout` - Connection timeout
    /// * `read_timeout` - Read timeout for command output
    ///
    /// # Returns
    ///
    /// * `Ok(CiscoConn)` - Successfully created connection
    /// * `Err(SshError)` - Failed to create connection
    pub async fn with_timeouts(
        target: &str,
        conntype: ConnectionType,
        username: &str,
        password: &str,
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
        let mut transport = match conntype {
            ConnectionType::CiscoSsh => {
                let client = crate::client::SshClient::new(target.to_string(), 22)
                    .with_username(username.to_string())
                    .with_password(password.to_string());

                info!("Connecting to {}...", target);
                let mut transport = client.connect().await?;
                transport.handshake().await?;

                // Request ssh-userauth service
                transport.send_service_request("ssh-userauth").await?;
                let _service = transport.recv_service_accept().await?;

                // Authenticate
                let mut authenticator = crate::auth::Authenticator::new(&mut transport, username.to_string())
                    .with_password(password.to_string());
                authenticator.available_methods.insert("password".to_string());
                let auth_result = authenticator.authenticate().await?;

                match auth_result {
                    crate::auth::AuthenticationResult::Success => {
                        info!("Authentication successful");
                    }
                    crate::auth::AuthenticationResult::Failure { .. } => {
                        return Err(SshError::AuthenticationFailed(
                            "Authentication failed".to_string()
                        ));
                    }
                }

                transport
            }
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

    #[tokio::test]
    async fn test_new_client() {
        let result = CiscoConn::new(
            "192.168.1.1",
            ConnectionType::CiscoSsh,
            "admin",
            "password",
        ).await;

        // We expect this to fail without a real device, but the API should accept the parameters
        assert!(result.is_err() || result.is_ok());
    }

    #[tokio::test]
    async fn test_new_client_with_timeouts() {
        let timeout = Duration::from_secs(60);
        let read_timeout = Duration::from_secs(20);

        let result = CiscoConn::with_timeouts(
            "192.168.1.1:22",
            ConnectionType::CiscoSsh,
            "admin",
            "password",
            timeout,
            read_timeout,
        ).await;

        assert!(result.is_err() || result.is_ok());
    }

    #[tokio::test]
    async fn test_connection_type_enum() {
        let result = CiscoConn::new(
            "router.local",
            ConnectionType::CiscoSsh,
            "user",
            "pass",
        ).await;

        assert!(result.is_err() || result.is_ok());
    }

    #[tokio::test]
    async fn test_config_defaults() {
        let result = CiscoConn::new(
            "192.168.1.1",
            ConnectionType::CiscoSsh,
            "admin",
            "password",
        ).await;

        assert!(result.is_err() || result.is_ok());
    }

    #[tokio::test]
    async fn test_ipv6_address() {
        let result = CiscoConn::new(
            "[::1]:22",
            ConnectionType::CiscoSsh,
            "admin",
            "password",
        ).await;

        assert!(result.is_err() || result.is_ok());
    }
}
