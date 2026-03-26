//! UnixConn - High-level Unix/Linux command executor over SSH
//!
//! This module provides a simple interface for executing commands
//! on Unix/Linux hosts via SSH.

#![deny(unused_must_use)]

use std::time::Duration;

use crate::error::SshError;
use tracing::{debug, info};

/// Connection type for Unix hosts
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionType {
    /// SSH connection with password authentication
    UnixSsh,
    /// SSH connection with RSA public key authentication
    UnixSshKey,
    /// SSH connection with keyboard-interactive authentication
    UnixSshKbdInteractive,
}

/// Configuration for UnixConn command execution
#[derive(Clone)]
pub struct UnixConnConfig {
    /// Target host address (IPv4/IPv6)
    pub target: String,
    /// Connection type
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

impl std::fmt::Debug for UnixConnConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixConnConfig")
            .field("target", &self.target)
            .field("conntype", &self.conntype)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("read_timeout", &self.read_timeout)
            .field("prompts", &self.prompts)
            .finish()
    }
}

impl Default for UnixConnConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            conntype: ConnectionType::UnixSsh,
            username: String::new(),
            password: String::new(),
            timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(30),
            prompts: vec![
                "$ ".to_string(),
                "# ".to_string(),
            ],
        }
    }
}

/// High-level Unix/Linux command executor over SSH
///
/// # Example
///
/// ```no_run
/// use ayssh::unix_conn::{UnixConn, ConnectionType};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut conn = UnixConn::new(
///         "192.168.1.1",
///         ConnectionType::UnixSsh,
///         "user",
///         "password"
///     ).await?;
///
///     let output = conn.run_cmd("uname -a").await?;
///     println!("{}", output);
///     Ok(())
/// }
/// ```
/// Cryptographic algorithm preferences
#[derive(Debug, Clone, Default)]
pub struct CryptoPrefs {
    pub cipher: Option<String>,
    pub mac: Option<String>,
    pub kex: Option<String>,
}

pub struct UnixConn {
    config: UnixConnConfig,
    transport: crate::transport::Transport,
    channel_id: u32,
    /// Bytes consumed from the SSH window but not yet reported via WINDOW_ADJUST.
    window_consumed: u32,
}

impl std::fmt::Debug for UnixConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixConn")
            .field("config", &self.config)
            .field("channel_id", &self.channel_id)
            .finish_non_exhaustive()
    }
}

impl UnixConn {
    /// Send WINDOW_ADJUST after this many bytes have been consumed.
    const WINDOW_ADJUST_THRESHOLD: u32 = 32768;

    /// Create a new UnixConn with password authentication and default timeouts
    pub async fn new(
        target: &str,
        conntype: ConnectionType,
        username: &str,
        password: &str,
    ) -> Result<Self, SshError> {
        Self::connect_internal(
            target, conntype, username, password, None,
            Duration::from_secs(30), Duration::from_secs(30),
            CryptoPrefs::default(),
        ).await
    }

    /// Create a new UnixConn with password authentication and custom timeouts
    pub async fn with_timeouts(
        target: &str,
        conntype: ConnectionType,
        username: &str,
        password: &str,
        timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, SshError> {
        Self::connect_internal(target, conntype, username, password, None, timeout, read_timeout, CryptoPrefs::default()).await
    }

    /// Create a new UnixConn with RSA key authentication
    pub async fn new_with_key(
        target: &str,
        username: &str,
        private_key: &[u8],
    ) -> Result<Self, SshError> {
        Self::new_with_key_and_prefs(target, username, private_key, CryptoPrefs::default()).await
    }

    /// Create a new UnixConn with RSA key authentication and crypto preferences
    pub async fn new_with_key_and_prefs(
        target: &str,
        username: &str,
        private_key: &[u8],
        prefs: CryptoPrefs,
    ) -> Result<Self, SshError> {
        Self::connect_internal(
            target, ConnectionType::UnixSshKey, username, "",
            Some(private_key.to_vec()),
            Duration::from_secs(30), Duration::from_secs(30),
            prefs,
        ).await
    }

    /// Set preferred cipher and MAC algorithms for the next connection
    pub fn with_crypto_prefs(
        preferred_cipher: Option<String>,
        preferred_mac: Option<String>,
    ) -> CryptoPrefs {
        CryptoPrefs { kex: None, cipher: preferred_cipher, mac: preferred_mac }
    }

    /// Create a new UnixConn with specific crypto preferences
    pub async fn new_with_prefs(
        target: &str,
        conntype: ConnectionType,
        username: &str,
        password: &str,
        prefs: CryptoPrefs,
    ) -> Result<Self, SshError> {
        Self::connect_internal(target, conntype, username, password, None, Duration::from_secs(30), Duration::from_secs(30), prefs).await
    }

    /// Internal connection method that handles all auth types
    async fn connect_internal(
        target: &str,
        conntype: ConnectionType,
        username: &str,
        password: &str,
        private_key: Option<Vec<u8>>,
        timeout: Duration,
        read_timeout: Duration,
        crypto_prefs: CryptoPrefs,
    ) -> Result<Self, SshError> {
        let prompts: Vec<String> = vec![
            "$ ".to_string(),
            "# ".to_string(),
        ];

        // Create SSH client and connect
        let mut transport = {
            let client = crate::client::SshClient::new(target.to_string(), 22)
                .with_username(username.to_string())
                .with_password(password.to_string());

            info!("Connecting to {}...", target);
            let mut transport = client.connect().await?;
            if let Some(ref kex) = crypto_prefs.kex {
                transport.set_preferred_kex(kex);
            }
            if let Some(ref cipher) = crypto_prefs.cipher {
                transport.set_preferred_cipher(cipher);
            }
            if let Some(ref mac) = crypto_prefs.mac {
                transport.set_preferred_mac(mac);
            }
            transport.handshake().await?;

            // Request ssh-userauth service
            transport.send_service_request("ssh-userauth").await?;
            let _service = transport.recv_service_accept().await?;

            // Authenticate based on connection type
            match conntype {
                ConnectionType::UnixSsh => {
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
                ConnectionType::UnixSshKey => {
                    let key_data = private_key.as_ref().ok_or_else(|| {
                        SshError::AuthenticationFailed("Private key required for UnixSshKey".to_string())
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
                ConnectionType::UnixSshKbdInteractive => {
                    let password = password.to_string();
                    let mut kbd_auth = crate::auth::KeyboardInteractiveAuthenticator::new(
                        &mut transport,
                        username.to_string(),
                    );

                    kbd_auth.authenticate(|challenge| {
                        debug!("Keyboard-interactive challenge: name={:?}, instruction={:?}, {} prompts",
                               challenge.name, challenge.instruction, challenge.num_prompts);
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

        // Request PTY
        {
            use bytes::BufMut;
            let mut pty_msg = bytes::BytesMut::new();
            pty_msg.put_u8(crate::protocol::MessageType::ChannelRequest as u8);
            pty_msg.put_u32(channel_id);
            let req_type = b"pty-req";
            pty_msg.put_u32(req_type.len() as u32);
            pty_msg.put_slice(req_type);
            pty_msg.put_u8(1); // want reply
            let term = b"xterm";
            pty_msg.put_u32(term.len() as u32);
            pty_msg.put_slice(term);
            pty_msg.put_u32(80);  // width chars
            pty_msg.put_u32(24);  // height chars
            pty_msg.put_u32(0);   // width pixels
            pty_msg.put_u32(0);   // height pixels
            pty_msg.put_u32(0);   // terminal modes (empty)
            transport.send_message(&pty_msg).await?;
            let pty_response = transport.recv_message().await?;
            debug!("PTY request response: msg_type={}", pty_response[0]);
        }

        // Request shell
        transport.send_channel_request(channel_id, "shell", true).await?;
        let shell_response = transport.recv_message().await?;
        debug!("Shell request response: msg_type={}", shell_response[0]);

        let mut conn = Self {
            config: UnixConnConfig {
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
            window_consumed: 0,
        };

        // Wait for initial shell prompt
        let _ = conn.receive_until_prompt(read_timeout).await;

        Ok(conn)
    }

    /// Send raw bytes to the host over the SSH channel
    async fn send(&mut self, data: &[u8]) -> Result<(), SshError> {
        self.transport.send_channel_data(self.channel_id, data).await
    }

    /// Receive data until any of the configured prompts is found or timeout
    async fn receive_until_prompt(&mut self, timeout: Duration) -> Result<String, SshError> {
        let mut output = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            match tokio::time::timeout_at(deadline, self.transport.recv_message()).await {
                Ok(Ok(msg)) => {
                    if !msg.is_empty() && msg[0] == crate::protocol::MessageType::ChannelData as u8 {
                        if msg.len() > 9 {
                            let data_len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
                            if msg.len() >= 9 + data_len {
                                self.window_consumed += data_len as u32;
                                if self.window_consumed >= Self::WINDOW_ADJUST_THRESHOLD {
                                    let adjust = self.window_consumed;
                                    self.window_consumed = 0;
                                    let _ = self.transport.send_channel_window_adjust(
                                        self.channel_id, adjust,
                                    ).await;
                                }
                                output.extend_from_slice(&msg[9..9 + data_len]);
                            }
                        }
                    } else if !msg.is_empty() && msg[0] == crate::protocol::MessageType::ChannelWindowAdjust as u8 {
                        continue;
                    } else {
                        debug!("Received non-data message type: {}", if msg.is_empty() { 0 } else { msg[0] });
                    }

                    // Check if any prompt is found in the output
                    let output_str = String::from_utf8_lossy(&output);
                    if self.config.prompts.iter().any(|p| output_str.contains(p)) {
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

    /// Execute a command on the connected host
    ///
    /// Sends the command and waits for the shell prompt to reappear.
    pub async fn run_cmd(&mut self, cmd: &str) -> Result<String, SshError> {
        debug!("Executing command: {}", cmd);

        let command_with_newline = format!("{}\n", cmd);
        self.send(command_with_newline.as_bytes()).await?;

        info!("Waiting for command output (timeout: {:?})", self.config.read_timeout);
        let output = self.receive_until_prompt(self.config.read_timeout).await?;
        debug!("Received output ({} bytes)", output.len());

        Ok(output)
    }

    /// Disconnect from the host
    pub async fn disconnect(&mut self) -> Result<(), SshError> {
        info!("Disconnecting from host...");
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
        assert_ne!(ConnectionType::UnixSsh, ConnectionType::UnixSshKey);
        assert_ne!(ConnectionType::UnixSsh, ConnectionType::UnixSshKbdInteractive);
    }

    #[test]
    fn test_config_defaults() {
        let config = UnixConnConfig::default();
        assert_eq!(config.conntype, ConnectionType::UnixSsh);
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(config.prompts.contains(&"$ ".to_string()));
        assert!(config.prompts.contains(&"# ".to_string()));
    }
}
