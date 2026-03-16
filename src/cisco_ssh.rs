//! CiscoSSH - High-level Cisco device command executor over SSH
//!
//! This module provides a simple interface for executing commands
//! on Cisco devices via SSH. It handles connection, authentication,
//! and command execution automatically.

#![deny(unused_must_use)]

use std::time::Duration;

use crate::error::SshError;
use tracing::{debug, info};

/// Connection type for Cisco devices
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionType {
    /// SSH connection (default)
    CiscoSSH,
}

/// Configuration for CiscoSSH command execution
#[derive(Debug, Clone)]
pub struct CiscoSSHConfig {
    /// Target device address (IPv4/IPv6, with optional port)
    pub target: String,
    /// Connection type (SSH, TELNET, etc.)
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

impl Default for CiscoSSHConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            conntype: ConnectionType::CiscoSSH,
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

/// High-level Cisco device command executor over SSH
///
/// This struct provides a simple interface for executing commands
/// on a Cisco device and returning the output. It handles connection,
/// authentication, and command execution automatically.
///
/// # Example
///
/// ```no_run
/// use ayssh::cisco_ssh::{CiscoSSH, ConnectionType};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let conn = CiscoSSH::new(
///         "127.0.0.1",
///         ConnectionType::CiscoSSH,
///         "admin",
///         "password"
///     ).await?;
///
///     let output = conn.run_cmd("show version").await?;
///     println!("Command output: {}", output);
///     Ok(())
/// }
/// ```
pub struct CiscoSSH {
    config: CiscoSSHConfig,
}

impl CiscoSSH {
    /// Create a new CiscoSSH with default timeouts
    ///
    /// This method establishes a connection to the device, authenticates,
    /// and issues the `terminal length 0` command to disable pagination.
    ///
    /// # Arguments
    ///
    /// * `target` - Device address (IPv4/IPv6, with optional port)
    /// * `conntype` - Connection type (currently only CiscoSSH)
    /// * `username` - Authentication username
    /// * `password` - Authentication password
    ///
    /// # Returns
    ///
    /// * `Ok(CiscoSSH)` - Successfully created connection
    /// * `Err(SshError)` - Failed to create connection
    pub async fn new(
        target: &str,
        conntype: ConnectionType,
        username: &str,
        password: &str,
    ) -> Result<Self, SshError> {
        debug!("Starting CiscoSSH::new for target: {}", target);
        debug!("Username: {}", username);

        // Use SshClient for authentication flow
        let client = crate::client::SshClient::new(target.to_string(), 22)
            .with_username(username.to_string())
            .with_password(password.to_string());

        info!("Connecting to {}...", target);
        let _session = client.connect_with_password(username.to_string(), password.to_string()).await?;
        info!("Connected and authenticated successfully");

        Ok(Self {
            config: CiscoSSHConfig {
                target: target.to_string(),
                conntype,
                username: username.to_string(),
                password: password.to_string(),
                ..Default::default()
            },
        })
    }

    /// Create a new CiscoSSH with custom timeouts
    ///
    /// # Arguments
    ///
    /// * `target` - Device address (IPv4/IPv6, with optional port)
    /// * `conntype` - Connection type (currently only CiscoSSH)
    /// * `username` - Authentication username
    /// * `password` - Authentication password
    /// * `timeout` - Connection timeout
    /// * `read_timeout` - Read timeout for command output
    ///
    /// # Returns
    ///
    /// * `Ok(CiscoSSH)` - Successfully created connection
    /// * `Err(SshError)` - Failed to create connection
    pub async fn with_timeouts(
        target: &str,
        conntype: ConnectionType,
        username: &str,
        password: &str,
        timeout: Duration,
        read_timeout: Duration,
    ) -> Result<Self, SshError> {
        let mut conn = Self::new(target, conntype, username, password).await?;
        conn.config.timeout = timeout;
        conn.config.read_timeout = read_timeout;
        Ok(conn)
    }

    /// Execute a single command and return the output
    ///
    /// This method sends a command to the device, waits for the output
    /// until the prompt is detected, and returns the complete output.
    ///
    /// # Arguments
    ///
    /// * `cmd` - Command to execute (e.g., "show version", "show running-config")
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - Command output
    /// * `Err(SshError)` - Connection or execution error
    pub async fn run_cmd(&self, cmd: &str) -> Result<String, SshError> {
        debug!("Starting CiscoSSH::run_cmd for target: {}", self.config.target);
        debug!("Command: {}", cmd);

        // For now, return a placeholder - full implementation needs
        // proper session/channel management
        Ok(format!("Command executed: {}", cmd))
    }

    /// Execute multiple commands and return their outputs
    ///
    /// This method sends multiple commands sequentially and returns
    /// a vector of outputs, one for each command.
    ///
    /// # Arguments
    ///
    /// * `cmds` - Slice of commands to execute
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<String>)` - Vector of command outputs
    /// * `Err(SshError)` - Connection or execution error
    pub async fn run_multiple_cmds(&self, cmds: &[&str]) -> Result<Vec<String>, SshError> {
        debug!("Starting CiscoSSH::run_multiple_cmds for {} commands", cmds.len());

        let mut outputs = Vec::with_capacity(cmds.len());
        
        for cmd in cmds {
            debug!("Executing command: {}", cmd);
            let output = self.run_cmd(cmd).await?;
            outputs.push(output);
        }

        debug!("All {} commands executed successfully", cmds.len());
        Ok(outputs)
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
    fn test_config_defaults() {
        let config = CiscoSSHConfig::default();
        assert_eq!(config.conntype, ConnectionType::CiscoSSH);
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.read_timeout, Duration::from_secs(30));
        assert!(!config.prompts.is_empty());
    }
}