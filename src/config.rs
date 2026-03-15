//! Configuration module for SSH client
//!
//! This module provides configuration structures and utilities
//! for setting up SSH connections.

use std::time::Duration;

/// SSH Client configuration
///
/// This structure holds all the configuration options needed
/// to establish an SSH connection.
#[derive(Debug, Clone)]
pub struct Config {
    /// Hostname or IP address of the SSH server
    pub host: String,
    /// Port number for the SSH connection
    pub port: u16,
    /// Username for authentication
    pub username: String,
    /// Connection timeout duration
    pub timeout: Duration,
    /// Maximum number of retries
    pub max_retries: u32,
    /// Whether to use strict host key checking
    pub strict_host_checking: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: String::from("localhost"),
            port: 22,
            username: String::from("user"),
            timeout: Duration::from_secs(30),
            max_retries: 3,
            strict_host_checking: true,
        }
    }
}

impl Config {
    /// Creates a new default configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration with custom host
    pub fn with_host(mut self, host: &str) -> Self {
        self.host = host.to_string();
        self
    }

    /// Creates a configuration with custom port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Creates a configuration with custom username
    pub fn with_username(mut self, username: &str) -> Self {
        self.username = username.to_string();
        self
    }

    /// Creates a configuration with custom timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns the connection string (host:port)
    pub fn connection_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 22);
        assert_eq!(config.username, "user");
        assert_eq!(config.max_retries, 3);
        assert!(config.strict_host_checking);
    }

    #[test]
    fn test_config_builder() {
        let config = Config::new()
            .with_host("example.com")
            .with_port(2222)
            .with_username("admin");
        
        assert_eq!(config.host, "example.com");
        assert_eq!(config.port, 2222);
        assert_eq!(config.username, "admin");
    }

    #[test]
    fn test_connection_string() {
        let config = Config::new().with_host("ssh.example.com").with_port(2222);
        assert_eq!(config.connection_string(), "ssh.example.com:2222");
    }
}
