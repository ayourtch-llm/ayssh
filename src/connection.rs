//! Connection module for SSH client
//!
//! This module handles the connection establishment and management
//! for SSH sessions.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::config::Config;
use crate::error::SshError;
use crate::transport::Transport;

/// Represents an established SSH connection
///
/// This structure holds the state and resources needed
/// for an active SSH connection.
pub struct Connection {
    /// The underlying transport layer
    transport: Option<Transport>,
    /// Connection configuration
    config: Config,
    /// Whether the connection is established
    is_connected: bool,
}

impl Connection {
    /// Creates a new connection with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            transport: None,
            config,
            is_connected: false,
        }
    }

    /// Attempts to establish a connection to the SSH server
    ///
    /// # Returns
    /// * `Ok(())` if the connection was successfully established
    /// * `Err(SshError)` if the connection failed
    pub async fn connect(&mut self) -> Result<(), SshError> {
        log::info!("Connecting to {}", self.config.connection_string());

        let addr = self.resolve_address().await?;
        let socket = self.connect_to_address(addr).await?;
        
        self.transport = Some(Transport::new(socket));
        self.is_connected = true;

        log::info!("Connected to {}", self.config.connection_string());
        Ok(())
    }

    /// Resolves the hostname to an IP address
    async fn resolve_address(&self) -> Result<SocketAddr, SshError> {
        use tokio::net::lookup_host;
        
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let mut addrs = lookup_host(&addr).await?;
        
        addrs
            .next()
            .ok_or_else(|| SshError::ConnectionError(format!("No address found for {}", addr)))
    }

    /// Connects to the specified address
    async fn connect_to_address(&self, addr: SocketAddr) -> Result<TcpStream, SshError> {
        let timeout = self.config.timeout;
        
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(SshError::ConnectionError(e.to_string())),
            Err(_) => Err(SshError::TimeoutError),
        }
    }

    /// Closes the connection
    pub async fn disconnect(&mut self) {
        if self.is_connected {
            log::info!("Disconnecting from {}", self.config.connection_string());
            self.transport = None;
            self.is_connected = false;
        }
    }

    /// Checks if the connection is established
    pub fn is_connected(&self) -> bool {
        self.is_connected
    }

    /// Returns a reference to the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_creation() {
        let config = Config::new();
        let connection = Connection::new(config);
        
        assert!(!connection.is_connected());
        assert_eq!(connection.config().host, "localhost");
    }

    #[test]
    fn test_connection_with_custom_config() {
        let config = Config::new()
            .with_host("example.com")
            .with_port(2222);
        let connection = Connection::new(config);
        
        assert_eq!(connection.config().host, "example.com");
        assert_eq!(connection.config().port, 2222);
    }
}
