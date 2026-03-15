//! Connection module - SSH connection protocol and channel management

use tracing::info;

use crate::config::Config;
use crate::error::SshError;
use tokio::net::TcpStream;

// Note: These modules will be implemented in later tasks
// pub mod channels;
// pub mod session;
// pub mod exec;
// pub mod forward;

/// Represents an established SSH connection
pub struct Connection {
    /// The underlying transport layer
    transport: Option<Transport>,
    /// Connection configuration
    config: Config,
    /// Whether the connection is established
    is_connected: bool,
}

/// Re-export commonly used items
pub use crate::transport::Transport;

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
    pub async fn connect(&mut self) -> Result<(), SshError> {
        info!("Connecting to {}", self.config.connection_string());

        let addr = self.resolve_address().await?;
        let socket = self.connect_to_address(addr).await?;
        
        self.transport = Some(Transport::new(socket));
        self.is_connected = true;

        info!("Connected to {}", self.config.connection_string());
        Ok(())
    }

    /// Resolves the hostname to an IP address
    async fn resolve_address(&self) -> Result<std::net::SocketAddr, SshError> {
        use tokio::net::lookup_host;
        
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let mut addrs = lookup_host(&addr).await?;
        
        addrs
            .next()
            .ok_or_else(|| SshError::ConnectionError(format!("No address found for {}", addr)))
    }

    /// Connects to the specified address
    async fn connect_to_address(&self, addr: std::net::SocketAddr) -> Result<TcpStream, SshError> {
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
            info!("Disconnecting from {}", self.config.connection_string());
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

