//! Connection module - SSH connection protocol and channel management

use tracing::{info, debug};

use crate::config::Config;
use crate::error::SshError;
use crate::session::SessionManager;
use tokio::net::TcpStream;

// Connection state machine
pub mod state;

/// Represents an established SSH connection
pub struct Connection {
    /// The underlying transport layer
    transport: Option<Transport>,
    /// Session manager for handling session channels
    session_manager: SessionManager,
    /// Connection configuration
    config: Config,
    /// Whether the connection is established
    is_connected: bool,
}

/// Re-export commonly used items
pub use crate::transport::Transport;
pub use state::ConnectionStateMachine;

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("is_connected", &self.is_connected)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Creates a new connection with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            transport: None,
            session_manager: SessionManager::new(),
            config,
            is_connected: false,
        }
    }

    /// Attempts to establish a connection to the SSH server
    pub async fn connect(&mut self) -> Result<(), SshError> {
        info!("Connecting to {}", self.config.connection_string());

        let addr = self.resolve_address().await?;
        debug!("Resolved address: {:?}", addr);
        
        let socket = self.connect_to_address(addr).await?;
        debug!("TCP connection established");
        
        self.transport = Some(Transport::new(socket));
        self.is_connected = true;

        info!("Connected to {}", self.config.connection_string());
        Ok(())
    }

    /// Resolve the hostname to an IP address
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

    /// Get mutable reference to transport
    pub fn transport_mut(&mut self) -> Option<&mut Transport> {
        self.transport.as_mut()
    }

    /// Get reference to session manager
    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }

    /// Get mutable reference to session manager
    pub fn session_manager_mut(&mut self) -> &mut SessionManager {
        &mut self.session_manager
    }

    /// Create a new session channel
    pub fn create_session_channel(&mut self, originator_address: &str, originator_port: u16) -> u32 {
        self.session_manager.create_session(originator_address, originator_port)
    }

    /// Get session by ID
    pub fn get_session(&self, channel_id: u32) -> Option<&crate::session::Session> {
        self.session_manager.get_session(channel_id)
    }

    /// Get mutable session by ID
    pub fn get_session_mut(&mut self, channel_id: u32) -> Option<&mut crate::session::Session> {
        self.session_manager.get_session_mut(channel_id)
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<u32> {
        self.session_manager.list_sessions()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.session_manager.session_count()
    }
}

