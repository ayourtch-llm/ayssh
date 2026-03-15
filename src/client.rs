//! SSH Client implementation

use crate::protocol::AuthMethod;
use crate::session::Session;

/// SSH Client for connecting to remote servers
pub struct SshClient {
    host: String,
    port: u16,
}

impl SshClient {
    /// Create a new SSH client
    pub fn new(host: String, port: u16) -> Self {
        Self { host, port }
    }

    /// Get the host
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Connect to the server
    pub async fn connect(&self) -> Result<Session, crate::SshError> {
        // Placeholder implementation
        Ok(Session::new(self.host.clone(), self.port))
    }

    /// Connect with authentication
    pub async fn connect_with_auth(
        &self,
        _auth_method: AuthMethod,
    ) -> Result<Session, crate::SshError> {
        // Placeholder implementation
        let session = Session::new(self.host.clone(), self.port);
        Ok(session)
    }
}
