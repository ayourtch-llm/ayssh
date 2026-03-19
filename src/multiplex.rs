//! Connection Multiplexing Stub
//!
//! Provides types for multiplexing multiple SSH sessions over a single
//! Transport connection, building on the multi-channel support from Feature 4.
//!
//! Currently implemented:
//! - `SharedTransport` — wraps a Transport in an `Arc<Mutex<>>` for shared access
//! - `MultiplexedSession` — a session handle that references a shared transport
//! - `MultiplexedConnection` — manages multiple sessions over one transport
//!
//! TODO:
//! - Implement actual concurrent I/O (demultiplex incoming data to correct channel)
//! - Add async read/write per channel with proper backpressure
//! - Handle window adjust messages per-channel
//! - Support channel close without tearing down the connection
//! - Integrate with the session module for higher-level operations

use crate::error::SshError;
use crate::transport::Transport;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A shared transport that can be used by multiple sessions.
///
/// Wraps `Transport` in `Arc<Mutex<>>` so multiple `MultiplexedSession`
/// handles can send/receive on the same TCP connection.
#[derive(Debug, Clone)]
pub struct SharedTransport {
    inner: Arc<Mutex<Transport>>,
}

impl SharedTransport {
    /// Create a shared transport from an owned Transport.
    pub fn new(transport: Transport) -> Self {
        Self {
            inner: Arc::new(Mutex::new(transport)),
        }
    }

    /// Get a lock on the underlying transport.
    ///
    /// Callers must hold the lock briefly to avoid starving other sessions.
    pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, Transport> {
        self.inner.lock().await
    }

    /// Get the number of references to this shared transport.
    pub fn ref_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }
}

/// A multiplexed session — one channel on a shared transport.
///
/// Each session has its own local and remote channel IDs but shares
/// the underlying encrypted TCP connection with other sessions.
#[derive(Debug)]
pub struct MultiplexedSession {
    /// Shared transport for I/O
    transport: SharedTransport,
    /// Local channel ID (our side)
    local_channel_id: u32,
    /// Remote channel ID (server side)
    remote_channel_id: u32,
    /// Whether this session's channel is open
    is_open: bool,
}

impl MultiplexedSession {
    /// Send data on this session's channel.
    ///
    /// TODO: Currently acquires a full transport lock for each send.
    /// A production implementation would use a channel-based approach
    /// with a dedicated I/O task.
    pub async fn send(&self, data: &[u8]) -> Result<(), SshError> {
        if !self.is_open {
            return Err(SshError::ChannelError("Session channel is closed".to_string()));
        }
        let mut transport = self.transport.lock().await;
        transport.send_channel_data(self.remote_channel_id, data).await
    }

    /// Get the local channel ID.
    pub fn local_channel_id(&self) -> u32 {
        self.local_channel_id
    }

    /// Get the remote channel ID.
    pub fn remote_channel_id(&self) -> u32 {
        self.remote_channel_id
    }

    /// Check if the session channel is open.
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Mark the session as closed.
    pub fn mark_closed(&mut self) {
        self.is_open = false;
    }
}

/// A multiplexed connection managing multiple sessions over one transport.
///
/// Keeps track of all open sessions and provides methods to open new ones.
#[derive(Debug)]
pub struct MultiplexedConnection {
    /// Shared transport
    transport: SharedTransport,
    /// Open sessions indexed by local channel ID
    sessions: HashMap<u32, MultiplexedSessionInfo>,
}

/// Information about an open multiplexed session.
#[derive(Debug, Clone)]
pub struct MultiplexedSessionInfo {
    /// Local channel ID
    pub local_channel_id: u32,
    /// Remote channel ID
    pub remote_channel_id: u32,
    /// Whether the channel is open
    pub is_open: bool,
}

impl MultiplexedConnection {
    /// Create a new multiplexed connection from an authenticated transport.
    ///
    /// The transport should already have completed handshake and authentication.
    pub fn new(transport: Transport) -> Self {
        Self {
            transport: SharedTransport::new(transport),
            sessions: HashMap::new(),
        }
    }

    /// Open a new session channel on this connection.
    ///
    /// Allocates a new channel ID, sends CHANNEL_OPEN, and waits for
    /// confirmation from the server.
    ///
    /// Returns a `MultiplexedSession` handle for the new channel.
    pub async fn open_session(&mut self) -> Result<MultiplexedSession, SshError> {
        let mut transport = self.transport.lock().await;
        let session = crate::session::Session::open(&mut transport).await?;
        let local_id = session.channel_id();
        let remote_id = session.remote_channel_id();
        drop(transport); // release lock

        let info = MultiplexedSessionInfo {
            local_channel_id: local_id,
            remote_channel_id: remote_id,
            is_open: true,
        };
        self.sessions.insert(local_id, info);

        Ok(MultiplexedSession {
            transport: self.transport.clone(),
            local_channel_id: local_id,
            remote_channel_id: remote_id,
            is_open: true,
        })
    }

    /// Get the number of open sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.values().filter(|s| s.is_open).count()
    }

    /// List all session channel IDs.
    pub fn session_ids(&self) -> Vec<u32> {
        self.sessions.keys().copied().collect()
    }

    /// Get info about a specific session.
    pub fn session_info(&self, local_channel_id: u32) -> Option<&MultiplexedSessionInfo> {
        self.sessions.get(&local_channel_id)
    }

    /// Get a reference to the shared transport.
    pub fn shared_transport(&self) -> &SharedTransport {
        &self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_transport_ref_count() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (client, _server) = tokio::join!(
                tokio::net::TcpStream::connect(addr),
                listener.accept()
            );
            let transport = Transport::new(client.unwrap());
            let shared = SharedTransport::new(transport);
            assert_eq!(shared.ref_count(), 1);

            let shared2 = shared.clone();
            assert_eq!(shared.ref_count(), 2);
            assert_eq!(shared2.ref_count(), 2);

            drop(shared2);
            assert_eq!(shared.ref_count(), 1);
        });
    }

    #[test]
    fn test_multiplexed_connection_creation() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (client, _server) = tokio::join!(
                tokio::net::TcpStream::connect(addr),
                listener.accept()
            );
            let transport = Transport::new(client.unwrap());
            let conn = MultiplexedConnection::new(transport);
            assert_eq!(conn.session_count(), 0);
            assert!(conn.session_ids().is_empty());
        });
    }

    #[test]
    fn test_multiplexed_session_info() {
        let info = MultiplexedSessionInfo {
            local_channel_id: 0,
            remote_channel_id: 42,
            is_open: true,
        };
        assert_eq!(info.local_channel_id, 0);
        assert_eq!(info.remote_channel_id, 42);
        assert!(info.is_open);
    }

    #[test]
    fn test_multiplexed_session_mark_closed() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (client, _server) = tokio::join!(
                tokio::net::TcpStream::connect(addr),
                listener.accept()
            );
            let transport = Transport::new(client.unwrap());
            let shared = SharedTransport::new(transport);
            let mut session = MultiplexedSession {
                transport: shared,
                local_channel_id: 0,
                remote_channel_id: 1,
                is_open: true,
            };
            assert!(session.is_open());
            session.mark_closed();
            assert!(!session.is_open());
        });
    }

    #[test]
    fn test_multiplexed_session_send_when_closed() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (client, _server) = tokio::join!(
                tokio::net::TcpStream::connect(addr),
                listener.accept()
            );
            let transport = Transport::new(client.unwrap());
            let shared = SharedTransport::new(transport);
            let session = MultiplexedSession {
                transport: shared,
                local_channel_id: 0,
                remote_channel_id: 1,
                is_open: false,
            };
            let result = session.send(b"hello").await;
            assert!(result.is_err());
        });
    }
}
