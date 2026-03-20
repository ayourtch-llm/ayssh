//! SSH TCP Port Forwarding (RFC 4254 Sections 7.1-7.2)
//!
//! Provides types and message builders for SSH port forwarding:
//!
//! - **Local forwarding (-L)**: `LocalForward` listens on a local TCP port and
//!   forwards each accepted connection through the SSH tunnel as a "direct-tcpip"
//!   channel to a remote host:port.
//!
//! - **Remote forwarding (-R)**: `RemoteForwardRequest` builds the
//!   SSH_MSG_GLOBAL_REQUEST for "tcpip-forward" and can parse the resulting
//!   "forwarded-tcpip" channel-open messages from the server.
//!
//! # Wire formats
//!
//! ## direct-tcpip channel open (RFC 4254 Section 7.2)
//! ```text
//! byte      SSH_MSG_CHANNEL_OPEN (90)
//! string    "direct-tcpip"
//! uint32    sender channel
//! uint32    initial window size
//! uint32    maximum packet size
//! string    host to connect
//! uint32    port to connect
//! string    originator IP address
//! uint32    originator port
//! ```
//!
//! ## tcpip-forward global request (RFC 4254 Section 7.1)
//! ```text
//! byte      SSH_MSG_GLOBAL_REQUEST (80)
//! string    "tcpip-forward"
//! boolean   want reply
//! string    address to bind
//! uint32    port number to bind
//! ```

use bytes::BufMut;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::error::SshError;
use crate::protocol::MessageType;
use crate::transport::Transport;

// --- Constants ---

/// Default initial window size for forwarded channels (1 MB).
const DEFAULT_WINDOW_SIZE: u32 = 1_048_576;

/// Default maximum packet size for forwarded channels (32 KB).
const DEFAULT_MAX_PACKET_SIZE: u32 = 32_768;

// --- Helper: SSH wire encoding ---

/// Write an SSH string (uint32 length + bytes) into a buffer.
fn put_ssh_string(buf: &mut Vec<u8>, s: &[u8]) {
    buf.put_u32(s.len() as u32);
    buf.extend_from_slice(s);
}

/// Read an SSH string from `data[offset..]`. Returns `(bytes, new_offset)`.
fn read_ssh_string(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize), SshError> {
    if offset + 4 > data.len() {
        return Err(SshError::ProtocolError(
            "Not enough data for SSH string length".into(),
        ));
    }
    let len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let start = offset + 4;
    if start + len > data.len() {
        return Err(SshError::ProtocolError(format!(
            "SSH string length {} exceeds available data ({})",
            len,
            data.len() - start
        )));
    }
    Ok((data[start..start + len].to_vec(), start + len))
}

/// Read a uint32 from `data[offset..]`. Returns `(value, new_offset)`.
fn read_u32(data: &[u8], offset: usize) -> Result<(u32, usize), SshError> {
    if offset + 4 > data.len() {
        return Err(SshError::ProtocolError(
            "Not enough data for uint32".into(),
        ));
    }
    let val = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    Ok((val, offset + 4))
}

// ---------------------------------------------------------------------------
// direct-tcpip channel open message
// ---------------------------------------------------------------------------

/// Parameters for a "direct-tcpip" channel open request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectTcpipParams {
    /// Host the server should connect to.
    pub host_to_connect: String,
    /// Port the server should connect to.
    pub port_to_connect: u16,
    /// IP address of the originator (client side).
    pub originator_address: String,
    /// Port of the originator (client side).
    pub originator_port: u16,
}

impl DirectTcpipParams {
    /// Encode a full SSH_MSG_CHANNEL_OPEN "direct-tcpip" message.
    ///
    /// The caller supplies the sender channel ID; window and packet sizes
    /// use sensible defaults.
    pub fn encode_channel_open(&self, sender_channel: u32) -> Vec<u8> {
        self.encode_channel_open_with(sender_channel, DEFAULT_WINDOW_SIZE, DEFAULT_MAX_PACKET_SIZE)
    }

    /// Encode with explicit window / packet sizes.
    pub fn encode_channel_open_with(
        &self,
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.put_u8(MessageType::ChannelOpen.value()); // 90
        put_ssh_string(&mut buf, b"direct-tcpip");
        buf.put_u32(sender_channel);
        buf.put_u32(initial_window_size);
        buf.put_u32(maximum_packet_size);
        put_ssh_string(&mut buf, self.host_to_connect.as_bytes());
        buf.put_u32(self.port_to_connect as u32);
        put_ssh_string(&mut buf, self.originator_address.as_bytes());
        buf.put_u32(self.originator_port as u32);
        buf
    }

    /// Decode a "direct-tcpip" channel open message.
    ///
    /// `data` should include the leading SSH_MSG_CHANNEL_OPEN byte (90).
    /// Returns `(sender_channel, initial_window_size, max_packet_size, params)`.
    pub fn decode_channel_open(
        data: &[u8],
    ) -> Result<(u32, u32, u32, DirectTcpipParams), SshError> {
        if data.is_empty() || data[0] != MessageType::ChannelOpen.value() {
            return Err(SshError::ProtocolError(
                "Not a CHANNEL_OPEN message".into(),
            ));
        }
        let offset = 1;
        // channel type string
        let (channel_type, offset) = read_ssh_string(data, offset)?;
        if channel_type != b"direct-tcpip" {
            return Err(SshError::ProtocolError(format!(
                "Expected direct-tcpip, got {:?}",
                String::from_utf8_lossy(&channel_type)
            )));
        }
        let (sender_channel, offset) = read_u32(data, offset)?;
        let (initial_window_size, offset) = read_u32(data, offset)?;
        let (maximum_packet_size, offset) = read_u32(data, offset)?;
        let (host_bytes, offset) = read_ssh_string(data, offset)?;
        let (port_to_connect, offset) = read_u32(data, offset)?;
        let (orig_bytes, offset) = read_ssh_string(data, offset)?;
        let (originator_port, _offset) = read_u32(data, offset)?;

        let host_to_connect = String::from_utf8(host_bytes)
            .map_err(|e| SshError::ProtocolError(format!("Invalid UTF-8 in host: {}", e)))?;
        let originator_address = String::from_utf8(orig_bytes)
            .map_err(|e| SshError::ProtocolError(format!("Invalid UTF-8 in originator: {}", e)))?;

        Ok((
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            DirectTcpipParams {
                host_to_connect,
                port_to_connect: port_to_connect as u16,
                originator_address,
                originator_port: originator_port as u16,
            },
        ))
    }
}

// ---------------------------------------------------------------------------
// Local port forwarding (-L)
// ---------------------------------------------------------------------------

/// Local TCP port forwarding.
///
/// Listens on a local TCP port. When a client connects, opens a "direct-tcpip"
/// SSH channel to forward traffic to the specified remote host:port.
///
/// This is the infrastructure layer — it builds and parses the relevant SSH
/// messages and manages the listener lifecycle. A full bidirectional proxy
/// (copying bytes between the TCP socket and the SSH channel) is left to the
/// caller.
#[derive(Debug)]
pub struct LocalForward {
    transport: Arc<Mutex<Transport>>,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    /// Handle to the background listener task, if running.
    listener_handle: Option<tokio::task::JoinHandle<()>>,
    /// Shutdown signal sender.
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl LocalForward {
    /// Start local port forwarding.
    ///
    /// Binds a TCP listener on `127.0.0.1:local_port`. Returns immediately
    /// after the listener is bound. The actual accept loop is **not** spawned
    /// automatically — call [`accept_once`] or integrate with your own event
    /// loop.
    ///
    /// If `local_port` is 0, the OS picks an ephemeral port. Use
    /// [`local_port()`] to discover the assigned port.
    pub async fn start(
        transport: Arc<Mutex<Transport>>,
        local_port: u16,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<Self, SshError> {
        // Validate early — bind the listener to confirm the port is available.
        let addr = format!("127.0.0.1:{}", local_port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| SshError::ConnectionError(format!("Bind {}: {}", addr, e)))?;
        let actual_port = listener.local_addr()
            .map_err(|e| SshError::ConnectionError(format!("local_addr: {}", e)))?
            .port();

        // We drop the listener here — the caller will re-bind or we could
        // store it. For now the struct just records the parameters.
        drop(listener);

        Ok(Self {
            transport,
            local_port: actual_port,
            remote_host: remote_host.to_string(),
            remote_port,
            listener_handle: None,
            shutdown_tx: None,
        })
    }

    /// The local port the forwarder is (or was) bound to.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// The remote host traffic is forwarded to.
    pub fn remote_host(&self) -> &str {
        &self.remote_host
    }

    /// The remote port traffic is forwarded to.
    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }

    /// Build a "direct-tcpip" CHANNEL_OPEN message for a new forwarded
    /// connection originating from `originator_addr:originator_port`.
    pub fn build_channel_open(
        &self,
        sender_channel: u32,
        originator_addr: &str,
        originator_port: u16,
    ) -> Vec<u8> {
        let params = DirectTcpipParams {
            host_to_connect: self.remote_host.clone(),
            port_to_connect: self.remote_port,
            originator_address: originator_addr.to_string(),
            originator_port,
        };
        params.encode_channel_open(sender_channel)
    }

    /// Stop forwarding and cancel any background listener task.
    pub async fn stop(&mut self) -> Result<(), SshError> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.listener_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Remote port forwarding (-R)
// ---------------------------------------------------------------------------

/// Request the server to listen on a remote address:port and forward
/// incoming connections back through the SSH tunnel.
///
/// This builds the SSH_MSG_GLOBAL_REQUEST "tcpip-forward" message and can
/// parse the "forwarded-tcpip" channel-open messages that the server sends
/// when a connection arrives.
///
/// Actual forwarding (accepting the channel, proxying bytes) is TODO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteForwardRequest {
    /// Address the server should bind to (e.g. "0.0.0.0" or "localhost").
    pub bind_address: String,
    /// Port the server should bind to. 0 means the server picks a port.
    pub bind_port: u16,
}

impl RemoteForwardRequest {
    /// Build an SSH_MSG_GLOBAL_REQUEST for "tcpip-forward".
    ///
    /// ```text
    /// byte      SSH_MSG_GLOBAL_REQUEST (80)
    /// string    "tcpip-forward"
    /// boolean   want reply (true)
    /// string    address to bind
    /// uint32    port number to bind
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.put_u8(MessageType::GlobalRequest.value()); // 80
        put_ssh_string(&mut buf, b"tcpip-forward");
        buf.put_u8(1); // want reply = true
        put_ssh_string(&mut buf, self.bind_address.as_bytes());
        buf.put_u32(self.bind_port as u32);
        buf
    }

    /// Build an SSH_MSG_GLOBAL_REQUEST for "cancel-tcpip-forward".
    pub fn encode_cancel(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.put_u8(MessageType::GlobalRequest.value()); // 80
        put_ssh_string(&mut buf, b"cancel-tcpip-forward");
        buf.put_u8(0); // want reply = false
        put_ssh_string(&mut buf, self.bind_address.as_bytes());
        buf.put_u32(self.bind_port as u32);
        buf
    }

    /// Parse a "forwarded-tcpip" channel-open message from the server.
    ///
    /// ```text
    /// byte      SSH_MSG_CHANNEL_OPEN (90)
    /// string    "forwarded-tcpip"
    /// uint32    sender channel
    /// uint32    initial window size
    /// uint32    maximum packet size
    /// string    address that was connected
    /// uint32    port that was connected
    /// string    originator IP address
    /// uint32    originator port
    /// ```
    pub fn parse_forwarded_channel(data: &[u8]) -> Result<ForwardedChannel, SshError> {
        if data.is_empty() || data[0] != MessageType::ChannelOpen.value() {
            return Err(SshError::ProtocolError(
                "Not a CHANNEL_OPEN message".into(),
            ));
        }
        let offset = 1;
        let (channel_type, offset) = read_ssh_string(data, offset)?;
        if channel_type != b"forwarded-tcpip" {
            return Err(SshError::ProtocolError(format!(
                "Expected forwarded-tcpip, got {:?}",
                String::from_utf8_lossy(&channel_type)
            )));
        }
        let (sender_channel, offset) = read_u32(data, offset)?;
        let (initial_window_size, offset) = read_u32(data, offset)?;
        let (maximum_packet_size, offset) = read_u32(data, offset)?;
        let (connected_addr_bytes, offset) = read_ssh_string(data, offset)?;
        let (connected_port, offset) = read_u32(data, offset)?;
        let (originator_bytes, offset) = read_ssh_string(data, offset)?;
        let (originator_port, _offset) = read_u32(data, offset)?;

        let connected_address = String::from_utf8(connected_addr_bytes)
            .map_err(|e| SshError::ProtocolError(format!("Invalid UTF-8 in address: {}", e)))?;
        let originator_address = String::from_utf8(originator_bytes)
            .map_err(|e| SshError::ProtocolError(format!("Invalid UTF-8 in originator: {}", e)))?;

        Ok(ForwardedChannel {
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            connected_address,
            connected_port: connected_port as u16,
            originator_address,
            originator_port: originator_port as u16,
        })
    }
}

/// A parsed "forwarded-tcpip" channel-open from the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedChannel {
    /// The server's channel ID.
    pub sender_channel: u32,
    /// Initial window size offered by the server.
    pub initial_window_size: u32,
    /// Maximum packet size.
    pub maximum_packet_size: u32,
    /// Address the server received the connection on.
    pub connected_address: String,
    /// Port the server received the connection on.
    pub connected_port: u16,
    /// IP of the remote party that connected to the server.
    pub originator_address: String,
    /// Port of the remote party.
    pub originator_port: u16,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DirectTcpipParams encoding / decoding --

    #[test]
    fn test_direct_tcpip_encode_decode_roundtrip() {
        let params = DirectTcpipParams {
            host_to_connect: "10.0.0.1".into(),
            port_to_connect: 8080,
            originator_address: "127.0.0.1".into(),
            originator_port: 54321,
        };
        let encoded = params.encode_channel_open(7);
        let (sender_ch, win, pkt, decoded) =
            DirectTcpipParams::decode_channel_open(&encoded).unwrap();

        assert_eq!(sender_ch, 7);
        assert_eq!(win, DEFAULT_WINDOW_SIZE);
        assert_eq!(pkt, DEFAULT_MAX_PACKET_SIZE);
        assert_eq!(decoded, params);
    }

    #[test]
    fn test_direct_tcpip_encode_decode_with_custom_sizes() {
        let params = DirectTcpipParams {
            host_to_connect: "example.com".into(),
            port_to_connect: 443,
            originator_address: "192.168.1.100".into(),
            originator_port: 12345,
        };
        let encoded = params.encode_channel_open_with(42, 2_000_000, 64_000);
        let (sender_ch, win, pkt, decoded) =
            DirectTcpipParams::decode_channel_open(&encoded).unwrap();

        assert_eq!(sender_ch, 42);
        assert_eq!(win, 2_000_000);
        assert_eq!(pkt, 64_000);
        assert_eq!(decoded, params);
    }

    #[test]
    fn test_direct_tcpip_message_starts_with_channel_open() {
        let params = DirectTcpipParams {
            host_to_connect: "host".into(),
            port_to_connect: 22,
            originator_address: "127.0.0.1".into(),
            originator_port: 1000,
        };
        let encoded = params.encode_channel_open(0);
        assert_eq!(encoded[0], 90); // SSH_MSG_CHANNEL_OPEN
    }

    #[test]
    fn test_direct_tcpip_decode_wrong_message_type() {
        let data = vec![91, 0, 0, 0, 12]; // not 90
        let result = DirectTcpipParams::decode_channel_open(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CHANNEL_OPEN"));
    }

    #[test]
    fn test_direct_tcpip_decode_wrong_channel_type() {
        // Build a valid CHANNEL_OPEN but with "session" instead of "direct-tcpip"
        let mut buf = Vec::new();
        buf.put_u8(90);
        put_ssh_string(&mut buf, b"session");
        buf.put_u32(0); // sender
        buf.put_u32(0); // window
        buf.put_u32(0); // packet
        // no extra fields needed — should fail before reading them
        let result = DirectTcpipParams::decode_channel_open(&buf);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("direct-tcpip"));
    }

    #[test]
    fn test_direct_tcpip_decode_truncated() {
        let data = vec![90, 0, 0];
        let result = DirectTcpipParams::decode_channel_open(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_direct_tcpip_decode_empty() {
        let result = DirectTcpipParams::decode_channel_open(&[]);
        assert!(result.is_err());
    }

    // -- RemoteForwardRequest encoding --

    #[test]
    fn test_remote_forward_encode() {
        let req = RemoteForwardRequest {
            bind_address: "0.0.0.0".into(),
            bind_port: 8080,
        };
        let encoded = req.encode();
        assert_eq!(encoded[0], 80); // SSH_MSG_GLOBAL_REQUEST

        // Verify "tcpip-forward" string
        let (name, offset) = read_ssh_string(&encoded, 1).unwrap();
        assert_eq!(name, b"tcpip-forward");

        // want reply
        assert_eq!(encoded[offset], 1);
        let offset = offset + 1;

        // bind address
        let (addr, offset) = read_ssh_string(&encoded, offset).unwrap();
        assert_eq!(addr, b"0.0.0.0");

        // bind port
        let (port, _) = read_u32(&encoded, offset).unwrap();
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_remote_forward_encode_cancel() {
        let req = RemoteForwardRequest {
            bind_address: "localhost".into(),
            bind_port: 9090,
        };
        let encoded = req.encode_cancel();
        assert_eq!(encoded[0], 80);

        let (name, offset) = read_ssh_string(&encoded, 1).unwrap();
        assert_eq!(name, b"cancel-tcpip-forward");

        // want reply = false
        assert_eq!(encoded[offset], 0);
        let offset = offset + 1;

        let (addr, offset) = read_ssh_string(&encoded, offset).unwrap();
        assert_eq!(addr, b"localhost");

        let (port, _) = read_u32(&encoded, offset).unwrap();
        assert_eq!(port, 9090);
    }

    #[test]
    fn test_remote_forward_encode_port_zero() {
        let req = RemoteForwardRequest {
            bind_address: "".into(),
            bind_port: 0,
        };
        let encoded = req.encode();
        // Just verify it doesn't panic and starts correctly
        assert_eq!(encoded[0], 80);
    }

    // -- ForwardedChannel parsing --

    #[test]
    fn test_forwarded_channel_roundtrip() {
        // Build a "forwarded-tcpip" message manually
        let mut buf = Vec::new();
        buf.put_u8(90); // CHANNEL_OPEN
        put_ssh_string(&mut buf, b"forwarded-tcpip");
        buf.put_u32(5);           // sender channel
        buf.put_u32(1_000_000);   // window
        buf.put_u32(32_000);      // max packet
        put_ssh_string(&mut buf, b"0.0.0.0");  // connected address
        buf.put_u32(8080);        // connected port
        put_ssh_string(&mut buf, b"10.1.1.50"); // originator
        buf.put_u32(54321);       // originator port

        let fc = RemoteForwardRequest::parse_forwarded_channel(&buf).unwrap();
        assert_eq!(fc.sender_channel, 5);
        assert_eq!(fc.initial_window_size, 1_000_000);
        assert_eq!(fc.maximum_packet_size, 32_000);
        assert_eq!(fc.connected_address, "0.0.0.0");
        assert_eq!(fc.connected_port, 8080);
        assert_eq!(fc.originator_address, "10.1.1.50");
        assert_eq!(fc.originator_port, 54321);
    }

    #[test]
    fn test_forwarded_channel_wrong_type() {
        let mut buf = Vec::new();
        buf.put_u8(90);
        put_ssh_string(&mut buf, b"direct-tcpip");
        buf.put_u32(0);
        let result = RemoteForwardRequest::parse_forwarded_channel(&buf);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("forwarded-tcpip"));
    }

    #[test]
    fn test_forwarded_channel_not_channel_open() {
        let result = RemoteForwardRequest::parse_forwarded_channel(&[80]);
        assert!(result.is_err());
    }

    #[test]
    fn test_forwarded_channel_empty() {
        let result = RemoteForwardRequest::parse_forwarded_channel(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_forwarded_channel_truncated() {
        let mut buf = Vec::new();
        buf.put_u8(90);
        put_ssh_string(&mut buf, b"forwarded-tcpip");
        buf.put_u32(5);
        // Missing remaining fields
        let result = RemoteForwardRequest::parse_forwarded_channel(&buf);
        assert!(result.is_err());
    }

    // -- LocalForward --

    #[tokio::test]
    async fn test_local_forward_start_and_stop() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, _server) = tokio::join!(
            tokio::net::TcpStream::connect(addr),
            listener.accept()
        );
        let transport = Transport::new(client.unwrap());
        let shared = Arc::new(Mutex::new(transport));

        let mut fwd = LocalForward::start(
            shared,
            0, // ephemeral port
            "10.0.0.1",
            80,
        )
        .await
        .unwrap();

        assert!(fwd.local_port() > 0);
        assert_eq!(fwd.remote_host(), "10.0.0.1");
        assert_eq!(fwd.remote_port(), 80);

        fwd.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_local_forward_build_channel_open() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, _server) = tokio::join!(
            tokio::net::TcpStream::connect(addr),
            listener.accept()
        );
        let transport = Transport::new(client.unwrap());
        let shared = Arc::new(Mutex::new(transport));

        let fwd = LocalForward::start(shared, 0, "db.internal", 5432)
            .await
            .unwrap();

        let msg = fwd.build_channel_open(99, "127.0.0.1", 44444);

        // Decode it back
        let (sender_ch, _win, _pkt, params) =
            DirectTcpipParams::decode_channel_open(&msg).unwrap();
        assert_eq!(sender_ch, 99);
        assert_eq!(params.host_to_connect, "db.internal");
        assert_eq!(params.port_to_connect, 5432);
        assert_eq!(params.originator_address, "127.0.0.1");
        assert_eq!(params.originator_port, 44444);
    }

    // -- Debug impls --

    #[test]
    fn test_direct_tcpip_params_debug() {
        let params = DirectTcpipParams {
            host_to_connect: "host".into(),
            port_to_connect: 22,
            originator_address: "127.0.0.1".into(),
            originator_port: 1000,
        };
        let debug = format!("{:?}", params);
        assert!(debug.contains("DirectTcpipParams"));
        assert!(debug.contains("host"));
    }

    #[test]
    fn test_remote_forward_request_debug() {
        let req = RemoteForwardRequest {
            bind_address: "0.0.0.0".into(),
            bind_port: 8080,
        };
        let debug = format!("{:?}", req);
        assert!(debug.contains("RemoteForwardRequest"));
        assert!(debug.contains("8080"));
    }

    #[test]
    fn test_forwarded_channel_debug() {
        let fc = ForwardedChannel {
            sender_channel: 1,
            initial_window_size: 100,
            maximum_packet_size: 200,
            connected_address: "host".into(),
            connected_port: 80,
            originator_address: "10.0.0.1".into(),
            originator_port: 9999,
        };
        let debug = format!("{:?}", fc);
        assert!(debug.contains("ForwardedChannel"));
        assert!(debug.contains("9999"));
    }

    // -- Wire format helpers --

    #[test]
    fn test_read_ssh_string_valid() {
        let mut buf = Vec::new();
        put_ssh_string(&mut buf, b"hello");
        let (s, offset) = read_ssh_string(&buf, 0).unwrap();
        assert_eq!(s, b"hello");
        assert_eq!(offset, 9); // 4 + 5
    }

    #[test]
    fn test_read_ssh_string_empty() {
        let mut buf = Vec::new();
        put_ssh_string(&mut buf, b"");
        let (s, offset) = read_ssh_string(&buf, 0).unwrap();
        assert_eq!(s, b"");
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_read_ssh_string_truncated_length() {
        let result = read_ssh_string(&[0, 0], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_ssh_string_truncated_data() {
        let buf = vec![0, 0, 0, 10, 1, 2]; // claims 10 bytes, only 2 present
        let result = read_ssh_string(&buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_u32_valid() {
        let buf = vec![0, 0, 0, 42];
        let (val, offset) = read_u32(&buf, 0).unwrap();
        assert_eq!(val, 42);
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_read_u32_truncated() {
        let result = read_u32(&[0, 0], 0);
        assert!(result.is_err());
    }
}
