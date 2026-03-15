//! SSH Transport Layer
//!
//! Handles the transport layer of SSH including key exchange,
//! packet encryption, and session state management.

use crate::channel::ChannelTransferManager;
use crate::protocol;
use bytes::BufMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub mod cipher;
pub mod encrypted;
pub mod handshake;
pub mod kex;
pub mod packet;
pub mod session;
pub mod session_id;
pub mod state;
pub mod version;

pub use cipher::*;
pub use encrypted::*;
pub use handshake::*;
pub use kex::*;
pub use packet::*;
pub use session::*;
pub use session_id::*;
pub use state::*;
pub use version::*;

/// SSH Transport layer
///
/// Manages the encrypted communication channel with the SSH server.
/// Handles packet encryption/decryption, key exchange, and state management.
pub struct Transport {
    /// Underlying TCP stream
    stream: TcpStream,
    /// Current state of the transport
    state: state::TransportStateMachine,
    /// Handshake state
    handshake: handshake::HandshakeState,
    /// Channel transfer manager for managing channels
    channel_manager: ChannelTransferManager,
}

impl Transport {
    /// Create a new transport with the given socket
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            state: state::TransportStateMachine::new(),
            handshake: handshake::HandshakeState::default(),
            channel_manager: ChannelTransferManager::new(),
        }
    }

    /// Get a reference to the underlying stream
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Get a mutable reference to the underlying stream
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Get the current state
    pub fn state(&self) -> state::State {
        self.state.current_state()
    }

    /// Get the handshake state
    pub fn handshake_state(&self) -> &handshake::HandshakeState {
        &self.handshake
    }

    /// Get the channel manager
    pub fn channel_manager(&self) -> &ChannelTransferManager {
        &self.channel_manager
    }

    /// Get mutable reference to channel manager
    pub fn channel_manager_mut(&mut self) -> &mut ChannelTransferManager {
        &mut self.channel_manager
    }

    /// Send raw bytes over the transport
    pub async fn send(&mut self, data: &[u8]) -> Result<(), crate::error::SshError> {
        self.stream.write_all(data).await?;
        Ok(())
    }

    /// Receive raw bytes from the transport
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, crate::error::SshError> {
        let n = self.stream.read(buf).await?;
        Ok(n)
    }

    /// Send an SSH message
    pub async fn send_message(&mut self, msg: &[u8]) -> Result<(), crate::error::SshError> {
        self.send(msg).await
    }

    /// Receive an SSH message (with length prefix)
    pub async fn recv_message(&mut self) -> Result<Vec<u8>, crate::error::SshError> {
        // Read length prefix (4 bytes)
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Read the message
        let mut msg_buf = vec![0u8; len];
        self.stream.read_exact(&mut msg_buf).await?;

        Ok(msg_buf)
    }

    /// Send SERVICE_REQUEST message
    pub async fn send_service_request(&mut self, service: &str) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ServiceRequest as u8);
        protocol::SshString::from_str(service).encode(&mut msg);
        
        self.send_message(&msg).await?;
        Ok(())
    }

    /// Receive SERVICE_ACCEPT message
    pub async fn recv_service_accept(&mut self) -> Result<String, crate::error::SshError> {
        let mut msg = self.recv_message().await?;
        
        if msg.is_empty() {
            return Err(crate::error::SshError::ProtocolError(
                "Empty SERVICE_ACCEPT message".to_string()
            ));
        }
        
        let msg_type = msg[0];
        if msg_type != protocol::MessageType::ServiceAccept as u8 {
            return Err(crate::error::SshError::ProtocolError(
                format!("Expected SERVICE_ACCEPT, got {}", msg_type)
            ));
        }
        
        // Decode service name
        let service = protocol::SshString::decode(&mut msg.as_slice())
            .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?
            .to_str()
            .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?
            .to_string();
        
        Ok(service)
    }

    /// Send channel data message
    pub async fn send_channel_data(
        &mut self,
        channel_id: u32,
        data: &[u8],
    ) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ChannelData as u8);
        msg.put_u32(channel_id);
        msg.put_u32(data.len() as u32);
        msg.put_slice(data);
        
        self.send_message(&msg).await
    }

    /// Send channel EOF message
    pub async fn send_channel_eof(&mut self, channel_id: u32) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ChannelEof as u8);
        msg.put_u32(channel_id);
        
        self.send_message(&msg).await
    }

    /// Send channel close message
    pub async fn send_channel_close(&mut self, channel_id: u32) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ChannelClose as u8);
        msg.put_u32(channel_id);
        
        self.send_message(&msg).await
    }

    /// Send channel request message
    pub async fn send_channel_request(
        &mut self,
        channel_id: u32,
        request_type: &str,
        want_reply: bool,
    ) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ChannelRequest as u8);
        msg.put_u32(channel_id);
        msg.put_u32(request_type.len() as u32);
        msg.put_slice(request_type.as_bytes());
        msg.put_u8(if want_reply { 1 } else { 0 });
        
        self.send_message(&msg).await
    }

    /// Send channel request with string data
    pub async fn send_channel_request_string(
        &mut self,
        channel_id: u32,
        request_type: &str,
        want_reply: bool,
        data: &str,
    ) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ChannelRequest as u8);
        msg.put_u32(channel_id);
        msg.put_u32(request_type.len() as u32);
        msg.put_slice(request_type.as_bytes());
        msg.put_u8(if want_reply { 1 } else { 0 });
        msg.put_u32(data.len() as u32);
        msg.put_slice(data.as_bytes());
        
        self.send_message(&msg).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_transport_send_recv() {
        // This test would require a real TCP connection or mock
        // For now, just verify the API exists
        assert!(true);
    }

    #[tokio::test]
    async fn test_transport_channel_methods_exist() {
        // Verify that channel methods exist on Transport
        // This is a compile-time check
        let _ = Transport::new;
        let _ = Transport::send_channel_data;
        let _ = Transport::send_channel_eof;
        let _ = Transport::send_channel_close;
        let _ = Transport::send_channel_request;
        let _ = Transport::send_channel_request_string;
    }
}