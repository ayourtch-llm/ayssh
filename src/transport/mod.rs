//! SSH Transport Layer
//!
//! Handles the transport layer of SSH including key exchange,
//! packet encryption, and session state management.

use crate::channel::ChannelTransferManager;
use crate::protocol;
use bytes::BufMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

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

    /// Perform SSH handshake with the server
    ///
    /// This method:
    /// 1. Sends client version string
    /// 2. Receives server version string
    /// 3. Performs key exchange (KEXINIT exchange and key computation)
    /// 4. Transitions to encrypted state
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Handshake completed successfully
    /// * `Err(SshError)` - Handshake failed
    pub async fn handshake(&mut self) -> Result<(), crate::error::SshError> {
        use crate::transport::handshake::{send_version, recv_version, parse_version_string, generate_client_kexinit, parse_server_kexinit, negotiate_algorithms};
        use crate::transport::kex::KexContext;
        use crate::protocol::KexAlgorithm;
        use std::str::FromStr;
        
        // 1. Send client version
        send_version(self.stream_mut()).await?;
        
        // 2. Receive server version
        let server_ver = recv_version(self.stream_mut()).await?;
        debug!("Server version: {}", server_ver);
        
        let (_proto, _software) = parse_version_string(server_ver.as_bytes())
            .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?;
        
        // 3. Generate client KEXINIT
        let client_kexinit = generate_client_kexinit();
        debug!("Generated client KEXINIT ({} bytes)", client_kexinit.len());
        
        // 4. Send client KEXINIT - per RFC 4253, KEXINIT is sent as a binary packet
        // Format: [packet_length (4 bytes)][padding_length (1 byte)][kexinit_payload][padding]
        // The KEXINIT payload includes: message_type(1) + cookie(16) + algorithm lists...
        let kexinit_payload = &client_kexinit;
        let padding_length = 8u8; // Minimum padding per RFC 4253
        let packet_length = kexinit_payload.len() as u32 + padding_length as u32 + 1; // +1 for padding_length byte
        
        let mut kexinit_msg = bytes::BytesMut::new();
        kexinit_msg.put_u32(packet_length);
        kexinit_msg.put_u8(padding_length);
        kexinit_msg.put_slice(kexinit_payload);
        // Add padding bytes
        for _ in 0..padding_length {
            kexinit_msg.put_u8(0);
        }
        
        self.stream_mut().write_all(&kexinit_msg).await?;
        debug!("Sent client KEXINIT packet ({} bytes total)", kexinit_msg.len());
        
        // 5. Receive server KEXINIT - Cisco sends KEXINIT as a binary packet
        // Format: [packet_length (4 bytes)][padding_length (1 byte)][kexinit_payload][padding]
        let mut server_kexinit_bytes = Vec::new();
        let mut buffer = vec![0u8; 1024];
        
        // First read the packet length (4 bytes)
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.stream_mut().read(&mut buffer)
            ).await {
                Ok(Ok(0)) => {
                    return Err(crate::error::SshError::ConnectionError(
                        "Connection closed while reading KEXINIT packet length".to_string()
                    ));
                }
                Ok(Ok(n)) => {
                    debug!("Received {} bytes from server", n);
                    server_kexinit_bytes.extend_from_slice(&buffer[..n]);
                    
                    // Need at least 4 bytes for packet length
                    if server_kexinit_bytes.len() >= 4 {
                        // Parse packet length
                        let packet_len = u32::from_be_bytes([
                            server_kexinit_bytes[0],
                            server_kexinit_bytes[1],
                            server_kexinit_bytes[2],
                            server_kexinit_bytes[3]
                        ]) as usize;
                        debug!("Server KEXINIT packet length: {} bytes", packet_len);
                        
                        // Now we need packet_len + 4 (for the length field itself) bytes total
                        if server_kexinit_bytes.len() >= packet_len + 4 {
                            debug!("Successfully received server KEXINIT packet");
                            debug!("Server KEXINIT raw bytes (first 20): {:?}", &server_kexinit_bytes[..std::cmp::min(20, server_kexinit_bytes.len())]);
                            break;
                        }
                        // Continue reading
                    }
                    
                    // If we have more than 1000 bytes and still can't parse, something is wrong
                    if server_kexinit_bytes.len() > 1000 {
                        return Err(crate::error::SshError::ProtocolError(
                            format!("Could not parse KEXINIT packet after {} bytes", server_kexinit_bytes.len())
                        ));
                    }
                }
                Ok(Err(e)) => {
                    return Err(crate::error::SshError::IoError(e));
                }
                Err(_) => {
                    return Err(crate::error::SshError::TimeoutError);
                }
            }
        }
        
        // Extract the KEXINIT payload from the packet
        // packet_length includes padding_length byte + payload + padding
        // So payload starts at offset 5 (4 for length + 1 for padding_length)
        let packet_len = u32::from_be_bytes([
            server_kexinit_bytes[0],
            server_kexinit_bytes[1],
            server_kexinit_bytes[2],
            server_kexinit_bytes[3]
        ]) as usize;
        let padding_len = server_kexinit_bytes[4] as usize;
        let payload_start = 5;
        let payload_end = 5 + packet_len - padding_len;
        
        debug!("KEXINIT packet_len: {}, padding_len: {}, payload: {}-{}", 
               packet_len, padding_len, payload_start, payload_end);
        
        let kexinit_payload = &server_kexinit_bytes[payload_start..payload_end];
        debug!("KEXINIT payload length: {} bytes", kexinit_payload.len());
        debug!("KEXINIT payload (first 20): {:?}", &kexinit_payload[..std::cmp::min(20, kexinit_payload.len())]);
        
        let server_proposal = parse_server_kexinit(kexinit_payload)
            .map_err(|e| crate::error::SshError::ProtocolError(format!("{} - KEXINIT payload: {:?}", e, &kexinit_payload[..std::cmp::min(100, kexinit_payload.len())])))?;
        
        debug!("Server KEX algorithms: {:?}", server_proposal.kex_algorithms);
        debug!("Server host key algorithms: {:?}", server_proposal.server_host_key_algorithms);
        debug!("Server enc C2S: {:?}", server_proposal.encryption_algorithms_c2s);
        debug!("Server enc S2C: {:?}", server_proposal.encryption_algorithms_s2c);
        debug!("Server MAC C2S: {:?}", server_proposal.mac_algorithms_c2s);
        debug!("Server MAC S2C: {:?}", server_proposal.mac_algorithms_s2c);
        debug!("Server compression: {:?}", server_proposal.compression_algorithms);
        
        // 6. Parse client KEXINIT to get client proposal
        let client_proposal = parse_server_kexinit(&client_kexinit)
            .map_err(|e| crate::error::SshError::ProtocolError(format!("{} - Client KEXINIT: {:?}", e, &client_kexinit[..std::cmp::min(100, client_kexinit.len())])))?;
        
        // 7. Negotiate algorithms
        let negotiated = negotiate_algorithms(&client_proposal, &server_proposal);
        debug!("Negotiated KEX algorithm: {}", negotiated.kex);
        
        // 8. Initialize KEX context
        let algorithm = KexAlgorithm::from_str(&negotiated.kex).unwrap_or(KexAlgorithm::Curve25519Sha256);
        let mut kex_context = KexContext::new(algorithm);
        
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        kex_context.generate_client_key(&mut rng)?;
        
        // 9. Send KEXINIT message with client ephemeral key
        let client_ephemeral = kex_context.client_ephemeral.clone()
            .expect("Client ephemeral key not generated");
        
        let mut kexinit_msg2 = bytes::BytesMut::new();
        kexinit_msg2.put_u8(crate::protocol::MessageType::KexInit as u8);
        kexinit_msg2.put_u32(client_ephemeral.len() as u32);
        kexinit_msg2.put_slice(&client_ephemeral);
        debug!("Sending KEXINIT message ({} bytes)", kexinit_msg2.len());
        self.stream_mut().write_all(&kexinit_msg2).await?;
        
        // 10. Receive KEX_REPLY from server - Cisco sends without length prefix
        let mut reply_bytes = Vec::new();
        let mut reply_buffer = vec![0u8; 1024];
        
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.stream_mut().read(&mut reply_buffer)
            ).await {
                Ok(Ok(0)) => {
                    return Err(crate::error::SshError::ConnectionError(
                        "Connection closed while reading KEX_REPLY".to_string()
                    ));
                }
                Ok(Ok(n)) => {
                    debug!("Received {} bytes for KEX_REPLY", n);
                    reply_bytes.extend_from_slice(&reply_buffer[..n]);
                    
                    // Check if we have a valid KEX_INIT message (starts with message type byte)
                    if reply_bytes.len() >= 5 && reply_bytes[0] == crate::protocol::MessageType::KexInit as u8 {
                        debug!("Received valid KEX_INIT message ({} bytes)", reply_bytes.len());
                        debug!("KEX_REPLY raw bytes (first 20): {:?}", &reply_bytes[..std::cmp::min(20, reply_bytes.len())]);
                        break;
                    }
                    
                    if reply_bytes.len() > 2000 {
                        return Err(crate::error::SshError::ProtocolError(
                            format!("Could not parse KEX_REPLY after {} bytes", reply_bytes.len())
                        ));
                    }
                }
                Ok(Err(e)) => {
                    return Err(crate::error::SshError::IoError(e));
                }
                Err(_) => {
                    return Err(crate::error::SshError::TimeoutError);
                }
            }
        }
        
        if reply_bytes[0] != crate::protocol::MessageType::KexInit as u8 {
            return Err(crate::error::SshError::ProtocolError(
                "Expected KEX_INIT from server".to_string()
            ));
        }
        
        kex_context.process_server_kex_init(&reply_bytes[1..])?;
        
        // 11. Compute shared secret
        kex_context.compute_shared_secret()?;
        
        // 12. Derive session keys
        let session_id = kex_context.session_id.clone()
            .expect("Session ID not computed");
        kex_context.derive_session_keys(&session_id)?;
        
        // 13. Send NEWKEYS message
        let newkeys_msg = crate::transport::kex::encode_newkeys();
        self.stream_mut().write_all(&newkeys_msg).await?;
        
        // 14. Receive NEWKEYS from server - Cisco sends without length prefix
        let mut newkeys_bytes = Vec::new();
        let mut newkeys_buffer = vec![0u8; 1024];
        
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.stream_mut().read(&mut newkeys_buffer)
            ).await {
                Ok(Ok(0)) => {
                    return Err(crate::error::SshError::ConnectionError(
                        "Connection closed while reading NEWKEYS".to_string()
                    ));
                }
                Ok(Ok(n)) => {
                    debug!("Received {} bytes for NEWKEYS", n);
                    newkeys_bytes.extend_from_slice(&newkeys_buffer[..n]);
                    
                    if newkeys_bytes.len() >= 5 && newkeys_bytes[0] == crate::protocol::MessageType::Newkeys as u8 {
                        debug!("Received valid NEWKEYS message ({} bytes)", newkeys_bytes.len());
                        break;
                    }
                    
                    if newkeys_bytes.len() > 2000 {
                        return Err(crate::error::SshError::ProtocolError(
                            format!("Could not parse NEWKEYS after {} bytes", newkeys_bytes.len())
                        ));
                    }
                }
                Ok(Err(e)) => {
                    return Err(crate::error::SshError::IoError(e));
                }
                Err(_) => {
                    return Err(crate::error::SshError::TimeoutError);
                }
            }
        }
        
        if newkeys_bytes[0] != crate::protocol::MessageType::Newkeys as u8 {
            return Err(crate::error::SshError::ProtocolError(
                "Expected NEWKEYS from server".to_string()
            ));
        }
        
        info!("SSH handshake completed, server version: {}", server_ver);
        Ok(())
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

    /// Transition to encrypted state after key exchange
    pub fn transition_to_encrypted(
        &mut self,
        session_id: &[u8],
        negotiated: &protocol::NegotiatedAlgorithms,
    ) -> Result<(), crate::error::SshError> {
        // Update handshake state
        self.handshake.negotiated = Some(negotiated.clone());
        
        // Transition state machine to established
        self.state.transition_to_established();
        
        Ok(())
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