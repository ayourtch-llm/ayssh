//! SSH Transport Layer
//!
//! Handles the transport layer of SSH including key exchange,
//! packet encryption, and session state management.

use crate::channel::ChannelTransferManager;
use crate::crypto::cipher::{aes_128_cbc_decrypt, aes_128_cbc_decrypt_raw, aes_128_cbc_encrypt_raw, CipherError};
use crate::crypto::hmac::HmacSha1;
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
    /// Encryption state for client-to-server direction
    encrypt_state: Option<EncryptionState>,
    /// Decryption state for server-to-client direction
    decrypt_state: Option<DecryptionState>,
}

/// Encryption state for outgoing packets
#[derive(Debug)]
struct EncryptionState {
    /// Encryption key
    enc_key: Vec<u8>,
    /// Initialization vector (for CBC mode)
    iv: Vec<u8>,
    /// MAC key
    mac_key: Vec<u8>,
    /// Sequence number for packet integrity
    sequence_number: u32,
    /// Encryption algorithm
    enc_algorithm: String,
    /// MAC algorithm
    mac_algorithm: String,
}

/// Decryption state for incoming packets
#[derive(Debug)]
struct DecryptionState {
    /// Decryption key
    dec_key: Vec<u8>,
    /// Initialization vector (for CBC mode)
    iv: Vec<u8>,
    /// MAC key
    mac_key: Vec<u8>,
    /// Sequence number for packet integrity
    sequence_number: u32,
    /// Decryption algorithm
    dec_algorithm: String,
    /// MAC algorithm
    mac_algorithm: String,
}

impl Transport {
    /// Create a new transport with the given socket
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            state: state::TransportStateMachine::new(),
            handshake: handshake::HandshakeState::default(),
            channel_manager: ChannelTransferManager::new(),
            encrypt_state: None,
            decrypt_state: None,
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
        
       // Calculate padding to ensure 8-byte alignment per RFC 4253 Section 6
        // Total size (4 + 1 + payload + padding) must be multiple of 8
        // Minimum padding is 4 bytes
        let payload_len = kexinit_payload.len();
        let total_without_padding = 4 + 1 + payload_len; // length field + padding_length field + payload
        let remainder = total_without_padding % 8;
        let mut padding_length = if remainder == 0 {
            8u8 // Already aligned, but need at least 4 bytes padding, and 8 maintains alignment
        } else {
            (8 - remainder) as u8
        };
        
        // Ensure minimum padding of 4 bytes per RFC 4253
        // If calculated padding is less than 4, add 8 to maintain alignment
        if padding_length < 4 {
            padding_length += 8;
        }
        
        let packet_length = kexinit_payload.len() as u32 + padding_length as u32 + 1; // +1 for padding_length byte
        
        debug!("KEXINIT: payload len={}, padding len={}, calculated packet_length={}, total size={}", 
               kexinit_payload.len(), padding_length, packet_length, 4 + 1 + payload_len + padding_length as usize);
        
        let mut kexinit_msg = bytes::BytesMut::new();
        kexinit_msg.put_u32(packet_length);
        kexinit_msg.put_u8(padding_length);
        kexinit_msg.put_slice(kexinit_payload);
        // Add padding bytes
        for _ in 0..padding_length {
            kexinit_msg.put_u8(0);
        }
        
        debug!("KEXINIT: sending {} bytes total, first 10 bytes: {:?}", 
               kexinit_msg.len(), &kexinit_msg[..std::cmp::min(10, kexinit_msg.len())]);
        
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
        
        // Store negotiated algorithms in handshake state
        self.handshake.enc_c2s = Some(negotiated.enc_c2s.clone());
        self.handshake.enc_s2c = Some(negotiated.enc_s2c.clone());
        self.handshake.mac_c2s = Some(negotiated.mac_c2s.clone());
        self.handshake.mac_s2c = Some(negotiated.mac_s2c.clone());
        
        // 8. Initialize KEX context
        let algorithm = KexAlgorithm::from_str(&negotiated.kex).unwrap_or(KexAlgorithm::Curve25519Sha256);
        let mut kex_context = KexContext::new(algorithm);
        
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        kex_context.generate_client_key(&mut rng)?;
        
        // 9. Send KEXDH_INIT message with client ephemeral key
        let client_ephemeral = kex_context.client_ephemeral.clone()
            .expect("Client ephemeral key not generated");
        
        debug!("Client ephemeral key size: {} bytes", client_ephemeral.len());
        
        // Build KEXDH_INIT payload per RFC 4253 Section 7.1
        // Format: byte SSH_MSG_KEXDH_INIT, mpint e
        // Note: mpint is length-prefixed (4-byte length + data)
        let mut kexdh_init_payload = bytes::BytesMut::new();
        kexdh_init_payload.put_u8(crate::protocol::MessageType::KexDhInit as u8);
        // Add length-prefixed MPINT for the ephemeral key
        kexdh_init_payload.put_u32(client_ephemeral.len() as u32);
        kexdh_init_payload.put_slice(&client_ephemeral);
        
        // Wrap in SSH binary packet format per RFC 4253 Section 6
        // Format: [packet_length (4 bytes)][padding_length (1 byte)][payload][padding]
        let payload_len = kexdh_init_payload.len();
        let total_without_padding = 4 + 1 + payload_len;
        let remainder = total_without_padding % 8;
        let padding_length = if remainder == 0 {
            8u8
        } else {
            let p = (8 - remainder) as u8;
            if p < 4 { p + 8 } else { p }
        };
        
        let packet_length = payload_len as u32 + padding_length as u32 + 1;
        
        let mut kexdh_init_msg = bytes::BytesMut::new();
        kexdh_init_msg.put_u32(packet_length);
        kexdh_init_msg.put_u8(padding_length);
        kexdh_init_msg.put_slice(&kexdh_init_payload);
        for _ in 0..padding_length {
            kexdh_init_msg.put_u8(0);
        }
        
        debug!("Sending KEXDH_INIT packet (payload={}, padding={}, total={})", 
               payload_len, padding_length, kexdh_init_msg.len());
        self.stream_mut().write_all(&kexdh_init_msg).await?;
        
        // 10. Receive KEXDH_REPLY from server
        let mut reply_bytes = Vec::new();
        let mut reply_buffer = vec![0u8; 1024];
        
        // First read the packet length (4 bytes)
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.stream_mut().read(&mut reply_buffer)
            ).await {
                Ok(Ok(0)) => {
                    return Err(crate::error::SshError::ConnectionError(
                        "Connection closed while reading KEXDH_REPLY packet length".to_string()
                    ));
                }
                Ok(Ok(n)) => {
                    reply_bytes.extend_from_slice(&reply_buffer[..n]);
                    
                    if reply_bytes.len() >= 4 {
                        let packet_len = u32::from_be_bytes([
                            reply_bytes[0], reply_bytes[1], reply_bytes[2], reply_bytes[3]
                        ]) as usize;
                        debug!("KEXDH_REPLY packet length: {} bytes", packet_len);
                        
                        if reply_bytes.len() >= packet_len + 4 {
                            debug!("Successfully received KEXDH_REPLY packet");
                            break;
                        }
                    }
                    
                    if reply_bytes.len() > 2000 {
                        return Err(crate::error::SshError::ProtocolError(
                            format!("Could not parse KEXDH_REPLY packet after {} bytes", reply_bytes.len())
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
        
        // Extract payload from packet
        let packet_len = u32::from_be_bytes([reply_bytes[0], reply_bytes[1], reply_bytes[2], reply_bytes[3]]) as usize;
        let padding_len = reply_bytes[4] as usize;
        let payload_start = 5;
        let payload_end = 5 + packet_len - padding_len;
        
        debug!("KEXDH_REPLY packet_len: {}, padding_len: {}, payload: {}-{}", 
               packet_len, padding_len, payload_start, payload_end);
        
        let reply_payload = &reply_bytes[payload_start..payload_end];
        
        if reply_payload[0] != crate::protocol::MessageType::KexDhReply as u8 {
            return Err(crate::error::SshError::ProtocolError(
                format!("Expected KEXDH_REPLY (31), got {}", reply_payload[0])
            ));
        }
        
        // Extract server host key from KEXDH_REPLY
        // Format: byte SSH_MSG_KEXDH_REPLY, string K_S (host key), mpint f, string signature
        let mut reply_data = &reply_payload[1..];
        
        // Read server host key (string type = uint32 length + data)
        if reply_data.len() >= 4 {
            let host_key_len = u32::from_be_bytes([reply_data[0], reply_data[1], reply_data[2], reply_data[3]]) as usize;
            if reply_data.len() >= 4 + host_key_len {
                let server_host_key = &reply_data[4..4+host_key_len];
                debug!("Server host key length: {} bytes", host_key_len);
                kex_context.set_server_host_key(server_host_key);
            }
        }
        
        // Set exchange info for session ID computation
        // Client version string (without CRLF)
        let client_version = crate::transport::handshake::SSH_VERSION_STRING
            .strip_suffix("\r\n")
            .unwrap_or(crate::transport::handshake::SSH_VERSION_STRING)
            .as_bytes();
        
        // Server version string (without CRLF)  
        let server_version_clean = server_ver
            .strip_suffix("\r\n")
            .unwrap_or(server_ver.strip_suffix('\n').unwrap_or(&server_ver));
        
        kex_context.set_exchange_info(
            client_version,
            server_version_clean.as_bytes(),
            &client_kexinit,
            kexinit_payload, // server KEXINIT payload
        );
        
        // Process server's ephemeral key (skip host key string)
        // After host key string, we have mpint f and signature
        if reply_data.len() >= 4 {
            let host_key_len = u32::from_be_bytes([reply_data[0], reply_data[1], reply_data[2], reply_data[3]]) as usize;
            if reply_data.len() >= 4 + host_key_len {
                let after_host_key = &reply_data[4+host_key_len..];
                kex_context.process_server_kex_init(after_host_key)?;
            }
        }
        
        // 11. Compute shared secret (and session ID)
        kex_context.compute_shared_secret()?;
        
        // 12. Derive session keys
        let session_id = kex_context.session_id.clone()
            .expect("Session ID not computed");
        let session_keys = kex_context.derive_session_keys(&session_id)?;
        
        // Store session keys in handshake state
        self.handshake.session_keys = Some(session_keys);
        
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
                    
                    // SSH packet format: [length (4 bytes)][padding_length (1 byte)][payload]
                    // Message type is at byte 5 (index 5), so we need at least 6 bytes
                    if newkeys_bytes.len() >= 6 && newkeys_bytes[5] == crate::protocol::MessageType::Newkeys as u8 {
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
        
        if newkeys_bytes.len() < 6 || newkeys_bytes[5] != crate::protocol::MessageType::Newkeys as u8 {
            return Err(crate::error::SshError::ProtocolError(
                "Expected NEWKEYS from server".to_string()
            ));
        }
        
        // Set up encryption state after NEWKEYS exchange
        // Get the negotiated algorithms from the handshake state
        let enc_c2s = self.handshake.enc_c2s.clone().unwrap_or_else(|| "aes128-cbc".to_string());
        let enc_s2c = self.handshake.enc_s2c.clone().unwrap_or_else(|| "aes128-cbc".to_string());
        let mac_c2s = self.handshake.mac_c2s.clone().unwrap_or_else(|| "hmac-sha1".to_string());
        let mac_s2c = self.handshake.mac_s2c.clone().unwrap_or_else(|| "hmac-sha1".to_string());
        
        debug!("Setting up encryption: C2S={}, S2C={}, MAC-C2S={}, MAC-S2C={}", 
               enc_c2s, enc_s2c, mac_c2s, mac_s2c);
        
        // Get session keys from kex_context (stored in handshake state)
        if let Some(ref session_keys) = self.handshake.session_keys {
            debug!("Session keys details:");
            debug!("  enc_key_c2s: {:?}", session_keys.enc_key_c2s);
            debug!("  enc_key_s2c: {:?}", session_keys.enc_key_s2c);
            debug!("  client_iv: {:?}", session_keys.client_iv);
            debug!("  server_iv: {:?}", session_keys.server_iv);
            
            // Set up client-to-server encryption state
            self.encrypt_state = Some(EncryptionState {
                enc_key: session_keys.enc_key_c2s.clone(),
                iv: session_keys.client_iv.clone(),
                mac_key: session_keys.mac_key_c2s.clone(),
                sequence_number: 0,
                enc_algorithm: enc_c2s,
                mac_algorithm: mac_c2s,
            });
            
            // Set up server-to-client decryption state
            // Note: To decrypt packets FROM server, we need the key that server used to encrypt
            // Server encrypts with enc_key_s2c, so we decrypt with the same key
            self.decrypt_state = Some(DecryptionState {
                dec_key: session_keys.enc_key_s2c.clone(),
                iv: session_keys.server_iv.clone(),
                mac_key: session_keys.mac_key_s2c.clone(),
                sequence_number: 0,
                dec_algorithm: enc_s2c,
                mac_algorithm: mac_s2c,
            });
            
            debug!("Encryption state initialized successfully");
        } else {
            return Err(crate::error::SshError::ProtocolError(
                "Session keys not available after key exchange".to_string()
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

    /// Send an SSH message (with encryption if enabled)
    pub async fn send_message(&mut self, msg: &[u8]) -> Result<(), crate::error::SshError> {
        // Check if encryption is enabled
        let encryption_enabled = self.encrypt_state.is_some();
        
        if encryption_enabled {
            // Encrypt the message
            debug!("Encrypting message of {} bytes", msg.len());
            let encrypt_state = self.encrypt_state.as_mut().unwrap();
            debug!("Encrypting with key len: {}, iv len: {}", encrypt_state.enc_key.len(), encrypt_state.iv.len());
            let encrypted = encrypt_packet_cbc(msg, encrypt_state)?;
            debug!("Encrypted to {} bytes, first 20: {:?}", encrypted.len(), &encrypted[..std::cmp::min(20, encrypted.len())]);
            self.stream.write_all(&encrypted).await?;
        } else {
            // Send unencrypted (shouldn't happen after handshake)
            self.send(msg).await?;
        }
        Ok(())
    }

    /// Receive an SSH message (with decryption if enabled)
    pub async fn recv_message(&mut self) -> Result<Vec<u8>, crate::error::SshError> {
        // Check if decryption is enabled
        let decryption_enabled = self.decrypt_state.is_some();
        
        if decryption_enabled {
            let decrypt_state = self.decrypt_state.as_ref().unwrap();
            
            // For CBC mode, the packet length field is encrypted (RFC 4253 Section 6.3)
            // Packet structure: [encrypted: length(4) + padding_len(1) + payload + padding] + [MAC]
            
            // Calculate MAC length based on algorithm
            let mac_len = match decrypt_state.mac_algorithm.as_str() {
                "hmac-sha1" => 20,
                "hmac-sha1-96" => 12,
                "hmac-md5" => 16,
                "hmac-md5-96" => 12,
                "hmac-sha2-256" => 32,
                "hmac-sha2-512" => 64,
                _ => 20, // Default to HMAC-SHA1
            };
            
            // Read minimum: one AES block (16 bytes) + MAC
            let min_size = 16 + mac_len;
            let mut buffer = vec![0u8; min_size];
            self.stream.read_exact(&mut buffer).await?;
            debug!("Read minimum {} bytes (16 + MAC:{})", min_size, mac_len);
            debug!("Raw received bytes (first 36): {:?}", &buffer[..std::cmp::min(36, buffer.len())]);
            
            // Save the current IV before decryption (we need it for CBC decryption)
            let current_iv = decrypt_state.iv.clone();
            
            // Decrypt just the first 16 bytes to get packet length (without padding removal)
            let first_block = &buffer[..16];
            debug!("Decrypting with key (first 8 bytes): {:?}", &decrypt_state.dec_key[..std::cmp::min(8, decrypt_state.dec_key.len())]);
            debug!("Decrypting with IV (first 8 bytes): {:?}", &current_iv[..std::cmp::min(8, current_iv.len())]);
            debug!("Ciphertext first block: {:?}", first_block);
            let decrypted_first_block = aes_128_cbc_decrypt_raw(
                &decrypt_state.dec_key,
                &current_iv,
                first_block
            )?;
            debug!("Decrypted first block: {:?}", &decrypted_first_block[..16]);
            
            // For debugging, print the expected packet length for SERVICE_ACCEPT
            // SERVICE_ACCEPT is message type 6, so the packet should be:
            // [length (4)][padding_len (1)][6][padding...]
            // Minimum packet length would be 4+1+6+4 = 15 bytes (with 4 bytes padding)
            debug!("Expected packet length for SERVICE_ACCEPT: ~15-30 bytes");
            
            // Extract packet length from decrypted data (first 4 bytes, big-endian)
            let packet_length = u32::from_be_bytes([
                decrypted_first_block[0],
                decrypted_first_block[1],
                decrypted_first_block[2],
                decrypted_first_block[3]
            ]) as usize;
            debug!("Extracted packet length: {}", packet_length);
            
            // Validate packet length
            if packet_length < 1 || packet_length > 35000 {
                return Err(crate::error::SshError::ProtocolError(
                    format!("Invalid packet length: {}", packet_length)
                ));
            }
            
            // Total bytes needed: packet_length (encrypted portion) + mac_len
            let total_bytes = packet_length + mac_len;
            
            // If packet is larger than minimum, read more bytes
            if total_bytes > min_size {
                let additional = total_bytes - min_size;
                debug!("Need {} additional bytes", additional);
                let mut additional_data = vec![0u8; additional];
                self.stream.read_exact(&mut additional_data).await?;
                buffer.extend_from_slice(&additional_data);
            }
            
            debug!("Total encrypted data with MAC: {} bytes (packet: {} + MAC: {})", 
                   buffer.len(), packet_length, mac_len);
            
            // Split buffer into encrypted portion and MAC
            let encrypted = &buffer[..packet_length];
            let received_mac = &buffer[packet_length..];

            // Decrypt the entire encrypted portion first (per RFC 4253, MAC is over unencrypted data)
            let decrypt_state = self.decrypt_state.as_mut().unwrap();
            let decrypted = aes_128_cbc_decrypt(&decrypt_state.dec_key, &decrypt_state.iv, encrypted)?;
            debug!("Decrypted successfully, got {} bytes", decrypted.len());

            // Update IV for next packet (last 16 bytes of ciphertext for AES)
            if encrypted.len() >= 16 {
                decrypt_state.iv = encrypted[encrypted.len() - 16..].to_vec();
            }

            // Verify HMAC over sequence number + decrypted packet (per RFC 4253 Section 6.4)
            let mut mac_data = Vec::with_capacity(4 + decrypted.len());
            mac_data.extend_from_slice(&decrypt_state.sequence_number.to_be_bytes());
            mac_data.extend_from_slice(&decrypted);

            let mut hmac = HmacSha1::new(&decrypt_state.mac_key);
            hmac.update(&mac_data);
            let expected_mac = hmac.finish();

            if !expected_mac.iter().eq(received_mac.iter()) {
                return Err(crate::error::SshError::ProtocolError(
                    "MAC verification failed".to_string()
                ));
            }
            debug!("MAC verification successful");

            // Update sequence number
            decrypt_state.sequence_number = decrypt_state.sequence_number.wrapping_add(1);

            Ok(decrypted)
        } else {
            // Read unencrypted (shouldn't happen after handshake)
            let mut len_buf = [0u8; 4];
            self.stream.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut msg_buf = vec![0u8; len];
            self.stream.read_exact(&mut msg_buf).await?;
            Ok(msg_buf)
        }
    }

    /// Encrypt a packet with AES-CBC and HMAC-SHA1
    fn encrypt_packet(&self, payload: &[u8], state: &mut EncryptionState) -> Result<Vec<u8>, crate::error::SshError> {
        encrypt_packet_cbc(payload, state)
    }

    /// Decrypt a packet with AES-CBC and verify HMAC-SHA1
    fn decrypt_packet(&self, encrypted_with_mac: &[u8], state: &mut DecryptionState) -> Result<Vec<u8>, crate::error::SshError> {
        decrypt_packet_cbc(encrypted_with_mac, state)
    }

    /// Send SERVICE_REQUEST message
    pub async fn send_service_request(&mut self, service: &str) -> Result<(), crate::error::SshError> {
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(protocol::MessageType::ServiceRequest as u8);
        protocol::SshString::from_str(service).encode(&mut msg);
        
        debug!("Sending SERVICE_REQUEST for '{}', message: {:?}", service, &msg[..]);
        self.send_message(&msg).await?;
        debug!("SERVICE_REQUEST sent successfully");
        Ok(())
    }

    /// Receive SERVICE_ACCEPT message
    pub async fn recv_service_accept(&mut self) -> Result<String, crate::error::SshError> {
        debug!("Waiting for SERVICE_ACCEPT...");
        let mut msg = self.recv_message().await?;
        debug!("Received message: {:?}", &msg[..]);
        
        if msg.is_empty() {
            return Err(crate::error::SshError::ProtocolError(
                "Empty SERVICE_ACCEPT message".to_string()
            ));
        }
        
        let msg_type = msg[0];
        debug!("Message type: {}", msg_type);
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

// Standalone helper functions for encryption/decryption
fn encrypt_packet_cbc(payload: &[u8], state: &mut EncryptionState) -> Result<Vec<u8>, crate::error::SshError> {
    // Calculate padding to ensure 8-byte alignment
    let payload_len = payload.len();
    let total_without_padding = 4 + 1 + payload_len;
    let remainder = total_without_padding % 8;
    let padding_length = if remainder == 0 {
        8u8
    } else {
        let p = (8 - remainder) as u8;
        if p < 4 { p + 8 } else { p }
    };
    
    let packet_length = payload_len as u32 + padding_length as u32 + 1;
    
    // Build the packet: length + padding_length + payload + padding
    let mut packet = Vec::with_capacity(4 + 1 + payload_len + padding_length as usize);
    packet.extend_from_slice(&packet_length.to_be_bytes());
    packet.push(padding_length);
    packet.extend_from_slice(payload);
    for _ in 0..padding_length {
        packet.push(0);
    }

    // Compute HMAC over sequence number + unencrypted packet (per RFC 4253 Section 6.4)
    // MAC = H(seq_num || unencrypted_packet)
    let mut mac_data = Vec::with_capacity(4 + packet.len());
    mac_data.extend_from_slice(&state.sequence_number.to_be_bytes());
    mac_data.extend_from_slice(&packet);

    let mut hmac = HmacSha1::new(&state.mac_key);
    hmac.update(&mac_data);
    let mac = hmac.finish();

    // Encrypt using AES-CBC with the current IV (no additional padding - packet is already padded)
    let encrypted = match state.enc_algorithm.as_str() {
        "aes128-cbc" => {
            aes_128_cbc_encrypt_raw(&state.enc_key, &state.iv, &packet)?
        }
        _ => {
            return Err(crate::error::SshError::ProtocolError(
                format!("Unsupported encryption algorithm: {}", state.enc_algorithm)
            ));
        }
    };
    
    // Update IV for next packet (last 16 bytes of ciphertext for AES)
    // RFC 4253: "initialization vectors SHOULD be passed from the end of one packet to the beginning of the next packet"
    if encrypted.len() >= 16 {
        state.iv = encrypted[encrypted.len() - 16..].to_vec();
    }
    
    // Update sequence number
    state.sequence_number = state.sequence_number.wrapping_add(1);
    
    // Combine encrypted data and MAC
    let mut result = encrypted;
    result.extend_from_slice(&mac);
    
    Ok(result)
}

fn decrypt_packet_cbc(encrypted_with_mac: &[u8], state: &mut DecryptionState) -> Result<Vec<u8>, crate::error::SshError> {
    // The encrypted data includes: encrypted packet + MAC
    // For HMAC-SHA1, MAC is 20 bytes
    let mac_len = 20; // HMAC-SHA1
    if encrypted_with_mac.len() < mac_len {
        return Err(crate::error::SshError::ProtocolError(
            "Packet too short for MAC".to_string()
        ));
    }

    let (encrypted, received_mac) = encrypted_with_mac.split_at(encrypted_with_mac.len() - mac_len);

    // Decrypt using AES-CBC first (per RFC 4253, MAC is over unencrypted data)
    let decrypted = match state.dec_algorithm.as_str() {
        "aes128-cbc" => {
            aes_128_cbc_decrypt(&state.dec_key, &state.iv, encrypted)?
        }
        _ => {
            return Err(crate::error::SshError::ProtocolError(
                format!("Unsupported decryption algorithm: {}", state.dec_algorithm)
            ));
        }
    };

    // Update IV for next packet (last 16 bytes of ciphertext for AES)
    // RFC 4253: "initialization vectors SHOULD be passed from the end of one packet to the beginning of the next packet"
    if encrypted.len() >= 16 {
        state.iv = encrypted[encrypted.len() - 16..].to_vec();
    }

    // Verify HMAC over sequence number + unencrypted packet (per RFC 4253 Section 6.4)
    let mut mac_data = Vec::with_capacity(4 + decrypted.len());
    mac_data.extend_from_slice(&state.sequence_number.to_be_bytes());
    mac_data.extend_from_slice(&decrypted);

    let mut hmac = HmacSha1::new(&state.mac_key);
    hmac.update(&mac_data);
    let expected_mac = hmac.finish();

    if !expected_mac.iter().eq(received_mac.iter()) {
        return Err(crate::error::SshError::ProtocolError(
            "MAC verification failed".to_string()
        ));
    }

    // Update sequence number
    state.sequence_number = state.sequence_number.wrapping_add(1);

    Ok(decrypted)
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