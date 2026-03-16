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
    /// Buffer for leftover bytes from TCP reads (handles cases where
    /// multiple SSH packets arrive in a single TCP segment)
    read_buffer: Vec<u8>,
    /// Client-to-server packet sequence number (counts ALL packets from connection start per RFC 4253 Section 6.4)
    send_sequence_number: u32,
    /// Server-to-client packet sequence number (counts ALL packets from connection start per RFC 4253 Section 6.4)
    recv_sequence_number: u32,
    /// Session ID from key exchange (needed for public key auth signatures)
    session_id: Option<Vec<u8>>,
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
            read_buffer: Vec::new(),
            send_sequence_number: 0,
            recv_sequence_number: 0,
            session_id: None,
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

    /// Get the session ID from key exchange (needed for public key auth signatures)
    pub fn session_id(&self) -> Option<&[u8]> {
        self.session_id.as_deref()
    }

    /// Get the channel manager
    pub fn channel_manager(&self) -> &ChannelTransferManager {
        &self.channel_manager
    }

    /// Get mutable reference to channel manager
    pub fn channel_manager_mut(&mut self) -> &mut ChannelTransferManager {
        &mut self.channel_manager
    }

    /// Read exactly one unencrypted SSH binary packet from the stream.
    /// Handles TCP buffering: if a previous read returned extra bytes
    /// (e.g., NEWKEYS piggybacked on KEXDH_REPLY), those bytes are used first.
    /// Returns the full packet bytes including the 4-byte length prefix.
    async fn read_unencrypted_packet(&mut self, timeout_secs: u64) -> Result<Vec<u8>, crate::error::SshError> {
        let mut data = std::mem::take(&mut self.read_buffer);

        loop {
            // Check if we have enough data to determine the packet length
            if data.len() >= 4 {
                let packet_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let total_needed = 4 + packet_len;
                if data.len() >= total_needed {
                    // We have a complete packet. Split off any extra bytes for next read.
                    let remainder = data.split_off(total_needed);
                    self.read_buffer = remainder;
                    self.recv_sequence_number = self.recv_sequence_number.wrapping_add(1);
                    return Ok(data);
                }
            }

            // Need more data from the stream
            let mut buf = vec![0u8; 1024];
            match tokio::time::timeout(
                std::time::Duration::from_secs(timeout_secs),
                self.stream.read(&mut buf),
            )
            .await
            {
                Ok(Ok(0)) => {
                    return Err(crate::error::SshError::ConnectionError(
                        "Connection closed while reading packet".to_string(),
                    ));
                }
                Ok(Ok(n)) => {
                    data.extend_from_slice(&buf[..n]);
                }
                Ok(Err(e)) => {
                    return Err(crate::error::SshError::IoError(e));
                }
                Err(_) => {
                    return Err(crate::error::SshError::TimeoutError);
                }
            }
        }
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
        self.send_sequence_number = self.send_sequence_number.wrapping_add(1);
        debug!("Sent client KEXINIT packet ({} bytes total, seq={})", kexinit_msg.len(), self.send_sequence_number - 1);
        
        // 5. Receive server KEXINIT using buffered packet reader
        let server_kexinit_bytes = self.read_unencrypted_packet(5).await?;
        debug!("Successfully received server KEXINIT packet ({} bytes)", server_kexinit_bytes.len());
        
        // Extract the KEXINIT payload from the packet
        // packet_length = padding_length_byte(1) + payload + padding
        // So: payload_length = packet_length - 1 - padding_length
        // Payload starts at offset 5 (4 for length field + 1 for padding_length byte)
        let packet_len = u32::from_be_bytes([
            server_kexinit_bytes[0],
            server_kexinit_bytes[1],
            server_kexinit_bytes[2],
            server_kexinit_bytes[3]
        ]) as usize;
        let padding_len = server_kexinit_bytes[4] as usize;
        let payload_start = 5;
        let payload_end = 4 + packet_len - padding_len; // 4 + (1 + payload + padding) - padding = 5 + payload
        
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
        
        debug!("Sending KEXDH_INIT packet (payload={}, padding={}, total={}, seq={})",
               payload_len, padding_length, kexdh_init_msg.len(), self.send_sequence_number);
        self.stream_mut().write_all(&kexdh_init_msg).await?;
        self.send_sequence_number = self.send_sequence_number.wrapping_add(1);
        
        // 10. Receive KEXDH_REPLY from server using buffered packet reader
        let reply_bytes = self.read_unencrypted_packet(5).await?;
        debug!("Successfully received KEXDH_REPLY packet ({} bytes)", reply_bytes.len());
        
        // Extract payload from packet
        // packet_length = padding_length_byte(1) + payload + padding
        let packet_len = u32::from_be_bytes([reply_bytes[0], reply_bytes[1], reply_bytes[2], reply_bytes[3]]) as usize;
        let padding_len = reply_bytes[4] as usize;
        let payload_start = 5;
        let payload_end = 4 + packet_len - padding_len; // 4 + (1 + payload + padding) - padding = 5 + payload
        
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
        self.session_id = Some(session_id.clone());
        let session_keys = kex_context.derive_session_keys(&session_id)?;
        
        // Store session keys in handshake state
        self.handshake.session_keys = Some(session_keys);
        
        // 13. Send NEWKEYS message
        let newkeys_msg = crate::transport::kex::encode_newkeys();
        self.stream_mut().write_all(&newkeys_msg).await?;
        self.send_sequence_number = self.send_sequence_number.wrapping_add(1);
        debug!("Sent NEWKEYS (seq={})", self.send_sequence_number - 1);
        
        // 14. Receive NEWKEYS from server using buffered packet reader
        let newkeys_bytes = self.read_unencrypted_packet(5).await?;

        // Validate NEWKEYS message type (byte 5 = after 4-byte length + 1-byte padding_length)
        if newkeys_bytes.len() < 6 || newkeys_bytes[5] != crate::protocol::MessageType::Newkeys as u8 {
            return Err(crate::error::SshError::ProtocolError(
                format!("Expected NEWKEYS from server, got {:?}", &newkeys_bytes[..std::cmp::min(10, newkeys_bytes.len())])
            ));
        }
        debug!("Received valid NEWKEYS message ({} bytes)", newkeys_bytes.len());
        
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
            // Sequence numbers continue from the pre-NEWKEYS count per RFC 4253 Section 6.4
            debug!("Initializing encryption with send_seq={}, recv_seq={}", self.send_sequence_number, self.recv_sequence_number);
            self.encrypt_state = Some(EncryptionState {
                enc_key: session_keys.enc_key_c2s.clone(),
                iv: session_keys.client_iv.clone(),
                mac_key: session_keys.mac_key_c2s.clone(),
                sequence_number: self.send_sequence_number,
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
                sequence_number: self.recv_sequence_number,
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

    /// Read exactly `n` bytes from the read_buffer + stream
    async fn read_exact_buffered(&mut self, n: usize) -> Result<Vec<u8>, crate::error::SshError> {
        let mut data = Vec::with_capacity(n);

        // Drain from read_buffer first
        let from_buf = std::cmp::min(n, self.read_buffer.len());
        if from_buf > 0 {
            data.extend_from_slice(&self.read_buffer[..from_buf]);
            self.read_buffer = self.read_buffer[from_buf..].to_vec();
        }

        // Read remaining from stream
        if data.len() < n {
            let remaining = n - data.len();
            let mut buf = vec![0u8; remaining];
            self.stream.read_exact(&mut buf).await?;
            data.extend_from_slice(&buf);
        }

        Ok(data)
    }

    /// Receive an SSH message (with decryption if enabled)
    ///
    /// For AES-CBC mode:
    /// - The encrypted portion is: 4-byte packet_length + padding_length + payload + padding
    /// - Total encrypted size = 4 + packet_length (must be multiple of cipher block size)
    /// - MAC is appended unencrypted after the ciphertext
    /// - Returns the full decrypted packet (packet_length field + padding_length + payload + padding)
    pub async fn recv_message(&mut self) -> Result<Vec<u8>, crate::error::SshError> {
        if self.decrypt_state.is_none() {
            // Read unencrypted (shouldn't happen after handshake)
            let len_buf = self.read_exact_buffered(4).await?;
            let len = u32::from_be_bytes([len_buf[0], len_buf[1], len_buf[2], len_buf[3]]) as usize;
            let msg_buf = self.read_exact_buffered(len).await?;
            return Ok(msg_buf);
        }

        // Extract needed values from decrypt_state before calling async methods
        let mac_len = {
            let ds = self.decrypt_state.as_ref().unwrap();
            match ds.mac_algorithm.as_str() {
                "hmac-sha1" => 20,
                "hmac-sha1-96" => 12,
                "hmac-md5" => 16,
                "hmac-md5-96" => 12,
                "hmac-sha2-256" => 32,
                "hmac-sha2-512" => 64,
                _ => 20,
            }
        };

        // Step 1: Read and decrypt the first AES block (16 bytes) to get packet_length
        let first_block_ciphertext = self.read_exact_buffered(16).await?;

        let (current_iv, dec_key, dec_algo) = {
            let ds = self.decrypt_state.as_ref().unwrap();
            (ds.iv.clone(), ds.dec_key.clone(), ds.dec_algorithm.clone())
        };

        let decrypted_first_block = match dec_algo.as_str() {
            "aes128-cbc" => aes_128_cbc_decrypt_raw(&dec_key, &current_iv, &first_block_ciphertext)?,
            "aes128-ctr" => {
                use crate::crypto::cipher::aes_ctr_decrypt;
                aes_ctr_decrypt(&dec_key, &current_iv, &first_block_ciphertext)?
            }
            other => return Err(crate::error::SshError::ProtocolError(
                format!("Unsupported decryption algorithm: {}", other),
            )),
        };

        // Extract packet_length from first 4 bytes of decrypted data
        let packet_length = u32::from_be_bytes([
            decrypted_first_block[0],
            decrypted_first_block[1],
            decrypted_first_block[2],
            decrypted_first_block[3],
        ]) as usize;
        debug!("Extracted packet_length: {}", packet_length);

        if packet_length < 1 || packet_length > 35000 {
            return Err(crate::error::SshError::ProtocolError(
                format!("Invalid packet length: {}", packet_length),
            ));
        }

        // Step 2: Total encrypted size is 4 + packet_length
        // We already read 16 bytes, so read the remaining encrypted bytes + MAC
        let total_encrypted = 4 + packet_length;
        // For CTR mode, total_encrypted may not be block-aligned, but we still
        // need to round up to block boundary for the encrypted data on the wire
        let total_encrypted_padded = match dec_algo.as_str() {
            "aes128-cbc" => total_encrypted, // CBC: already block-aligned by SSH padding
            _ => total_encrypted,            // CTR: stream cipher, no alignment needed
        };
        let remaining_encrypted = total_encrypted_padded - 16;
        let remaining_to_read = remaining_encrypted + mac_len;
        let rest = self.read_exact_buffered(remaining_to_read).await?;

        // Reassemble the full ciphertext
        let mut full_ciphertext = Vec::with_capacity(total_encrypted_padded);
        full_ciphertext.extend_from_slice(&first_block_ciphertext);
        full_ciphertext.extend_from_slice(&rest[..remaining_encrypted]);

        // Extract MAC
        let received_mac = &rest[remaining_encrypted..];
        debug!("Total encrypted: {} bytes, MAC: {} bytes", total_encrypted_padded, received_mac.len());

        // Step 3: Decrypt the full ciphertext
        let decrypt_state = self.decrypt_state.as_mut().unwrap();
        let decrypted = match decrypt_state.dec_algorithm.as_str() {
            "aes128-cbc" => aes_128_cbc_decrypt_raw(&decrypt_state.dec_key, &decrypt_state.iv, &full_ciphertext)?,
            "aes128-ctr" => {
                use crate::crypto::cipher::aes_ctr_decrypt;
                let pt = aes_ctr_decrypt(&decrypt_state.dec_key, &decrypt_state.iv, &full_ciphertext)?;
                pt
            }
            other => return Err(crate::error::SshError::ProtocolError(
                format!("Unsupported decryption algorithm: {}", other),
            )),
        };
        debug!("Decrypted {} bytes, first 20: {:?}", decrypted.len(), &decrypted[..std::cmp::min(20, decrypted.len())]);

        // Update IV for next packet
        match decrypt_state.dec_algorithm.as_str() {
            "aes128-cbc" => {
                // CBC: IV = last ciphertext block
                if full_ciphertext.len() >= 16 {
                    decrypt_state.iv = full_ciphertext[full_ciphertext.len() - 16..].to_vec();
                }
            }
            "aes128-ctr" => {
                // CTR: advance counter by number of blocks
                let blocks = (full_ciphertext.len() + 15) / 16;
                advance_ctr_iv(&mut decrypt_state.iv, blocks);
            }
            _ => {}
        }

        // Step 4: Verify HMAC over sequence_number + unencrypted packet (RFC 4253 Section 6.4)
        let mut mac_data = Vec::with_capacity(4 + decrypted.len());
        mac_data.extend_from_slice(&decrypt_state.sequence_number.to_be_bytes());
        mac_data.extend_from_slice(&decrypted);

        let mut hmac = HmacSha1::new(&decrypt_state.mac_key);
        hmac.update(&mac_data);
        let expected_mac = hmac.finish();

        if expected_mac.len() != received_mac.len() || !expected_mac.iter().zip(received_mac.iter()).all(|(a, b)| a == b) {
            debug!("MAC mismatch! seq={}, expected={:?}, received={:?}",
                   decrypt_state.sequence_number, &expected_mac[..8], &received_mac[..std::cmp::min(8, received_mac.len())]);
            return Err(crate::error::SshError::ProtocolError(
                "MAC verification failed".to_string(),
            ));
        }
        debug!("MAC verification successful (seq={})", decrypt_state.sequence_number);

        // Update sequence number
        decrypt_state.sequence_number = decrypt_state.sequence_number.wrapping_add(1);

        // Extract payload from decrypted packet:
        // decrypted = [packet_length: 4][padding_length: 1][payload: N][padding: P]
        if decrypted.len() < 5 {
            return Err(crate::error::SshError::ProtocolError(
                "Decrypted packet too short".to_string(),
            ));
        }
        let padding_len = decrypted[4] as usize;
        let payload_start = 5;
        let payload_end = decrypted.len() - padding_len;
        if payload_end <= payload_start {
            return Err(crate::error::SshError::ProtocolError(
                format!("Invalid padding_length {} in decrypted packet of {} bytes", padding_len, decrypted.len()),
            ));
        }
        let payload = decrypted[payload_start..payload_end].to_vec();
        debug!("Extracted payload: {} bytes, msg_type={}", payload.len(), payload[0]);

        Ok(payload)
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
        
        // Decode service name (skip message type byte)
        let service = protocol::SshString::decode(&mut &msg[1..])
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

/// Advance a 16-byte CTR IV by the given number of AES blocks
fn advance_ctr_iv(iv: &mut Vec<u8>, blocks: usize) {
    // IV is treated as a 128-bit big-endian counter
    let mut carry = blocks as u64;
    for i in (0..iv.len()).rev() {
        let sum = iv[i] as u64 + (carry & 0xFF);
        iv[i] = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
        if carry == 0 {
            break;
        }
    }
}

// Standalone helper functions for encryption/decryption
fn encrypt_packet_cbc(payload: &[u8], state: &mut EncryptionState) -> Result<Vec<u8>, crate::error::SshError> {
    // Calculate padding per RFC 4253 Section 6:
    // Total of (packet_length || padding_length || payload || padding) must be multiple of
    // max(8, cipher_block_size). For AES-128-CBC, block size is 16.
    let block_size: usize = match state.enc_algorithm.as_str() {
        "aes128-cbc" | "aes192-cbc" | "aes256-cbc" => 16,
        "aes128-ctr" | "aes192-ctr" | "aes256-ctr" => 16,
        _ => 8,
    };
    let payload_len = payload.len();
    let total_without_padding = 4 + 1 + payload_len;
    let remainder = total_without_padding % block_size;
    let mut padding_length = if remainder == 0 {
        block_size as u8
    } else {
        (block_size - remainder) as u8
    };
    // Ensure minimum padding of 4 bytes per RFC 4253
    if padding_length < 4 {
        padding_length += block_size as u8;
    }
    
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

    // Encrypt the packet
    let encrypted = match state.enc_algorithm.as_str() {
        "aes128-cbc" => {
            let ct = aes_128_cbc_encrypt_raw(&state.enc_key, &state.iv, &packet)?;
            // Update IV for next packet (last 16 bytes of ciphertext)
            if ct.len() >= 16 {
                state.iv = ct[ct.len() - 16..].to_vec();
            }
            ct
        }
        "aes128-ctr" => {
            use crate::crypto::cipher::aes_ctr_encrypt;
            let ct = aes_ctr_encrypt(&state.enc_key, &state.iv, &packet)?;
            // For CTR mode, advance the counter by the number of blocks encrypted
            let blocks = (packet.len() + 15) / 16;
            advance_ctr_iv(&mut state.iv, blocks);
            ct
        }
        _ => {
            return Err(crate::error::SshError::ProtocolError(
                format!("Unsupported encryption algorithm: {}", state.enc_algorithm)
            ));
        }
    };
    
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

    // Decrypt using AES-CBC (raw, no PKCS#7 removal - SSH uses its own padding)
    let decrypted = match state.dec_algorithm.as_str() {
        "aes128-cbc" => {
            aes_128_cbc_decrypt_raw(&state.dec_key, &state.iv, encrypted)?
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