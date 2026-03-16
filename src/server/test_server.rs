//! Test SSH Server - minimal server for crypto algorithm testing
//!
//! Implements just enough of the SSH server protocol to exercise all
//! crypto paths: version exchange, KEXINIT, key exchange, NEWKEYS,
//! service request, authentication, channel open, and data exchange.

use crate::crypto::dh::{DhGroup, Mpint};
use crate::crypto::ecdh::{CurveType, EcdhKeyPair};
use crate::crypto::kdf;
use crate::error::SshError;
use crate::protocol::{self, KexAlgorithm};
use crate::transport::handshake::{
    generate_client_kexinit_with_prefs, negotiate_algorithms, parse_server_kexinit,
    recv_version, send_version_custom, SSH_SERVER_VERSION_STRING,
};
use crate::transport::kex::{KexContext, SessionKeys};
use crate::transport::{EncryptionState, DecryptionState};

use super::encrypted_io::{build_unencrypted_packet, ServerEncryptedIO};
use super::host_key::HostKeyPair;

use bytes::{BufMut, BytesMut};
use std::str::FromStr;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, error};

/// Algorithm filter for controlling which algorithms the server offers
#[derive(Debug, Clone, Default)]
pub struct AlgorithmFilter {
    pub kex: Option<String>,
    pub cipher: Option<String>,
    pub mac: Option<String>,
}

/// Minimal SSH test server
pub struct TestSshServer {
    listener: TcpListener,
    host_key: HostKeyPair,
    filter: AlgorithmFilter,
}

impl TestSshServer {
    /// Create a new test server on the specified port (0 = OS-assigned)
    pub async fn new(port: u16) -> Result<Self, SshError> {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| SshError::ConnectionError(format!("Failed to bind {}: {}", addr, e)))?;
        let host_key = HostKeyPair::generate_ed25519();
        info!("Test SSH server listening on {}", listener.local_addr().unwrap());

        Ok(Self {
            listener,
            host_key,
            filter: AlgorithmFilter::default(),
        })
    }

    /// Set the host key
    pub fn with_host_key(mut self, key: HostKeyPair) -> Self {
        self.host_key = key;
        self
    }

    /// Set algorithm filter
    pub fn with_filter(mut self, filter: AlgorithmFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Get the local address this server is listening on
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.listener.local_addr().unwrap()
    }

    /// Accept one TCP connection and return the raw stream
    pub async fn accept_stream(&self) -> Result<TcpStream, SshError> {
        let (stream, addr) = self.listener.accept().await
            .map_err(|e| SshError::ConnectionError(format!("Accept failed: {}", e)))?;
        info!("Accepted connection from {}", addr);
        Ok(stream)
    }

    /// Perform SSH handshake + auth on a stream, returning an authenticated
    /// ServerEncryptedIO with an open channel ready for data exchange.
    /// Returns (io, client_channel_id) on success.
    pub async fn handshake_and_auth(&self, stream: TcpStream) -> Result<(ServerEncryptedIO, u32), SshError> {
        server_handshake(stream, &self.host_key, &self.filter).await
    }

    /// Accept one connection, do full SSH protocol with test data, then close
    pub async fn accept_one(&self) -> Result<(), SshError> {
        let stream = self.accept_stream().await?;
        let (mut io, client_channel) = self.handshake_and_auth(stream).await?;

        // Send test data
        let test_data = b"AYSSH_TEST_OK\n";
        let mut data_msg = BytesMut::new();
        data_msg.put_u8(94); // SSH_MSG_CHANNEL_DATA
        data_msg.put_u32(client_channel);
        data_msg.put_u32(test_data.len() as u32);
        data_msg.put_slice(test_data);
        io.send_message(&data_msg).await?;

        // Send EOF + CLOSE
        let mut eof = BytesMut::new();
        eof.put_u8(96);
        eof.put_u32(client_channel);
        io.send_message(&eof).await?;
        let mut close = BytesMut::new();
        close.put_u8(97);
        close.put_u32(client_channel);
        io.send_message(&close).await?;

        info!("Test connection handled successfully");
        Ok(())
    }
}

/// Perform SSH handshake + auth on a connection.
/// Returns (ServerEncryptedIO, client_channel_id) ready for data exchange.
pub async fn server_handshake(
    stream: TcpStream,
    host_key: &HostKeyPair,
    filter: &AlgorithmFilter,
) -> Result<(ServerEncryptedIO, u32), SshError> {
    let mut io = ServerEncryptedIO::new(stream);
    let mut send_seq: u32 = 0;
    let mut recv_seq: u32 = 0;

    // Step 1: Version exchange (server sends first)
    send_version_custom(&mut io.stream, SSH_SERVER_VERSION_STRING).await?;
    let client_version = recv_version(&mut io.stream).await?;
    debug!("Client version: {}", client_version);

    // Step 2: Send server KEXINIT
    let server_kexinit = generate_client_kexinit_with_prefs(
        filter.kex.as_deref(),
        filter.cipher.as_deref(),
        filter.mac.as_deref(),
    );
    let server_kexinit_packet = build_unencrypted_packet(&server_kexinit);
    io.stream.write_all(&server_kexinit_packet).await?;
    send_seq += 1;
    debug!("Sent server KEXINIT ({} bytes)", server_kexinit.len());

    // Step 3: Receive client KEXINIT
    let client_kexinit_packet = io.read_unencrypted_packet(30).await?;
    recv_seq += 1;
    let pkt_len = u32::from_be_bytes([
        client_kexinit_packet[0], client_kexinit_packet[1],
        client_kexinit_packet[2], client_kexinit_packet[3],
    ]) as usize;
    let pad_len = client_kexinit_packet[4] as usize;
    let client_kexinit_payload = &client_kexinit_packet[5..4 + pkt_len - pad_len];
    debug!("Received client KEXINIT ({} bytes payload)", client_kexinit_payload.len());

    // Step 4: Negotiate algorithms
    let server_proposal = parse_server_kexinit(&server_kexinit)
        .map_err(|e| SshError::ProtocolError(e.to_string()))?;
    let client_proposal = parse_server_kexinit(client_kexinit_payload)
        .map_err(|e| SshError::ProtocolError(e.to_string()))?;
    // For negotiation, the CLIENT's proposal takes priority (first match wins)
    let negotiated = negotiate_algorithms(&client_proposal, &server_proposal);
    info!("Negotiated: kex={}, enc={}, mac={}", negotiated.kex, negotiated.enc_c2s, negotiated.mac_c2s);
    eprintln!("[SERVER-HS] Negotiated: kex={}, enc={}, mac={}", negotiated.kex, negotiated.enc_c2s, negotiated.mac_c2s);

    // Step 5: Key exchange (receive KEXDH_INIT, send KEXDH_REPLY)
    let kex_algorithm = KexAlgorithm::from_str(&negotiated.kex)
        .unwrap_or(KexAlgorithm::DiffieHellmanGroup14Sha256);

    let mut kex_context = KexContext::new(kex_algorithm);

    // Set version strings and KEXINIT payloads for exchange hash
    let client_ver_clean = client_version
        .strip_suffix("\r\n")
        .unwrap_or(client_version.strip_suffix('\n').unwrap_or(&client_version));
    let server_ver_clean = SSH_SERVER_VERSION_STRING
        .strip_suffix("\r\n")
        .unwrap_or(SSH_SERVER_VERSION_STRING);

    kex_context.set_exchange_info(
        client_ver_clean.as_bytes(),
        server_ver_clean.as_bytes(),
        client_kexinit_payload,
        &server_kexinit,
    );
    kex_context.set_server_host_key(&host_key.public_key_blob());

    // Receive KEXDH_INIT (message type 30)
    let kexdh_init_packet = io.read_unencrypted_packet(30).await?;
    recv_seq += 1;
    let ki_pkt_len = u32::from_be_bytes([
        kexdh_init_packet[0], kexdh_init_packet[1],
        kexdh_init_packet[2], kexdh_init_packet[3],
    ]) as usize;
    let ki_pad_len = kexdh_init_packet[4] as usize;
    let kexdh_init_payload = &kexdh_init_packet[5..4 + ki_pkt_len - ki_pad_len];

    if kexdh_init_payload[0] != 30 {
        return Err(SshError::ProtocolError(format!("Expected KEXDH_INIT (30), got {}", kexdh_init_payload[0])));
    }

    // Extract client's ephemeral public key (e)
    let client_e_data = &kexdh_init_payload[1..]; // skip msg type
    // e is encoded as SSH string (length-prefixed)
    if client_e_data.len() < 4 {
        return Err(SshError::ProtocolError("KEXDH_INIT too short".to_string()));
    }
    let e_len = u32::from_be_bytes([client_e_data[0], client_e_data[1], client_e_data[2], client_e_data[3]]) as usize;
    let client_e = &client_e_data[4..4 + e_len];
    debug!("Client ephemeral key: {} bytes", client_e.len());

    // Generate server's ephemeral key and compute shared secret
    use rand::rngs::OsRng;
    kex_context.generate_client_key(&mut OsRng)?;
    let server_ephemeral = kex_context.client_ephemeral.clone().unwrap();

    // Process client's ephemeral key
    // process_server_kex_init expects the data AFTER the host key string
    // in KEXDH_REPLY format: [string Q_S][string sig]
    // For the server receiving KEXDH_INIT, the data is just [string e]
    // which is already length-prefixed in client_e_data
    debug!("Client e: {} bytes, first 4: {:?}", client_e.len(),
           &client_e[..std::cmp::min(4, client_e.len())]);
    // Wrap as length-prefixed for process_server_kex_init
    let mut client_e_for_kex = Vec::with_capacity(4 + client_e.len());
    client_e_for_kex.extend_from_slice(&(client_e.len() as u32).to_be_bytes());
    client_e_for_kex.extend_from_slice(client_e);
    kex_context.process_server_kex_init(&client_e_for_kex)?;

    // For the exchange hash, swap client/server ephemeral keys:
    // client_ephemeral in KexContext = server's key (f), but for hash we need it as client's (e)
    // Let's set them correctly:
    // The hash needs: e = client's key, f = server's key
    // KexContext stores: client_ephemeral = what generate_client_key produced = server's f
    // server_ephemeral = what process_server_kex_init stored = client's e (length-prefixed)
    // But build_hash_input uses client_ephemeral as e and server_ephemeral as f
    // So we need to SWAP them for the server side:
    let server_f = kex_context.client_ephemeral.take();
    let client_e_lp = kex_context.server_ephemeral.take();
    kex_context.client_ephemeral = Some(client_e.to_vec()); // e = client's raw key
    kex_context.server_ephemeral = Some({
        // f needs to be length-prefixed for the hash
        let mut f_lp = Vec::with_capacity(4 + server_ephemeral.len());
        f_lp.extend_from_slice(&(server_ephemeral.len() as u32).to_be_bytes());
        f_lp.extend_from_slice(&server_ephemeral);
        f_lp
    });

    // Compute shared secret and session ID
    kex_context.compute_shared_secret()?;
    let session_id = kex_context.session_id.clone().unwrap();
    debug!("Session ID computed ({} bytes)", session_id.len());

    // Sign the exchange hash with the host key
    let signature = host_key.sign(&session_id)?;
    debug!("Exchange hash signed ({} bytes)", signature.len());

    // Build KEXDH_REPLY: msg_type(31) || string(K_S) || mpint(f) || string(sig)
    let host_key_blob = host_key.public_key_blob();
    let mut reply_payload = BytesMut::new();
    reply_payload.put_u8(31); // SSH_MSG_KEXDH_REPLY
    // K_S (host key blob as SSH string)
    reply_payload.put_u32(host_key_blob.len() as u32);
    reply_payload.put_slice(&host_key_blob);
    // f (server's ephemeral public key as SSH string/mpint)
    reply_payload.put_u32(server_ephemeral.len() as u32);
    reply_payload.put_slice(&server_ephemeral);
    // signature
    reply_payload.put_u32(signature.len() as u32);
    reply_payload.put_slice(&signature);

    let reply_packet = build_unencrypted_packet(&reply_payload);
    io.stream.write_all(&reply_packet).await?;
    send_seq += 1;
    debug!("Sent KEXDH_REPLY");

    // Step 6: NEWKEYS exchange
    let newkeys_msg = crate::transport::kex::encode_newkeys();
    io.stream.write_all(&newkeys_msg).await?;
    send_seq += 1;
    debug!("Sent NEWKEYS");

    // Receive client NEWKEYS
    let newkeys_packet = io.read_unencrypted_packet(30).await?;
    recv_seq += 1;
    if newkeys_packet.len() >= 6 && newkeys_packet[5] == 21 {
        debug!("Received client NEWKEYS");
    } else {
        return Err(SshError::ProtocolError("Expected NEWKEYS".to_string()));
    }

    // Derive session keys
    let session_keys = kex_context.derive_session_keys_for(
        &session_id,
        Some(&negotiated.enc_c2s),
        Some(&negotiated.mac_c2s),
    )?;

    // Set up encryption: server encrypts with S2C keys, decrypts with C2S keys
    io.encrypt_state = Some(EncryptionState {
        enc_key: session_keys.enc_key_s2c.clone(),
        iv: session_keys.server_iv.clone(),
        mac_key: session_keys.mac_key_s2c.clone(),
        sequence_number: send_seq,
        aead_counter: 0,
        enc_algorithm: negotiated.enc_s2c.clone(),
        mac_algorithm: negotiated.mac_s2c.clone(),
    });
    io.decrypt_state = Some(DecryptionState {
        dec_key: session_keys.enc_key_c2s.clone(),
        iv: session_keys.client_iv.clone(),
        mac_key: session_keys.mac_key_c2s.clone(),
        sequence_number: recv_seq,
        aead_counter: 0,
        dec_algorithm: negotiated.enc_c2s.clone(),
        mac_algorithm: negotiated.mac_c2s.clone(),
    });
    info!("Encryption established: enc={}, mac={}", negotiated.enc_c2s, negotiated.mac_c2s);
    eprintln!("[SERVER-HS] Encryption established");

    // Step 7: Handle SERVICE_REQUEST
    let service_req = io.recv_message().await?;
    if service_req.is_empty() || service_req[0] != 5 {
        return Err(SshError::ProtocolError(format!("Expected SERVICE_REQUEST (5), got {}", service_req.get(0).unwrap_or(&0))));
    }
    debug!("Received SERVICE_REQUEST");
    eprintln!("[SERVER-HS] Received SERVICE_REQUEST");

    // Send SERVICE_ACCEPT
    let mut accept = BytesMut::new();
    accept.put_u8(6); // SSH_MSG_SERVICE_ACCEPT
    accept.put_u32(12);
    accept.put_slice(b"ssh-userauth");
    io.send_message(&accept).await?;
    debug!("Sent SERVICE_ACCEPT");

    // Step 8: Handle USERAUTH_REQUEST - accept any password
    let auth_req = io.recv_message().await?;
    if auth_req.is_empty() || auth_req[0] != 50 {
        return Err(SshError::ProtocolError(format!("Expected USERAUTH_REQUEST (50), got {}", auth_req.get(0).unwrap_or(&0))));
    }
    debug!("Received USERAUTH_REQUEST, accepting");

    // Send USERAUTH_SUCCESS
    io.send_message(&[52]).await?; // SSH_MSG_USERAUTH_SUCCESS
    debug!("Sent USERAUTH_SUCCESS");

    // Step 9: Handle CHANNEL_OPEN
    let chan_open = io.recv_message().await?;
    if chan_open.is_empty() || chan_open[0] != 90 {
        return Err(SshError::ProtocolError(format!("Expected CHANNEL_OPEN (90), got {}", chan_open.get(0).unwrap_or(&0))));
    }
    debug!("Received CHANNEL_OPEN");

    // Parse sender channel from CHANNEL_OPEN
    // Format: type(1) || string(channel_type) || uint32(sender_channel) || uint32(window) || uint32(max_packet)
    let mut offset = 1;
    let ct_len = u32::from_be_bytes([chan_open[offset], chan_open[offset+1], chan_open[offset+2], chan_open[offset+3]]) as usize;
    offset += 4 + ct_len;
    let client_channel = u32::from_be_bytes([chan_open[offset], chan_open[offset+1], chan_open[offset+2], chan_open[offset+3]]);
    let server_channel: u32 = 0;

    // Send CHANNEL_OPEN_CONFIRMATION
    let mut conf = BytesMut::new();
    conf.put_u8(91); // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    conf.put_u32(client_channel); // recipient channel
    conf.put_u32(server_channel); // sender channel
    conf.put_u32(1048576); // window size
    conf.put_u32(32768); // max packet size
    io.send_message(&conf).await?;
    debug!("Sent CHANNEL_OPEN_CONFIRMATION");

    // Handle channel requests (pty-req, shell) - accept them all
    for _ in 0..10 {
        let msg = io.recv_message().await?;
        if msg.is_empty() { continue; }
        match msg[0] {
            98 => {
                // SSH_MSG_CHANNEL_REQUEST
                // Check if want_reply is set
                let want_reply = if msg.len() > 9 {
                    let req_len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
                    if msg.len() > 9 + req_len { msg[9 + req_len] != 0 } else { false }
                } else { false };

                if want_reply {
                    let mut success = BytesMut::new();
                    success.put_u8(99); // SSH_MSG_CHANNEL_SUCCESS
                    success.put_u32(client_channel);
                    io.send_message(&success).await?;
                }

                // Check if this is shell or exec request
                if msg.len() > 9 {
                    let req_len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
                    if msg.len() >= 9 + req_len {
                        let req_type = std::str::from_utf8(&msg[9..9+req_len]).unwrap_or("");
                        debug!("CHANNEL_REQUEST type={}", req_type);
                        if req_type == "shell" || req_type == "exec" {
                            break; // Shell/exec received, ready for data
                        }
                    }
                }
            }
            93 => {
                // SSH_MSG_CHANNEL_WINDOW_ADJUST
                debug!("Received CHANNEL_WINDOW_ADJUST");
                continue;
            }
            _ => {
                debug!("Received message type {} during channel setup", msg[0]);
                break;
            }
        }
    }

    info!("SSH handshake + auth + channel complete");
    Ok((io, client_channel))
}

use tokio::io::AsyncWriteExt;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_binds_to_random_port() {
        let server = TestSshServer::new(0).await.unwrap();
        let addr = server.local_addr();
        assert_ne!(addr.port(), 0);
    }

    /// Server-client end-to-end test: full SSH protocol through encrypted data.
    /// Server runs on a separate OS thread to avoid scheduling interference
    /// with the test framework's parallel test execution.
    #[test]
    fn test_server_accepts_client_connection() {
        // Bind on main thread so port is known before spawning
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = std_listener.local_addr().unwrap().port();
        std_listener.set_nonblocking(true).unwrap();

        // Server: separate thread + runtime (avoids Send issues with tokio::spawn)
        let server_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
                let host_key = HostKeyPair::generate_ed25519();
                let filter = AlgorithmFilter::default();

                let (stream, _addr) = listener.accept().await.unwrap();
                let (mut io, client_channel) = server_handshake(stream, &host_key, &filter).await
                    .expect("Server handshake failed");

                let mut data_msg = BytesMut::new();
                data_msg.put_u8(94);
                data_msg.put_u32(client_channel);
                let test_data = b"AYSSH_TEST_OK\n";
                data_msg.put_u32(test_data.len() as u32);
                data_msg.put_slice(test_data);
                io.send_message(&data_msg).await.unwrap();

                let mut eof = BytesMut::new();
                eof.put_u8(96);
                eof.put_u32(client_channel);
                io.send_message(&eof).await.unwrap();

                let mut close = BytesMut::new();
                close.put_u8(97);
                close.put_u32(client_channel);
                io.send_message(&close).await.unwrap();
            });
        });

        // Client: separate thread + runtime
        let client_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                eprintln!("[CLIENT] Connecting to port {}...", port);
                let mut transport = crate::transport::Transport::new(
                    TcpStream::connect(format!("127.0.0.1:{}", port)).await
                        .expect("Failed to connect to server")
                );
                eprintln!("[CLIENT] Connected, starting handshake...");

                transport.handshake().await.expect("[CLIENT] Handshake failed");
                eprintln!("[CLIENT] Handshake OK");

                transport.send_service_request("ssh-userauth").await.unwrap();
                let service = transport.recv_service_accept().await.unwrap();
                assert_eq!(service, "ssh-userauth");
                eprintln!("[CLIENT] Service accepted");

                let mut auth = crate::auth::Authenticator::new(&mut transport, "test".to_string())
                    .with_password("test".to_string());
                auth.available_methods.insert("password".to_string());
                let auth_result = auth.authenticate().await.unwrap();
                assert!(matches!(auth_result, crate::auth::AuthenticationResult::Success));
                eprintln!("[CLIENT] Auth OK");

                let session = crate::session::Session::open(&mut transport).await.unwrap();
                let channel_id = session.remote_channel_id();
                transport.send_channel_request(channel_id, "shell", true).await.unwrap();
                let _ = transport.recv_message().await.unwrap(); // CHANNEL_SUCCESS

                let data = transport.recv_message().await.unwrap();
                assert!(!data.is_empty() && data[0] == 94, "Expected CHANNEL_DATA");
                let data_len = u32::from_be_bytes([data[5], data[6], data[7], data[8]]) as usize;
                let text = std::str::from_utf8(&data[9..9+data_len]).unwrap_or("");
                assert!(text.contains("AYSSH_TEST_OK"), "Expected AYSSH_TEST_OK, got {:?}", text);
                eprintln!("[CLIENT] Got AYSSH_TEST_OK - full protocol test passed!");
            });
        });

        server_handle.join().expect("Server thread panicked");
        client_handle.join().expect("Client thread panicked");
    }
}
