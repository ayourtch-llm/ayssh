//! SSH Transport Handshake
//!
//! Implements the initial key exchange and authentication handshake.

use crate::protocol;
use crate::protocol::KexAlgorithm;
use crate::transport::kex::SessionKeys;
use crate::transport::TransportSession;
use bytes::{Buf, BufMut, BytesMut};
use rand::RngCore;
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug};

/// SSH protocol version string with CRLF terminator
/// Format: SSH-2.0-software_version\r\n
/// Cisco devices expect CRLF-terminated version strings
pub const SSH_VERSION_STRING: &str = "SSH-2.0-OpenSSH_7.4\r\n";

/// Transport handshake state
#[derive(Debug, Clone)]
pub struct HandshakeState {
    /// Client's KEXINIT message
    pub client_kexinit: Option<Vec<u8>>,
    /// Server's KEXINIT message
    pub server_kexinit: Option<Vec<u8>>,
    /// Negotiated algorithms
    pub negotiated: Option<protocol::NegotiatedAlgorithms>,
    /// Session keys after key exchange
    pub session_keys: Option<SessionKeys>,
    /// Client-to-server encryption algorithm
    pub enc_c2s: Option<String>,
    /// Server-to-client encryption algorithm
    pub enc_s2c: Option<String>,
    /// Client-to-server MAC algorithm
    pub mac_c2s: Option<String>,
    /// Server-to-client MAC algorithm
    pub mac_s2c: Option<String>,
}

impl Default for HandshakeState {
    fn default() -> Self {
        Self {
            client_kexinit: None,
            server_kexinit: None,
            negotiated: None,
            session_keys: None,
            enc_c2s: None,
            enc_s2c: None,
            mac_c2s: None,
            mac_s2c: None,
        }
    }
}

/// Parse SSH version string
pub fn parse_version_string(data: &[u8]) -> Result<(u32, String), &'static str> {
    let version = std::str::from_utf8(data).map_err(|_| "Invalid UTF-8 in version string")?;
    
    if !version.starts_with("SSH-") {
        return Err("Invalid version string prefix");
    }
    
    let parts: Vec<&str> = version.split('-').collect();
    if parts.len() < 2 {
        return Err("Invalid version string format");
    }
    
    // parts[1] contains the protocol version (e.g., "2.0" -> extract "2")
    let protocol_version_str = parts[1].split('.').next().ok_or("Invalid protocol version")?;
    let protocol_version: u32 = protocol_version_str.parse().map_err(|_| "Invalid protocol version")?;
    
    // Accept SSH-2.0 or SSH-1.99 (RFC 4253 Section 5.1: Clients using protocol 2.0
    // MUST be able to identify "1.99" as identical to "2.0")
    // Cisco devices send SSH-1.99-Cisco-1.25 for their SSH2-compatible implementation.
    let full_proto_version = parts[1]; // e.g. "2.0" or "1.99"
    if protocol_version == 2 || full_proto_version == "1.99" {
        // OK - SSH 2.0 compatible
    } else {
        return Err("Only SSH protocol version 2.0 or 1.99 supported");
    }
    
    let software_version = parts[2..].join("-");
    
    Ok((protocol_version, software_version))
}

/// Generate client KEXINIT message
/// Generate a client KEXINIT with preferred cipher and MAC placed first.
/// If `preferred_cipher` or `preferred_mac` is None, uses default ordering.
pub fn generate_client_kexinit_with_prefs(
    preferred_kex: Option<&str>,
    preferred_cipher: Option<&str>,
    preferred_mac: Option<&str>,
) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(200);

    buf.put_u8(20);

    let mut cookie = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut cookie);
    buf.put(&cookie[..]);

    let default_kex = "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,curve25519-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521";
    let kex_list = if let Some(pref) = preferred_kex {
        let others: Vec<&str> = default_kex.split(',').filter(|k| *k != pref).collect();
        format!("{},{}", pref, others.join(","))
    } else {
        default_kex.to_string()
    };
    let kex_algorithms = &kex_list;
    let host_key_algorithms = "ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-512,rsa-sha2-256";

    let default_ciphers = "aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com";
    let default_macs = "hmac-sha1,hmac-sha2-256,hmac-sha2-512,hmac-sha1-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com";

    // Put preferred algorithm first if specified
    let enc_list = if let Some(pref) = preferred_cipher {
        let others: Vec<&str> = default_ciphers.split(',').filter(|c| *c != pref).collect();
        format!("{},{}", pref, others.join(","))
    } else {
        default_ciphers.to_string()
    };
    let mac_list = if let Some(pref) = preferred_mac {
        let others: Vec<&str> = default_macs.split(',').filter(|m| *m != pref).collect();
        format!("{},{}", pref, others.join(","))
    } else {
        default_macs.to_string()
    };

    let enc_c2s = &enc_list;
    let enc_s2c = &enc_list;
    let mac_c2s = &mac_list;
    let mac_s2c = &mac_list;
    let comp_c2s = "none,zlib@openssh.com";
    let comp_s2c = "none,zlib@openssh.com";
    let lang_c2s = "";
    let lang_s2c = "";
    
    // Encode each algorithm list as a string
    protocol::SshString::from_str(kex_algorithms).encode(&mut buf);
    protocol::SshString::from_str(host_key_algorithms).encode(&mut buf);
    protocol::SshString::from_str(enc_c2s).encode(&mut buf);
    protocol::SshString::from_str(enc_s2c).encode(&mut buf);
    protocol::SshString::from_str(mac_c2s).encode(&mut buf);
    protocol::SshString::from_str(mac_s2c).encode(&mut buf);
    protocol::SshString::from_str(comp_c2s).encode(&mut buf);
    protocol::SshString::from_str(comp_s2c).encode(&mut buf);
    protocol::SshString::from_str(lang_c2s).encode(&mut buf);
    protocol::SshString::from_str(lang_s2c).encode(&mut buf);
    
    // first_kex_packet_follows (1 byte boolean, typically 0)
    buf.put_u8(0);
    
    // Reserved uint32 (always 0)
    buf.put_u32(0);
    
    buf.to_vec()
}

/// Generate a client KEXINIT with default algorithm ordering
pub fn generate_client_kexinit() -> Vec<u8> {
    generate_client_kexinit_with_prefs(None, None, None)
}

/// Parse server KEXINIT message
pub fn parse_server_kexinit(data: &[u8]) -> Result<protocol::AlgorithmProposal, &'static str> {
    let mut buf = data;
    
    // Skip message type byte (SSH_MSG_KEXINIT = 20)
    if buf.len() < 1 {
        return Err("KEXINIT too short");
    }
    let msg_type = buf.get_u8();
    if msg_type != 20 {
        return Err("Expected SSH_MSG_KEXINIT (20)");
    }
    
    // Skip 16 bytes of cookie
    if buf.len() < 16 {
        return Err("KEXINIT too short for cookie");
    }
    buf.advance(16);
    
    // Parse algorithm lists (each is a comma-separated string)
    let kex_algorithms_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode kex_algorithms")?
        .to_str()
        .map_err(|_| "Invalid kex_algorithms UTF-8")?
        .to_string();
    
    let host_key_algorithms_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode host_key_algorithms")?
        .to_str()
        .map_err(|_| "Invalid host_key_algorithms UTF-8")?
        .to_string();
    
    let enc_c2s_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode enc_c2s")?
        .to_str()
        .map_err(|_| "Invalid enc_c2s UTF-8")?
        .to_string();
    
    let enc_s2c_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode enc_s2c")?
        .to_str()
        .map_err(|_| "Invalid enc_s2c UTF-8")?
        .to_string();
    
    let mac_c2s_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode mac_c2s")?
        .to_str()
        .map_err(|_| "Invalid mac_c2s UTF-8")?
        .to_string();
    
    let mac_s2c_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode mac_s2c")?
        .to_str()
        .map_err(|_| "Invalid mac_s2c UTF-8")?
        .to_string();
    
    let comp_c2s_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode comp_c2s")?
        .to_str()
        .map_err(|_| "Invalid comp_c2s UTF-8")?
        .to_string();
    
    let _comp_s2c_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode comp_s2c")?
        .to_str()
        .map_err(|_| "Invalid comp_s2c UTF-8")?
        .to_string();
    
    let lang_c2s_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode lang_c2s")?
        .to_str()
        .map_err(|_| "Invalid lang_c2s UTF-8")?
        .to_string();
    
    let lang_s2c_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode lang_s2c")?
        .to_str()
        .map_err(|_| "Invalid lang_s2c UTF-8")?
        .to_string();
    
    // Parse first_kex_packet_follows (1 byte boolean) per RFC 4253
    if buf.len() < 1 {
        return Err("KEXINIT too short for first_kex_packet_follows");
    }
    let first_kex_packet_follows = buf.get_u8() != 0;
    
    // Skip reserved uint32 (4 bytes) per RFC 4253
    if buf.len() < 4 {
        return Err("KEXINIT too short for reserved uint32");
    }
    buf.advance(4);
    
    // Convert comma-separated strings to Vec<String>
    let kex_algorithms: Vec<String> = kex_algorithms_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let server_host_key_algorithms: Vec<String> = host_key_algorithms_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let encryption_algorithms_c2s: Vec<String> = enc_c2s_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let encryption_algorithms_s2c: Vec<String> = enc_s2c_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let mac_algorithms_c2s: Vec<String> = mac_c2s_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let mac_algorithms_s2c: Vec<String> = mac_s2c_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    let compression_algorithms: Vec<String> = comp_c2s_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    
    Ok(protocol::AlgorithmProposal {
        kex_algorithms,
        server_host_key_algorithms,
        encryption_algorithms_c2s,
        encryption_algorithms_s2c,
        mac_algorithms_c2s,
        mac_algorithms_s2c,
        compression_algorithms,
        languages_c2s: lang_c2s_str,
        languages_s2c: lang_s2c_str,
        first_kex_packet_follows,
    })
}

/// Select the first matching algorithm from a list
pub fn select_algorithm(preferred: &[String], server_list: &[String]) -> Option<String> {
    for algo in preferred {
        if server_list.contains(algo) {
            return Some(algo.clone());
        }
    }
    None
}

/// Negotiate algorithms from client and server proposals
pub fn negotiate_algorithms(client: &protocol::AlgorithmProposal, server: &protocol::AlgorithmProposal) -> protocol::NegotiatedAlgorithms {
    let kex = select_algorithm(&client.kex_algorithms, &server.kex_algorithms)
        .expect("No common KEX algorithm");
    
    let host_key = select_algorithm(&client.server_host_key_algorithms, &server.server_host_key_algorithms)
        .expect("No common host key algorithm");
    
    let enc_c2s = select_algorithm(&client.encryption_algorithms_c2s, &server.encryption_algorithms_c2s)
        .expect("No common encryption algorithm (C2S)");
    
    let enc_s2c = select_algorithm(&client.encryption_algorithms_s2c, &server.encryption_algorithms_s2c)
        .expect("No common encryption algorithm (S2C)");
    
    let mac_c2s = select_algorithm(&client.mac_algorithms_c2s, &server.mac_algorithms_c2s)
        .expect("No common MAC algorithm (C2S)");
    
    let mac_s2c = select_algorithm(&client.mac_algorithms_s2c, &server.mac_algorithms_s2c)
        .expect("No common MAC algorithm (S2C)");
    
    let comp = select_algorithm(&client.compression_algorithms, &server.compression_algorithms)
        .expect("No common compression algorithm");
    
    protocol::NegotiatedAlgorithms {
        kex,
        host_key,
        enc_c2s,
        enc_s2c,
        mac_c2s,
        mac_s2c,
        compression: comp,
    }
}

/// Send SSH version string
pub async fn send_version<T: AsyncWriteExt + Unpin>(stream: &mut T) -> Result<(), crate::error::SshError> {
    let version_bytes = SSH_VERSION_STRING.as_bytes();
    debug!("Sending version string: {:?}", std::str::from_utf8(version_bytes));
    // Send version string directly without length prefix (Cisco doesn't use length prefix for version)
    stream.write_all(version_bytes).await?;
    stream.flush().await?;
    debug!("Version string sent successfully");
    Ok(())
}

/// Receive SSH version string
pub async fn recv_version<T: AsyncReadExt + Unpin>(stream: &mut T) -> Result<String, crate::error::SshError> {
    // Cisco devices send version string without length prefix, just line-based with CRLF
    // We'll use a BufReader to read line-by-line
    use tokio::io::AsyncBufReadExt;
    let mut reader = tokio::io::BufReader::new(stream);
    let mut buf = String::new();
    
    match reader.read_line(&mut buf).await {
        Ok(n) => {
            debug!("Read {} bytes from version line", n);
            debug!("Raw version bytes: {:?}", buf.as_bytes());
            
            // Remove CRLF terminator if present
            if buf.ends_with("\r\n") {
                buf.pop();
                buf.pop();
            } else if buf.ends_with('\n') {
                buf.pop();
            }
            
            debug!("Cleaned version string: {:?}", buf);
            Ok(buf)
        }
        Err(e) => {
            debug!("Error reading version line: {}", e);
            Err(e.into())
        }
    }
}

/// Perform the key exchange handshake
pub async fn perform_handshake<T: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut stream: T,
    server_version: &str,
) -> Result<(TransportSession<T>, protocol::NegotiatedAlgorithms), crate::error::SshError> {
    // 1. Send client version
    send_version(&mut stream).await?;
    
    // 2. Receive server version
    let server_ver = recv_version(&mut stream).await?;
    let (_proto, _software) = parse_version_string(server_ver.as_bytes())
        .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?;
    
    // 3. Generate and send client KEXINIT
    let client_kexinit = generate_client_kexinit();
    stream.write_all(&client_kexinit).await?;
    
    // 4. Receive and parse server KEXINIT
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    
    let mut server_kexinit_bytes = vec![0u8; len];
    stream.read_exact(&mut server_kexinit_bytes).await?;
    
    let server_proposal = parse_server_kexinit(&server_kexinit_bytes)
        .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?;
    
    // 5. Negotiate algorithms
    let client_proposal = parse_server_kexinit(&client_kexinit)
        .map_err(|e| crate::error::SshError::ProtocolError(e.to_string()))?;
    let negotiated = negotiate_algorithms(&client_proposal, &server_proposal);
    
    // 6. Create transport session and initiate KEX
    let mut transport_session = TransportSession::new(stream, KexAlgorithm::from_str(&negotiated.kex).unwrap_or(KexAlgorithm::Curve25519Sha256));
    transport_session.init_kex()?;
    
    // 7. Send KEXINIT message (with client ephemeral key)
    let client_ephemeral = transport_session.kex_context().client_ephemeral.clone()
        .expect("Client ephemeral key not generated");
    
    let mut kexinit_msg = BytesMut::new();
    kexinit_msg.put_u8(protocol::MessageType::KexInit as u8);
    kexinit_msg.put_u32(client_ephemeral.len() as u32);
    kexinit_msg.put_slice(&client_ephemeral);
    transport_session.stream_mut().write_all(&kexinit_msg).await?;
    
    // 8. Receive KEX_REPLY from server (server ephemeral key)
    let mut len_buf2 = [0u8; 4];
    transport_session.stream_mut().read_exact(&mut len_buf2).await?;
    let len2 = u32::from_be_bytes(len_buf2) as usize;
    
    let mut reply_bytes = vec![0u8; len2];
    transport_session.stream_mut().read_exact(&mut reply_bytes).await?;
    
    if reply_bytes[0] != protocol::MessageType::KexInit as u8 {
        return Err(crate::error::SshError::ProtocolError(
            "Expected KEX_INIT from server".to_string()
        ));
    }
    
    transport_session.kex_context_mut().process_server_kex_init(&reply_bytes[1..])?;
    
    // 9. Compute shared secret
    transport_session.kex_context_mut().compute_shared_secret()?;
    
    // 10. Derive session keys
    let session_id = transport_session.session_id().cloned()
        .expect("Session ID not set");
    transport_session.kex_context_mut().derive_session_keys(&session_id)?;
    
    // 11. Send NEWKEYS message to transition to encrypted mode
    let newkeys_msg = crate::transport::kex::encode_newkeys();
    transport_session.stream_mut().write_all(&newkeys_msg).await?;
    
    // 12. Receive NEWKEYS from server
    let mut len_buf3 = [0u8; 4];
    transport_session.stream_mut().read_exact(&mut len_buf3).await?;
    let len3 = u32::from_be_bytes(len_buf3) as usize;
    
    let mut newkeys_bytes = vec![0u8; len3];
    transport_session.stream_mut().read_exact(&mut newkeys_bytes).await?;
    
    // newkeys_bytes contains: [padding_length (1 byte)][payload][padding]
    // The message type is at byte 1 (after padding_length byte)
    if newkeys_bytes.len() < 2 || newkeys_bytes[1] != protocol::MessageType::Newkeys as u8 {
        return Err(crate::error::SshError::ProtocolError(
            "Expected NEWKEYS from server".to_string()
        ));
    }
    
    // 13. Transition to encrypted state
    transport_session.transition_to_encrypted()?;
    
    Ok((transport_session, negotiated))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_string_valid() {
        let version = b"SSH-2.0-libssh_0.9.6";
        let (proto, software) = parse_version_string(version).unwrap();
        assert_eq!(proto, 2);
        assert_eq!(software, "libssh_0.9.6");
    }

    #[test]
    fn test_parse_version_string_with_dash_in_software() {
        let version = b"SSH-2.0-OpenSSH_8.0";
        let (proto, software) = parse_version_string(version).unwrap();
        assert_eq!(proto, 2);
        assert_eq!(software, "OpenSSH_8.0");
    }

    #[test]
    fn test_parse_version_string_invalid_prefix() {
        let version = b"SSH-1.0-invalid";
        assert!(parse_version_string(version).is_err());
    }

    #[test]
    fn test_parse_version_string_invalid_protocol() {
        // SSH-1.99 MUST be accepted as identical to 2.0 per RFC 4253 Section 5.1
        let version = b"SSH-1.99-Cisco-1.25";
        let (proto, software) = parse_version_string(version).unwrap();
        assert_eq!(proto, 1); // major version is 1, but 1.99 is accepted
        assert_eq!(software, "Cisco-1.25");

        // SSH-1.0 should be rejected
        let version_old = b"SSH-1.0-OldServer";
        assert!(parse_version_string(version_old).is_err());
    }

    #[test]
    fn test_parse_version_string_invalid_utf8() {
        let version = b"SSH-2.0-\xFF\xFE";
        assert!(parse_version_string(version).is_err());
    }

    #[test]
    fn test_generate_client_kexinit() {
        let kexinit = generate_client_kexinit();
        assert!(!kexinit.is_empty());
        assert!(kexinit.len() >= 16); // At least cookie + some data
    }

    #[test]
    fn test_kexinit_round_trip() {
        let client_kexinit = generate_client_kexinit();
        let proposal = parse_server_kexinit(&client_kexinit).unwrap();
        
        assert!(!proposal.kex_algorithms.is_empty());
        assert!(!proposal.server_host_key_algorithms.is_empty());
        assert!(!proposal.encryption_algorithms_c2s.is_empty());
        assert!(!proposal.encryption_algorithms_s2c.is_empty());
    }

    #[test]
    fn test_kexinit_parse_too_short() {
        let short_data = vec![0u8; 10];
        assert!(parse_server_kexinit(&short_data).is_err());
    }

    #[test]
    fn test_handshake_state_default() {
        let state = HandshakeState::default();
        assert!(state.client_kexinit.is_none());
        assert!(state.server_kexinit.is_none());
        assert!(state.negotiated.is_none());
    }

    #[test]
    fn test_handshake_state_update() {
        let mut state = HandshakeState::default();
        state.client_kexinit = Some(vec![1, 2, 3]);
        state.server_kexinit = Some(vec![4, 5, 6]);
        
        assert_eq!(state.client_kexinit, Some(vec![1, 2, 3]));
        assert_eq!(state.server_kexinit, Some(vec![4, 5, 6]));
    }

    #[test]
    fn test_select_algorithm() {
        let preferred = vec!["aes256-gcm".to_string(), "aes128-gcm".to_string()];
        let server_list = vec!["aes128-gcm".to_string(), "chacha20-poly1305".to_string()];
        
        let result = select_algorithm(&preferred, &server_list);
        assert_eq!(result, Some("aes128-gcm".to_string()));
    }

    #[test]
    fn test_select_algorithm_no_match() {
        let preferred = vec!["aes256-gcm".to_string()];
        let server_list = vec!["chacha20-poly1305".to_string()];
        
        let result = select_algorithm(&preferred, &server_list);
        assert!(result.is_none());
    }

    #[test]
    fn test_negotiate_algorithms() {
        let client = parse_server_kexinit(&generate_client_kexinit()).unwrap();
        let server = parse_server_kexinit(&generate_client_kexinit()).unwrap();

        let negotiated = negotiate_algorithms(&client, &server);

        // According to RFC 4253 Section 7.1: "The first algorithm in each list
        // that is also in the other's list is chosen."
        // The client's KEX list starts with "diffie-hellman-group1-sha1"
        assert_eq!(negotiated.kex, "diffie-hellman-group1-sha1");
        assert_eq!(negotiated.compression, "none");
    }
}
