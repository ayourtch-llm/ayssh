//! SSH Transport Handshake
//!
//! Implements the initial key exchange and authentication handshake.

use crate::protocol;
use bytes::{Buf, BufMut, BytesMut};

/// SSH protocol version string
pub const SSH_VERSION_STRING: &str = "SSH-2.0-ayssh_1.0.0";

/// Transport handshake state
#[derive(Debug, Clone)]
pub struct HandshakeState {
    /// Client's KEXINIT message
    pub client_kexinit: Option<Vec<u8>>,
    /// Server's KEXINIT message
    pub server_kexinit: Option<Vec<u8>>,
    /// Negotiated algorithms
    pub negotiated: Option<protocol::NegotiatedAlgorithms>,
}

impl Default for HandshakeState {
    fn default() -> Self {
        Self {
            client_kexinit: None,
            server_kexinit: None,
            negotiated: None,
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
    
    if protocol_version != 2 {
        return Err("Only SSH protocol version 2 is supported");
    }
    
    let software_version = parts[2..].join("-");
    
    Ok((protocol_version, software_version))
}

/// Generate client KEXINIT message
pub fn generate_client_kexinit() -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(200);
    
    // 16 bytes of random cookie
    buf.put(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07][..]);
    buf.put(&[0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15][..]);
    
    // Negotiation strings (algorithm lists)
    let kex_algorithms = "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group14-sha256@libssh.org,diffie-hellman-group-exchange-sha256";
    let host_key_algorithms = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256";
    let enc_c2s = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr";
    let enc_s2c = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr";
    let mac_c2s = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512";
    let mac_s2c = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512";
    let comp_c2s = "none";
    let comp_s2c = "none";
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
    
    // Reserved byte (always 0)
    buf.put_u8(0);
    
    // Initial kex algorithm (single string)
    protocol::SshString::from_str("curve25519-sha256").encode(&mut buf);
    
    // first_kex_packet_follows (1 byte boolean, typically 0)
    buf.put_u8(0);
    
    buf.to_vec()
}

/// Parse server KEXINIT message
pub fn parse_server_kexinit(data: &[u8]) -> Result<protocol::AlgorithmProposal, &'static str> {
    let mut buf = data;
    
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
    
    let comp_s2c_str = protocol::SshString::decode(&mut buf)
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
    
    // Skip reserved byte
    if buf.len() < 1 {
        return Err("KEXINIT too short for reserved byte");
    }
    buf.advance(1);
    
    // Parse initial kex algorithm
    let initial_kex_str = protocol::SshString::decode(&mut buf)
        .map_err(|_| "Failed to decode initial_kex")?
        .to_str()
        .map_err(|_| "Invalid initial_kex UTF-8")?
        .to_string();
    
    // Parse first_kex_packet_follows (1 byte boolean)
    if buf.len() < 1 {
        return Err("KEXINIT too short for first_kex_packet_follows");
    }
    let first_kex_packet_follows = buf.get_u8() != 0;
    
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

/// Perform the key exchange handshake
pub async fn perform_handshake(_client_kexinit: &[u8], _server_kexinit: &[u8]) -> anyhow::Result<()> {
    // Placeholder for actual handshake implementation
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

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
        let version = b"SSH-1.99-libssh_0.9.6";
        assert!(parse_version_string(version).is_err());
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
}
