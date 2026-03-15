//! SSH Version Exchange Implementation
//!
//! Implements SSH protocol version string exchange as defined in RFC 4253 Section 4.2.
//! Handles client and server version string parsing and validation.

use crate::error::SshError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// SSH protocol version string with CRLF
/// Format: SSH-2.0-software_version\r\n
pub const SSH_VERSION_STRING: &str = "SSH-2.0-ayssh_1.0.0\r\n";

/// Maximum version string length (RFC 256 bytes)
pub const MAX_VERSION_STRING_LENGTH: usize = 256;

/// Send SSH version string to the remote peer
pub async fn send_version<T: AsyncWriteExt + Unpin>(stream: &mut T) -> Result<(), SshError> {
    let version_bytes = SSH_VERSION_STRING.as_bytes();
    stream.write_all(version_bytes).await?;
    Ok(())
}

/// Receive SSH version string from the remote peer
pub async fn recv_version<T: AsyncReadExt + Unpin>(stream: &mut T) -> Result<String, SshError> {
    let mut buf = vec![0u8; MAX_VERSION_STRING_LENGTH];
    let n = stream.read(&mut buf).await?;
    
    if n == 0 {
        return Err(SshError::ProtocolError("Empty version string".to_string()));
    }
    
    // Find CRLF
    let end = buf[..n].iter().rposition(|&b| b == b'\n')
        .ok_or(SshError::ProtocolError("No CRLF in version string".to_string()))?;
    
    let version = std::str::from_utf8(&buf[..end])
        .map_err(|_| SshError::ProtocolError("Invalid UTF-8 in version string".to_string()))?;
    
    Ok(version.to_string())
}

/// Parse and validate SSH version string
///
/// # Arguments
///
/// * `data` - Raw bytes of the version string (must end with CRLF)
///
/// # Returns
///
/// * `Ok((protocol_version, software_version))` - Protocol version and software version
/// * `Err(SshError)` - If parsing fails
///
/// # Example
///
/// ```
/// use ssh_client::transport::version::parse_version_string;
///
/// let data = b"SSH-2.0-OpenSSH_8.4\r\n";
/// let (protocol_version, software_version) = parse_version_string(data).unwrap();
/// assert_eq!(protocol_version, 2);
/// assert_eq!(software_version, "OpenSSH_8.4");
/// ```
pub fn parse_version_string(data: &[u8]) -> Result<(u32, String), SshError> {
    // Validate length
    if data.len() > MAX_VERSION_STRING_LENGTH {
        return Err(SshError::ProtocolError(
            "Version string too long".to_string(),
        ));
    }

    // Must end with CRLF
    if !data.ends_with(b"\r\n") {
        return Err(SshError::ProtocolError(
            "Version string must end with CRLF".to_string(),
        ));
    }

    // Remove CRLF for parsing
    let version = std::str::from_utf8(&data[..data.len() - 2])
        .map_err(|_| SshError::ProtocolError("Invalid UTF-8 in version string".to_string()))?;

    if !version.starts_with("SSH-") {
        return Err(SshError::ProtocolError(
            "Invalid version string prefix".to_string(),
        ));
    }

    let parts: Vec<&str> = version.split('-').collect();
    if parts.len() < 3 {
        return Err(SshError::ProtocolError(
            "Invalid version string format".to_string(),
        ));
    }

    // parts[1] contains the protocol version (e.g., "2.0" -> extract "2")
    let protocol_version_str = parts[1].split('.').next().ok_or(SshError::ProtocolError(
        "Invalid protocol version".to_string(),
    ))?;
    let protocol_version: u32 = protocol_version_str
        .parse()
        .map_err(|_| SshError::ProtocolError("Invalid protocol version".to_string()))?;

    if protocol_version != 2 {
        return Err(SshError::ProtocolError(format!(
            "Only SSH protocol version 2 is supported (got {})",
            protocol_version
        )));
    }

    // parts[2..] contains the software version (may contain dashes)
    let software_version = parts[2..].join("-");

    if software_version.is_empty() {
        return Err(SshError::ProtocolError(
            "Software version cannot be empty".to_string(),
        ));
    }

    Ok((protocol_version, software_version))
}

/// Generate client version string
pub fn generate_client_version() -> Vec<u8> {
    SSH_VERSION_STRING.as_bytes().to_vec()
}

/// Parse server version string
pub fn parse_server_version(data: &[u8]) -> Result<String, SshError> {
    let (_, software_version) = parse_version_string(data)?;
    Ok(software_version)
}

/// Validate client version string
pub fn validate_client_version(data: &[u8]) -> Result<(), SshError> {
    let (protocol_version, software_version) = parse_version_string(data)?;
    
    if protocol_version != 2 {
        return Err(SshError::ProtocolError(
            "Client must support SSH protocol version 2".to_string(),
        ));
    }

    if software_version.is_empty() {
        return Err(SshError::ProtocolError(
            "Client software version cannot be empty".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_version() {
        let data = b"SSH-2.0-OpenSSH_8.4\r\n";
        let (protocol_version, software_version) = parse_version_string(data).unwrap();
        
        assert_eq!(protocol_version, 2);
        assert_eq!(software_version, "OpenSSH_8.4");
    }

    #[test]
    fn test_parse_version_with_dashes() {
        let data = b"SSH-2.0-My-SSH-Client_v1.0\r\n";
        let (protocol_version, software_version) = parse_version_string(data).unwrap();
        
        assert_eq!(protocol_version, 2);
        assert_eq!(software_version, "My-SSH-Client_v1.0");
    }

    #[test]
    fn test_parse_version_missing_crlf() {
        let data = b"SSH-2.0-OpenSSH_8.4";
        let result = parse_version_string(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_invalid_prefix() {
        let data = b"SSH-3.0-OpenSSH_8.4\r\n";
        let result = parse_version_string(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_old_protocol() {
        let data = b"SSH-1.0-OpenSSH_8.4\r\n";
        let result = parse_version_string(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_empty_software() {
        let data = b"SSH-2.0-\r\n";
        let result = parse_version_string(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_invalid_utf8() {
        let data = b"SSH-2.0-\xff\xfe\r\n";
        let result = parse_version_string(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_too_long() {
        let long_software = "a".repeat(300);
        let data = format!("SSH-2.0-{}\r\n", long_software).into_bytes();
        let result = parse_version_string(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_client_version() {
        let data = b"SSH-2.0-ayssh_1.0.0\r\n";
        let result = validate_client_version(data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_client_version_old() {
        let data = b"SSH-1.0-OldClient\r\n";
        let result = validate_client_version(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_client_version() {
        let version = generate_client_version();
        assert_eq!(version, SSH_VERSION_STRING.as_bytes());
        assert!(version.ends_with(b"\r\n"));
    }

    #[test]
    fn test_parse_server_version() {
        let data = b"SSH-2.0-OpenSSH_8.4\r\n";
        let software_version = parse_server_version(data).unwrap();
        assert_eq!(software_version, "OpenSSH_8.4");
    }

    #[test]
    fn test_version_string_format() {
        assert!(SSH_VERSION_STRING.starts_with("SSH-2.0-"));
        assert!(SSH_VERSION_STRING.ends_with("\r\n"));
        assert_eq!(SSH_VERSION_STRING.len(), 21);
    }
}