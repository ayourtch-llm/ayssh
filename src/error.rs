//! SSH Client Error Module
//!
//! Defines error types for the SSH client.

use thiserror::Error;

/// SSH Client Error Types
#[derive(Error, Debug)]
pub enum SshError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Channel error: {0}")]
    ChannelError(String),

    #[error("Session error: {0}")]
    SessionError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Timeout error")]
    TimeoutError,

    #[error("KEX error: {0}")]
    KexError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl SshError {
    pub fn connection(msg: &str) -> Self {
        SshError::ConnectionFailed(msg.to_string())
    }

    pub fn auth(msg: &str) -> Self {
        SshError::AuthenticationFailed(msg.to_string())
    }

    pub fn protocol(msg: &str) -> Self {
        SshError::ProtocolError(msg.to_string())
    }
}

impl From<anyhow::Error> for SshError {
    fn from(err: anyhow::Error) -> Self {
        SshError::KexError(err.to_string())
    }
}

impl From<rsa::Error> for SshError {
    fn from(err: rsa::Error) -> Self {
        SshError::CryptoError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Constructor helpers ---

    #[test]
    fn test_connection_helper() {
        let err = SshError::connection("refused");
        assert!(matches!(err, SshError::ConnectionFailed(ref s) if s == "refused"));
        assert!(format!("{}", err).contains("Connection failed: refused"));
    }

    #[test]
    fn test_auth_helper() {
        let err = SshError::auth("bad password");
        assert!(matches!(err, SshError::AuthenticationFailed(ref s) if s == "bad password"));
        assert!(format!("{}", err).contains("Authentication failed: bad password"));
    }

    #[test]
    fn test_protocol_helper() {
        let err = SshError::protocol("unexpected msg");
        assert!(matches!(err, SshError::ProtocolError(ref s) if s == "unexpected msg"));
        assert!(format!("{}", err).contains("Protocol error: unexpected msg"));
    }

    // --- Display for all variants ---

    #[test]
    fn test_display_connection_error() {
        let err = SshError::ConnectionError("timeout".into());
        assert_eq!(format!("{}", err), "Connection error: timeout");
    }

    #[test]
    fn test_display_channel_error() {
        let err = SshError::ChannelError("closed".into());
        assert_eq!(format!("{}", err), "Channel error: closed");
    }

    #[test]
    fn test_display_session_error() {
        let err = SshError::SessionError("not found".into());
        assert_eq!(format!("{}", err), "Session error: not found");
    }

    #[test]
    fn test_display_crypto_error() {
        let err = SshError::CryptoError("bad key".into());
        assert_eq!(format!("{}", err), "Crypto error: bad key");
    }

    #[test]
    fn test_display_timeout_error() {
        let err = SshError::TimeoutError;
        assert_eq!(format!("{}", err), "Timeout error");
    }

    #[test]
    fn test_display_kex_error() {
        let err = SshError::KexError("no common algo".into());
        assert_eq!(format!("{}", err), "KEX error: no common algo");
    }

    #[test]
    fn test_display_unknown_error() {
        let err = SshError::Unknown("mystery".into());
        assert_eq!(format!("{}", err), "Unknown error: mystery");
    }

    // --- From conversions ---

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err: SshError = io_err.into();
        assert!(matches!(err, SshError::IoError(_)));
        assert!(format!("{}", err).contains("refused"));
    }

    #[test]
    fn test_from_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("something went wrong");
        let err: SshError = anyhow_err.into();
        assert!(matches!(err, SshError::KexError(_)));
        assert!(format!("{}", err).contains("something went wrong"));
    }

    // --- Debug ---

    #[test]
    fn test_debug_format() {
        let err = SshError::TimeoutError;
        let debug = format!("{:?}", err);
        assert!(debug.contains("TimeoutError"));
    }

    #[test]
    fn test_debug_format_with_message() {
        let err = SshError::CryptoError("aes failed".into());
        let debug = format!("{:?}", err);
        assert!(debug.contains("CryptoError"));
        assert!(debug.contains("aes failed"));
    }
}
