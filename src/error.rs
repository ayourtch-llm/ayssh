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

    #[test]
    fn test_error_creation() {
        let err = SshError::connection("test message");
        assert!(matches!(err, SshError::ConnectionFailed(_)));
    }

    #[test]
    fn test_error_display() {
        let err = SshError::auth("auth failed");
        let msg = format!("{}", err);
        assert!(msg.contains("Authentication failed"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "io test");
        let err: SshError = io_err.into();
        assert!(matches!(err, SshError::IoError(_)));
    }
}
