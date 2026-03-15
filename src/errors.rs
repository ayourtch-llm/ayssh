//! Error types for the SSH client

use thiserror::Error;

/// SSH Client Errors
#[derive(Error, Debug)]
pub enum SshError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Channel error: {0}")]
    ChannelError(String),

    #[error("Session error: {0}")]
    SessionError(String),
}
