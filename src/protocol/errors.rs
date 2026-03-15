//! SSH Protocol Errors
//!
//! Defines error types for protocol-level operations.

use thiserror::Error;

/// Errors that can occur during SSH protocol operations
#[derive(Error, Debug)]
pub enum ProtocolError {
    /// Invalid message type received
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    /// Message format is invalid
    #[error("Invalid message format: {0}")]
    InvalidMessageFormat(String),

    /// Algorithm negotiation failed
    #[error("Algorithm negotiation failed: {0}")]
    AlgorithmNegotiationFailed(String),

    /// Protocol state error
    #[error("Protocol state error: {0}")]
    ProtocolStateError(String),

    /// Unexpected message in current state
    #[error("Unexpected message type {0} in state {1}")]
    UnexpectedMessage(u8, String),

    /// Message length mismatch
    #[error("Message length mismatch: expected {0}, got {1}")]
    MessageLengthMismatch(u32, u32),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// Connection-level protocol errors
#[derive(Error, Debug)]
pub enum ConnectionError {
    /// Connection was disconnected
    #[error("Connection disconnected")]
    Disconnected,

    /// Connection timeout
    #[error("Connection timeout")]
    Timeout,

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Channel operation failed
    #[error("Channel operation failed: {0}")]
    ChannelError(String),
}

/// Result type for protocol operations
pub type ProtocolResult<T> = Result<T, ProtocolError>;
pub type ConnectionResult<T> = Result<T, ConnectionError>;
