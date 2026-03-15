//! SSH Session Management (RFC 4254)
//!
//! This module implements SSH session management, providing:
//! - Interactive shell sessions
//! - Pseudo-terminal (PTY) allocation
//! - Window resize notifications
//! - Subsystem requests (e.g., SFTP)
//! - Environment variable passing
//! - Signal forwarding
//!
//! Sessions are opened as "session" channels and support various channel requests.

pub mod types;

pub use types::{
    Session, SessionRequest, TerminalModes, WindowDimensions,
};