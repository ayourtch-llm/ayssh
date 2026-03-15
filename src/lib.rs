//! SSH Client Library
//!
//! This library provides a Rust implementation of an SSH client with support for:
//! - Asynchronous connections using Tokio
//! - Secure authentication
//! - Channel management
//!
//! # Example
//!
//! ```no_run
//! use ssh_client::Config;
//!
//! // Example configuration
//! let config = Config::new()
//!     .with_host("example.com")
//!     .with_port(22)
//!     .with_username("user");
//! ```

pub mod auth;
pub mod channel;
pub mod client;
pub mod config;
pub mod connection;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod protocol;
pub mod session;
pub mod transport;
pub mod utils;

// Re-export commonly used items
pub use auth::AuthMethod;
pub use auth::AuthMethodManager;
pub use channel::Channel;
pub use channel::ChannelId;
pub use channel::ChannelType;
pub use config::Config;
pub use connection::Connection;
pub use error::SshError;
pub use protocol::{AuthMethod as ProtocolAuthMethod, MessageType};
pub use session::Session;
pub use session::SessionManager;
pub use session::WindowDimensions;
pub use session::TerminalModes;
pub use session::TerminalMode;
pub use session::SessionState;
pub use transport::Transport;

/// Version information for the SSH client
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Initializes the logging system.
///
/// This should be called early in the application lifecycle to enable
/// logging output. Uses `tracing-subscriber` for flexible log configuration
/// via the `RUST_LOG` environment variable (consistent with aytelnet).
pub fn init_logging() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_constants() {
        assert!(!NAME.is_empty());
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_logging_initialization() {
        // Test that logging can be initialized
        let result = init_logging();
        assert!(result.is_ok());
    }
}
