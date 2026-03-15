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
//! use ssh_client::Client;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Example usage
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod connection;
pub mod error;
pub mod session;
pub mod transport;

// Re-export commonly used items
pub use config::Config;
pub use connection::Connection;
pub use error::SshError;
pub use session::Session;
pub use transport::Transport;

/// Version information for the SSH client
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Initializes the logging system.
///
/// This should be called early in the application lifecycle to enable
/// logging output. Uses `env_logger` for flexible log configuration
/// via the `RUST_LOG` environment variable.
pub fn init_logging() -> Result<(), env_logger::Error> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();
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
