//! SSH Utils module
//!
//! This module contains utility types and functions for SSH protocol handling.

pub mod buffer;
pub mod string;

// Re-export buffer types for convenience
pub use buffer::{SshReader, SshWriter};

/// Initialize logging framework
pub fn init_logging() {
    // Logging initialization is optional and not required for library functionality
}

