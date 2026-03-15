//! SSH Authentication Module
//!
//! Implements various SSH authentication methods including
/// public key and password authentication.

pub mod state;
pub mod publickey;
pub mod password;
pub mod methods;

pub use state::*;
pub use publickey::*;
pub use password::*;
pub use methods::*;

// Re-export AuthMethod from protocol for convenience
pub use crate::protocol::AuthMethod;
