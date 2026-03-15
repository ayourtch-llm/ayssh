//! Crypto module - Cryptographic primitives for SSH
//!
//! This module provides cryptographic primitives used in the SSH protocol.
//! All implementations follow RFC 4253 and related specifications.

pub mod hmac;
pub mod kdf;

// Note: Other modules will be implemented in later tasks
// pub mod cipher;
// pub mod hash;

// Re-export commonly used items
pub use hmac::*;
pub use kdf::*;

