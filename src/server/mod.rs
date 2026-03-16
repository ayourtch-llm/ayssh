//! SSH Test Server
//!
//! A minimal SSH server implementation for testing all crypto algorithm
//! combinations. Reuses the same Transport primitives as the client,
//! validating the symmetric architecture.

pub mod host_key;

pub use host_key::HostKeyPair;
