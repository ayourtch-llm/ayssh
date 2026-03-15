//! SSH Channel Management (RFC 4254)
//!
//! This module implements the SSH Connection Protocol, providing:
//! - Channel creation and management
//! - Shell sessions
//! - Command execution (exec)
//! - TCP/IP port forwarding
//! - Channel data transfer
//!
//! All channels are multiplexed over a single encrypted SSH transport tunnel.

pub mod types;
pub mod state;

pub use types::{Channel, ChannelId, ChannelType, ChannelOpenRequest, ChannelData};
pub use state::ChannelManager;