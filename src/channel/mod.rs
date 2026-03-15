//! SSH Channel Data Transfer Implementation
//!
//! Implements channel data transfer, EOF, close, and window adjust messages
//! as defined in RFC 4254 Section 5.

pub mod types;
pub mod state;

pub use types::{Channel, ChannelId, ChannelType, ChannelData};
pub use state::ChannelManager;

// Re-export channel data transfer functionality
pub use self::channel_transfer::*;

mod channel_transfer {
    use super::*;
    use crate::protocol::messages::MessageType;
    use bytes::{BufMut, BytesMut};
    use std::collections::HashMap;

    /// Channel manager for handling multiple channels
    #[derive(Debug)]
    pub struct ChannelTransferManager {
        /// Map of channel IDs to channels
        channels: HashMap<ChannelId, Channel>,
        /// Next channel ID to assign
        next_channel_id: u32,
        /// Default window size
        default_window_size: u32,
        /// Default max packet size
        default_max_packet_size: u32,
    }

    impl ChannelTransferManager {
        /// Create a new channel manager
        pub fn new() -> Self {
            Self {
                channels: HashMap::new(),
                next_channel_id: 0,
                default_window_size: 32768,
                default_max_packet_size: 32768,
            }
        }

        /// Create a new session channel
        pub fn create_session_channel(&mut self, originator_address: &str, originator_port: u16) -> ChannelId {
            let local_id = ChannelId::new(self.next_channel_id);
            let remote_id = ChannelId::new(self.next_channel_id + 1);
            self.next_channel_id += 2;

            let channel = Channel::new_session(local_id, remote_id);

            self.channels.insert(local_id, channel);
            local_id
        }

        /// Get a channel by ID
        pub fn get_channel(&self, channel_id: ChannelId) -> Option<&Channel> {
            self.channels.get(&channel_id)
        }

        /// Send channel data
        pub fn send_data(&mut self, channel_id: ChannelId, data: &[u8]) -> Option<Vec<u8>> {
            let channel = self.channels.get(&channel_id)?;
            
            // Check window size
            if data.len() > channel.window_size as usize {
                return None;
            }

            // Encode channel data message
            let mut msg = BytesMut::with_capacity(1 + 4 + 4 + data.len());
            msg.put_u8(MessageType::ChannelData as u8);
            msg.put_u32(channel_id.to_u32());
            msg.put_u32(data.len() as u32);
            msg.put_slice(data);

            Some(msg.to_vec())
        }

        /// Send channel EOF
        pub fn send_eof(&mut self, channel_id: ChannelId) -> Option<Vec<u8>> {
            let mut msg = BytesMut::with_capacity(1 + 4);
            msg.put_u8(MessageType::ChannelEof as u8);
            msg.put_u32(channel_id.to_u32());

            Some(msg.to_vec())
        }

        /// Send channel close
        pub fn send_close(&mut self, channel_id: ChannelId) -> Option<Vec<u8>> {
            let mut msg = BytesMut::with_capacity(1 + 4);
            msg.put_u8(MessageType::ChannelClose as u8);
            msg.put_u32(channel_id.to_u32());

            Some(msg.to_vec())
        }
    }

    impl Default for ChannelTransferManager {
        fn default() -> Self {
            Self::new()
        }
    }
}