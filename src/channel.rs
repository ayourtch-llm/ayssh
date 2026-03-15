//! SSH Channel management

/// Types of channels supported in SSH
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelType {
    /// Session channel (shell)
    Session,
    /// Direct TCP/IP channel
    DirectTcpIp,
    /// Local port forwarding
    LocalForward,
    /// Remote port forwarding
    RemoteForward,
}

/// Represents an SSH channel
pub struct Channel {
    channel_type: ChannelType,
    id: u32,
    open: bool,
}

impl Channel {
    /// Create a new channel
    pub fn new(channel_type: ChannelType, id: u32) -> Self {
        Self {
            channel_type,
            id,
            open: false,
        }
    }

    /// Get the channel type
    pub fn channel_type(&self) -> ChannelType {
        self.channel_type
    }

    /// Get the channel ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Check if channel is open
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Open the channel
    pub fn open(&mut self) {
        self.open = true;
    }

    /// Close the channel
    pub fn close(&mut self) {
        self.open = false;
    }
}
