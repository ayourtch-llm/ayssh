//! Channel state management for SSH Connection Protocol

use super::types::{
    ChannelClose, ChannelData, ChannelEof, ChannelId, ChannelOpenFailure,
    ChannelOpenRequest, ChannelRequest, ReasonCode,
};
use crate::protocol::message::Message;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Channel states
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelState {
    /// Channel is open and ready for data
    Open,
    /// Channel has received EOF
    EofReceived,
    /// Channel is closing
    Closing,
    /// Channel is closed
    Closed,
}

/// Channel information
#[derive(Debug, Clone)]
pub struct ChannelInfo {
    /// Local channel ID
    pub local_id: ChannelId,
    /// Remote channel ID
    pub remote_id: ChannelId,
    /// Channel type
    pub channel_type: String,
    /// Current state
    pub state: ChannelState,
    /// Local window size
    pub local_window_size: u32,
    /// Remote window size
    pub remote_window_size: u32,
    /// Local max packet size
    pub local_max_packet_size: u32,
    /// Remote max packet size
    pub remote_max_packet_size: u32,
}

/// Channel manager for tracking all channels
#[derive(Debug, Clone)]
pub struct ChannelManager {
    channels: Arc<Mutex<HashMap<ChannelId, ChannelInfo>>>,
}

impl ChannelManager {
    /// Create a new channel manager
    pub fn new() -> Self {
        Self {
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Allocate a new local channel ID
    pub fn allocate_local_id(&self) -> ChannelId {
        let mut guard = self.channels.lock().unwrap();
        let id = guard.keys().map(|k| k.to_u32()).max().unwrap_or(0) + 1;
        ChannelId::new(id)
    }
    
    /// Open a new channel (client -> server)
    pub fn open_channel(&self, request: &ChannelOpenRequest) -> Result<ChannelId, String> {
        let local_id = self.allocate_local_id();
        
        let mut guard = self.channels.lock().unwrap();
        guard.insert(
            local_id,
            ChannelInfo {
                local_id,
                remote_id: ChannelId::INVALID,
                channel_type: request.channel_type.as_str().to_string(),
                state: ChannelState::Open,
                local_window_size: request.initial_window_size,
                remote_window_size: request.initial_window_size,
                local_max_packet_size: request.max_packet_size,
                remote_max_packet_size: request.max_packet_size,
            },
        );
        
        Ok(local_id)
    }
    
    /// Confirm a channel open (server -> client)
    pub fn confirm_channel(
        &self,
        recipient_id: ChannelId,
        sender_id: ChannelId,
        initial_window_size: u32,
        max_packet_size: u32,
    ) -> Result<(), String> {
        let mut guard = self.channels.lock().unwrap();
        
        let channel = guard.get_mut(&recipient_id).ok_or_else(|| {
            format!("Channel {} not found", recipient_id.to_u32())
        })?;
        
        channel.remote_id = sender_id;
        channel.remote_window_size = initial_window_size;
        channel.remote_max_packet_size = max_packet_size;
        
        Ok(())
    }
    
    /// Fail a channel open request
    pub fn fail_channel(&self, recipient_id: ChannelId) -> Result<ChannelOpenFailure, String> {
        let mut guard = self.channels.lock().unwrap();
        
        guard.remove(&recipient_id);
        
        Ok(ChannelOpenFailure {
            recipient_channel: recipient_id,
            reason_code: ReasonCode::ConnectionRefused,
            description: "Connection refused".to_string(),
            language_tag: "en".to_string(),
        })
    }
    
    /// Send data on a channel
    pub fn send_data(&self, channel_id: ChannelId, data: &[u8]) -> Result<ChannelData, String> {
        let guard = self.channels.lock().unwrap();
        
        let channel = guard.get(&channel_id).ok_or_else(|| {
            format!("Channel {} not found", channel_id.to_u32())
        })?;
        
        if channel.state != ChannelState::Open {
            return Err(format!(
                "Cannot send data on channel {} in state {:?}",
                channel_id.to_u32(),
                channel.state
            ));
        }
        
        // Check window size
        if data.len() as u32 > channel.remote_window_size {
            return Err(format!(
                "Window size exceeded: {} > {}",
                data.len(),
                channel.remote_window_size
            ));
        }
        
        // Update window size
        let mut guard = guard;
        guard.get_mut(&channel_id).unwrap().remote_window_size -= data.len() as u32;
        
        Ok(ChannelData {
            channel_id,
            data: data.to_vec(),
        })
    }
    
    /// Receive data on a channel
    pub fn receive_data(&self, channel_id: ChannelId, data: &[u8]) -> Result<(), String> {
        let mut guard = self.channels.lock().unwrap();
        
        let channel = guard.get_mut(&channel_id).ok_or_else(|| {
            format!("Channel {} not found", channel_id.to_u32())
        })?;
        
        if channel.state == ChannelState::Closed {
            return Err(format!(
                "Cannot receive data on closed channel {}",
                channel_id.to_u32()
            ));
        }
        
        // Check window size
        if data.len() as u32 > channel.local_window_size {
            return Err(format!(
                "Window size exceeded: {} > {}",
                data.len(),
                channel.local_window_size
            ));
        }
        
        // Update window size
        channel.local_window_size -= data.len() as u32;
        
        Ok(())
    }
    
    /// Send EOF on a channel
    pub fn send_eof(&self, channel_id: ChannelId) -> Result<ChannelEof, String> {
        let mut guard = self.channels.lock().unwrap();
        
        let channel = guard.get_mut(&channel_id).ok_or_else(|| {
            format!("Channel {} not found", channel_id.to_u32())
        })?;
        
        if channel.state == ChannelState::Closed {
            return Err(format!(
                "Cannot send EOF on closed channel {}",
                channel_id.to_u32()
            ));
        }
        
        channel.state = ChannelState::EofReceived;
        
        Ok(ChannelEof { channel_id })
    }
    
    /// Receive EOF on a channel
    pub fn receive_eof(&self, channel_id: ChannelId) -> Result<(), String> {
        let mut guard = self.channels.lock().unwrap();
        
        let channel = guard.get_mut(&channel_id).ok_or_else(|| {
            format!("Channel {} not found", channel_id.to_u32())
        })?;
        
        if channel.state == ChannelState::Closed {
            return Err(format!(
                "Cannot receive EOF on closed channel {}",
                channel_id.to_u32()
            ));
        }
        
        channel.state = ChannelState::EofReceived;
        
        Ok(())
    }
    
    /// Close a channel
    pub fn close(&self, channel_id: ChannelId) -> Result<ChannelClose, String> {
        let mut guard = self.channels.lock().unwrap();
        
        let channel = guard.get_mut(&channel_id).ok_or_else(|| {
            format!("Channel {} not found", channel_id.to_u32())
        })?;
        
        channel.state = ChannelState::Closed;
        
        Ok(ChannelClose { channel_id })
    }

    /// Receive a close message on a channel
    ///
    /// Per RFC 4254 Section 5.3: "Upon receiving this message, a party MUST
    /// send back an SSH_MSG_CHANNEL_CLOSE unless it has already sent this
    /// message for the channel."
    ///
    /// Returns `Ok(Some(ChannelClose))` if a close response needs to be sent,
    /// or `Ok(None)` if close was already sent.
    pub fn receive_close(&self, channel_id: ChannelId) -> Result<Option<ChannelClose>, String> {
        let mut guard = self.channels.lock().unwrap();

        let channel = guard.get_mut(&channel_id).ok_or_else(|| {
            format!("Channel {} not found", channel_id.to_u32())
        })?;

        let needs_response = channel.state != ChannelState::Closed;
        channel.state = ChannelState::Closed;

        if needs_response {
            Ok(Some(ChannelClose { channel_id }))
        } else {
            Ok(None)
        }
    }
    
    /// Send channel request
    pub fn send_request(
        &self,
        channel_id: ChannelId,
        request: &ChannelRequest,
        want_reply: bool,
    ) -> Result<Message, String> {
        let guard = self.channels.lock().unwrap();
        
        let channel = guard.get(&channel_id).ok_or_else(|| {
            format!("Channel {} not found", channel_id.to_u32())
        })?;
        
        if channel.state == ChannelState::Closed {
            return Err(format!(
                "Cannot send request on closed channel {}",
                channel_id.to_u32()
            ));
        }
        
        Ok(request.encode(channel_id, want_reply))
    }
    
    /// Receive channel request
    pub fn receive_request(&self, channel_id: ChannelId, request: ChannelRequest) -> Result<(), String> {
        let mut guard = self.channels.lock().unwrap();
        
        let channel = guard.get_mut(&channel_id).ok_or_else(|| {
            format!("Channel {} not found", channel_id.to_u32())
        })?;
        
        if channel.state == ChannelState::Closed {
            return Err(format!(
                "Cannot receive request on closed channel {}",
                channel_id.to_u32()
            ));
        }
        
        // Handle specific requests
        match &request {
            ChannelRequest::ExitStatus { exit_status } => {
                // Shell session exit
                channel.state = ChannelState::Closed;
            }
            _ => {}
        }
        
        Ok(())
    }
    
    /// Get channel info
    pub fn get_channel(&self, channel_id: ChannelId) -> Option<ChannelInfo> {
        let guard = self.channels.lock().unwrap();
        guard.get(&channel_id).cloned()
    }
    
    /// List all channels
    pub fn list_channels(&self) -> Vec<ChannelInfo> {
        let guard = self.channels.lock().unwrap();
        guard.values().cloned().collect()
    }
    
    /// Check if channel exists
    pub fn channel_exists(&self, channel_id: ChannelId) -> bool {
        let guard = self.channels.lock().unwrap();
        guard.contains_key(&channel_id)
    }
}

impl Default for ChannelManager {
    fn default() -> Self {
        Self::new()
    }
}