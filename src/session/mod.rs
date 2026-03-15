//! SSH Session Channel Implementation
//!
//! Implements session channel operations as defined in RFC 4254 Section 6:
//! - exec: Execute commands
//! - shell: Start interactive shell
//! - pty-req: PTY allocation
//! - env: Environment variable requests
//! - window-size: Window size changes
//! - signal: Signal requests

use crate::channel::ChannelManager;
use bytes::{Buf, BufMut, BytesMut};
use std::collections::HashMap;

/// Session request types
#[derive(Debug, Clone, PartialEq)]
pub enum SessionRequest {
    /// Execute a command
    Exec(String),
    /// Start interactive shell
    Shell,
    /// Allocate PTY
    Pty {
        /// Terminal type (e.g., "xterm")
        term: String,
        /// Terminal width in characters
        width: u32,
        /// Terminal height in characters
        height: u32,
        /// Terminal width in pixels
        width_pixels: u32,
        /// Terminal height in pixels
        height_pixels: u32,
    },
    /// Set environment variable
    Env {
        /// Variable name
        name: String,
        /// Variable value
        value: String,
    },
    /// Change window size
    WindowSize {
        /// Terminal width in characters
        width: u32,
        /// Terminal height in characters
        height: u32,
        /// Terminal width in pixels
        width_pixels: u32,
        /// Terminal height in pixels
        height_pixels: u32,
    },
    /// Send signal
    Signal(String),
    /// Subsystem request
    Subsystem(String),
}

/// Session state
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// Initial state, no session started
    Initial,
    /// Executing a command
    Executing,
    /// Interactive shell running
    Shell,
    /// PTY allocated
    Pty,
    /// Session closed
    Closed,
}

/// SSH Session handler
#[derive(Debug)]
pub struct Session {
    /// Channel ID
    channel_id: u32,
    /// Session state
    state: SessionState,
    /// Channel manager
    manager: ChannelManager,
    /// Environment variables
    environment: HashMap<String, String>,
    /// Terminal type
    terminal_type: Option<String>,
}

impl Session {
    /// Create a new session
    pub fn new(channel_id: u32, manager: ChannelManager) -> Self {
        Self {
            channel_id,
            state: SessionState::Initial,
            manager,
            environment: HashMap::new(),
            terminal_type: None,
        }
    }

    /// Get the channel ID
    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    /// Get the current session state
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Execute a command
    pub fn exec(&mut self, command: &str) -> Option<Vec<u8>> {
        if self.state != SessionState::Initial {
            return None;
        }

        self.state = SessionState::Executing;

        // Encode exec request
        let mut msg = BytesMut::with_capacity(1 + 4 + 4 + command.len() + 1);
        msg.put_u8(0x10); // SSH_MSG_CHANNEL_REQUEST (16)
        msg.put_u32(self.channel_id);
        msg.put_u32(5); // "exec\0".len()
        msg.put_slice(b"exec\0");
        msg.put_u8(0); // want_reply = false
        msg.put_slice(command.as_bytes());

        Some(msg.to_vec())
    }

    /// Start interactive shell
    pub fn shell(&mut self) -> Option<Vec<u8>> {
        if self.state != SessionState::Initial {
            return None;
        }

        self.state = SessionState::Shell;

        // Encode shell request
        let mut msg = BytesMut::with_capacity(1 + 4 + 4 + 5 + 1);
        msg.put_u8(0x10); // SSH_MSG_CHANNEL_REQUEST (16)
        msg.put_u32(self.channel_id);
        msg.put_u32(5); // "shell\0".len()
        msg.put_slice(b"shell\0");
        msg.put_u8(0); // want_reply = false

        Some(msg.to_vec())
    }

    /// Allocate PTY
    pub fn pty_allocate(
        &mut self,
        term: &str,
        width: u32,
        height: u32,
        width_pixels: u32,
        height_pixels: u32,
    ) -> Option<Vec<u8>> {
        self.terminal_type = Some(term.to_string());

        let mut msg = BytesMut::with_capacity(1 + 4 + 4 + 7 + 1 + 4 + 4 + 4 + 4 + term.len() + 1);
        msg.put_u8(0x10); // SSH_MSG_CHANNEL_REQUEST (16)
        msg.put_u32(self.channel_id);
        msg.put_u32(7); // "pty-req\0".len()
        msg.put_slice(b"pty-req\0");
        msg.put_u8(1); // want_reply = true
        msg.put_slice(term.as_bytes());
        msg.put_u8(0); // null terminator
        msg.put_u32(width);
        msg.put_u32(height);
        msg.put_u32(width_pixels);
        msg.put_u32(height_pixels);

        Some(msg.to_vec())
    }

    /// Set environment variable
    pub fn set_env(&mut self, name: &str, value: &str) -> Option<Vec<u8>> {
        self.environment.insert(name.to_string(), value.to_string());

        let mut msg = BytesMut::with_capacity(1 + 4 + 4 + 4 + name.len() + 1 + value.len() + 1);
        msg.put_u8(0x10); // SSH_MSG_CHANNEL_REQUEST (16)
        msg.put_u32(self.channel_id);
        msg.put_u32(4); // "env\0".len()
        msg.put_slice(b"env\0");
        msg.put_u8(1); // want_reply = true
        msg.put_slice(name.as_bytes());
        msg.put_u8(0); // null terminator
        msg.put_slice(value.as_bytes());
        msg.put_u8(0); // null terminator

        Some(msg.to_vec())
    }

    /// Change window size
    pub fn window_size(&mut self, width: u32, height: u32, width_pixels: u32, height_pixels: u32) -> Option<Vec<u8>> {
        let mut msg = BytesMut::with_capacity(1 + 4 + 4 + 11 + 1 + 4 + 4 + 4 + 4);
        msg.put_u8(0x11); // SSH_MSG_CHANNEL_REQUEST (17)
        msg.put_u32(self.channel_id);
        msg.put_u32(11); // "window-size\0".len()
        msg.put_slice(b"window-size\0");
        msg.put_u8(0); // want_reply = false
        msg.put_u32(width);
        msg.put_u32(height);
        msg.put_u32(width_pixels);
        msg.put_u32(height_pixels);

        Some(msg.to_vec())
    }

    /// Send signal
    pub fn signal(&mut self, signal: &str) -> Option<Vec<u8>> {
        let mut msg = BytesMut::with_capacity(1 + 4 + 4 + 6 + 1 + signal.len() + 1);
        msg.put_u8(0x11); // SSH_MSG_CHANNEL_REQUEST (17)
        msg.put_u32(self.channel_id);
        msg.put_u32(6); // "signal\0".len()
        msg.put_slice(b"signal\0");
        msg.put_u8(0); // want_reply = false
        msg.put_slice(signal.as_bytes());
        msg.put_u8(0); // null terminator

        Some(msg.to_vec())
    }

    /// Request subsystem
    pub fn subsystem(&mut self, name: &str) -> Option<Vec<u8>> {
        let mut msg = BytesMut::with_capacity(1 + 4 + 4 + name.len() + 1 + 1);
        msg.put_u8(0x10); // SSH_MSG_CHANNEL_REQUEST (16)
        msg.put_u32(self.channel_id);
        msg.put_u32(name.len() as u32 + 1);
        msg.put_slice(name.as_bytes());
        msg.put_u8(0); // null terminator
        msg.put_u8(1); // want_reply = true

        Some(msg.to_vec())
    }

    /// Handle incoming channel data
    pub fn handle_channel_data(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        // In a real implementation, this would process incoming data
        // For now, return None
        None
    }

    /// Handle incoming channel EOF
    pub fn handle_eof(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Handle incoming channel close
    pub fn handle_close(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Get environment variables
    pub fn environment(&self) -> &HashMap<String, String> {
        &self.environment
    }

    /// Get terminal type
    pub fn terminal_type(&self) -> Option<&str> {
        self.terminal_type.as_deref()
    }
}

/// Session manager for handling multiple sessions
#[derive(Debug)]
pub struct SessionManager {
    /// Map of channel IDs to sessions
    sessions: HashMap<u32, Session>,
    /// Channel manager
    channel_manager: crate::channel::ChannelManager,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            channel_manager: crate::channel::ChannelManager::new(),
        }
    }

    /// Create a new session channel
    pub fn create_session(&mut self, originator_address: &str, originator_port: u16) -> u32 {
        let channel_id = self.channel_manager.allocate_local_id();
        let session = Session::new(channel_id.to_u32(), self.channel_manager.clone());
        
        self.sessions.insert(channel_id.to_u32(), session);
        channel_id.to_u32()
    }

    /// Get a session by ID
    pub fn get_session(&self, channel_id: u32) -> Option<&Session> {
        self.sessions.get(&channel_id)
    }

    /// Get a mutable session by ID
    pub fn get_session_mut(&mut self, channel_id: u32) -> Option<&mut Session> {
        self.sessions.get_mut(&channel_id)
    }

    /// Execute a command in a session
    pub fn exec(&mut self, channel_id: u32, command: &str) -> Option<Vec<u8>> {
        self.sessions.get_mut(&channel_id)?.exec(command)
    }

    /// Start shell in a session
    pub fn shell(&mut self, channel_id: u32) -> Option<Vec<u8>> {
        self.sessions.get_mut(&channel_id)?.shell()
    }

    /// Allocate PTY in a session
    pub fn pty_allocate(
        &mut self,
        channel_id: u32,
        term: &str,
        width: u32,
        height: u32,
    ) -> Option<Vec<u8>> {
        self.sessions.get_mut(&channel_id)?.pty_allocate(term, width, height, 0, 0)
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<u32> {
        self.sessions.keys().copied().collect()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let mut manager = SessionManager::new();
        let channel_id = manager.create_session("127.0.0.1", 12345);
        
        assert!(channel_id != 0);
        assert!(manager.get_session(channel_id).is_some());
    }

    #[test]
    fn test_session_exec() {
        let mut manager = SessionManager::new();
        let channel_id = manager.create_session("127.0.0.1", 12345);
        
        let encoded = manager.exec(channel_id, "ls -la").unwrap();
        
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], 0x10); // SSH_MSG_CHANNEL_REQUEST
    }

    #[test]
    fn test_session_shell() {
        let mut manager = SessionManager::new();
        let channel_id = manager.create_session("127.0.0.1", 12345);
        
        let encoded = manager.shell(channel_id).unwrap();
        
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_session_pty_allocate() {
        let mut manager = SessionManager::new();
        let channel_id = manager.create_session("127.0.0.1", 12345);
        
        let encoded = manager.pty_allocate(channel_id, "xterm", 80, 24).unwrap();
        
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_session_window_size() {
        let mut manager = SessionManager::new();
        let channel_id = manager.create_session("127.0.0.1", 12345);
        
        let encoded = manager.sessions.get_mut(&channel_id).unwrap().window_size(80, 24, 0, 0);
        
        assert!(encoded.is_some());
    }

    #[test]
    fn test_session_env() {
        let mut manager = SessionManager::new();
        let channel_id = manager.create_session("127.0.0.1", 12345);
        
        let encoded = manager.sessions.get_mut(&channel_id).unwrap().set_env("TERM", "xterm");
        
        assert!(encoded.is_some());
    }

    #[test]
    fn test_session_signal() {
        let mut manager = SessionManager::new();
        let channel_id = manager.create_session("127.0.0.1", 12345);
        
        let encoded = manager.sessions.get_mut(&channel_id).unwrap().signal("SIGINT");
        
        assert!(encoded.is_some());
    }

    #[test]
    fn test_session_eof() {
        let mut manager = SessionManager::new();
        let channel_id = manager.create_session("127.0.0.1", 12345);
        
        manager.sessions.get_mut(&channel_id).unwrap().handle_eof();
        
        assert_eq!(manager.sessions.get(&channel_id).unwrap().state(), &SessionState::Closed);
    }
}