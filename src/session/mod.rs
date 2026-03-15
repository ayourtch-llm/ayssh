//! SSH Session Channel Implementation
//!
//! Implements session channel operations as defined in RFC 4254 Section 6:
//! - exec: Execute commands
//! - shell: Start interactive shell
//! - pty-req: PTY allocation
//! - env: Environment variable requests
//! - window-size: Window size changes
//! - signal: Signal requests

use crate::channel::types::{Channel, ChannelId, ChannelType};
use crate::protocol::message::Message;
use crate::protocol::messages::MessageType;
use bytes::{BufMut, BytesMut};
use std::collections::HashMap;

/// Terminal mode values (RFC 4254 Section 8)
#[derive(Debug, Clone, PartialEq)]
pub struct TerminalMode {
    pub term: u8,
    pub echo: u8,
    pub raw: u8,
    pub input: u8,
    pub opost: u8,
    pub olcur: u8,
    pub nl2cr: u8,
    pub nlparm: u8,
    pub ixon: u8,
    pub ixoff: u8,
    pub crmod: u8,
    pub ttyop: u8,
    pub isig: u8,
    pub icrnl: u8,
    pub imap: u8,
    pub noktty: u8,
    pub istrip: u8,
    pub iutf8: u8,
    pub vmin: u8,
    pub vtime: u8,
    pub veof: u8,
    pub veol: u8,
    pub verase: u8,
    pub vintr: u8,
    pub vkill: u8,
    pub vquit: u8,
    pub vsusp: u8,
    pub vdsusp: u8,
    pub vstart: u8,
    pub vstop: u8,
    pub vlnext: u8,
    pub vdiscard: u8,
    pub vwerase: u8,
    pub vreprint: u8,
    pub vlnext2: u8,
    pub vpreview: u8,
    pub vstatus: u8,
    pub vswtch: u8,
    pub vhalt: u8,
    pub vreprint2: u8,
}

impl TerminalMode {
    /// Encode terminal mode to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40);
        buf.put_u8(self.term);
        buf.put_u8(self.echo);
        buf.put_u8(self.raw);
        buf.put_u8(self.input);
        buf.put_u8(self.opost);
        buf.put_u8(self.olcur);
        buf.put_u8(self.nl2cr);
        buf.put_u8(self.nlparm);
        buf.put_u8(self.ixon);
        buf.put_u8(self.ixoff);
        buf.put_u8(self.crmod);
        buf.put_u8(self.ttyop);
        buf.put_u8(self.isig);
        buf.put_u8(self.icrnl);
        buf.put_u8(self.imap);
        buf.put_u8(self.noktty);
        buf.put_u8(self.istrip);
        buf.put_u8(self.iutf8);
        buf.put_u8(self.vmin);
        buf.put_u8(self.vtime);
        buf.put_u8(self.veof);
        buf.put_u8(self.veol);
        buf.put_u8(self.verase);
        buf.put_u8(self.vintr);
        buf.put_u8(self.vkill);
        buf.put_u8(self.vquit);
        buf.put_u8(self.vsusp);
        buf.put_u8(self.vdsusp);
        buf.put_u8(self.vstart);
        buf.put_u8(self.vstop);
        buf.put_u8(self.vlnext);
        buf.put_u8(self.vdiscard);
        buf.put_u8(self.vwerase);
        buf.put_u8(self.vreprint);
        buf.put_u8(self.vlnext2);
        buf.put_u8(self.vpreview);
        buf.put_u8(self.vstatus);
        buf.put_u8(self.vswtch);
        buf.put_u8(self.vhalt);
        buf.put_u8(self.vreprint2);
        buf
    }
}

/// Terminal modes array (37 modes as per RFC 4254)
#[derive(Debug, Clone, PartialEq)]
pub struct TerminalModes {
    pub modes: [u8; 37],
}

impl TerminalModes {
    /// Create default terminal modes (all zeros)
    pub fn default() -> Self {
        Self { modes: [0; 37] }
    }

    /// Create raw terminal mode
    pub fn raw() -> Self {
        let mut modes = [0; 37];
        // RAW flag is at index 2
        modes[2] = 1;
        Self { modes }
    }
}

impl Default for TerminalModes {
    fn default() -> Self {
        Self::default()
    }
}

/// Window dimensions for PTY allocation
#[derive(Debug, Clone, PartialEq)]
pub struct WindowDimensions {
    pub width_chars: u32,
    pub height_chars: u32,
    pub width_pixels: u32,
    pub height_pixels: u32,
}

impl WindowDimensions {
    /// Create default terminal dimensions (80x24)
    pub fn default_terminal() -> Self {
        Self {
            width_chars: 80,
            height_chars: 24,
            width_pixels: 0,
            height_pixels: 0,
        }
    }

    /// Create dimensions with character sizes
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width_chars: width,
            height_chars: height,
            width_pixels: 0,
            height_pixels: 0,
        }
    }

    /// Create dimensions with character and pixel sizes
    pub fn with_pixels(width: u32, height: u32, width_px: u32, height_px: u32) -> Self {
        Self {
            width_chars: width,
            height_chars: height,
            width_pixels: width_px,
            height_pixels: height_px,
        }
    }

    /// Encode window dimensions to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.put_u32(self.width_chars);
        buf.put_u32(self.height_chars);
        buf.put_u32(self.width_pixels);
        buf.put_u32(self.height_pixels);
        buf
    }
}

impl Default for WindowDimensions {
    fn default() -> Self {
        Self::default_terminal()
    }
}

/// Helper trait for reading uint32 from byte slices
pub trait ReadUint32 {
    fn read_uint32(&self, offset: usize) -> Option<u32>;
}

impl ReadUint32 for Vec<u8> {
    fn read_uint32(&self, offset: usize) -> Option<u32> {
        if offset + 4 <= self.len() {
            Some(u32::from_be_bytes([
                self[offset],
                self[offset + 1],
                self[offset + 2],
                self[offset + 3],
            ]))
        } else {
            None
        }
    }
}

/// Session state
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Initial,
    Executing,
    Shell,
    Pty,
    Closed,
}

/// SSH Session handler
#[derive(Debug)]
pub struct Session {
    /// Channel ID
    channel_id: u32,
    /// Session state
    state: SessionState,
    /// Terminal type
    pub terminal_type: Option<String>,
    /// Window dimensions
    pub dimensions: WindowDimensions,
    /// Terminal modes
    pub terminal_modes: TerminalModes,
    /// Environment variables
    pub environment: HashMap<String, String>,
    /// Exit status
    pub exit_status: Option<u32>,
}

impl Session {
    /// Create a new session from a channel
    pub fn new(channel: Channel) -> Self {
        Self {
            channel_id: channel.local_id.to_u32(),
            state: SessionState::Initial,
            terminal_type: None,
            dimensions: WindowDimensions::default_terminal(),
            terminal_modes: TerminalModes::default(),
            environment: HashMap::new(),
            exit_status: None,
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

    /// Request PTY allocation
    pub fn request_pty(&self, term: &str, dims: WindowDimensions, modes: TerminalModes) -> Message {
        let mut buf = BytesMut::with_capacity(
            1 + 4 + 7 + 1 + term.len() + 1 + 4 + 4 + 4 + 4 + 37
        );
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(7); // "pty-req\0".len()
        buf.put_slice(b"pty-req\0");
        buf.put_u8(1); // want_reply = true
        buf.put_slice(term.as_bytes());
        buf.put_u8(0); // null terminator
        buf.put_u32(dims.width_chars);
        buf.put_u32(dims.height_chars);
        buf.put_u32(dims.width_pixels);
        buf.put_u32(dims.height_pixels);
        buf.put_slice(&modes.modes);

        Message::from_bytes(buf.to_vec())
    }

    /// Request shell
    pub fn request_shell(&self) -> Message {
        let mut buf = BytesMut::with_capacity(1 + 4 + 5 + 1);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(5); // "shell\0".len()
        buf.put_slice(b"shell\0");
        buf.put_u8(0); // want_reply = false

        Message::from_bytes(buf.to_vec())
    }

    /// Request exec
    pub fn request_exec(&self, command: &str) -> Message {
        let mut buf = BytesMut::with_capacity(1 + 4 + 4 + 1 + command.len() + 1);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(4); // "exec\0".len()
        buf.put_slice(b"exec\0");
        buf.put_u8(0); // want_reply = false
        buf.put_slice(command.as_bytes());
        buf.put_u8(0); // null terminator

        Message::from_bytes(buf.to_vec())
    }

    /// Request subsystem
    pub fn request_subsystem(&self, name: &str) -> Message {
        let mut buf = BytesMut::with_capacity(1 + 4 + name.len() + 1 + 1);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(name.len() as u32 + 1);
        buf.put_slice(name.as_bytes());
        buf.put_u8(0); // null terminator
        buf.put_u8(1); // want_reply = true

        Message::from_bytes(buf.to_vec())
    }

    /// Request X11 forwarding
    pub fn request_x11(
        &self,
        want_reply: bool,
        protocol: &str,
        cookie: &str,
        display: u32,
    ) -> Message {
        let mut buf = BytesMut::with_capacity(
            1 + 4 + 7 + 1 + protocol.len() + 1 + cookie.len() + 1 + 4
        );
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(7); // "x11-req\0".len()
        buf.put_slice(b"x11-req\0");
        buf.put_u8(if want_reply { 1 } else { 0 });
        buf.put_slice(protocol.as_bytes());
        buf.put_u8(0); // null terminator
        buf.put_slice(cookie.as_bytes());
        buf.put_u8(0); // null terminator
        buf.put_u32(display);

        Message::from_bytes(buf.to_vec())
    }

    /// Request environment variable
    pub fn request_env(&self, name: &str, value: &str) -> Message {
        let mut buf = BytesMut::with_capacity(1 + 4 + 4 + 1 + name.len() + 1 + value.len() + 1);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(4); // "env\0".len()
        buf.put_slice(b"env\0");
        buf.put_u8(1); // want_reply = true
        buf.put_slice(name.as_bytes());
        buf.put_u8(0); // null terminator
        buf.put_slice(value.as_bytes());
        buf.put_u8(0); // null terminator

        Message::from_bytes(buf.to_vec())
    }

    /// Send signal
    pub fn send_signal(&self, signal: &str) -> Message {
        let mut buf = BytesMut::with_capacity(1 + 4 + 6 + 1 + signal.len() + 1);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(6); // "signal\0".len()
        buf.put_slice(b"signal\0");
        buf.put_u8(0); // want_reply = false
        buf.put_slice(signal.as_bytes());
        buf.put_u8(0); // null terminator

        Message::from_bytes(buf.to_vec())
    }

    /// Notify window change
    pub fn notify_window_change(&self, dims: WindowDimensions) -> Message {
        let request_name = b"window-change";
        let mut buf = BytesMut::with_capacity(1 + 4 + 4 + request_name.len() + 1 + 4 + 4 + 4 + 4);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(request_name.len() as u32);
        buf.put_slice(request_name);
        buf.put_u8(0); // want_reply = false
        buf.put_u32(dims.width_chars);
        buf.put_u32(dims.height_chars);
        buf.put_u32(dims.width_pixels);
        buf.put_u32(dims.height_pixels);

        Message::from_bytes(buf.to_vec())
    }

    /// Send exit status
    pub fn send_exit_status(&self, status: u32) -> Message {
        let mut buf = BytesMut::with_capacity(1 + 4 + 11 + 1 + 4);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(11); // "exit-status\0".len()
        buf.put_slice(b"exit-status\0");
        buf.put_u8(0); // want_reply = false
        buf.put_u32(status);

        Message::from_bytes(buf.to_vec())
    }

    /// Send keepalive
    pub fn send_keepalive(&self, want_reply: bool) -> Message {
        let mut buf = BytesMut::with_capacity(1 + 4 + 18 + 1);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(18); // "keepalive@openssh.com".len()
        buf.put_slice(b"keepalive@openssh.com\0");
        buf.put_u8(if want_reply { 1 } else { 0 });

        Message::from_bytes(buf.to_vec())
    }

    /// Set terminal type
    pub fn set_terminal_type(&mut self, term: String) {
        self.terminal_type = Some(term);
    }

    /// Set window dimensions
    pub fn set_dimensions(&mut self, dims: WindowDimensions) {
        self.dimensions = dims;
    }

    /// Set terminal modes
    pub fn set_terminal_modes(&mut self, modes: TerminalModes) {
        self.terminal_modes = modes;
    }

    /// Add environment variable
    pub fn add_environment(&mut self, name: &str, value: &str) {
        self.environment.insert(name.to_string(), value.to_string());
    }

    /// Set exit status
    pub fn set_exit_status(&mut self, status: u32) {
        self.exit_status = Some(status);
    }

    /// Handle incoming channel data
    pub fn handle_channel_data(&mut self, data: &[u8]) -> Option<Vec<u8>> {
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
        let channel = Channel::new_session(channel_id, ChannelId::new(0));
        let session = Session::new(channel);
        
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
        let channel = Channel::new(
            ChannelId::new(1),
            ChannelId::new(100),
            ChannelType::Session,
            65536,
            32768,
        );
        let session = Session::new(channel);
        
        assert_eq!(session.channel_id(), 1);
        assert_eq!(session.state(), &SessionState::Initial);
    }

    #[test]
    fn test_session_shell() {
        let channel = Channel::new(
            ChannelId::new(1),
            ChannelId::new(100),
            ChannelType::Session,
            65536,
            32768,
        );
        let session = Session::new(channel);
        let msg = session.request_shell();
        
        println!("Message type: {:?}", msg.msg_type());
        println!("Message bytes: {:?}", msg.as_bytes());
        println!("Expected: {:?}", MessageType::ChannelRequest);
        
        assert!(msg.msg_type() == Some(MessageType::ChannelRequest));
    }

    #[test]
    fn test_session_exec() {
        let channel = Channel::new(
            ChannelId::new(1),
            ChannelId::new(100),
            ChannelType::Session,
            65536,
            32768,
        );
        let session = Session::new(channel);
        let msg = session.request_exec("ls -la");
        
        assert!(msg.msg_type() == Some(MessageType::ChannelRequest));
    }

    #[test]
    fn test_window_dimensions_creation() {
        let dims = WindowDimensions::default_terminal();
        assert_eq!(dims.width_chars, 80);
        assert_eq!(dims.height_chars, 24);
        assert_eq!(dims.width_pixels, 0);
        assert_eq!(dims.height_pixels, 0);
    }

    #[test]
    fn test_terminal_modes_default() {
        let modes = TerminalModes::default();
        assert_eq!(modes.modes.len(), 37);
        assert!(modes.modes.iter().all(|&m| m == 0));
    }

    #[test]
    fn test_terminal_modes_raw() {
        let modes = TerminalModes::raw();
        assert_eq!(modes.modes.len(), 37);
        assert_eq!(modes.modes[2], 1);
    }
}