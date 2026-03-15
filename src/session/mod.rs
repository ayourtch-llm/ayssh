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

/// Interactive shell handle for full TTY support
#[derive(Debug)]
pub struct InteractiveShell {
    channel_id: u32,
    stdin_write: tokio::sync::mpsc::Sender<Vec<u8>>,
    stdout_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    stderr_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Terminal type (e.g., "xterm-256color")
    pub term: String,
    /// Window dimensions
    pub dimensions: WindowDimensions,
    /// Terminal modes
    pub terminal_modes: TerminalModes,
}

impl InteractiveShell {
    /// Write data to shell stdin
    pub async fn write(&mut self, data: &[u8]) -> Result<(), crate::error::SshError> {
        self.stdin_write.send(data.to_vec()).await.map_err(|_| {
            crate::error::SshError::IoError(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Interactive shell stdin closed",
            ))
        })?;
        Ok(())
    }

    /// Read data from shell stdout
    pub async fn read_stdout(&mut self) -> Result<Option<Vec<u8>>, crate::error::SshError> {
        Ok(self.stdout_rx.recv().await)
    }

    /// Read data from shell stderr
    pub async fn read_stderr(&mut self) -> Result<Option<Vec<u8>>, crate::error::SshError> {
        Ok(self.stderr_rx.recv().await)
    }

    /// Close the interactive shell
    pub async fn close(&mut self) -> Result<(), crate::error::SshError> {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Check if shell is closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Change window size (sends window-change request)
    pub fn notify_window_change(&self) -> Message {
        let request_name = b"window-change";
        let mut buf = BytesMut::with_capacity(1 + 4 + 4 + request_name.len() + 1 + 4 + 4 + 4 + 4);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(request_name.len() as u32);
        buf.put_slice(request_name);
        buf.put_u8(0); // want_reply = false
        buf.put_u32(self.dimensions.width_chars);
        buf.put_u32(self.dimensions.height_chars);
        buf.put_u32(self.dimensions.width_pixels);
        buf.put_u32(self.dimensions.height_pixels);

        Message::from_bytes(buf.to_vec())
    }

    /// Send signal to shell (e.g., SIGINT, SIGTERM)
    pub fn send_signal(&self, signal: &str) -> Message {
        let signal_len = signal.len();
        let mut buf = BytesMut::with_capacity(1 + 4 + 6 + 1 + 4 + signal_len);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(6); // "signal".len()
        buf.put_slice(b"signal");
        buf.put_u8(0); // want_reply = false
        buf.put_u32(signal_len as u32);
        buf.put_slice(signal.as_bytes());

        Message::from_bytes(buf.to_vec())
    }

    /// Get terminal type
    pub fn term(&self) -> &str {
        &self.term
    }

    /// Get window dimensions
    pub fn dimensions(&self) -> &WindowDimensions {
        &self.dimensions
    }

    /// Get terminal modes
    pub fn terminal_modes(&self) -> &TerminalModes {
        &self.terminal_modes
    }
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
    /// Interactive shell handle (if shell is active)
    interactive_shell: Option<InteractiveShell>,
    /// Senders for stdout/stderr (used when processing channel data)
    _stdout_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
    _stderr_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>>,
}

impl Session {
    /// Create a new session from a channel
    pub fn new(channel: Channel) -> Self {
        // Create channels for shell I/O
        // stdin: client writes to shell
        let (stdin_write, _) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
        // stdout: shell writes to client
        let (stdout_tx, stdout_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
        // stderr: shell writes to client
        let (stderr_tx, stderr_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        Self {
            channel_id: channel.local_id.to_u32(),
            state: SessionState::Initial,
            terminal_type: None,
            dimensions: WindowDimensions::default_terminal(),
            terminal_modes: TerminalModes::default(),
            environment: HashMap::new(),
            exit_status: None,
            interactive_shell: None,
            // Store senders for use when processing data
            _stdout_tx: Some(stdout_tx),
            _stderr_tx: Some(stderr_tx),
        }
    }

    /// Create a new session from a channel without shell handle
    pub fn new_without_shell(channel: Channel) -> Self {
        Self {
            channel_id: channel.local_id.to_u32(),
            state: SessionState::Initial,
            terminal_type: None,
            dimensions: WindowDimensions::default_terminal(),
            terminal_modes: TerminalModes::default(),
            environment: HashMap::new(),
            exit_status: None,
            interactive_shell: None,
            _stdout_tx: None,
            _stderr_tx: None,
        }
    }

    /// Create a default session (for testing)
    pub fn default_for_test() -> Self {
        use crate::channel::types::ChannelId;
        let channel = Channel::new(
            ChannelId::new(1),
            ChannelId::new(100),
            ChannelType::Session,
            65536,
            32768,
        );
        Self::new(channel)
    }

    /// Open a new session channel
    pub async fn open(transport: &mut crate::transport::Transport) -> Result<Self, crate::error::SshError> {
        use crate::channel::types::ChannelId;
        use crate::protocol::messages::MessageType;

        // Open session channel
        let mut msg = bytes::BytesMut::new();
        msg.put_u8(MessageType::ChannelOpen as u8);
        msg.put_u32(0); // recipient channel (0 for server)
        msg.put_u32(1024); // initial window size
        msg.put_u32(32768); // maximum packet size
        msg.put_u32(0); // channel type length
        msg.put_slice(b"session");
        msg.put_u32(0); // extra data length

        transport.send_message(&msg).await?;

        // Receive confirmation
        let response = transport.recv_message().await?;
        let msg_type = response[0];

        if msg_type != MessageType::ChannelOpenConfirmation as u8 {
            return Err(crate::error::SshError::ProtocolError(
                format!("Expected ChannelOpenConfirmation, got {}", msg_type)
            ));
        }

        // Parse channel ID
        let mut buf = &response[1..];
        let local_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let _recipient_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let _window_size = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let _max_packet = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);

        // Create channel and session
        let channel = Channel::new_session(
            ChannelId::new(local_id),
            ChannelId::new(0),
        );

        Ok(Session::new(channel))
    }

    /// Get the channel ID
    pub fn channel_id(&self) -> u32 {
        self.channel_id
    }

    /// Get the current session state
    pub fn state(&self) -> &SessionState {
        &self.state
    }

    /// Get shell handle if shell is active
    pub fn interactive_shell(&self) -> Option<&InteractiveShell> {
        self.interactive_shell.as_ref()
    }

    /// Set interactive shell
    pub fn set_interactive_shell(&mut self, shell: InteractiveShell) {
        self.interactive_shell = Some(shell);
    }

    /// Start shell session
    pub fn start_shell(&mut self) -> Result<(), crate::error::SshError> {
        self.state = SessionState::Shell;
        Ok(())
    }

    /// Start exec session
    pub fn start_exec(&mut self) -> Result<(), crate::error::SshError> {
        self.state = SessionState::Executing;
        Ok(())
    }

    /// Request PTY allocation
    pub fn request_pty(&self, term: &str, dims: WindowDimensions, modes: TerminalModes) -> Message {
        let term_bytes = term.as_bytes();
        let mut buf = BytesMut::with_capacity(
            1 + 4 + 7 + 1 + term_bytes.len() + 1 + 4 + 4 + 4 + 4 + 37
        );
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(7); // "pty-req\0".len()
        buf.put_slice(b"pty-req\0");
        buf.put_u8(1); // want_reply = true
        buf.put_slice(term_bytes);
        buf.put_u8(0); // null terminator
        buf.put_u32(dims.width_chars);
        buf.put_u32(dims.height_chars);
        buf.put_u32(dims.width_pixels);
        buf.put_u32(dims.height_pixels);
        buf.put_slice(&modes.modes);

        Message::from_bytes(buf.to_vec())
    }

    /// Create interactive shell with PTY allocation
    pub fn create_interactive_shell(
        &self,
        term: String,
        dimensions: WindowDimensions,
        terminal_modes: TerminalModes,
    ) -> InteractiveShell {
        let (stdin_write, _) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
        let (_, stdout_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
        let (_, stderr_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
        
        InteractiveShell {
            channel_id: self.channel_id,
            stdin_write,
            stdout_rx,
            stderr_rx,
            closed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            term,
            dimensions,
            terminal_modes,
        }
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
        let command_len = command.len();
        let mut buf = BytesMut::with_capacity(1 + 4 + 4 + 1 + 4 + command_len);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(4); // "exec".len()
        buf.put_slice(b"exec");
        buf.put_u8(0); // want_reply = false
        buf.put_u32(command_len as u32);
        buf.put_slice(command.as_bytes());

        Message::from_bytes(buf.to_vec())
    }

    /// Request subsystem
    pub fn request_subsystem(&self, name: &str) -> Message {
        let name_len = name.len();
        let mut buf = BytesMut::with_capacity(1 + 4 + 4 + 1 + 4 + name_len);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(9); // "subsystem".len()
        buf.put_slice(b"subsystem");
        buf.put_u8(0); // want_reply = false
        buf.put_u32(name_len as u32);
        buf.put_slice(name.as_bytes());

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
        let name_len = name.len();
        let value_len = value.len();
        let request_name_len = 3; // "env".len()
        let mut buf = BytesMut::with_capacity(1 + 4 + 4 + 1 + 4 + name_len + 4 + value_len);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(request_name_len as u32);
        buf.put_slice(b"env");
        buf.put_u8(0); // want_reply = false
        buf.put_u32(name_len as u32);
        buf.put_slice(name.as_bytes());
        buf.put_u32(value_len as u32);
        buf.put_slice(value.as_bytes());

        Message::from_bytes(buf.to_vec())
    }

    /// Send signal
    pub fn send_signal(&self, signal: &str) -> Message {
        let signal_len = signal.len();
        let mut buf = BytesMut::with_capacity(1 + 4 + 6 + 1 + 4 + signal_len);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(6); // "signal".len()
        buf.put_slice(b"signal");
        buf.put_u8(0); // want_reply = false
        buf.put_u32(signal_len as u32);
        buf.put_slice(signal.as_bytes());

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
        let mut buf = BytesMut::with_capacity(1 + 4 + 21 + 1);
        buf.put_u8(MessageType::ChannelRequest.value());
        buf.put_u32(self.channel_id);
        buf.put_u32(21); // "keepalive@openssh.com".len()
        buf.put_slice(b"keepalive@openssh.com");
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

    /// Handle incoming channel data (stdout)
    pub fn handle_channel_data(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        // For now, just return the data to be displayed
        // In a full implementation, this would send to stdout
        if let Some(ref mut shell) = self.interactive_shell {
            // This would need access to stdout_rx, which requires refactoring
            // For now, return data for display
            Some(data.to_vec())
        } else {
            Some(data.to_vec())
        }
    }

    /// Handle incoming extended data (stderr)
    pub fn handle_extended_data(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        // For now, just return the data to be displayed
        // In a full implementation, this would send to stderr
        if let Some(ref mut shell) = self.interactive_shell {
            // This would need access to stderr_rx, which requires refactoring
            // For now, return data for display
            Some(data.to_vec())
        } else {
            Some(data.to_vec())
        }
    }

    /// Handle incoming channel EOF
    pub fn handle_eof(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Handle incoming channel close
    pub fn handle_close(&mut self) {
        self.state = SessionState::Closed;
    }

    /// Process shell stdin data
    pub async fn process_shell_stdin(
        &mut self,
        data: &[u8],
        transport: &mut crate::transport::Transport,
    ) -> Result<(), crate::error::SshError> {
        // Send data to remote shell
        transport.send_channel_data(self.channel_id, data).await?;
        Ok(())
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