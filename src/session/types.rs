//! Session types and structures for SSH Connection Protocol (RFC 4254)

use crate::channel::types::{Channel, ChannelId, ChannelRequest};
use crate::protocol::message::Message;

/// Terminal mode flags (RFC 4254 Section 8)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalMode {
    /// TERM
    pub term: u8,
    /// ECHO
    pub echo: u8,
    /// RAW
    pub raw: u8,
    /// INPUT
    pub input: u8,
    /// OPOST
    pub opost: u8,
    /// OLCUR
    pub olcur: u8,
    /// NL2CR
    pub nl2cr: u8,
    /// NLPARM
    pub nlparm: u8,
    /// IXON
    pub ixon: u8,
    /// IXOFF
    pub ixoff: u8,
    /// CRMOD
    pub crmod: u8,
    /// TTYOP
    pub ttyop: u8,
    /// ISIG
    pub isig: u8,
    /// ICRNL
    pub icrnl: u8,
    /// IMAP
    pub imap: u8,
    /// NOKTTY
    pub noktty: u8,
    /// ISTRIP
    pub istrip: u8,
    /// IUTF8
    pub iutf8: u8,
    /// VMIN
    pub vmin: u8,
    /// VTIME
    pub vtime: u8,
    /// VEOF
    pub veof: u8,
    /// VEOL
    pub veol: u8,
    /// VERASE
    pub verase: u8,
    /// VINTR
    pub vintr: u8,
    /// VKILL
    pub vkill: u8,
    /// VQUIT
    pub vquit: u8,
    /// VSUSP
    pub vsusp: u8,
    /// VDSUSP
    pub vdsusp: u8,
    /// VSTART
    pub vstart: u8,
    /// VSTOP
    pub vstop: u8,
    /// VLNEXT
    pub vlnext: u8,
    /// VDISCARD
    pub vdiscard: u8,
    /// VWERASE
    pub vwerase: u8,
    /// VREPRINT
    pub vreprint: u8,
    /// VLNEXT
    pub vlnext2: u8,
    /// VPREVIEW
    pub vpreview: u8,
    /// VSTATUS
    pub vstatus: u8,
    /// VSWTCH
    pub vswtch: u8,
    /// VHALT
    pub vhalt: u8,
    /// VREPRINT2
    pub vreprint2: u8,
}

impl Default for TerminalMode {
    fn default() -> Self {
        Self {
            term: 0,
            echo: 0,
            raw: 0,
            input: 0,
            opost: 0,
            olcur: 0,
            nl2cr: 0,
            nlparm: 0,
            ixon: 0,
            ixoff: 0,
            crmod: 0,
            ttyop: 0,
            isig: 0,
            icrnl: 0,
            imap: 0,
            noktty: 0,
            istrip: 0,
            iutf8: 0,
            vmin: 0,
            vtime: 0,
            veof: 0,
            veol: 0,
            verase: 0,
            vintr: 0,
            vkill: 0,
            vquit: 0,
            vsusp: 0,
            vdsusp: 0,
            vstart: 0,
            vstop: 0,
            vlnext: 0,
            vdiscard: 0,
            vwerase: 0,
            vreprint: 0,
            vlnext2: 0,
            vpreview: 0,
            vstatus: 0,
            vswtch: 0,
            vhalt: 0,
            vreprint2: 0,
        }
    }
}

impl TerminalMode {
    /// Encode terminal modes to bytes
    pub fn encode(&self) -> Vec<u8> {
        // RFC 4254 Section 8 defines terminal modes as a sequence of uint8 values
        // The sequence is encoded as a string with length prefix
        let mut modes = Vec::new();
        
        modes.push(self.term);
        modes.push(self.echo);
        modes.push(self.raw);
        modes.push(self.input);
        modes.push(self.opost);
        modes.push(self.olcur);
        modes.push(self.nl2cr);
        modes.push(self.nlparm);
        modes.push(self.ixon);
        modes.push(self.ixoff);
        modes.push(self.crmod);
        modes.push(self.ttyop);
        modes.push(self.isig);
        modes.push(self.icrnl);
        modes.push(self.imap);
        modes.push(self.noktty);
        modes.push(self.istrip);
        modes.push(self.iutf8);
        modes.push(self.vmin);
        modes.push(self.vtime);
        modes.push(self.veof);
        modes.push(self.veol);
        modes.push(self.verase);
        modes.push(self.vintr);
        modes.push(self.vkill);
        modes.push(self.vquit);
        modes.push(self.vsusp);
        modes.push(self.vdsusp);
        modes.push(self.vstart);
        modes.push(self.vstop);
        modes.push(self.vlnext);
        modes.push(self.vdiscard);
        modes.push(self.vwerase);
        modes.push(self.vreprint);
        modes.push(self.vlnext2);
        modes.push(self.vpreview);
        modes.push(self.vstatus);
        modes.push(self.vswtch);
        modes.push(self.vhalt);
        modes.push(self.vreprint2);
        
        modes
    }
    
    /// Create default raw terminal mode
    pub fn raw() -> Self {
        let mut modes = Self::default();
        modes.raw = 1;
        modes
    }
    
    /// Create default cooked terminal mode
    pub fn cooked() -> Self {
        Self::default()
    }
}

/// Terminal dimensions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowDimensions {
    /// Width in characters (columns)
    pub width_chars: u32,
    /// Height in characters (rows)
    pub height_chars: u32,
    /// Width in pixels
    pub width_pixels: u32,
    /// Height in pixels
    pub height_pixels: u32,
}

impl WindowDimensions {
    /// Create new dimensions
    pub fn new(width_chars: u32, height_chars: u32) -> Self {
        Self {
            width_chars,
            height_chars,
            width_pixels: 0,
            height_pixels: 0,
        }
    }
    
    /// Create dimensions with pixel values
    pub fn with_pixels(width_chars: u32, height_chars: u32, width_px: u32, height_px: u32) -> Self {
        Self {
            width_chars,
            height_chars,
            width_pixels: width_px,
            height_pixels: height_px,
        }
    }
    
    /// Encode dimensions to message
    pub fn encode(&self) -> Message {
        let mut msg = Message::new();
        msg.write_uint32(self.width_chars);
        msg.write_uint32(self.height_chars);
        msg.write_uint32(self.width_pixels);
        msg.write_uint32(self.height_pixels);
        msg
    }
    
    /// Get default terminal size
    pub fn default_terminal() -> Self {
        Self::new(80, 24)
    }
}

/// Session request types
#[derive(Debug, Clone)]
pub enum SessionRequest {
    /// Request pseudo-terminal
    PseudoTerminal {
        /// Terminal type (e.g., "xterm-256color", "vt100")
        term: String,
        /// Terminal dimensions
        dimensions: WindowDimensions,
        /// Terminal modes
        modes: TerminalModes,
    },
    /// Request shell
    Shell,
    /// Request command execution
    Exec {
        /// Command to execute
        command: String,
    },
    /// Request subsystem
    Subsystem {
        /// Subsystem name (e.g., "sftp")
        subsystem: String,
    },
    /// Request X11 forwarding
    X11 {
        /// Single connection flag
        single_connection: bool,
        /// X11 authentication protocol
        protocol: String,
        /// X11 authentication cookie
        cookie: String,
        /// X11 screen number
        screen_number: u32,
    },
    /// Request environment variable
    Environment {
        /// Variable name
        name: String,
        /// Variable value
        value: String,
    },
    /// Request signal
    Signal {
        /// Signal name (e.g., "SIGINT", "SIGTERM")
        signal: String,
    },
    /// Request window change
    WindowChange {
        /// Terminal dimensions
        dimensions: WindowDimensions,
    },
    /// Request exit status
    ExitStatus {
        /// Exit status code
        exit_status: u32,
    },
    /// Request keep-alive
    KeepAlive(bool),
}

impl SessionRequest {
    /// Encode session request to message
    pub fn encode(&self, channel_id: ChannelId, want_reply: bool) -> Message {
        match self {
            SessionRequest::PseudoTerminal {
                term,
                dimensions,
                modes,
            } => {
                let mut msg = Message::with_type(crate::protocol::messages::MessageType::ChannelRequest);
                msg.write_uint32(channel_id.to_u32());
                msg.write_string(b"pty-req");
                msg.write_bool(want_reply);
                msg.write_string(term.as_bytes());
                msg.write_uint32(dimensions.width_chars);
                msg.write_uint32(dimensions.height_chars);
                msg.write_uint32(dimensions.width_pixels);
                msg.write_uint32(dimensions.height_pixels);
                msg.write_string(&modes.modes);
                msg
            }
            SessionRequest::Shell => {
                let mut msg = Message::with_type(crate::protocol::messages::MessageType::ChannelRequest);
                msg.write_uint32(channel_id.to_u32());
                msg.write_string(b"shell");
                msg.write_bool(want_reply);
                msg
            }
            SessionRequest::Exec { command } => {
                let mut msg = Message::with_type(crate::protocol::messages::MessageType::ChannelRequest);
                msg.write_uint32(channel_id.to_u32());
                msg.write_string(b"exec");
                msg.write_bool(want_reply);
                msg.write_string(command.as_bytes());
                msg
            }
            SessionRequest::Subsystem { subsystem } => {
                let mut msg = Message::with_type(crate::protocol::messages::MessageType::ChannelRequest);
                msg.write_uint32(channel_id.to_u32());
                msg.write_string(b"subsystem");
                msg.write_bool(want_reply);
                msg.write_string(subsystem.as_bytes());
                msg
            }
            SessionRequest::X11 {
                single_connection,
                protocol,
                cookie,
                screen_number,
            } => {
                let mut msg = Message::with_type(crate::protocol::messages::MessageType::ChannelRequest);
                msg.write_uint32(channel_id.to_u32());
                msg.write_string(b"x11-req");
                msg.write_bool(want_reply);
                msg.write_bool(*single_connection);
                msg.write_string(protocol.as_bytes());
                msg.write_string(cookie.as_bytes());
                msg.write_uint32(*screen_number);
                msg
            }
            SessionRequest::Environment { name, value } => {
                let mut msg = Message::with_type(crate::protocol::messages::MessageType::ChannelRequest);
                msg.write_uint32(channel_id.to_u32());
                msg.write_string(b"env");
                msg.write_bool(want_reply);
                msg.write_string(name.as_bytes());
                msg.write_string(value.as_bytes());
                msg
            }
            SessionRequest::Signal { signal } => {
                let mut msg = Message::with_type(crate::protocol::messages::MessageType::ChannelRequest);
                msg.write_uint32(channel_id.to_u32());
                msg.write_string(b"signal");
                msg.write_bool(want_reply);
                msg.write_string(signal.as_bytes());
                msg
            }
            SessionRequest::WindowChange { dimensions } => {
                let mut msg = Message::with_type(crate::protocol::messages::MessageType::ChannelRequest);
                msg.write_uint32(channel_id.to_u32());
                msg.write_string(b"window-change");
                msg.write_bool(false); // No reply for window-change
                msg.write_uint32(dimensions.width_chars);
                msg.write_uint32(dimensions.height_chars);
                msg.write_uint32(dimensions.width_pixels);
                msg.write_uint32(dimensions.height_pixels);
                msg
            }
            SessionRequest::ExitStatus { exit_status } => {
                let mut msg = Message::with_type(crate::protocol::messages::MessageType::ChannelRequest);
                msg.write_uint32(channel_id.to_u32());
                msg.write_string(b"exit-status");
                msg.write_bool(want_reply);
                msg.write_uint32(*exit_status);
                msg
            }
            SessionRequest::KeepAlive(want_reply) => {
                let mut msg = Message::with_type(crate::protocol::messages::MessageType::ChannelRequest);
                msg.write_uint32(channel_id.to_u32());
                msg.write_string(b"keepalive@openssh.com");
                msg.write_bool(*want_reply);
                msg
            }
        }
    }
}

/// Terminal modes as a byte string (RFC 4254 Section 8)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalModes {
    /// Raw mode bytes
    pub modes: Vec<u8>,
}

impl TerminalModes {
    /// Create from raw bytes
    pub fn new(modes: Vec<u8>) -> Self {
        Self { modes }
    }
    
    /// Create default terminal modes
    pub fn default() -> Self {
        Self { modes: vec![0; 37] }
    }
    
    /// Create raw terminal modes
    pub fn raw() -> Self {
        // RFC 4254 Section 8 defines the mode encoding
        // Raw mode: disable all processing
        let mut modes = vec![0; 37];
        modes[2] = 1; // RAW flag
        Self { modes }
    }
    
    /// Encode to bytes
    pub fn encode(&self) -> &[u8] {
        &self.modes
    }
}

impl Default for TerminalModes {
    fn default() -> Self {
        Self::default()
    }
}

/// SSH session representing an interactive shell or command execution
#[derive(Debug, Clone)]
pub struct Session {
    /// Underlying channel
    pub channel: Channel,
    /// Terminal type (if PTY allocated)
    pub terminal_type: Option<String>,
    /// Terminal dimensions
    pub dimensions: WindowDimensions,
    /// Terminal modes
    pub terminal_modes: TerminalModes,
    /// Environment variables
    pub environment: Vec<(String, String)>,
    /// Exit status (if session has exited)
    pub exit_status: Option<u32>,
}

impl Session {
    /// Create a new session from a channel
    pub fn new(channel: Channel) -> Self {
        Self {
            channel,
            terminal_type: None,
            dimensions: WindowDimensions::default_terminal(),
            terminal_modes: TerminalModes::default(),
            environment: Vec::new(),
            exit_status: None,
        }
    }
    
    /// Request pseudo-terminal allocation
    pub fn request_pty(
        &self,
        term: &str,
        dimensions: WindowDimensions,
        modes: TerminalModes,
    ) -> Message {
        SessionRequest::PseudoTerminal {
            term: term.to_string(),
            dimensions,
            modes,
        }
        .encode(self.channel.local_id, true)
    }
    
    /// Request shell
    pub fn request_shell(&self) -> Message {
        SessionRequest::Shell.encode(self.channel.local_id, false)
    }
    
    /// Request command execution
    pub fn request_exec(&self, command: &str) -> Message {
        SessionRequest::Exec {
            command: command.to_string(),
        }
        .encode(self.channel.local_id, false)
    }
    
    /// Request subsystem
    pub fn request_subsystem(&self, subsystem: &str) -> Message {
        SessionRequest::Subsystem {
            subsystem: subsystem.to_string(),
        }
        .encode(self.channel.local_id, false)
    }
    
    /// Request X11 forwarding
    pub fn request_x11(
        &self,
        single_connection: bool,
        protocol: &str,
        cookie: &str,
        screen_number: u32,
    ) -> Message {
        SessionRequest::X11 {
            single_connection,
            protocol: protocol.to_string(),
            cookie: cookie.to_string(),
            screen_number,
        }
        .encode(self.channel.local_id, true)
    }
    
    /// Request environment variable
    pub fn request_env(&self, name: &str, value: &str) -> Message {
        SessionRequest::Environment {
            name: name.to_string(),
            value: value.to_string(),
        }
        .encode(self.channel.local_id, true)
    }
    
    /// Send signal to session
    pub fn send_signal(&self, signal: &str) -> Message {
        SessionRequest::Signal {
            signal: signal.to_string(),
        }
        .encode(self.channel.local_id, false)
    }
    
    /// Notify window size change
    pub fn notify_window_change(&self, dimensions: WindowDimensions) -> Message {
        SessionRequest::WindowChange { dimensions }.encode(self.channel.local_id, false)
    }
    
    /// Send exit status
    pub fn send_exit_status(&self, status: u32) -> Message {
        SessionRequest::ExitStatus { exit_status: status }
            .encode(self.channel.local_id, false)
    }
    
    /// Send keep-alive
    pub fn send_keepalive(&self, want_reply: bool) -> Message {
        SessionRequest::KeepAlive(want_reply).encode(self.channel.local_id, false)
    }
    
    /// Update terminal type
    pub fn set_terminal_type(&mut self, term: String) {
        self.terminal_type = Some(term);
    }
    
    /// Update terminal dimensions
    pub fn set_dimensions(&mut self, dimensions: WindowDimensions) {
        self.dimensions = dimensions;
    }
    
    /// Update terminal modes
    pub fn set_terminal_modes(&mut self, modes: TerminalModes) {
        self.terminal_modes = modes;
    }
    
    /// Add environment variable
    pub fn add_environment(&mut self, name: &str, value: &str) {
        self.environment.push((name.to_string(), value.to_string()));
    }
    
    /// Set exit status
    pub fn set_exit_status(&mut self, status: u32) {
        self.exit_status = Some(status);
    }
}