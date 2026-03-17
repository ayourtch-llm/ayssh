//! Channel types and structures for SSH Connection Protocol (RFC 4254)

use crate::protocol::message::Message;
use crate::protocol::messages::MessageType;

/// Unique identifier for an SSH channel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId(u32);

impl ChannelId {
    pub const INVALID: ChannelId = ChannelId(0xFFFFFFFF);
    
    pub fn new(id: u32) -> Self {
        ChannelId(id)
    }
    
    pub fn to_u32(&self) -> u32 {
        self.0
    }
    
    pub fn is_invalid(&self) -> bool {
        self.0 == Self::INVALID.0
    }
}

/// Channel type identifiers (RFC 4254)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelType {
    /// Interactive session (shell)
    Session,
    /// Direct TCP/IP forwarding
    DirectTcpIp {
        /// Address to connect (from client perspective)
        originator_address: String,
        /// Port to connect (from client perspective)
        originator_port: u16,
        /// Address to bind (server will listen on this)
        host_to_connect: String,
        /// Port to connect to (server will connect to this)
        port_to_connect: u16,
    },
    /// Remote TCP/IP forwarding (server listens, client connects)
    ForwardedTcpIp {
        /// Address to bind (server will listen on this)
        address_to_bind: String,
        /// Port to bind (server will listen on this)
        port_to_bind: u16,
        /// Address client will connect to
        originator_address: String,
        /// Port client will connect from
        originator_port: u16,
    },
    /// Dynamic TCP/IP forwarding (SOCKS proxy)
    ForwardedDontCare {
        /// Address client will connect to
        originator_address: String,
        /// Port client will connect from
        originator_port: u16,
    },
}

impl ChannelType {
    /// Get the channel type name as string
    pub fn as_str(&self) -> &'static str {
        match self {
            ChannelType::Session => "session",
            ChannelType::DirectTcpIp { .. } => "direct-tcpip",
            ChannelType::ForwardedTcpIp { .. } => "forwarded-tcpip",
            ChannelType::ForwardedDontCare { .. } => "forwarded-dontcare",
        }
    }
    
    /// Parse channel type from bytes
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "session" => Some(ChannelType::Session),
            "direct-tcpip" => Some(ChannelType::DirectTcpIp {
                originator_address: String::new(),
                originator_port: 0,
                host_to_connect: String::new(),
                port_to_connect: 0,
            }),
            "forwarded-tcpip" => Some(ChannelType::ForwardedTcpIp {
                address_to_bind: String::new(),
                port_to_bind: 0,
                originator_address: String::new(),
                originator_port: 0,
            }),
            "forwarded-dontcare" => Some(ChannelType::ForwardedDontCare {
                originator_address: String::new(),
                originator_port: 0,
            }),
            _ => None,
        }
    }
}

/// Channel open request (client -> server)
#[derive(Debug, Clone)]
pub struct ChannelOpenRequest {
    /// Sender's channel ID
    pub sender_channel: ChannelId,
    /// Initial window size (bytes)
    pub initial_window_size: u32,
    /// Maximum packet size (bytes)
    pub max_packet_size: u32,
    /// Channel type
    pub channel_type: ChannelType,
}

impl ChannelOpenRequest {
    /// Encode channel open request to message
    pub fn encode(&self) -> Message {
        let mut msg = Message::with_type(MessageType::ChannelOpen);
        
        msg.write_string(self.channel_type.as_str().as_bytes());
        msg.write_uint32(self.sender_channel.to_u32());
        msg.write_uint32(self.initial_window_size);
        msg.write_uint32(self.max_packet_size);
        
        // Channel type specific data
        match &self.channel_type {
            ChannelType::Session => {}
            ChannelType::DirectTcpIp {
                originator_address,
                originator_port,
                host_to_connect,
                port_to_connect,
            } => {
                msg.write_string(originator_address.as_bytes());
                msg.write_uint32(*originator_port as u32);
                msg.write_string(host_to_connect.as_bytes());
                msg.write_uint32(*port_to_connect as u32);
            }
            ChannelType::ForwardedTcpIp {
                address_to_bind,
                port_to_bind,
                originator_address,
                originator_port,
            } => {
                msg.write_string(address_to_bind.as_bytes());
                msg.write_uint32(*port_to_bind as u32);
                msg.write_string(originator_address.as_bytes());
                msg.write_uint32(*originator_port as u32);
            }
            ChannelType::ForwardedDontCare {
                originator_address,
                originator_port,
            } => {
                msg.write_string(originator_address.as_bytes());
                msg.write_uint32(*originator_port as u32);
            }
        }
        
        msg
    }
    
    /// Parse channel open request from message
    pub fn parse(msg: &Message) -> Result<Self, String> {
        let mut offset = 1; // Skip message type
        
        let channel_type_str = msg.read_string_slice(offset)
            .ok_or_else(|| "Failed to read channel type")?;
        offset += 4 + channel_type_str.len();
        
        let sender_channel = ChannelId::new(msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read sender channel")?);
        offset += 4;
        
        let initial_window_size = msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read initial window size")?;
        offset += 4;
        
        let max_packet_size = msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read max packet size")?;
        offset += 4;
        
        // Channel type specific data
        let channel_type = match channel_type_str.as_str() {
            "session" => ChannelType::Session,
            "direct-tcpip" => {
                let originator_address = msg.read_string_slice(offset)
                    .ok_or_else(|| "Failed to read originator address")?;
                offset += 4 + originator_address.len();
                
                let originator_port = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read originator port")?;
                offset += 4;
                
                let host_to_connect = msg.read_string_slice(offset)
                    .ok_or_else(|| "Failed to read host to connect")?;
                offset += 4 + host_to_connect.len();
                
                let port_to_connect = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read port to connect")?;
                
                ChannelType::DirectTcpIp {
                    originator_address: originator_address.to_string(),
                    originator_port: originator_port as u16,
                    host_to_connect: host_to_connect.to_string(),
                    port_to_connect: port_to_connect as u16,
                }
            }
            "forwarded-tcpip" => {
                let address_to_bind = msg.read_string_slice(offset)
                    .ok_or_else(|| "Failed to read address to bind")?;
                offset += 4 + address_to_bind.len();
                
                let port_to_bind = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read port to bind")?;
                offset += 4;
                
                let originator_address = msg.read_string_slice(offset)
                    .ok_or_else(|| "Failed to read originator address")?;
                offset += 4 + originator_address.len();
                
                let originator_port = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read originator port")?;
                
                ChannelType::ForwardedTcpIp {
                    address_to_bind: address_to_bind.to_string(),
                    port_to_bind: port_to_bind as u16,
                    originator_address: originator_address.to_string(),
                    originator_port: originator_port as u16,
                }
            }
            "forwarded-dontcare" => {
                let originator_address = msg.read_string_slice(offset)
                    .ok_or_else(|| "Failed to read originator address")?;
                offset += 4 + originator_address.len();
                
                let originator_port = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read originator port")?;
                
                ChannelType::ForwardedDontCare {
                    originator_address: originator_address.to_string(),
                    originator_port: originator_port as u16,
                }
            }
            _ => return Err(format!("Unknown channel type: {}", channel_type_str)),
        };
        
        Ok(Self {
            sender_channel,
            initial_window_size,
            max_packet_size,
            channel_type,
        })
    }
}

/// Channel open confirmation (server -> client)
#[derive(Debug, Clone)]
pub struct ChannelOpenConfirmation {
    /// Recipient's channel ID (from original request)
    pub recipient_channel: ChannelId,
    /// Sender's allocated channel ID
    pub sender_channel: ChannelId,
    /// Initial window size
    pub initial_window_size: u32,
    /// Maximum packet size
    pub max_packet_size: u32,
}

impl ChannelOpenConfirmation {
    /// Encode channel open confirmation to message
    pub fn encode(&self) -> Message {
        let mut msg = Message::with_type(MessageType::ChannelOpenConfirmation);
        
        msg.write_uint32(self.recipient_channel.to_u32());
        msg.write_uint32(self.sender_channel.to_u32());
        msg.write_uint32(self.initial_window_size);
        msg.write_uint32(self.max_packet_size);
        
        msg
    }
    
    /// Parse channel open confirmation from message
    pub fn parse(msg: &Message) -> Result<Self, String> {
        let mut offset = 1; // Skip message type
        
        let recipient_channel = ChannelId::new(msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read recipient channel")?);
        offset += 4;
        
        let sender_channel = ChannelId::new(msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read sender channel")?);
        offset += 4;
        
        let initial_window_size = msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read initial window size")?;
        offset += 4;
        
        let max_packet_size = msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read max packet size")?;
        
        Ok(Self {
            recipient_channel,
            sender_channel,
            initial_window_size,
            max_packet_size,
        })
    }
}

/// Channel open failure (server -> client)
#[derive(Debug, Clone)]
pub struct ChannelOpenFailure {
    /// Recipient's channel ID (from original request)
    pub recipient_channel: ChannelId,
    /// Reason code
    pub reason_code: ReasonCode,
    /// Description
    pub description: String,
    /// Language tag
    pub language_tag: String,
}

/// Reason codes for channel open failure
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum ReasonCode {
    /// Connection refused - could not open connection
    ConnectionRefused = 1,
    /// Host unreachable
    HostUnreachable = 2,
    /// Network unreachable
    NetworkUnreachable = 3,
    /// Host unknown
    HostUnknown = 4,
    /// Privilege denied
    AdminProhibited = 5,
    /// No more connections
    NoMoreConnections = 6,
    /// Unknown error
    Unknown = 999,
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReasonCode::ConnectionRefused => write!(f, "Connection refused"),
            ReasonCode::HostUnreachable => write!(f, "Host unreachable"),
            ReasonCode::NetworkUnreachable => write!(f, "Network unreachable"),
            ReasonCode::HostUnknown => write!(f, "Host unknown"),
            ReasonCode::AdminProhibited => write!(f, "Administratively prohibited"),
            ReasonCode::NoMoreConnections => write!(f, "No more connections"),
            ReasonCode::Unknown => write!(f, "Unknown error"),
        }
    }
}

impl ChannelOpenFailure {
    /// Encode channel open failure to message
    pub fn encode(&self) -> Message {
        let mut msg = Message::with_type(MessageType::ChannelOpenFailure);
        
        msg.write_uint32(self.recipient_channel.to_u32());
        msg.write_uint32(self.reason_code as u32);
        msg.write_string(self.description.as_bytes());
        msg.write_string(self.language_tag.as_bytes());
        
        msg
    }
    
    /// Parse channel open failure from message
    pub fn parse(msg: &Message) -> Result<Self, String> {
        let mut offset = 1; // Skip message type
        
        let recipient_channel = ChannelId::new(msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read recipient channel")?);
        offset += 4;
        
        let reason_code = msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read reason code")?;
        offset += 4;
        
        let description = msg.read_string_slice(offset)
            .ok_or_else(|| "Failed to read description")?;
        offset += 4 + description.len();
        
        let language_tag = msg.read_string_slice(offset)
            .ok_or_else(|| "Failed to read language tag")?;
        
        let reason = match reason_code {
            1 => ReasonCode::ConnectionRefused,
            2 => ReasonCode::HostUnreachable,
            3 => ReasonCode::NetworkUnreachable,
            4 => ReasonCode::HostUnknown,
            5 => ReasonCode::AdminProhibited,
            6 => ReasonCode::NoMoreConnections,
            _ => ReasonCode::Unknown,
        };
        
        Ok(Self {
            recipient_channel,
            reason_code: reason,
            description: description.to_string(),
            language_tag: language_tag.to_string(),
        })
    }
}

/// Channel data (any direction)
#[derive(Debug, Clone)]
pub struct ChannelData {
    /// Channel ID
    pub channel_id: ChannelId,
    /// Data payload
    pub data: Vec<u8>,
}

impl ChannelData {
    /// Encode channel data to message
    pub fn encode(&self) -> Message {
        let mut msg = Message::with_type(MessageType::ChannelData);
        
        msg.write_uint32(self.channel_id.to_u32());
        msg.write_string(&self.data);
        
        msg
    }
    
    /// Parse channel data from message
    pub fn parse(msg: &Message) -> Result<Self, String> {
        let mut offset = 1; // Skip message type
        
        let channel_id = ChannelId::new(msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read channel id")?);
        offset += 4;
        
        let data = msg.read_string(offset)
            .ok_or_else(|| "Failed to read data")?;
        
        Ok(Self {
            channel_id,
            data,
        })
    }
}

/// Channel close (any direction)
#[derive(Debug, Clone)]
pub struct ChannelClose {
    /// Channel ID
    pub channel_id: ChannelId,
}

impl ChannelClose {
    /// Encode channel close to message
    pub fn encode(&self) -> Message {
        let mut msg = Message::with_type(MessageType::ChannelClose);
        
        msg.write_uint32(self.channel_id.to_u32());
        
        msg
    }
    
    /// Parse channel close from message
    pub fn parse(msg: &Message) -> Result<Self, String> {
        let mut offset = 1; // Skip message type
        
        let channel_id = ChannelId::new(msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read channel id")?);
        
        Ok(Self { channel_id })
    }
}

/// Channel EOF (any direction)
#[derive(Debug, Clone)]
pub struct ChannelEof {
    /// Channel ID
    pub channel_id: ChannelId,
}

impl ChannelEof {
    /// Encode channel EOF to message
    pub fn encode(&self) -> Message {
        let mut msg = Message::with_type(MessageType::ChannelEof);
        
        msg.write_uint32(self.channel_id.to_u32());
        
        msg
    }
    
    /// Parse channel EOF from message
    pub fn parse(msg: &Message) -> Result<Self, String> {
        let mut offset = 1; // Skip message type
        
        let channel_id = ChannelId::new(msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read channel id")?);
        
        Ok(Self { channel_id })
    }
}

/// Channel success/failure (response to channel request)
#[derive(Debug, Clone)]
pub enum ChannelSuccessOrFailure {
    Success,
    Failure,
}

impl ChannelSuccessOrFailure {
    /// Encode channel success/failure to message
    pub fn encode(&self, channel_id: ChannelId) -> Message {
        let msg_type = match self {
            ChannelSuccessOrFailure::Success => MessageType::ChannelSuccess,
            ChannelSuccessOrFailure::Failure => MessageType::ChannelFailure,
        };
        
        let mut msg = Message::with_type(msg_type);
        msg.write_uint32(channel_id.to_u32());
        msg
    }
    
    /// Parse channel success/failure from message
    pub fn parse(msg: &Message) -> Result<Self, String> {
        let msg_type = msg.msg_type()
            .ok_or_else(|| "Failed to read message type")?;
        
        match msg_type {
            MessageType::ChannelSuccess => Ok(ChannelSuccessOrFailure::Success),
            MessageType::ChannelFailure => Ok(ChannelSuccessOrFailure::Failure),
            _ => Err(format!("Expected ChannelSuccess/ChannelFailure, got {:?}", msg_type)),
        }
    }
}

/// Channel request (any direction)
#[derive(Debug, Clone)]
pub enum ChannelRequest {
    /// Shell request (session only)
    Shell,
    /// Exec request
    Exec {
        /// Command to execute
        command: String,
    },
    /// Pseudo-terminal request
    PseudoTerminal {
        /// Terminal type
        term: String,
        /// Terminal width (characters)
        width: u32,
        /// Terminal height (characters)
        height: u32,
        /// Terminal width (pixels)
        pixel_width: u32,
        /// Terminal height (pixels)
        pixel_height: u32,
        /// Terminal modes (UTF-8 encoded)
        modes: String,
    },
    /// Window change notification
    WindowChange {
        /// Terminal width (characters)
        width: u32,
        /// Terminal height (characters)
        height: u32,
        /// Terminal width (pixels)
        pixel_width: u32,
        /// Terminal height (pixels)
        pixel_height: u32,
    },
    /// Signal request
    Signal {
        /// Signal name (e.g., "SIGINT", "SIGTERM")
        signal: String,
    },
    /// Exit status (shell session exit)
    ExitStatus {
        /// Exit status code
        exit_status: u32,
    },
    /// Environment variable
    Environment {
        /// Variable name
        name: String,
        /// Variable value
        value: String,
    },
    /// Keep-alive
    KeepAlive(bool),
    /// Unknown request
    Unknown {
        /// Request name
        request: String,
        /// Want reply flag
        want_reply: bool,
    },
}

impl ChannelRequest {
    /// Encode channel request to message
    pub fn encode(&self, channel_id: ChannelId, want_reply: bool) -> Message {
        let mut msg = Message::with_type(MessageType::ChannelRequest);
        
        msg.write_uint32(channel_id.to_u32());
        msg.write_string(match self {
            ChannelRequest::Shell => b"shell",
            ChannelRequest::Exec { .. } => b"exec",
            ChannelRequest::PseudoTerminal { .. } => b"pty-req",
            ChannelRequest::WindowChange { .. } => b"window-change",
            ChannelRequest::Signal { .. } => b"signal",
            ChannelRequest::ExitStatus { .. } => b"exit-status",
            ChannelRequest::Environment { .. } => b"env",
            ChannelRequest::KeepAlive(_) => b"keepalive@openssh.com",
            ChannelRequest::Unknown { request, .. } => request.as_bytes(),
        });
        msg.write_bool(want_reply);
        
        match self {
            ChannelRequest::Shell => {}
            ChannelRequest::Exec { command } => {
                msg.write_string(command.as_bytes());
            }
            ChannelRequest::PseudoTerminal {
                term,
                width,
                height,
                pixel_width,
                pixel_height,
                modes,
            } => {
                msg.write_string(term.as_bytes());
                msg.write_uint32(*width);
                msg.write_uint32(*height);
                msg.write_uint32(*pixel_width);
                msg.write_uint32(*pixel_height);
                msg.write_string(modes.as_bytes());
            }
            ChannelRequest::WindowChange {
                width,
                height,
                pixel_width,
                pixel_height,
            } => {
                msg.write_uint32(*width);
                msg.write_uint32(*height);
                msg.write_uint32(*pixel_width);
                msg.write_uint32(*pixel_height);
            }
            ChannelRequest::Signal { signal } => {
                msg.write_string(signal.as_bytes());
            }
            ChannelRequest::ExitStatus { exit_status } => {
                msg.write_uint32(*exit_status);
            }
            ChannelRequest::Environment { name, value } => {
                msg.write_string(name.as_bytes());
                msg.write_string(value.as_bytes());
            }
            ChannelRequest::KeepAlive(_) => {}
            ChannelRequest::Unknown { request, want_reply } => {
                msg.write_bool(*want_reply);
            }
        }
        
        msg
    }
    
    /// Parse channel request from message
    pub fn parse(msg: &Message) -> Result<(Self, bool), String> {
        let mut offset = 1; // Skip message type
        
        let _channel_id = msg.read_uint32(offset)
            .ok_or_else(|| "Failed to read channel id")?;
        offset += 4;
        
        let request_name = msg.read_string_slice(offset)
            .ok_or_else(|| "Failed to read request name")?;
        offset += 4 + request_name.len();
        
        let want_reply = msg.read_bool(offset)
            .ok_or_else(|| "Failed to read want_reply")?;
        offset += 1;
        
        let request = match request_name.as_str() {
            "shell" => ChannelRequest::Shell,
            "exec" => {
                let command = msg.read_string_slice(offset)
                    .ok_or_else(|| "Failed to read command")?;
                let _offset = offset + 4 + command.len();
                ChannelRequest::Exec { command: command.to_string() }
            }
            "pty-req" => {
                let term = msg.read_string_slice(offset)
                    .ok_or_else(|| "Failed to read term")?;
                offset += 4 + term.len();
                
                let width = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read width")?;
                offset += 4;
                
                let height = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read height")?;
                offset += 4;
                
                let pixel_width = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read pixel_width")?;
                offset += 4;
                
                let pixel_height = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read pixel_height")?;
                offset += 4;
                
                let modes = msg.read_string_slice(offset)
                    .ok_or_else(|| "Failed to read modes")?;
                
                ChannelRequest::PseudoTerminal {
                    term: term.to_string(),
                    width,
                    height,
                    pixel_width,
                    pixel_height,
                    modes: modes.to_string(),
                }
            }
            "window-change" => {
                let width = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read width")?;
                offset += 4;
                
                let height = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read height")?;
                offset += 4;
                
                let pixel_width = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read pixel_width")?;
                offset += 4;
                
                let pixel_height = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read pixel_height")?;
                
                ChannelRequest::WindowChange {
                    width,
                    height,
                    pixel_width,
                    pixel_height,
                }
            }
            "signal" => {
                let signal = msg.read_string_slice(offset)
                    .ok_or_else(|| "Failed to read signal")?;
                ChannelRequest::Signal { signal: signal.to_string() }
            }
            "exit-status" => {
                let exit_status = msg.read_uint32(offset)
                    .ok_or_else(|| "Failed to read exit_status")?;
                ChannelRequest::ExitStatus { exit_status }
            }
            "env" => {
                let name = msg.read_string_slice(offset)
                    .ok_or_else(|| "Failed to read name")?;
                offset += 4 + name.len();
                
                let value = msg.read_string_slice(offset)
                    .ok_or_else(|| "Failed to read value")?;
                
                ChannelRequest::Environment {
                    name: name.to_string(),
                    value: value.to_string(),
                }
            }
            "keepalive@openssh.com" => {
                ChannelRequest::KeepAlive(want_reply)
            }
            _ => ChannelRequest::Unknown {
                request: request_name.to_string(),
                want_reply,
            },
        };
        
        Ok((request, want_reply))
    }
}

/// Channel represents an open SSH connection channel
#[derive(Debug, Clone)]
pub struct Channel {
    /// Local channel ID
    pub local_id: ChannelId,
    /// Remote channel ID
    pub remote_id: ChannelId,
    /// Channel type
    pub channel_type: ChannelType,
    /// Window size (bytes we can send)
    pub window_size: u32,
    /// Max packet size
    pub max_packet_size: u32,
}

impl Channel {
    /// Create a new channel
    pub fn new(
        local_id: ChannelId,
        remote_id: ChannelId,
        channel_type: ChannelType,
        window_size: u32,
        max_packet_size: u32,
    ) -> Self {
        Self {
            local_id,
            remote_id,
            channel_type,
            window_size,
            max_packet_size,
        }
    }
    
    /// Create a new session channel with default sizes
    pub fn new_session(local_id: ChannelId, remote_id: ChannelId) -> Self {
        Self {
            local_id,
            remote_id,
            channel_type: ChannelType::Session,
            window_size: 32768,
            max_packet_size: 32768,
        }
    }
    
    /// Get channel type as string
    pub fn channel_type_str(&self) -> &str {
        self.channel_type.as_str()
    }
    
    /// Send data on this channel
    pub fn send_data(&self, data: &[u8]) -> ChannelData {
        ChannelData {
            channel_id: self.local_id,
            data: data.to_vec(),
        }
    }
    
    /// Close this channel
    pub fn close(&self) -> ChannelClose {
        ChannelClose {
            channel_id: self.local_id,
        }
    }
    
    /// Send EOF on this channel
    pub fn send_eof(&self) -> ChannelEof {
        ChannelEof {
            channel_id: self.local_id,
        }
    }
}