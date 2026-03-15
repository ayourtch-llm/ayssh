//! SSH Protocol Messages
//!
//! Defines all SSH protocol message types and their structures.

/// Represents an SSH protocol message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// SSH_MSG_DISCONNECT
    Disconnect = 1,
    /// SSH_MSG_IGNORE
    Ignore = 2,
    /// SSH_MSG_UNIMPLEMENTED
    Unimplemented = 3,
    /// SSH_MSG_DEBUG
    Debug = 4,
    /// SSH_MSG_SERVICE_REQUEST
    ServiceRequest = 5,
    /// SSH_MSG_SERVICE_ACCEPT
    ServiceAccept = 6,
    /// SSH_MSG_KEXINIT
    KexInit = 20,
    /// SSH_MSG_NEWKEYS
    Newkeys = 21,
    /// SSH_MSG_USERAUTH_REQUEST
    UserauthRequest = 50,
    /// SSH_MSG_USERAUTH_FAILURE
    UserauthFailure = 51,
    /// SSH_MSG_USERAUTH_SUCCESS
    UserauthSuccess = 52,
    /// SSH_MSG_USERAUTH_BANNER
    UserauthBanner = 53,
    /// SSH_MSG_USERAUTH_INFO_REQUEST
    UserauthInfoRequest = 60,
    /// SSH_MSG_USERAUTH_INFO_RESPONSE
    UserauthInfoResponse = 61,
    /// SSH_MSG_GLOBAL_REQUEST
    GlobalRequest = 80,
    /// SSH_MSG_REQUEST_SUCCESS
    RequestSuccess = 81,
    /// SSH_MSG_REQUEST_FAILURE
    RequestFailure = 82,
    /// SSH_MSG_CHANNEL_OPEN
    ChannelOpen = 90,
    /// SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    ChannelOpenConfirmation = 91,
    /// SSH_MSG_CHANNEL_OPEN_FAILURE
    ChannelOpenFailure = 92,
    /// SSH_MSG_CHANNEL_WINDOW_ADJUST
    ChannelWindowAdjust = 93,
    /// SSH_MSG_CHANNEL_DATA
    ChannelData = 94,
    /// SSH_MSG_CHANNEL_EXTENDED_DATA
    ChannelExtendedData = 95,
    /// SSH_MSG_CHANNEL_EOF
    ChannelEof = 96,
    /// SSH_MSG_CHANNEL_CLOSE
    ChannelClose = 97,
    /// SSH_MSG_CHANNEL_REQUEST
    ChannelRequest = 98,
    /// SSH_MSG_CHANNEL_SUCCESS
    ChannelSuccess = 99,
    /// SSH_MSG_CHANNEL_FAILURE
    ChannelFailure = 100,
}

impl MessageType {
    /// Get the numeric value of the message type
    pub const fn value(&self) -> u8 {
        match self {
            MessageType::Disconnect => 1,
            MessageType::Ignore => 2,
            MessageType::Unimplemented => 3,
            MessageType::Debug => 4,
            MessageType::ServiceRequest => 5,
            MessageType::ServiceAccept => 6,
            MessageType::KexInit => 20,
            MessageType::Newkeys => 21,
            MessageType::UserauthRequest => 50,
            MessageType::UserauthFailure => 51,
            MessageType::UserauthSuccess => 52,
            MessageType::UserauthBanner => 53,
            MessageType::UserauthInfoRequest => 60,
            MessageType::UserauthInfoResponse => 61,
            MessageType::GlobalRequest => 80,
            MessageType::RequestSuccess => 81,
            MessageType::RequestFailure => 82,
            MessageType::ChannelOpen => 90,
            MessageType::ChannelOpenConfirmation => 91,
            MessageType::ChannelOpenFailure => 92,
            MessageType::ChannelWindowAdjust => 93,
            MessageType::ChannelData => 94,
            MessageType::ChannelExtendedData => 95,
            MessageType::ChannelEof => 96,
            MessageType::ChannelClose => 97,
            MessageType::ChannelRequest => 98,
            MessageType::ChannelSuccess => 99,
            MessageType::ChannelFailure => 100,
        }
    }

    /// Create a message type from its numeric value
    pub const fn from_value(value: u8) -> Option<Self> {
        match value {
            1 => Some(MessageType::Disconnect),
            2 => Some(MessageType::Ignore),
            3 => Some(MessageType::Unimplemented),
            4 => Some(MessageType::Debug),
            5 => Some(MessageType::ServiceRequest),
            6 => Some(MessageType::ServiceAccept),
            20 => Some(MessageType::KexInit),
            21 => Some(MessageType::Newkeys),
            50 => Some(MessageType::UserauthRequest),
            51 => Some(MessageType::UserauthFailure),
            52 => Some(MessageType::UserauthSuccess),
            53 => Some(MessageType::UserauthBanner),
            60 => Some(MessageType::UserauthInfoRequest),
            61 => Some(MessageType::UserauthInfoResponse),
            80 => Some(MessageType::GlobalRequest),
            81 => Some(MessageType::RequestSuccess),
            82 => Some(MessageType::RequestFailure),
            90 => Some(MessageType::ChannelOpen),
            91 => Some(MessageType::ChannelOpenConfirmation),
            92 => Some(MessageType::ChannelOpenFailure),
            93 => Some(MessageType::ChannelWindowAdjust),
            94 => Some(MessageType::ChannelData),
            95 => Some(MessageType::ChannelExtendedData),
            96 => Some(MessageType::ChannelEof),
            97 => Some(MessageType::ChannelClose),
            98 => Some(MessageType::ChannelRequest),
            99 => Some(MessageType::ChannelSuccess),
            100 => Some(MessageType::ChannelFailure),
            _ => None,
        }
    }
}

/// Placeholder for future message encoding/decoding
pub fn encode_message(_msg_type: MessageType, _data: &[u8]) -> Vec<u8> {
    Vec::new()
}

/// Placeholder for future message decoding
pub fn decode_message(_data: &[u8]) -> Option<(MessageType, Vec<u8>)> {
    None
}
