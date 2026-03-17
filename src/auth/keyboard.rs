//! Keyboard-interactive authentication (RFC 4256)
//!
//! Implements SSH keyboard-interactive authentication as specified in RFC 4256.
//! This method allows for flexible challenge-response authentication mechanisms.

use crate::error::SshError;
use crate::protocol::message::Message;
use crate::protocol::messages::MessageType;
use crate::transport::Transport;

/// Represents a single challenge in the keyboard-interactive flow
#[derive(Debug, Clone)]
pub struct Challenge {
    /// Challenge name (can be empty)
    pub name: String,
    /// Challenge instruction (can be empty)
    pub instruction: String,
    /// Number of prompts
    pub num_prompts: u32,
    /// Challenge prompts
    pub prompts: Vec<ChallengePrompt>,
}

/// Represents a single prompt within a challenge
#[derive(Debug, Clone)]
pub struct ChallengePrompt {
    /// Prompt text (what the user sees)
    pub prompt: String,
    /// Whether the response should be echoed (for passwords)
    pub echo: bool,
}

/// Keyboard-interactive authentication handler
pub struct KeyboardInteractiveAuthenticator<'a> {
    /// Transport layer for sending messages
    transport: &'a mut Transport,
    /// Username to authenticate as
    username: String,
    /// Service being requested (usually "ssh-connection")
    service: String,
    /// Language tag (usually empty)
    language_tag: String,
}

impl<'a> KeyboardInteractiveAuthenticator<'a> {
    /// Creates a new keyboard-interactive authenticator
    pub fn new(transport: &'a mut Transport, username: String) -> Self {
        Self {
            transport,
            username,
            service: "ssh-connection".to_string(),
            language_tag: String::new(),
        }
    }

    /// Sets the service name
    pub fn with_service(mut self, service: String) -> Self {
        self.service = service;
        self
    }

    /// Sets the language tag
    pub fn with_language_tag(mut self, language_tag: String) -> Self {
        self.language_tag = language_tag;
        self
    }

    /// Starts keyboard-interactive authentication
    ///
    /// This sends the initial request and processes challenges until authentication
    /// succeeds or fails.
    pub async fn authenticate<F>(&mut self, response_handler: F) -> Result<(), SshError>
    where
        F: Fn(&Challenge) -> Result<Vec<String>, SshError>,
    {
        // Send initial keyboard-interactive request
        self.send_auth_request().await?;

        // Process challenges
        loop {
            let response = self.transport.recv_message().await?;
            let msg = Message::from(response);

            match msg.msg_type() {
                Some(MessageType::UserauthSuccess) => {
                    return Ok(());
                }
                Some(MessageType::UserauthFailure) => {
                    let (partial_success, available_methods) = msg.parse_userauth_failure()
                        .unwrap_or((Vec::new(), Vec::new()));
                    
                    return Err(SshError::ProtocolError(format!(
                        "Authentication failed. Partial success: {:?}, Available methods: {:?}",
                        partial_success, available_methods
                    )));
                }
                Some(MessageType::UserauthInfoRequest) => {
                    // Parse the challenge
                    let challenge = self.parse_challenge(&msg)?;
                    
                    // Get responses from the handler
                    let responses = response_handler(&challenge)?;
                    
                    // Send responses
                    self.send_responses(&responses).await?;
                }
                Some(MessageType::UserauthBanner) => {
                    // Handle banner message (display to user)
                    let banner = msg.parse_userauth_banner()
                        .unwrap_or_else(|| String::from("Authentication banner"));
                    eprintln!("Banner: {}", banner);
                }
                Some(msg_type) => {
                    return Err(SshError::ProtocolError(format!(
                        "Unexpected message type during keyboard-interactive auth: {:?}",
                        msg_type
                    )));
                }
                None => {
                    return Err(SshError::ProtocolError(
                        "Invalid message: no message type".to_string()
                    ));
                }
            }
        }
    }

    /// Sends the initial keyboard-interactive authentication request per RFC 4256 Section 3.1
    async fn send_auth_request(&mut self) -> Result<(), SshError> {
        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(self.username.as_bytes());
        msg.write_string(self.service.as_bytes());
        msg.write_string(b"keyboard-interactive");
        msg.write_string(self.language_tag.as_bytes()); // language tag (usually empty)
        msg.write_string(b""); // submethods (usually empty)

        self.transport.send_message(&msg.as_bytes()).await?;
        Ok(())
    }

    /// Parses a UserauthInfoRequest message into a Challenge per RFC 4256 Section 3.3
    fn parse_challenge(&self, msg: &Message) -> Result<Challenge, SshError> {
        let mut offset = 1; // Skip message type

        // Name (can be empty)
        let name_bytes = msg.read_string(offset).ok_or_else(|| {
            SshError::ProtocolError("Failed to read challenge name".to_string())
        })?;
        let name = String::from_utf8_lossy(&name_bytes).to_string();
        offset += 4 + name_bytes.len();

        // Instruction (can be empty)
        let instruction_bytes = msg.read_string(offset).ok_or_else(|| {
            SshError::ProtocolError("Failed to read instruction".to_string())
        })?;
        let instruction = String::from_utf8_lossy(&instruction_bytes).to_string();
        offset += 4 + instruction_bytes.len();

        // Language tag (can be empty, usually is)
        let _lang_bytes = msg.read_string(offset).ok_or_else(|| {
            SshError::ProtocolError("Failed to read language tag".to_string())
        })?;
        offset += 4 + _lang_bytes.len();

        // Number of prompts
        let num_prompts = msg.read_uint32(offset).ok_or_else(|| {
            SshError::ProtocolError("Failed to read number of prompts".to_string())
        })?;
        offset += 4;

        // Prompts
        let mut prompts = Vec::with_capacity(num_prompts as usize);
        for _ in 0..num_prompts {
            // Prompt text
            let prompt_bytes = msg.read_string(offset).ok_or_else(|| {
                SshError::ProtocolError("Failed to read prompt".to_string())
            })?;
            let prompt = String::from_utf8_lossy(&prompt_bytes).to_string();
            offset += 4 + prompt_bytes.len();

            // Echo flag
            let echo = msg.read_bool(offset).ok_or_else(|| {
                SshError::ProtocolError("Failed to read echo flag".to_string())
            })?;
            offset += 1;

            prompts.push(ChallengePrompt { prompt, echo });
        }

        Ok(Challenge {
            name,
            instruction,
            num_prompts,
            prompts,
        })
    }

    /// Sends responses to a challenge per RFC 4256 Section 3.4
    async fn send_responses(&mut self, responses: &[String]) -> Result<(), SshError> {
        let mut msg = Message::new();
        // SSH_MSG_USERAUTH_INFO_RESPONSE = 61
        msg.write_byte(MessageType::UserauthInfoResponse.value());

        // Number of responses
        msg.write_uint32(responses.len() as u32);

        // Each response as SSH string
        for response in responses {
            msg.write_string(response.as_bytes());
        }

        self.transport.send_message(&msg.as_bytes()).await?;
        Ok(())
    }
}

impl Message {
    /// Parses a UserauthBanner message
    pub fn parse_userauth_banner(&self) -> Option<String> {
        let mut offset = 1; // Skip message type

        // Message
        let message_bytes = self.read_string(offset)?;
        offset += 4 + message_bytes.len();

        // Language tag
        let _lang_bytes = self.read_string(offset)?;
        // Language tag is typically not used

        Some(String::from_utf8_lossy(&message_bytes).to_string())
    }
}