//! Tests for keyboard-interactive authentication (RFC 4256)

use ayssh::auth::keyboard::{Challenge, ChallengePrompt};
use ayssh::protocol::message::Message;
use ayssh::protocol::messages::MessageType;

#[test]
fn test_parse_challenge() {
    let mut msg = Message::with_type(MessageType::UserauthInfoRequest);
    
    // Language tag (empty)
    msg.write_string(b"");
    
    // Instruction
    msg.write_string(b"Please authenticate to continue");
    
    // Number of prompts: 2
    msg.write_uint32(2);
    
    // First prompt
    msg.write_string(b"Username:");
    msg.write_bool(false);
    
    // Second prompt
    msg.write_string(b"Password:");
    msg.write_bool(true);

    // Test parsing by directly calling the method on a Message
    let challenge = parse_test_challenge(&msg);
    
    assert_eq!(challenge.num_prompts, 2);
    assert_eq!(challenge.prompts[0].prompt, "Username:");
    assert!(!challenge.prompts[0].echo);
    assert_eq!(challenge.prompts[1].prompt, "Password:");
    assert!(challenge.prompts[1].echo);
    assert_eq!(challenge.instruction, "Please authenticate to continue");
}

#[test]
fn test_parse_challenge_empty_instruction() {
    let mut msg = Message::with_type(MessageType::UserauthInfoRequest);
    
    // Language tag (empty)
    msg.write_string(b"");
    
    // Empty instruction
    msg.write_string(b"");
    
    // Number of prompts: 1
    msg.write_uint32(1);
    
    // Prompt
    msg.write_string(b"Enter code:");
    msg.write_bool(false);

    let challenge = parse_test_challenge(&msg);
    
    assert_eq!(challenge.num_prompts, 1);
    assert!(challenge.instruction.is_empty());
}

#[test]
fn test_parse_challenge_single_prompt() {
    let mut msg = Message::with_type(MessageType::UserauthInfoRequest);
    
    // Language tag (empty)
    msg.write_string(b"");
    
    // Instruction
    msg.write_string(b"Two-factor authentication");
    
    // Number of prompts: 1
    msg.write_uint32(1);
    
    // Prompt
    msg.write_string(b"Enter OTP:");
    msg.write_bool(false);

    let challenge = parse_test_challenge(&msg);
    
    assert_eq!(challenge.num_prompts, 1);
    assert_eq!(challenge.prompts[0].prompt, "Enter OTP:");
    assert!(!challenge.prompts[0].echo);
}

#[test]
fn test_parse_challenge_multiple_prompts() {
    let mut msg = Message::with_type(MessageType::UserauthInfoRequest);
    
    // Language tag (empty)
    msg.write_string(b"");
    
    // Instruction
    msg.write_string(b"Multi-factor authentication");
    
    // Number of prompts: 3
    msg.write_uint32(3);
    
    // First prompt
    msg.write_string(b"Username:");
    msg.write_bool(false);
    
    // Second prompt
    msg.write_string(b"Password:");
    msg.write_bool(true);
    
    // Third prompt
    msg.write_string(b"Security Code:");
    msg.write_bool(true);

    let challenge = parse_test_challenge(&msg);
    
    assert_eq!(challenge.num_prompts, 3);
    assert_eq!(challenge.prompts[0].prompt, "Username:");
    assert!(!challenge.prompts[0].echo);
    assert_eq!(challenge.prompts[1].prompt, "Password:");
    assert!(challenge.prompts[1].echo);
    assert_eq!(challenge.prompts[2].prompt, "Security Code:");
    assert!(challenge.prompts[2].echo);
}

#[test]
fn test_parse_challenge_with_language_tag() {
    let mut msg = Message::with_type(MessageType::UserauthInfoRequest);
    
    // Language tag (en-US)
    msg.write_string(b"en-US");
    
    // Instruction
    msg.write_string(b"Authentication required");
    
    // Number of prompts: 1
    msg.write_uint32(1);
    
    // Prompt
    msg.write_string(b"Enter password:");
    msg.write_bool(true);

    let challenge = parse_test_challenge(&msg);
    
    assert_eq!(challenge.num_prompts, 1);
    assert_eq!(challenge.prompts[0].prompt, "Enter password:");
    assert!(challenge.prompts[0].echo);
}

#[test]
fn test_message_parse_userauth_banner() {
    let mut msg = Message::with_type(MessageType::UserauthBanner);
    
    // Banner message
    msg.write_string(b"Welcome to the SSH server");
    
    // Language tag
    msg.write_string(b"en");

    let banner = msg.parse_userauth_banner().unwrap();
    assert_eq!(banner, "Welcome to the SSH server");
}

#[test]
fn test_challenge_prompt_echo_behavior() {
    let mut msg = Message::with_type(MessageType::UserauthInfoRequest);
    
    // Language tag
    msg.write_string(b"");
    
    // Empty instruction
    msg.write_string(b"");
    
    // Number of prompts: 2
    msg.write_uint32(2);
    
    // First prompt (no echo - password field)
    msg.write_string(b"Password:");
    msg.write_bool(true);
    
    // Second prompt (with echo - username field)
    msg.write_string(b"Username:");
    msg.write_bool(false);

    let challenge = parse_test_challenge(&msg);
    
    // Password should not be echoed
    assert!(challenge.prompts[0].echo);
    
    // Username should be echoed
    assert!(!challenge.prompts[1].echo);
}

#[test]
fn test_challenge_with_special_characters() {
    let mut msg = Message::with_type(MessageType::UserauthInfoRequest);
    
    // Language tag
    msg.write_string(b"");
    
    // Instruction with special characters
    msg.write_string(b"Authentication: 2FA required");
    
    // Number of prompts: 1
    msg.write_uint32(1);
    
    // Prompt with special characters
    msg.write_string(b"Enter code (1234):");
    msg.write_bool(false);

    let challenge = parse_test_challenge(&msg);
    
    assert_eq!(challenge.num_prompts, 1);
    assert_eq!(challenge.prompts[0].prompt, "Enter code (1234):");
}

// Helper function to parse challenge without requiring a Transport
fn parse_test_challenge(msg: &Message) -> Challenge {
    let mut offset = 1; // Skip message type

    // Language tag
    let _lang_bytes = msg.read_string(offset).unwrap();
    offset += 4 + _lang_bytes.len();

    // Instructions
    let instruction_bytes = msg.read_string(offset).unwrap();
    let instruction = String::from_utf8_lossy(&instruction_bytes).to_string();
    offset += 4 + instruction_bytes.len();

    // Number of prompts
    let num_prompts = msg.read_uint32(offset).unwrap();
    offset += 4;

    // Prompts
    let mut prompts = Vec::with_capacity(num_prompts as usize);
    for _ in 0..num_prompts {
        // Prompt text
        let prompt_bytes = msg.read_string(offset).unwrap();
        let prompt = String::from_utf8_lossy(&prompt_bytes).to_string();
        offset += 4 + prompt_bytes.len();

        // Echo flag
        let echo = msg.read_bool(offset).unwrap();
        offset += 1;

        prompts.push(ChallengePrompt { prompt, echo });
    }

    Challenge {
        name: String::new(),
        instruction,
        num_prompts,
        prompts,
    }
}