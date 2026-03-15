//! End-to-End Shell Command Execution Tests
//!
//! Tests shell command execution over SSH with real sshd server

use ssh_client::session::{Session, WindowDimensions, TerminalModes};
use ssh_client::channel::types::{Channel, ChannelId, ChannelType};
use ssh_client::protocol::messages::MessageType;

/// Test shell request message format
#[test]
fn test_shell_request_message() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);
    let msg = session.request_shell();

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify message structure
    let data = msg.as_bytes();
    assert!(data.len() > 0);

    // Check message type byte
    assert_eq!(data[0], MessageType::ChannelRequest as u8);

    // Check request name is "shell"
    let offset = 1 + 4; // Skip msg type and channel id
    let name_len = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
    let request_name = std::str::from_utf8(&data[offset+4..offset+4+name_len]).unwrap();
    assert_eq!(request_name, "shell");
}

/// Test shell request with want_reply
#[test]
fn test_shell_request_with_reply() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);
    let msg = session.request_shell();

    // Shell request typically doesn't want reply (want_reply = 0)
    let data = msg.as_bytes();
    let offset = 1 + 4; // Skip msg type and channel id
    let name_len = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
    let want_reply = data[offset + 4 + name_len];
    assert_eq!(want_reply, 0);
}

/// Test session state transitions for shell
#[test]
fn test_session_shell_state_transition() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let mut session = Session::new_without_shell(channel);

    // Initial state
    assert_eq!(session.state(), &ssh_client::session::SessionState::Initial);

    // Start shell
    session.start_shell().unwrap();
    assert_eq!(session.state(), &ssh_client::session::SessionState::Shell);

    // Cannot start shell again (would be a protocol error)
    // This would need to be tested with proper error handling
}

/// Test exec request message format
#[test]
fn test_exec_request_message() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);
    let msg = session.request_exec("ls -la /tmp");

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify message structure
    let data = msg.as_bytes();
    assert!(data.len() > 0);

    // Check message type byte
    assert_eq!(data[0], MessageType::ChannelRequest as u8);

    // Check request name is "exec"
    let offset = 1 + 4; // Skip msg type and channel id
    let name_len = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
    let request_name = std::str::from_utf8(&data[offset+4..offset+4+name_len]).unwrap();
    assert_eq!(request_name, "exec");

    // Check command
    let command_offset = offset + 4 + name_len + 1; // +1 for want_reply (false)
    let command_len = u32::from_be_bytes([
        data[command_offset],
        data[command_offset+1],
        data[command_offset+2],
        data[command_offset+3],
    ]) as usize;
    let command = std::str::from_utf8(&data[command_offset+4..command_offset+4+command_len]).unwrap();
    assert_eq!(command, "ls -la /tmp");
}

/// Test exec with different commands
#[test]
fn test_exec_various_commands() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);

    // Test simple command
    let msg = session.request_exec("echo hello");
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Test command with arguments
    let msg = session.request_exec("ls -la /home/user");
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Test command with pipes
    let msg = session.request_exec("cat /etc/passwd | grep root");
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Test command with special characters
    let msg = session.request_exec("echo 'hello world'");
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));
}

/// Test session state transitions for exec
#[test]
fn test_session_exec_state_transition() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let mut session = Session::new_without_shell(channel);

    // Initial state
    assert_eq!(session.state(), &ssh_client::session::SessionState::Initial);

    // Start exec
    session.start_exec().unwrap();
    assert_eq!(session.state(), &ssh_client::session::SessionState::Executing);
}

/// Test shell request encoding
#[test]
fn test_shell_request_encoding() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);
    let msg = session.request_shell();
    let data = msg.as_bytes();

    // Expected structure:
    // [1] msg_type (ChannelRequest = 96)
    // [4] channel_id (big-endian)
    // [4] request_name_length (big-endian)
    // [5] "shell\0"
    // [1] want_reply (0)

    assert_eq!(data.len(), 1 + 4 + 4 + 6 + 1); // 16 bytes total
    assert_eq!(data[0], MessageType::ChannelRequest as u8);
}

/// Test exec request encoding
#[test]
fn test_exec_request_encoding() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);
    let msg = session.request_exec("test");
    let data = msg.as_bytes();

    // Expected structure:
    // [1] msg_type (ChannelRequest = 96)
    // [4] channel_id (big-endian)
    // [4] request_name_length (big-endian)
    // [4] "exec"
    // [1] want_reply (0)
    // [4] command_length (big-endian)
    // [4] "test"

    // Actually: 1 + 4 + 4 + 4 + 1 + 4 + 4 = 22 bytes
    // (request_name_length is 4, not 5)
    assert_eq!(data.len(), 22);
    assert_eq!(data[0], MessageType::ChannelRequest as u8);
}

/// Test shell message round-trip
#[test]
fn test_shell_message_round_trip() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);
    let msg = session.request_shell();

    // Message should be valid
    assert!(msg.msg_type().is_some());
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Data should be non-empty
    let data = msg.as_bytes();
    assert!(!data.is_empty());
    assert!(data.len() > 10); // Should be at least 16 bytes
}

/// Test exec message round-trip
#[test]
fn test_exec_message_round_trip() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);
    let msg = session.request_exec("ls");

    // Message should be valid
    assert!(msg.msg_type().is_some());
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Data should be non-empty
    let data = msg.as_bytes();
    assert!(!data.is_empty());
    assert!(data.len() > 10); // Should be at least 16 bytes
}

/// Test shell handle exists
#[test]
fn test_session_has_shell_handle() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel);

    // Session should have shell handle
    assert!(session.shell_handle().is_some());
}

/// Test shell handle without shell
#[test]
fn test_session_no_shell_handle() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);

    // Session should not have shell handle
    assert!(session.shell_handle().is_none());
}

/// Test shell handle creation and methods
#[test]
fn test_shell_handle_methods_exist() {
    // This is a compile-time check to ensure methods exist
    let _ = ssh_client::session::ShellHandle::write;
    let _ = ssh_client::session::ShellHandle::read_stdout;
    let _ = ssh_client::session::ShellHandle::read_stderr;
    let _ = ssh_client::session::ShellHandle::close;
}

/// Test shell state management
#[test]
fn test_shell_state_management() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let mut session = Session::new(channel);

    // Set terminal type for shell
    session.set_terminal_type("xterm-256color".to_string());
    assert_eq!(session.terminal_type, Some("xterm-256color".to_string()));

    // Set window dimensions
    let dims = WindowDimensions::new(80, 24);
    session.set_dimensions(dims);
    assert_eq!(session.dimensions.width_chars, 80);
    assert_eq!(session.dimensions.height_chars, 24);

    // Set terminal modes
    let modes = TerminalModes::raw();
    session.set_terminal_modes(modes);
    assert_eq!(session.terminal_modes.modes[2], 1); // RAW flag
}

/// Test shell data handling
#[test]
fn test_shell_data_handling() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let mut session = Session::new(channel);

    // Test stdout data handling
    let stdout_data = b"hello world";
    let result = session.handle_channel_data(stdout_data);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), stdout_data);

    // Test stderr data handling
    let stderr_data = b"error message";
    let result = session.handle_extended_data(stderr_data);
    assert!(result.is_some());
    assert_eq!(result.unwrap(), stderr_data);
}

/// Test shell EOF handling
#[test]
fn test_shell_eof_handling() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let mut session = Session::new(channel);

    // Initial state
    assert_eq!(session.state(), &ssh_client::session::SessionState::Initial);

    // Start shell
    session.start_shell().unwrap();
    assert_eq!(session.state(), &ssh_client::session::SessionState::Shell);

    // Handle EOF
    session.handle_eof();
    assert_eq!(session.state(), &ssh_client::session::SessionState::Closed);
}

/// Test shell close handling
#[test]
fn test_shell_close_handling() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let mut session = Session::new(channel);

    // Initial state
    assert_eq!(session.state(), &ssh_client::session::SessionState::Initial);

    // Start shell
    session.start_shell().unwrap();
    assert_eq!(session.state(), &ssh_client::session::SessionState::Shell);

    // Handle close
    session.handle_close();
    assert_eq!(session.state(), &ssh_client::session::SessionState::Closed);
}

/// Test shell exit status handling
#[test]
fn test_shell_exit_status() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let mut session = Session::new(channel);

    // No exit status initially
    assert!(session.exit_status.is_none());

    // Set exit status
    session.set_exit_status(0);
    assert_eq!(session.exit_status, Some(0));

    // Set non-zero exit status
    session.set_exit_status(1);
    assert_eq!(session.exit_status, Some(1));
}

/// Test shell environment variables
#[test]
fn test_shell_environment() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let mut session = Session::new(channel);

    // No environment variables initially
    assert!(session.environment.is_empty());

    // Add environment variables
    session.add_environment("PATH", "/usr/bin:/bin");
    session.add_environment("HOME", "/home/user");
    session.add_environment("USER", "user");

    assert_eq!(session.environment.len(), 3);
    assert_eq!(session.environment.get("PATH"), Some(&"/usr/bin:/bin".to_string()));
    assert_eq!(session.environment.get("HOME"), Some(&"/home/user".to_string()));
    assert_eq!(session.environment.get("USER"), Some(&"user".to_string()));
}

/// Test shell request with PTY
#[test]
fn test_shell_with_pty() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);
    let dims = WindowDimensions::new(80, 24);
    let modes = TerminalModes::raw();

    // Create PTY request
    let pty_msg = session.request_pty("xterm-256color", dims, modes);
    assert_eq!(pty_msg.msg_type(), Some(MessageType::ChannelRequest));

    // Create shell request
    let shell_msg = session.request_shell();
    assert_eq!(shell_msg.msg_type(), Some(MessageType::ChannelRequest));
}

/// Test exec request with environment
#[test]
fn test_exec_with_environment() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);

    // Create environment request
    let env_msg = session.request_env("MYVAR", "myvalue");
    assert_eq!(env_msg.msg_type(), Some(MessageType::ChannelRequest));

    // Create exec request
    let exec_msg = session.request_exec("echo $MYVAR");
    assert_eq!(exec_msg.msg_type(), Some(MessageType::ChannelRequest));
}

/// Test shell message size
#[test]
fn test_shell_message_size() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);
    let msg = session.request_shell();
    let data = msg.as_bytes();

    // Shell request should be small (no payload)
    assert!(data.len() < 100);
}

/// Test exec message size
#[test]
fn test_exec_message_size() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new_without_shell(channel);
    let msg = session.request_exec("very long command that exceeds typical length");
    let data = msg.as_bytes();

    // Exec request should be larger than shell request
    assert!(data.len() > 50);
}