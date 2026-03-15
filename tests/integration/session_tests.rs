//! Session Management Integration Tests (RFC 4254)

use ssh_client::session::{Session, WindowDimensions, TerminalModes, TerminalMode, ReadUint32};
use ssh_client::channel::types::{Channel, ChannelId, ChannelType};
use ssh_client::protocol::messages::MessageType;

#[test]
fn test_window_dimensions_creation() {
    // Test default dimensions
    let dims = ssh_client::session::WindowDimensions::default_terminal();
    assert_eq!(dims.width_chars, 80);
    assert_eq!(dims.height_chars, 24);
    assert_eq!(dims.width_pixels, 0);
    assert_eq!(dims.height_pixels, 0);

    // Test custom dimensions
    let dims = ssh_client::session::WindowDimensions::new(120, 40);
    assert_eq!(dims.width_chars, 120);
    assert_eq!(dims.height_chars, 40);

    // Test with pixels
    let dims = ssh_client::session::WindowDimensions::with_pixels(120, 40, 960, 800);
    assert_eq!(dims.width_chars, 120);
    assert_eq!(dims.height_chars, 40);
    assert_eq!(dims.width_pixels, 960);
    assert_eq!(dims.height_pixels, 800);
}

#[test]
fn test_window_dimensions_encode() {
    let dims = WindowDimensions::new(120, 40);
    let msg = dims.encode();

    // Verify encoding
    assert_eq!(msg.read_uint32(0), Some(120));
    assert_eq!(msg.read_uint32(4), Some(40));
    assert_eq!(msg.read_uint32(8), Some(0));
    assert_eq!(msg.read_uint32(12), Some(0));
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
    // RAW flag is at index 2
    assert_eq!(modes.modes[2], 1);
}

#[test]
fn test_terminal_mode_struct() {
    let mode = TerminalMode {
        term: 0,
        echo: 0,
        raw: 1,
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
    };

    let encoded = mode.encode();
    assert_eq!(encoded.len(), 40);
    assert_eq!(encoded[2], 1); // RAW flag
}

#[test]
fn test_session_request_pty() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel.clone());
    let dims = WindowDimensions::new(80, 24);
    let modes = TerminalModes::raw();

    let msg = session.request_pty("xterm-256color", dims, modes);

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify request name
    let offset = 1 + 4; // Skip msg type and channel id
    let request_name = msg.read_string_slice(offset).unwrap();
    assert_eq!(request_name, "pty-req");
}

#[test]
fn test_session_request_shell() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel.clone());
    let msg = session.request_shell();

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify request name
    let offset = 1 + 4; // Skip msg type and channel id
    let request_name = msg.read_string_slice(offset).unwrap();
    assert_eq!(request_name, "shell");
}

#[test]
fn test_session_request_exec() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel.clone());
    let msg = session.request_exec("ls -la");

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Message structure:
    // byte: message type (1)
    // uint32: channel_id (4)
    // string: "exec" (4 + 4)
    // boolean: want_reply (1)
    // string: "ls -la" (4 + 6)
    
    // Command starts at offset: 1 + 4 + 8 + 1 = 14
    let command_offset = 14;
    let command = msg.read_string_slice(command_offset).unwrap();
    assert_eq!(command, "ls -la");
}

#[test]
fn test_session_request_subsystem() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel.clone());
    let msg = session.request_subsystem("sftp");

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Message structure:
    // byte: message type (1)
    // uint32: channel_id (4)
    // string: "subsystem" (4 + 9)
    // boolean: want_reply (1)
    // string: "sftp" (4 + 4)
    
    // Subsystem starts at offset: 1 + 4 + 13 + 1 = 19
    let subsystem_offset = 19;
    let subsystem = msg.read_string_slice(subsystem_offset).unwrap();
    assert_eq!(subsystem, "sftp");
}

#[test]
fn test_session_request_x11() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel.clone());
    let msg = session.request_x11(false, "X11-AUTH-METHOD-1", "00:11:22:33:44:55", 0);

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify request name
    let offset = 1 + 4; // Skip msg type and channel id
    let request_name = msg.read_string_slice(offset).unwrap();
    assert_eq!(request_name, "x11-req");
}

#[test]
fn test_session_request_env() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel.clone());
    let msg = session.request_env("PATH", "/usr/bin:/bin");

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Message structure:
    // byte: message type (1)
    // uint32: channel_id (4)
    // string: "env" (4 + 3)
    // boolean: want_reply (1)
    // string: "PATH" (4 + 4)
    // string: "/usr/bin:/bin" (4 + 13)
    
    // Name starts at offset: 1 + 4 + 7 + 1 = 13
    let name_offset = 13;
    let name = msg.read_string_slice(name_offset).unwrap();
    assert_eq!(name, "PATH");

    // Value starts at offset: 13 + 4 + 4 = 21
    let value_offset = 21;
    let value = msg.read_string_slice(value_offset).unwrap();
    assert_eq!(value, "/usr/bin:/bin");
}

#[test]
fn test_session_send_signal() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel.clone());
    let msg = session.send_signal("SIGINT");

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify request name - offset after channel_id (4 bytes)
    let request_offset = 1 + 4; // Skip msg type and channel id
    let request_name = msg.read_string_slice(request_offset).unwrap();
    assert_eq!(request_name, "signal");
    
    // Calculate signal offset: after request_name string and want_reply (1 byte)
    let name_len = request_name.len();
    let signal_offset = request_offset + 4 + name_len + 1;
    let signal = msg.read_string_slice(signal_offset).unwrap();
    assert_eq!(signal, "SIGINT");
}

#[test]
fn test_session_notify_window_change() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel.clone());
    let dims = WindowDimensions::new(120, 40);
    let msg = session.notify_window_change(dims);

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify request name
    let offset = 1 + 4; // Skip msg type and channel id
    let request_name = msg.read_string_slice(offset).unwrap();
    assert_eq!(request_name, "window-change");

    // Verify dimensions
    let dims_offset = offset + 4 + request_name.len() + 1; // +1 for want_reply (false)
    assert_eq!(msg.read_uint32(dims_offset), Some(120));
    assert_eq!(msg.read_uint32(dims_offset + 4), Some(40));
}

#[test]
fn test_session_send_exit_status() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel.clone());
    let msg = session.send_exit_status(0);

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify request name
    let offset = 1 + 4; // Skip msg type and channel id
    let request_name = msg.read_string_slice(offset).unwrap();
    assert_eq!(request_name, "exit-status");

    // Verify exit status
    let status_offset = offset + 4 + request_name.len() + 1; // +1 for want_reply (false)
    assert_eq!(msg.read_uint32(status_offset), Some(0));
}

#[test]
fn test_session_send_keepalive() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel.clone());
    let msg = session.send_keepalive(false);

    // Verify message type
    assert_eq!(msg.msg_type(), Some(MessageType::ChannelRequest));

    // Verify request name
    let offset = 1 + 4; // Skip msg type and channel id
    let request_name = msg.read_string_slice(offset).unwrap();
    assert_eq!(request_name, "keepalive@openssh.com");
}

#[test]
fn test_session_methods() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let mut session = Session::new(channel.clone());

    // Test set_terminal_type
    session.set_terminal_type("xterm-256color".to_string());
    assert_eq!(session.terminal_type, Some("xterm-256color".to_string()));

    // Test set_dimensions
    let dims = WindowDimensions::new(120, 40);
    session.set_dimensions(dims.clone());
    assert_eq!(session.dimensions, dims);

    // Test set_terminal_modes
    let modes = TerminalModes::raw();
    session.set_terminal_modes(modes.clone());
    assert_eq!(session.terminal_modes, modes);

    // Test add_environment
    session.add_environment("PATH", "/usr/bin");
    assert_eq!(session.environment.len(), 1);
    assert_eq!(session.environment.get("PATH"), Some(&"/usr/bin".to_string()));

    // Test set_exit_status
    session.set_exit_status(0);
    assert_eq!(session.exit_status, Some(0));
}

#[test]
fn test_session_request_encode_all() {
    let channel = Channel::new(
        ChannelId::new(1),
        ChannelId::new(100),
        ChannelType::Session,
        65536,
        32768,
    );

    let session = Session::new(channel.clone());
    let dims = WindowDimensions::new(80, 24);
    let modes = TerminalModes::default();

    // Test all request types encode correctly
    let dims = WindowDimensions::new(80, 24);
    let modes = TerminalModes::default();
    let _pty_msg = session.request_pty("xterm", dims.clone(), modes);
    let _shell_msg = session.request_shell();
    let _exec_msg = session.request_exec("ls");
    let _subsystem_msg = session.request_subsystem("sftp");
    let _x11_msg = session.request_x11(false, "protocol", "cookie", 0);
    let _env_msg = session.request_env("VAR", "value");
    let _signal_msg = session.send_signal("SIGINT");
    let _window_msg = session.notify_window_change(dims);
    let _exit_msg = session.send_exit_status(0);
    let _keepalive_msg = session.send_keepalive(false);

    // All should encode without panic
}