//! Interactive SSH Shell Server
//!
//! Spawns a command (default: user's shell) when a client connects
//! and proxies I/O between the SSH channel and the process.
//!
//! Usage:
//!   cargo run --example shell_server -- --command /bin/bash
//!   cargo run --example shell_server -- --command "python3 -i"
//!
//! Connect with:
//!   ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
//!       -p 2222 anyuser@127.0.0.1

#![deny(unused_must_use)]

use ayssh::server::{TestSshServer, AlgorithmFilter, HostKeyPair};
use ayssh::server::encrypted_io::ServerEncryptedIO;
use ayssh::error::SshError;

use bytes::{BufMut, BytesMut};
use std::env;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tracing::{info, error, debug};
use tracing_subscriber;

/// Translate bare LF (0x0A) to CR+LF (0x0D 0x0A) for terminal display.
/// Without a real PTY, child processes output bare LF which the SSH
/// client's terminal doesn't handle correctly.
fn translate_lf_to_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 10);
    for &b in data {
        if b == 0x0A {
            // Only add CR if previous byte wasn't already CR
            if out.last() != Some(&0x0D) {
                out.push(0x0D);
            }
        }
        out.push(b);
    }
    out
}

/// Proxy data between SSH channel and a spawned process
async fn run_shell(
    io: &mut ServerEncryptedIO,
    client_channel: u32,
    cmd: &str,
) -> Result<(), SshError> {
    // Parse command into program and args
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let (program, args) = parts.split_first()
        .ok_or_else(|| SshError::ProtocolError("Empty command".to_string()))?;

    info!("Spawning: {} {:?}", program, args);

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| SshError::ProtocolError(format!("Failed to spawn {}: {}", cmd, e)))?;

    let mut child_stdin = child.stdin.take().unwrap();
    let mut child_stdout = child.stdout.take().unwrap();
    let mut child_stderr = child.stderr.take().unwrap();

    // Buffer for reading from child stdout/stderr
    let mut stdout_buf = vec![0u8; 4096];
    let mut stderr_buf = vec![0u8; 4096];

    loop {
        tokio::select! {
            // Read from child stdout → send as SSH channel data
            result = child_stdout.read(&mut stdout_buf) => {
                match result {
                    Ok(0) => {
                        debug!("Child stdout closed");
                        break;
                    }
                    Ok(n) => {
                        // Translate bare LF → CR+LF for proper terminal display
                        // (without a real PTY, the child sends bare LF)
                        let output = translate_lf_to_crlf(&stdout_buf[..n]);
                        let mut msg = BytesMut::new();
                        msg.put_u8(94); // SSH_MSG_CHANNEL_DATA
                        msg.put_u32(client_channel);
                        msg.put_u32(output.len() as u32);
                        msg.put_slice(&output);
                        io.send_message(&msg).await?;
                    }
                    Err(e) => {
                        debug!("Child stdout error: {}", e);
                        break;
                    }
                }
            }

            // Read from child stderr → send as SSH channel extended data (type 1 = stderr)
            result = child_stderr.read(&mut stderr_buf) => {
                match result {
                    Ok(0) => {} // stderr closed, don't break - stdout might still have data
                    Ok(n) => {
                        let output = translate_lf_to_crlf(&stderr_buf[..n]);
                        let mut msg = BytesMut::new();
                        msg.put_u8(95); // SSH_MSG_CHANNEL_EXTENDED_DATA
                        msg.put_u32(client_channel);
                        msg.put_u32(1); // data_type = SSH_EXTENDED_DATA_STDERR
                        msg.put_u32(output.len() as u32);
                        msg.put_slice(&output);
                        io.send_message(&msg).await?;
                    }
                    Err(_) => {}
                }
            }

            // Read from SSH channel → write to child stdin
            result = io.recv_message() => {
                match result {
                    Ok(msg) => {
                        if msg.is_empty() { continue; }
                        match msg[0] {
                            94 => {
                                // SSH_MSG_CHANNEL_DATA
                                if msg.len() > 9 {
                                    let data_len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
                                    if msg.len() >= 9 + data_len {
                                        let data = &msg[9..9 + data_len];
                                        // Translate CR → LF (SSH client sends CR for Enter,
                                        // but child process on pipes expects LF)
                                        let translated: Vec<u8> = data.iter()
                                            .map(|&b| if b == 0x0D { 0x0A } else { b })
                                            .collect();
                                        if child_stdin.write_all(&translated).await.is_err() {
                                            debug!("Child stdin closed");
                                            break;
                                        }
                                    }
                                }
                            }
                            96 => {
                                // SSH_MSG_CHANNEL_EOF
                                debug!("Received SSH channel EOF");
                                drop(child_stdin);
                                // Don't break - let child finish producing output
                                // Create a dummy stdin so the select doesn't try to write
                                break;
                            }
                            97 => {
                                // SSH_MSG_CHANNEL_CLOSE
                                debug!("Received SSH channel CLOSE");
                                break;
                            }
                            93 => {
                                // SSH_MSG_CHANNEL_WINDOW_ADJUST - ignore
                            }
                            _ => {
                                debug!("Received message type {} during shell session", msg[0]);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("SSH recv error: {}", e);
                        break;
                    }
                }
            }

            // Wait for child to exit
            result = child.wait() => {
                match result {
                    Ok(status) => {
                        info!("Child exited with: {}", status);
                    }
                    Err(e) => {
                        debug!("Child wait error: {}", e);
                    }
                }
                break;
            }
        }
    }

    // Send remaining stdout data
    loop {
        match child_stdout.read(&mut stdout_buf).await {
            Ok(0) => break,
            Ok(n) => {
                let mut msg = BytesMut::new();
                msg.put_u8(94);
                msg.put_u32(client_channel);
                msg.put_u32(n as u32);
                msg.put_slice(&stdout_buf[..n]);
                let _ = io.send_message(&msg).await;
            }
            Err(_) => break,
        }
    }

    // Send exit status, EOF, CLOSE
    // SSH_MSG_CHANNEL_REQUEST "exit-status"
    let exit_code = child.try_wait().ok().flatten().map(|s| s.code().unwrap_or(1) as u32).unwrap_or(0);
    let mut exit_msg = BytesMut::new();
    exit_msg.put_u8(98); // SSH_MSG_CHANNEL_REQUEST
    exit_msg.put_u32(client_channel);
    let req_type = b"exit-status";
    exit_msg.put_u32(req_type.len() as u32);
    exit_msg.put_slice(req_type);
    exit_msg.put_u8(0); // want_reply = false
    exit_msg.put_u32(exit_code);
    let _ = io.send_message(&exit_msg).await;

    let mut eof = BytesMut::new();
    eof.put_u8(96);
    eof.put_u32(client_channel);
    let _ = io.send_message(&eof).await;

    let mut close = BytesMut::new();
    close.put_u8(97);
    close.put_u32(client_channel);
    let _ = io.send_message(&close).await;

    info!("Shell session ended (exit code {})", exit_code);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    let args: Vec<String> = env::args().collect();

    let mut port: u16 = 2222;
    let mut command: Option<String> = None;
    let mut host_key_file: Option<String> = None;
    let mut skip_next = false;

    for (i, arg) in args.iter().enumerate() {
        if skip_next { skip_next = false; continue; }
        match arg.as_str() {
            "--port" => {
                if let Some(v) = args.get(i + 1) {
                    port = v.parse().expect("Invalid port");
                    skip_next = true;
                }
            }
            "--command" | "-c" => {
                if let Some(v) = args.get(i + 1) {
                    command = Some(v.clone());
                    skip_next = true;
                }
            }
            "--host-key" => {
                if let Some(v) = args.get(i + 1) {
                    host_key_file = Some(v.clone());
                    skip_next = true;
                }
            }
            "--help" | "-h" => {
                eprintln!("Usage: {} [OPTIONS]", args[0]);
                eprintln!("");
                eprintln!("Interactive SSH shell server.");
                eprintln!("");
                eprintln!("Options:");
                eprintln!("  --port <N>        Listen port (default: 2222)");
                eprintln!("  -c, --command <cmd>  Command to spawn (default: $SHELL or /bin/sh)");
                eprintln!("  --host-key <file> RSA host key (default: generate Ed25519)");
                eprintln!("");
                eprintln!("Examples:");
                eprintln!("  {} -c /bin/bash", args[0]);
                eprintln!("  {} -c 'python3 -i' --port 3333", args[0]);
                eprintln!("  {} -c /usr/bin/top", args[0]);
                std::process::exit(0);
            }
            _ => {}
        }
    }

    let cmd = command.unwrap_or_else(|| {
        env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
    });

    let host_key = if let Some(ref path) = host_key_file {
        HostKeyPair::load_openssh_rsa(std::path::Path::new(path))?
    } else {
        HostKeyPair::generate_ed25519()
    };

    let server = TestSshServer::new(port).await?
        .with_host_key(host_key)
        .with_filter(AlgorithmFilter::default());

    let addr = server.local_addr();
    println!("=== ayssh Shell Server ===");
    println!("Listening on {}", addr);
    println!("Command: {}", cmd);
    println!("");
    println!("Connect with:");
    println!("  ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\");
    println!("      -p {} anyuser@127.0.0.1", addr.port());
    println!("");

    loop {
        info!("Waiting for connection...");
        match server.accept_stream().await {
            Ok(stream) => {
                let cmd = cmd.clone();
                // Handle each connection
                match server.handshake_and_auth(stream).await {
                    Ok((mut io, channel)) => {
                        match run_shell(&mut io, channel, &cmd).await {
                            Ok(()) => info!("Session completed"),
                            Err(e) => error!("Shell error: {}", e),
                        }
                    }
                    Err(e) => error!("Handshake error: {}", e),
                }
            }
            Err(e) => error!("Accept error: {}", e),
        }
    }
}
