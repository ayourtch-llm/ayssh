//! UnixConn - Simple command execution on Unix/Linux hosts

#![deny(unused_must_use)]

use ssh_client::unix_conn::{UnixConn, ConnectionType, CryptoPrefs};
use std::env;
use tracing::{info, error};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    let args: Vec<String> = env::args().collect();

    // Parse flags
    let mut key_file: Option<String> = None;
    let mut kbd_interactive = false;
    let mut preferred_kex: Option<String> = None;
    let mut preferred_cipher: Option<String> = None;
    let mut preferred_mac: Option<String> = None;
    let mut filtered_args: Vec<String> = Vec::new();
    let mut skip_next = false;

    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--key" {
            if let Some(next) = args.get(i + 1) {
                key_file = Some(next.clone());
                skip_next = true;
            } else {
                eprintln!("Error: --key requires a filename argument");
                std::process::exit(1);
            }
        } else if arg == "--kex" {
            if let Some(next) = args.get(i + 1) {
                preferred_kex = Some(next.clone());
                skip_next = true;
            } else {
                eprintln!("Error: --kex requires an algorithm name");
                std::process::exit(1);
            }
        } else if arg == "--cipher" {
            if let Some(next) = args.get(i + 1) {
                preferred_cipher = Some(next.clone());
                skip_next = true;
            } else {
                eprintln!("Error: --cipher requires an algorithm name");
                std::process::exit(1);
            }
        } else if arg == "--mac" {
            if let Some(next) = args.get(i + 1) {
                preferred_mac = Some(next.clone());
                skip_next = true;
            } else {
                eprintln!("Error: --mac requires an algorithm name");
                std::process::exit(1);
            }
        } else if arg == "--kbd-interactive" {
            kbd_interactive = true;
        } else {
            filtered_args.push(arg.clone());
        }
    }

    let min_args = if key_file.is_some() { 4 } else { 5 };
    if filtered_args.len() < min_args {
        eprintln!("Usage: {} <target> <username> <password> <command>", filtered_args[0]);
        eprintln!("       {} <target> <username> --key <private_key_file> <command>", filtered_args[0]);
        eprintln!("       {} <target> <username> <password> --kbd-interactive <command>", filtered_args[0]);
        eprintln!("");
        eprintln!("Options:");
        eprintln!("  --key <file>        Use RSA public key authentication");
        eprintln!("  --kbd-interactive   Use keyboard-interactive authentication");
        eprintln!("  --kex <name>        Prefer KEX (curve25519-sha256, diffie-hellman-group14-sha256, ...)");
        eprintln!("  --cipher <name>     Prefer cipher (aes128-ctr, aes256-ctr, aes128-cbc, ...)");
        eprintln!("  --mac <name>        Prefer MAC (hmac-sha1, hmac-sha2-256, hmac-sha2-256-etm@openssh.com, ...)");
        eprintln!("");
        eprintln!("Examples:");
        eprintln!("  {} 192.168.1.1 ubuntu password \"uname -a\"", filtered_args[0]);
        eprintln!("  {} 192.168.1.1 ubuntu --key ~/.ssh/id_rsa \"ls -la\"", filtered_args[0]);
        eprintln!("  {} 192.168.1.1 ubuntu password --kbd-interactive \"whoami\"", filtered_args[0]);
        std::process::exit(1);
    }

    let target = &filtered_args[1];
    let username = &filtered_args[2];

    if let Some(ref key_path) = key_file {
        let command = &filtered_args[3];

        info!("=== UnixConn Key-Based Command Execution ===");
        info!("Target: {}", target);
        info!("Username: {}", username);
        info!("Key file: {}", key_path);
        info!("Command: {}", command);
        println!("");

        let private_key = std::fs::read(key_path)
            .map_err(|e| format!("Failed to read private key {}: {}", key_path, e))?;

        let prefs = CryptoPrefs { kex: preferred_kex.clone(), cipher: preferred_cipher.clone(), mac: preferred_mac.clone() };
        let mut conn = UnixConn::new_with_key_and_prefs(target, username, &private_key, prefs).await?;
        println!("Connected with public key authentication!");

        run_commands(&mut conn, command).await?;
    } else {
        let password = &filtered_args[3];
        let command = &filtered_args[4];

        let conn_type = if kbd_interactive {
            ConnectionType::UnixSshKbdInteractive
        } else {
            ConnectionType::UnixSsh
        };
        let auth_label = if kbd_interactive { "keyboard-interactive" } else { "password" };

        info!("=== UnixConn Command Execution ({}) ===", auth_label);
        info!("Target: {}", target);
        info!("Username: {}", username);
        info!("Command: {}", command);
        println!("");

        let prefs = CryptoPrefs { kex: preferred_kex.clone(), cipher: preferred_cipher.clone(), mac: preferred_mac.clone() };
        let mut conn = UnixConn::new_with_prefs(target, conn_type, username, password, prefs).await?;
        println!("Connected with {} authentication!", auth_label);

        run_commands(&mut conn, command).await?;
    }

    info!("=== Execution Complete ===");
    Ok(())
}

async fn run_commands(conn: &mut UnixConn, command: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cmds = command.split(";");
    for ref cmd in cmds {
        let cmd = cmd.trim();
        if cmd.is_empty() {
            continue;
        }
        match conn.run_cmd(cmd).await {
            Ok(output) => {
                println!("\n=== Command Output ===");
                println!("{}", output);
            }
            Err(e) => {
                error!("Error executing command: {}", e);
                eprintln!("\nError executing command: {}", e);
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
