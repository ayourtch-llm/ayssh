//! CiscoConn - Simple command execution example
//!
//! Supports both password and RSA public key authentication.

#![deny(unused_must_use)]

use ssh_client::cisco_conn::{CiscoConn, ConnectionType};
use std::env;
use std::path::Path;
use tracing::{info, error};
use tracing_subscriber;

/// Format a public key file for Cisco IOS `key-string` configuration.
/// Returns the IOS CLI commands needed to install the key.
fn format_ios_pubkey_commands(username: &str, pub_key_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let pub_key_content = std::fs::read_to_string(pub_key_path)?;
    let parts: Vec<&str> = pub_key_content.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err("Invalid public key format".into());
    }
    let key_type = parts[0];
    let key_base64 = parts[1];
    let _comment = parts.get(2).unwrap_or(&"");

    // Cisco IOS key-string accepts the base64 data in lines of up to 254 chars
    // (typically 72 chars per line for readability)
    let mut key_lines = String::new();
    for chunk in key_base64.as_bytes().chunks(72) {
        key_lines.push_str("    ");
        key_lines.push_str(std::str::from_utf8(chunk).unwrap());
        key_lines.push('\n');
    }

    Ok(format!(
        r#"
=== Cisco IOS Public Key Installation ===
Key type: {key_type}
Key file: {pub_key_path}

Paste the following commands on the Cisco device:

  configure terminal
  ip ssh pubkey-chain
   username {username}
    key-string
{key_lines}    exit
   exit
  exit

"#
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber with RUST_LOG support
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    // Check for --key flag
    let mut key_file: Option<String> = None;
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
        } else {
            filtered_args.push(arg.clone());
        }
    }

    let min_args = if key_file.is_some() { 4 } else { 5 };
    if filtered_args.len() < min_args {
        eprintln!("Usage: {} <target> <username> <password> <command>", filtered_args[0]);
        eprintln!("       {} <target> <username> --key <private_key_file> <command>", filtered_args[0]);
        eprintln!("");
        eprintln!("Options:");
        eprintln!("  --key <file>  Use RSA public key authentication (private key in OpenSSH format)");
        eprintln!("");
        eprintln!("Examples:");
        eprintln!("  # Password auth:");
        eprintln!("  {} 192.168.1.1 admin password \"show version\"", filtered_args[0]);
        eprintln!("");
        eprintln!("  # Key auth:");
        eprintln!("  {} 192.168.1.1 admin --key ~/.ssh/id_rsa \"show version\"", filtered_args[0]);
        std::process::exit(1);
    }

    let target = &filtered_args[1];
    let username = &filtered_args[2];

    if let Some(ref key_path) = key_file {
        // Key-based authentication
        let command = &filtered_args[3];

        // Show the IOS commands to install the public key
        let pub_key_path = format!("{}.pub", key_path);
        if Path::new(&pub_key_path).exists() {
            match format_ios_pubkey_commands(username, &pub_key_path) {
                Ok(ios_cmds) => eprint!("{}", ios_cmds),
                Err(e) => eprintln!("Warning: Could not read public key {}: {}", pub_key_path, e),
            }
        } else {
            eprintln!("Warning: Public key file {} not found (expected alongside private key)", pub_key_path);
        }

        info!("=== CiscoConn Key-Based Command Execution ===");
        info!("Target: {}", target);
        info!("Username: {}", username);
        info!("Key file: {}", key_path);
        info!("Command: {}", command);
        println!("");

        // Read private key
        let private_key = std::fs::read(key_path)
            .map_err(|e| format!("Failed to read private key {}: {}", key_path, e))?;

        // Create CiscoConn with key authentication
        let mut conn = CiscoConn::new_with_key(target, username, &private_key).await?;

        println!("Connected with public key authentication!");

        let cmds = command.split(";");
        for ref cmd in cmds {
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
    } else {
        // Password-based authentication
        let password = &filtered_args[3];
        let command = &filtered_args[4];

        info!("=== CiscoConn Command Execution ===");
        info!("Target: {}", target);
        info!("Username: {}", username);
        info!("Command: {}", command);
        println!("");

        let mut conn = CiscoConn::new(
            target,
            ConnectionType::CiscoSsh,
            username,
            password,
        ).await?;

        println!("Connected with password authentication!");

        let cmds = command.split(";");
        for ref cmd in cmds {
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
    }

    info!("=== Execution Complete ===");
    Ok(())
}
