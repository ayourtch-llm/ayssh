//! CiscoConn - Simple command execution example

#![deny(unused_must_use)]

use ssh_client::cisco_conn::{CiscoConn, ConnectionType};
use std::env;
use tracing_subscriber;
use tracing::{info, error};

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

    if args.len() < 5 {
        eprintln!("Usage: {} <target> <username> <password> <command>", args[0]);
        eprintln!("");
        eprintln!("Examples:");
        eprintln!("  {} 192.168.1.1 admin password \"show version\"", args[0]);
        eprintln!("  {} router.local cisco cisco123 \"show running-config\"", args[0]);
        eprintln!("  {} [::1]:22 admin secret \"show interfaces\"", args[0]);
        std::process::exit(1);
    }

    let target = &args[1];
    let username = &args[2];
    let password = &args[3];
    let command = &args[4];

    info!("=== CiscoConn Command Execution ===");
    info!("Target: {}", target);
    info!("Username: {}", username);
    info!("Command: {}", command);
    println!("");

    // Create CiscoConn with default timeouts
    // This opens the connection and issues 'term len 0'
    let mut conn = CiscoConn::new(
        target,
        ConnectionType::CiscoSsh,
        username,
        password,
    ).await?;

    println!("Connecting and executing command...");

    // Execute the command using run_cmd
    // Note: This will attempt to connect to the actual device
    let cmds = command.split(";");
    for ref command in cmds {
        match conn.run_cmd(command).await {
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

    info!("=== Execution Complete ===");

    Ok(())
}
