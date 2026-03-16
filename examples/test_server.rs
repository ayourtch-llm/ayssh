//! Test SSH Server - standalone binary for testing crypto algorithm combinations
//!
//! Usage:
//!   cargo run --example test_server -- [OPTIONS]
//!
//! The server accepts one connection, handles the full SSH protocol,
//! sends "AYSSH_TEST_OK\n" to the client, and exits.
//!
//! Connect with: ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
//!               -p <port> testuser@127.0.0.1

#![deny(unused_must_use)]

use ayssh::server::{TestSshServer, AlgorithmFilter, HostKeyPair};
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

    // Parse arguments
    let mut port: u16 = 2222;
    let mut preferred_kex: Option<String> = None;
    let mut preferred_cipher: Option<String> = None;
    let mut preferred_mac: Option<String> = None;
    let mut host_key_file: Option<String> = None;
    let mut loop_mode = false;
    let mut skip_next = false;

    for (i, arg) in args.iter().enumerate() {
        if skip_next { skip_next = false; continue; }
        match arg.as_str() {
            "--port" => {
                if let Some(v) = args.get(i + 1) {
                    port = v.parse().expect("Invalid port number");
                    skip_next = true;
                }
            }
            "--kex" => {
                if let Some(v) = args.get(i + 1) {
                    preferred_kex = Some(v.clone());
                    skip_next = true;
                }
            }
            "--cipher" => {
                if let Some(v) = args.get(i + 1) {
                    preferred_cipher = Some(v.clone());
                    skip_next = true;
                }
            }
            "--mac" => {
                if let Some(v) = args.get(i + 1) {
                    preferred_mac = Some(v.clone());
                    skip_next = true;
                }
            }
            "--host-key" => {
                if let Some(v) = args.get(i + 1) {
                    host_key_file = Some(v.clone());
                    skip_next = true;
                }
            }
            "--loop" => {
                loop_mode = true;
            }
            "--help" | "-h" => {
                eprintln!("Usage: {} [OPTIONS]", args[0]);
                eprintln!("");
                eprintln!("Options:");
                eprintln!("  --port <N>          Listen port (default: 2222)");
                eprintln!("  --kex <name>        Prefer KEX algorithm");
                eprintln!("  --cipher <name>     Prefer cipher");
                eprintln!("  --mac <name>        Prefer MAC");
                eprintln!("  --host-key <file>   RSA host key (OpenSSH format, default: generate Ed25519)");
                eprintln!("  --loop              Accept multiple connections (default: one-shot)");
                eprintln!("");
                eprintln!("Connect with:");
                eprintln!("  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\");
                eprintln!("      -p <port> testuser@127.0.0.1");
                eprintln!("");
                eprintln!("Available algorithms:");
                eprintln!("  KEX:    diffie-hellman-group1-sha1, diffie-hellman-group14-sha1,");
                eprintln!("          diffie-hellman-group14-sha256, curve25519-sha256,");
                eprintln!("          ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521");
                eprintln!("  Cipher: aes128-cbc, aes192-cbc, aes256-cbc, aes128-ctr, aes192-ctr,");
                eprintln!("          aes256-ctr, aes128-gcm@openssh.com, aes256-gcm@openssh.com");
                eprintln!("  MAC:    hmac-sha1, hmac-sha2-256, hmac-sha2-512,");
                eprintln!("          hmac-sha1-etm@openssh.com, hmac-sha2-256-etm@openssh.com,");
                eprintln!("          hmac-sha2-512-etm@openssh.com");
                std::process::exit(0);
            }
            _ => {}
        }
    }

    // Set up host key
    let host_key = if let Some(ref path) = host_key_file {
        info!("Loading RSA host key from {}", path);
        HostKeyPair::load_openssh_rsa(std::path::Path::new(path))?
    } else {
        info!("Generating Ed25519 host key");
        HostKeyPair::generate_ed25519()
    };

    // Set up algorithm filter
    let filter = AlgorithmFilter {
        kex: preferred_kex.clone(),
        cipher: preferred_cipher.clone(),
        mac: preferred_mac.clone(),
    };

    // Create server
    let server = TestSshServer::new(port).await?
        .with_host_key(host_key)
        .with_filter(filter);

    let addr = server.local_addr();
    println!("=== ayssh Test SSH Server ===");
    println!("Listening on {}", addr);
    if let Some(ref k) = preferred_kex { println!("  Preferred KEX: {}", k); }
    if let Some(ref c) = preferred_cipher { println!("  Preferred cipher: {}", c); }
    if let Some(ref m) = preferred_mac { println!("  Preferred MAC: {}", m); }
    println!("");
    println!("Connect with:");
    println!("  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\");
    println!("      -p {} testuser@127.0.0.1", addr.port());
    println!("");

    if loop_mode {
        println!("Running in loop mode (Ctrl-C to stop)");
        loop {
            match server.accept_one().await {
                Ok(()) => info!("Connection handled successfully"),
                Err(e) => error!("Connection error: {}", e),
            }
        }
    } else {
        println!("Waiting for one connection...");
        match server.accept_one().await {
            Ok(()) => {
                info!("Connection handled successfully");
                println!("Done!");
            }
            Err(e) => {
                error!("Connection error: {}", e);
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
