//! SSH Client Binary
//!
//! This is the main entry point for the SSH client application.
//! It provides a command-line interface for connecting to SSH servers.

use ssh_client::{init_logging, NAME, VERSION};

fn print_usage() {
    println!("SSH Client v{}", VERSION);
    println!();
    println!("Usage: ssh_client [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -h, --help       Print this help message");
    println!("  -v, --version    Print version information");
    println!("  --debug          Enable debug logging");
    println!();
    println!("Examples:");
    println!("  ssh_client --debug");
    println!("  RUST_LOG=info ssh_client");
}

fn print_version() {
    println!("{} v{}", NAME, VERSION);
    println!("Edition: 2021");
    println!();
    println!("Dependencies:");
    println!("  - tokio: async runtime");
    println!("  - tokio-util: async utilities");
    println!("  - async-trait: async trait support");
    println!("  - thiserror: error handling");
    println!("  - log: logging framework");
    println!("  - env_logger: logging initialization");
    println!("  - hex: hex encoding");
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return;
    }

    let mut debug_mode = false;
    
    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage();
                return;
            }
            "-v" | "--version" => {
                print_version();
                return;
            }
            "--debug" => {
                debug_mode = true;
            }
            _ => {
                eprintln!("Unknown option: {}", arg);
                print_usage();
                std::process::exit(1);
            }
        }
    }

    // Initialize logging
    if debug_mode {
        std::env::set_var("RUST_LOG", "debug");
    }

    if let Err(e) = init_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(1);
    }

    log::info!("SSH Client starting up");
    log::info!("Version: {}", VERSION);
    
    if debug_mode {
        log::debug!("Debug mode enabled");
    }

    log::info!("SSH Client initialized successfully");
    println!("SSH Client v{} - initialized", VERSION);
    println!("Use --help for usage information");
}
