//! CiscoSSH Example - Command execution on Cisco devices

use ssh_client::cisco_ssh::{CiscoSSH, ConnectionType};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .init();

    // Target device configuration
    let target = "192.168.0.130";
    let username = "ayourtch";
    let password = "cisco123";

    println!("Connecting to Cisco device at {}...", target);

    // Create connection with default timeouts
    let conn = CiscoSSH::new(target, ConnectionType::CiscoSSH, username, password).await?;
    println!("Connected successfully!");

    // Execute single command
    println!("\n=== Executing 'show version' ===");
    let output = conn.run_cmd("show version").await?;
    println!("{}", output);

    // Execute multiple commands
    println!("\n=== Executing 'show proc' ===");
    let proc_output = conn.run_cmd("show proc").await?;
    println!("{}", proc_output);

    // Execute multiple commands at once
    println!("\n=== Executing multiple commands ===");
    let cmds = vec!["show version", "show proc"];
    let outputs = conn.run_multiple_cmds(&cmds).await?;
    
    for (i, cmd) in cmds.iter().enumerate() {
        println!("\n--- Command: {} ---", cmd);
        println!("{}", outputs[i]);
    }

    println!("\nDone!");
    Ok(())
}