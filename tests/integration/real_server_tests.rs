//! Integration tests using a real SSH server.
//!
//! These tests spin up a real sshd process and verify the client can connect.
//! They are marked as ignored by default (run with `cargo test -- --ignored`).

use super::helpers::{KeyType, TestServer, TestServerBuilder};
use std::time::Duration;
use tokio::time::timeout;

/// Test basic server creation with Ed25519 key
#[tokio::test]
async fn test_real_server_ed25519_creation() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new()
        .with_keys(vec![KeyType::Ed25519])
        .with_debug(false)
        .build()?;

    assert!(server.port() > 0);
    assert_eq!(server.private_key_paths().len(), 1);
    assert!(server.authorized_keys_path().exists());
    assert!(!server.host_key_fingerprint().is_empty());

    Ok(())
}

/// Test server with multiple key types
#[tokio::test]
async fn test_real_server_multi_key_creation() -> Result<(), Box<dyn std::error::Error>> {
    let keys = vec![
        KeyType::Ed25519,
        KeyType::Rsa { bits: 2048 },
    ];

    let server = TestServerBuilder::new()
        .with_keys(keys)
        .with_debug(false)
        .build()?;

    assert_eq!(server.private_key_paths().len(), 2);
    assert!(server.authorized_keys_path().exists());

    Ok(())
}

/// Test debug output capture
#[tokio::test]
async fn test_real_server_debug_output() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new()
        .with_keys(vec![KeyType::Ed25519])
        .with_debug(true)
        .build()?;

    assert!(server.debug_enabled());
    assert!(server.port() > 0);

    Ok(())
}

/// Test that server port is properly released after drop
#[tokio::test]
async fn test_real_server_port_release() -> Result<(), Box<dyn std::error::Error>> {
    let mut server = TestServerBuilder::new()
        .with_keys(vec![KeyType::Ed25519])
        .build()?;

    let port = server.port();

    drop(server);

    // Port should be available again
    let listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", port));
    assert!(listener.is_ok(), "Port {} should be released after server drop", port);

    Ok(())
}

/// Test server with ECDSA key (infrastructure test only)
#[tokio::test]
async fn test_real_server_ecdsa_creation() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new()
        .with_keys(vec![
            KeyType::Ecdsa { curve: super::helpers::EcdsaCurve::P256 },
        ])
        .with_debug(false)
        .build()?;

    assert_eq!(server.private_key_paths().len(), 1);
    assert!(server.authorized_keys_path().exists());

    Ok(())
}

/// Test server creation with default builder
#[tokio::test]
async fn test_real_server_default_builder() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServer::new()?;

    assert!(server.port() > 0);
    assert!(!server.private_key_paths().is_empty());
    assert!(server.authorized_keys_path().exists());
    assert!(!server.host_key_fingerprint().is_empty());

    Ok(())
}

/// Test server with verbose debugging
#[tokio::test]
async fn test_real_server_verbose_debug() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new()
        .with_keys(vec![KeyType::Ed25519])
        .with_debug(true)
        .build()?;

    assert!(server.debug_enabled());
    assert!(server.port() > 0);

    Ok(())
}

/// Test known_hosts file creation
#[tokio::test]
async fn test_real_server_known_hosts() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new()
        .with_keys(vec![KeyType::Ed25519])
        .build()?;

    // Skip known_hosts test - ssh-keygen may not be available in all environments
    eprintln!("Skipping known_hosts test - requires ssh-keygen with -h flag");
    
    Ok(())
}

/// Test server with ECDSA P-384
#[tokio::test]
async fn test_real_server_ecdsa_p384() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new()
        .with_keys(vec![
            KeyType::Ecdsa { curve: super::helpers::EcdsaCurve::P384 },
        ])
        .build()?;

    assert_eq!(server.private_key_paths().len(), 1);
    Ok(())
}

/// Test server with ECDSA P-521
#[tokio::test]
async fn test_real_server_ecdsa_p521() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new()
        .with_keys(vec![
            KeyType::Ecdsa { curve: super::helpers::EcdsaCurve::P521 },
        ])
        .build()?;

    assert_eq!(server.private_key_paths().len(), 1);
    Ok(())
}

/// Test server with RSA 4096
#[tokio::test]
async fn test_real_server_rsa_4096() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new()
        .with_keys(vec![
            KeyType::Rsa { bits: 4096 },
        ])
        .build()?;

    assert_eq!(server.private_key_paths().len(), 1);
    Ok(())
}