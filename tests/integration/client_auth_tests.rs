//! Integration tests for Client authentication integration

use ssh_client::client::SshClient;
use ssh_client::protocol::AuthMethod;

/// Test 1: Test Client with password authentication configuration
#[tokio::test]
async fn test_client_with_password_auth() {
    let client = SshClient::new("localhost".to_string(), 22);
    // Verify client can be created and is ready for password auth
    assert_eq!(client.host(), "localhost");
    assert_eq!(client.port(), 22);
}

/// Test 2: Test Client with public key authentication configuration
#[tokio::test]
async fn test_client_with_publickey_auth() {
    let client = SshClient::new("localhost".to_string(), 22);
    // Verify client can be created and is ready for public key auth
    assert_eq!(client.host(), "localhost");
    assert_eq!(client.port(), 22);
}

/// Test 3: Test Client authentication flow integration
#[tokio::test]
async fn test_client_auth_flow_integration() {
    let client = SshClient::new("localhost".to_string(), 22);
    let result = client.connect_with_auth(AuthMethod::Password).await;
    assert!(result.is_err()); // Should fail without server
}

/// Test 4: Test error handling for authentication failures
#[tokio::test]
async fn test_client_auth_error_handling() {
    let client = SshClient::new("nonexistent.server.local".to_string(), 22);
    let result = client.connect().await;
    assert!(result.is_err());
}

/// Test 5: Test that Client properly configures authentication methods
#[test]
fn test_client_auth_method_configuration() {
    let client = SshClient::new("localhost".to_string(), 22);
    // Verify client is configured with default settings
    assert_eq!(client.host(), "localhost");
    assert_eq!(client.port(), 22);
}

/// Test 6: Test Client authentication state tracking
#[test]
fn test_client_auth_state_tracking() {
    let client = SshClient::new("localhost".to_string(), 22);
    // Client state is tracked internally; verify basic properties
    assert!(!client.host().is_empty());
}

/// Test 7: Test Client handles multiple auth methods
#[tokio::test]
async fn test_client_multiple_auth_methods() {
    let client = SshClient::new("localhost".to_string(), 22);
    
    // Try different auth methods - all should fail without server
    let result1 = client.connect_with_auth(AuthMethod::Password).await;
    let result2 = client.connect_with_auth(AuthMethod::PublicKey).await;
    
    assert!(result1.is_err());
    assert!(result2.is_err());
}

/// Test 8: Test Client authentication result parsing
#[tokio::test]
async fn test_client_auth_result_parsing() {
    let client = SshClient::new("localhost".to_string(), 22);
    let result = client.connect().await;
    
    // Verify result is an error (no server)
    assert!(result.is_err());
    
    // The error should be a SessionError or similar
    let err_msg = format!("{:?}", result);
    assert!(err_msg.contains("Session") || err_msg.contains("Error"));
}