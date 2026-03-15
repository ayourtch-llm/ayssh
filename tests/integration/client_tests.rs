//! Integration tests for Client module

use ssh_client::client::SshClient;

/// Test 1: Verify Client::new() creates client with correct host and port
#[test]
fn test_client_new() {
    let client = SshClient::new("localhost".to_string(), 22);
    assert_eq!(client.host(), "localhost");
    assert_eq!(client.port(), 22);
}

/// Test 2: Verify Client::host() returns correct host
#[test]
fn test_client_host() {
    let client = SshClient::new("example.com".to_string(), 2222);
    assert_eq!(client.host(), "example.com");
}

/// Test 3: Verify Client::port() returns correct port
#[test]
fn test_client_port() {
    let client = SshClient::new("localhost".to_string(), 8080);
    assert_eq!(client.port(), 8080);
}

/// Test 4: Verify Client::connect() returns error (no server)
#[tokio::test]
async fn test_client_connect_fails_without_server() {
    // Use a port that's unlikely to have a server running
    let client = SshClient::new("localhost".to_string(), 65432);
    let result = client.connect().await;
    
    // Should fail to connect to non-existent server
    assert!(result.is_err());
}

/// Test 5: Verify Client::connect_with_auth() returns error (no server)
#[tokio::test]
async fn test_client_connect_with_auth_fails_without_server() {
    use ssh_client::auth::AuthMethod;
    
    let client = SshClient::new("localhost".to_string(), 22);
    let result = client.connect_with_auth(AuthMethod::Password {
        username: "test".to_string(),
        password: "test".to_string(),
    }).await;
    assert!(result.is_err());
}

/// Test 6: Verify Client with different host
#[test]
fn test_client_different_host() {
    let client = SshClient::new("192.168.1.1".to_string(), 22);
    assert_eq!(client.host(), "192.168.1.1");
}

/// Test 7: Verify Client with different port
#[test]
fn test_client_different_port() {
    let client = SshClient::new("localhost".to_string(), 2222);
    assert_eq!(client.port(), 2222);
}

/// Test 8: Verify Client with IPv6-like host
#[test]
fn test_client_ipv6_host() {
    let client = SshClient::new("::1".to_string(), 22);
    assert_eq!(client.host(), "::1");
}

/// Test 9: Verify Client with custom port
#[test]
fn test_client_custom_port() {
    let client = SshClient::new("localhost".to_string(), 443);
    assert_eq!(client.port(), 443);
}

/// Test 10: Verify Client handles long hostnames
#[test]
fn test_client_long_hostname() {
    let long_host = "very-long-subdomain-name.very-long-domain-name.example.com".to_string();
    let client = SshClient::new(long_host.clone(), 22);
    assert_eq!(client.host(), long_host);
}