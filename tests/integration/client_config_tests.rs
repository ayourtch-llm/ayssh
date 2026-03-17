//! Integration tests for Client configuration

use ayssh::client::SshClient;

/// Test 1: Client with default configuration (port 22, localhost)
#[test]
fn test_client_default_configuration() {
    let client = SshClient::new("localhost".to_string(), 22);
    assert_eq!(client.host(), "localhost");
    assert_eq!(client.port(), 22);
}

/// Test 2: Client with custom host configuration
#[test]
fn test_client_custom_host() {
    let custom_host = "example.com".to_string();
    let client = SshClient::new(custom_host.clone(), 22);
    assert_eq!(client.host(), custom_host);
}

/// Test 3: Client with custom port configuration
#[test]
fn test_client_custom_port() {
    let custom_port = 2222;
    let client = SshClient::new("localhost".to_string(), custom_port);
    assert_eq!(client.port(), custom_port);
}

/// Test 4: Client configuration validation - valid hostname
#[test]
fn test_client_valid_hostname() {
    let valid_hosts = vec![
        "localhost",
        "127.0.0.1",
        "example.com",
        "ssh.example.org",
        "subdomain.example.com",
    ];
    
    for host in valid_hosts {
        let client = SshClient::new(host.to_string(), 22);
        assert_eq!(client.host(), host);
    }
}

/// Test 5: Client configuration validation - valid port range
#[test]
fn test_client_valid_port_range() {
    let valid_ports = vec![
        1,     // Minimum valid port
        22,    // Default SSH port
        1024,  // Well-known port
        8080,  // Common alternative port
        65535, // Maximum port
    ];
    
    for port in valid_ports {
        let client = SshClient::new("localhost".to_string(), port);
        assert_eq!(client.port(), port);
    }
}

/// Test 6: Client handles invalid configurations - empty host
#[test]
fn test_client_empty_host() {
    let client = SshClient::new("".to_string(), 22);
    assert_eq!(client.host(), "");
}

/// Test 7: Client handles invalid configurations - special characters in host
#[test]
fn test_client_special_chars_in_host() {
    let special_host = "host-with-dashes_underscores.dots.example.com".to_string();
    let client = SshClient::new(special_host.clone(), 22);
    assert_eq!(client.host(), special_host);
}

/// Test 8: Client configuration persistence - host remains unchanged
#[test]
fn test_client_host_persistence() {
    let client = SshClient::new("persistent-host".to_string(), 22);
    assert_eq!(client.host(), "persistent-host");
    
    // Multiple accesses should return same value
    assert_eq!(client.host(), "persistent-host");
    assert_eq!(client.host(), "persistent-host");
}

/// Test 9: Client configuration persistence - port remains unchanged
#[test]
fn test_client_port_persistence() {
    let client = SshClient::new("localhost".to_string(), 9999);
    assert_eq!(client.port(), 9999);
    
    // Multiple accesses should return same value
    assert_eq!(client.port(), 9999);
    assert_eq!(client.port(), 9999);
}

/// Test 10: Client with different custom configurations
#[test]
fn test_client_various_configurations() {
    let configs = vec![
        ("server1.example.com", 22),
        ("server2.example.com", 2222),
        ("10.0.0.1", 8022),
        ("192.168.0.100", 3333),
        ("ssh.example.org", 4444),
    ];
    
    for (host, port) in configs {
        let client = SshClient::new(host.to_string(), port);
        assert_eq!(client.host(), host);
        assert_eq!(client.port(), port);
    }
}

/// Test 11: Client with IPv4 address configuration
#[test]
fn test_client_ipv4_address() {
    let ipv4_addresses = vec![
        "127.0.0.1",
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
    ];
    
    for ip in ipv4_addresses {
        let client = SshClient::new(ip.to_string(), 22);
        assert_eq!(client.host(), ip);
        assert_eq!(client.port(), 22);
    }
}

/// Test 12: Client with IPv6 address configuration
#[test]
fn test_client_ipv6_address() {
    let ipv6_addresses = vec![
        "::1",
        "::ffff:127.0.0.1",
        "2001:db8::1",
    ];
    
    for ip in ipv6_addresses {
        let client = SshClient::new(ip.to_string(), 22);
        assert_eq!(client.host(), ip);
        assert_eq!(client.port(), 22);
    }
}

/// Test 13: Client configuration with boundary port values
#[test]
fn test_client_boundary_ports() {
    // Test minimum and maximum port values
    let min_port_client = SshClient::new("localhost".to_string(), 1);
    assert_eq!(min_port_client.port(), 1);
    
    let max_port_client = SshClient::new("localhost".to_string(), 65535);
    assert_eq!(max_port_client.port(), 65535);
}

/// Test 14: Client configuration immutability - host cannot be modified after creation
#[test]
fn test_client_host_immutable() {
    let client = SshClient::new("original-host".to_string(), 22);
    
    // Verify initial state
    assert_eq!(client.host(), "original-host");
    
    // Note: The host() method returns &str, not &mut str, so it's immutable
    // This test verifies that we can only read, not modify, the host
    let host_ref = client.host();
    assert_eq!(host_ref, "original-host");
}

/// Test 15: Client configuration immutability - port cannot be modified after creation
#[test]
fn test_client_port_immutable() {
    let client = SshClient::new("localhost".to_string(), 9999);
    
    // Verify initial state
    assert_eq!(client.port(), 9999);
    
    // Note: The port() method returns u16, not &mut u16, so it's immutable
    // This test verifies that we can only read, not modify, the port
    let port_val = client.port();
    assert_eq!(port_val, 9999);
}

/// Test 16: Client with long hostname configuration
#[test]
fn test_client_long_hostname() {
    let long_hostname = "very-long-subdomain-name.very-long-domain-name.example.com".to_string();
    let client = SshClient::new(long_hostname.clone(), 22);
    assert_eq!(client.host(), long_hostname);
}

/// Test 17: Client with numeric hostname (edge case)
#[test]
fn test_client_numeric_hostname() {
    let numeric_host = "12345".to_string();
    let client = SshClient::new(numeric_host.clone(), 22);
    assert_eq!(client.host(), numeric_host);
}

/// Test 18: Client configuration with standard SSH port
#[test]
fn test_client_standard_ssh_port() {
    let client = SshClient::new("ssh.example.com".to_string(), 22);
    assert_eq!(client.port(), 22);
}

/// Test 19: Client configuration with non-standard SSH port
#[test]
fn test_client_non_standard_ssh_port() {
    let non_standard_ports = vec![2222, 2200, 22222, 10000];
    
    for port in non_standard_ports {
        let client = SshClient::new("localhost".to_string(), port);
        assert_eq!(client.port(), port);
    }
}

/// Test 20: Client configuration consistency - both host and port set correctly
#[test]
fn test_client_configuration_consistency() {
    let test_cases = vec![
        ("host1.com", 22, "host1.com", 22),
        ("host2.com", 2222, "host2.com", 2222),
        ("127.0.0.1", 8080, "127.0.0.1", 8080),
        ("::1", 65535, "::1", 65535),
    ];
    
    for (host, port, expected_host, expected_port) in test_cases {
        let client = SshClient::new(host.to_string(), port);
        assert_eq!(client.host(), expected_host);
        assert_eq!(client.port(), expected_port);
    }
}

/// Test 21: Client configuration with Unicode characters in hostname
#[test]
fn test_client_unicode_hostname() {
    let unicode_host = "сервер.example.com".to_string();
    let client = SshClient::new(unicode_host.clone(), 22);
    assert_eq!(client.host(), unicode_host);
}

/// Test 22: Client configuration with subdomain variations
#[test]
fn test_client_subdomain_configurations() {
    let subdomains = vec![
        "www.example.com",
        "api.example.com",
        "ssh.example.com",
        "dev.example.com",
        "staging.example.com",
        "prod.example.com",
    ];
    
    for subdomain in subdomains {
        let client = SshClient::new(subdomain.to_string(), 22);
        assert_eq!(client.host(), subdomain);
    }
}

/// Test 23: Client configuration with multiple instances
#[test]
fn test_client_multiple_instances() {
    let client1 = SshClient::new("server1.example.com".to_string(), 22);
    let client2 = SshClient::new("server2.example.com".to_string(), 2222);
    let client3 = SshClient::new("server3.example.com".to_string(), 8080);
    
    assert_eq!(client1.host(), "server1.example.com");
    assert_eq!(client1.port(), 22);
    
    assert_eq!(client2.host(), "server2.example.com");
    assert_eq!(client2.port(), 2222);
    
    assert_eq!(client3.host(), "server3.example.com");
    assert_eq!(client3.port(), 8080);
}

/// Test 24: Client configuration with repeated access patterns
#[test]
fn test_client_repeated_access() {
    let client = SshClient::new("test.example.com".to_string(), 4444);
    
    // Access host and port multiple times
    for _ in 0..10 {
        assert_eq!(client.host(), "test.example.com");
        assert_eq!(client.port(), 4444);
    }
}

/// Test 25: Client connect with configuration - verify configuration is used
#[tokio::test]
async fn test_client_connect_uses_configuration() {
    let client = SshClient::new("configured-host".to_string(), 9999);
    
    // Verify configuration is set correctly
    assert_eq!(client.host(), "configured-host");
    assert_eq!(client.port(), 9999);
    
    // Connect should use the configured host and port
    // (In real implementation, this would attempt to connect to configured-host:9999)
    let result = client.connect().await;
    assert!(result.is_err()); // Expected to fail as there's no server
}

/// Test 26: Client connect_with_auth with configuration
#[tokio::test]
async fn test_client_connect_with_auth_uses_configuration() {
    let client = SshClient::new("auth-host".to_string(), 8888);
    
    // Verify configuration is set correctly
    assert_eq!(client.host(), "auth-host");
    assert_eq!(client.port(), 8888);
    
    // Connect with auth should use the configured host and port
    use ayssh::auth::AuthMethod;
    let result = client.connect_with_auth(AuthMethod::Password {
        username: "test".to_string(),
        password: "test".to_string(),
    }).await;
    assert!(result.is_err()); // Expected to fail as there's no server
}

/// Test 27: Client configuration validation - port zero (edge case)
#[test]
fn test_client_port_zero() {
    let client = SshClient::new("localhost".to_string(), 0);
    assert_eq!(client.port(), 0);
}

/// Test 28: Client configuration with empty port string representation
#[test]
fn test_client_port_zero_display() {
    let client = SshClient::new("localhost".to_string(), 0);
    
    // Port 0 should be displayed correctly
    let port_display = format!("{}", client.port());
    assert_eq!(port_display, "0");
}

/// Test 29: Client configuration with very short hostname
#[test]
fn test_client_short_hostname() {
    let short_hosts = vec!["a", "ab", "abc", "localhost"];
    
    for host in short_hosts {
        let client = SshClient::new(host.to_string(), 22);
        assert_eq!(client.host(), host);
    }
}

/// Test 30: Client configuration with mixed case hostname
#[test]
fn test_client_mixed_case_hostname() {
    let mixed_case_hosts = vec![
        "Example.COM",
        "example.Com",
        "ExAmPlE.cOm",
        "LOCALHOST",
    ];
    
    for host in mixed_case_hosts {
        let client = SshClient::new(host.to_string(), 22);
        assert_eq!(client.host(), host);
    }
}