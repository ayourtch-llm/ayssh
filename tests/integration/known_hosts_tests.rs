//! Known Hosts Tests

use ayssh::known_hosts::{KnownHosts, HostKey, HostKeyType, MatchPattern};
use std::io::Cursor;

#[test]
fn test_known_hosts_create() {
    let hosts = KnownHosts::new();
    assert_eq!(hosts.hosts.len(), 0);
}

#[test]
fn test_known_hosts_add_host() {
    let mut hosts = KnownHosts::new();
    
    let host_key = HostKey {
        key_type: HostKeyType::Ed25519,
        key_data: vec![0x01, 0x02, 0x03, 0x04],
    };
    
    hosts.add_host("example.com", host_key.clone());
    
    assert_eq!(hosts.hosts.len(), 1);
    assert!(hosts.get_host("example.com").is_some());
}

#[test]
fn test_known_hosts_add_multiple_hosts() {
    let mut hosts = KnownHosts::new();
    
    let ed25519_key = HostKey {
        key_type: HostKeyType::Ed25519,
        key_data: vec![0x01, 0x02, 0x03, 0x04],
    };
    
    let rsa_key = HostKey {
        key_type: HostKeyType::Rsa,
        key_data: vec![0x05, 0x06, 0x07, 0x08],
    };
    
    hosts.add_host("example.com", ed25519_key);
    hosts.add_host("github.com", rsa_key);
    
    assert_eq!(hosts.hosts.len(), 2);
    assert!(hosts.get_host("example.com").is_some());
    assert!(hosts.get_host("github.com").is_some());
    assert!(hosts.get_host("nonexistent.com").is_none());
}

#[test]
fn test_known_hosts_verify_host() {
    let mut hosts = KnownHosts::new();
    
    let host_key = HostKey {
        key_type: HostKeyType::Ed25519,
        key_data: vec![0x01, 0x02, 0x03, 0x04],
    };
    
    hosts.add_host("example.com", host_key.clone());
    
    // Verify correct key
    assert!(hosts.verify_host("example.com", &host_key));
    
    // Verify incorrect key
    let wrong_key = HostKey {
        key_type: HostKeyType::Ed25519,
        key_data: vec![0x05, 0x06, 0x07, 0x08],
    };
    assert!(!hosts.verify_host("example.com", &wrong_key));
    
    // Verify non-existent host
    assert!(!hosts.verify_host("nonexistent.com", &host_key));
}

#[test]
fn test_known_hosts_parse_openssh_format() {
    let mut hosts = KnownHosts::new();
    
    // Parse a sample known_hosts line
    let line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    
    hosts.parse_line(line).expect("Should parse line");
    
    assert_eq!(hosts.hosts.len(), 1);
    assert!(hosts.get_host("example.com").is_some());
}

#[test]
fn test_known_hosts_parse_wildcard_host() {
    let mut hosts = KnownHosts::new();
    
    // Parse a wildcard host pattern
    let line = "*.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    
    hosts.parse_line(line).expect("Should parse line");
    
    assert_eq!(hosts.patterns.len(), 1);
    
    // Should match wildcard
    assert!(hosts.get_host("foo.example.com").is_some());
    assert!(hosts.get_host("bar.example.com").is_some());
    
    // Should not match non-wildcard
    assert!(hosts.get_host("example.com").is_none());
    assert!(hosts.get_host("evil.com").is_none());
}

#[test]
fn test_known_hosts_parse_comment() {
    let mut hosts = KnownHosts::new();
    
    // Parse a line with comment
    let line = "# This is a comment";
    
    hosts.parse_line(line).expect("Should parse comment");
    
    // Comments should not add hosts
    assert_eq!(hosts.hosts.len(), 0);
}

#[test]
fn test_known_hosts_parse_empty_line() {
    let mut hosts = KnownHosts::new();
    
    // Parse an empty line
    let line = "";
    
    hosts.parse_line(line).expect("Should parse empty line");
    
    // Empty lines should not add hosts
    assert_eq!(hosts.hosts.len(), 0);
}

#[test]
fn test_known_hosts_parse_invalid_line() {
    let mut hosts = KnownHosts::new();
    
    // Parse an invalid line
    let line = "invalid line without enough fields";
    
    // Should return an error for invalid line
    assert!(hosts.parse_line(line).is_err());
}

#[test]
fn test_known_hosts_match_pattern() {
    // Test match pattern matching
    let pattern = MatchPattern::new("*.example.com");
    
    assert!(pattern.matches("foo.example.com"));
    assert!(pattern.matches("bar.example.com"));
    assert!(!pattern.matches("example.com"));
    assert!(!pattern.matches("evil.com"));
    
    let pattern = MatchPattern::new("example.com");
    
    assert!(pattern.matches("example.com"));
    assert!(!pattern.matches("foo.example.com"));
}

#[test]
fn test_known_hosts_host_key_types() {
    // Test different host key types
    let ed25519_key = HostKey {
        key_type: HostKeyType::Ed25519,
        key_data: vec![0x01, 0x02, 0x03, 0x04],
    };
    
    let rsa_key = HostKey {
        key_type: HostKeyType::Rsa,
        key_data: vec![0x05, 0x06, 0x07, 0x08],
    };
    
    let ecdsa_key = HostKey {
        key_type: HostKeyType::Ecdsa,
        key_data: vec![0x09, 0x0a, 0x0b, 0x0c],
    };
    
    assert_eq!(ed25519_key.key_type.key_type_str(), "ssh-ed25519");
    assert_eq!(rsa_key.key_type.key_type_str(), "ssh-rsa");
    assert_eq!(ecdsa_key.key_type.key_type_str(), "ecdsa-sha2-nistp256");
}

#[test]
fn test_known_hosts_serialization() {
    let mut hosts = KnownHosts::new();
    
    let host_key = HostKey {
        key_type: HostKeyType::Ed25519,
        key_data: vec![0x01, 0x02, 0x03, 0x04],
    };
    
    hosts.add_host("example.com", host_key.clone());
    
    // Serialize to string
    let serialized = hosts.to_string();
    
    // Should contain the host and key
    assert!(serialized.contains("example.com"));
    assert!(serialized.contains("ssh-ed25519"));
}

#[test]
fn test_known_hosts_from_string() {
    let known_hosts_content = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ssh-rsa dGVzdF9yc2Ffa2V5X2RhdGFfaGVyZQ==";
    
    let hosts = KnownHosts::from_string(known_hosts_content).expect("Should parse content");
    
    assert_eq!(hosts.hosts.len(), 2);
    assert!(hosts.get_host("example.com").is_some());
    assert!(hosts.get_host("github.com").is_some());
}

#[test]
fn test_known_hosts_update_host() {
    let mut hosts = KnownHosts::new();
    
    let old_key = HostKey {
        key_type: HostKeyType::Ed25519,
        key_data: vec![0x01, 0x02, 0x03, 0x04],
    };
    
    let new_key = HostKey {
        key_type: HostKeyType::Ed25519,
        key_data: vec![0x05, 0x06, 0x07, 0x08],
    };
    
    hosts.add_host("example.com", old_key.clone());
    assert!(hosts.verify_host("example.com", &old_key));
    
    // Update the host key
    hosts.add_host("example.com", new_key.clone());
    
    // Old key should no longer verify
    assert!(!hosts.verify_host("example.com", &old_key));
    
    // New key should verify
    assert!(hosts.verify_host("example.com", &new_key));
}

#[test]
fn test_known_hosts_remove_host() {
    let mut hosts = KnownHosts::new();
    
    let host_key = HostKey {
        key_type: HostKeyType::Ed25519,
        key_data: vec![0x01, 0x02, 0x03, 0x04],
    };
    
    hosts.add_host("example.com", host_key.clone());
    assert!(hosts.get_host("example.com").is_some());
    
    hosts.remove_host("example.com");
    assert!(hosts.get_host("example.com").is_none());
}