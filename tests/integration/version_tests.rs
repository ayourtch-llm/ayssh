//! Version exchange tests for SSH protocol

use ayssh::transport::handshake::{parse_version_string, SSH_VERSION_STRING};

#[test]
fn test_client_version_string_format() {
    // Client version string should be "SSH-2.0-<software>"
    assert!(SSH_VERSION_STRING.starts_with("SSH-2.0-"));
}

#[test]
fn test_parse_server_version_standard() {
    let version = b"SSH-2.0-libssh_0.9.6";
    let (proto, software) = parse_version_string(version).unwrap();

    assert_eq!(proto, 2);
    assert_eq!(software, "libssh_0.9.6");
}

#[test]
fn test_parse_server_version_openssh() {
    let version = b"SSH-2.0-OpenSSH_8.0";
    let (proto, software) = parse_version_string(version).unwrap();

    assert_eq!(proto, 2);
    assert_eq!(software, "OpenSSH_8.0");
}

#[test]
fn test_parse_server_version_with_dashes() {
    let version = b"SSH-2.0-MySSH_Server-v1.0-beta";
    let (proto, software) = parse_version_string(version).unwrap();

    assert_eq!(proto, 2);
    assert_eq!(software, "MySSH_Server-v1.0-beta");
}

#[test]
fn test_reject_ssh_1_x_versions() {
    // SSH-1.99 MUST be accepted per RFC 4253 Section 5.1 (Cisco compatibility)
    // Only SSH-1.0 and earlier should be rejected
    let version = b"SSH-1.99-libssh_0.9.6";
    let (proto, software) = parse_version_string(version).unwrap();
    assert_eq!(proto, 1); // Major version is 1, but 1.99 is accepted as 2.0-compatible
    assert_eq!(software, "libssh_0.9.6");

    // SSH-1.0 should still be rejected
    let old_version = b"SSH-1.0-OldServer";
    assert!(parse_version_string(old_version).is_err());
}

#[test]
fn test_reject_invalid_version_prefix() {
    let version = b"SSH-1.0-invalid";
    assert!(parse_version_string(version).is_err());
}

#[test]
fn test_reject_invalid_utf8() {
    let version = b"SSH-2.0-\xFF\xFE";
    assert!(parse_version_string(version).is_err());
}

#[test]
fn test_reject_missing_protocol_version() {
    let version = b"SSH-";
    assert!(parse_version_string(version).is_err());
}
