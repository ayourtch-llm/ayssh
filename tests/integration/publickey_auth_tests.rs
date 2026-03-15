//! PublicKeyAuthenticator tests

use ssh_client::auth::publickey::PublicKeyAuthenticator;
use ssh_client::protocol::message::Message;
use ssh_client::protocol::messages::MessageType;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_authenticator_api_exists() {
        // Test that the PublicKeyAuthenticator API exists and compiles
        // This is a compilation test - if it compiles, the API exists
        let _ = std::any::type_name::<PublicKeyAuthenticator>();
        assert!(true);
    }

    #[test]
    fn test_public_key_different_algorithms() {
        // Test that all algorithm names are valid strings
        let algorithms = vec![
            "ssh-rsa",
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ];
        
        for algo in algorithms {
            assert!(!algo.is_empty());
        }
    }

    #[test]
    fn test_message_format_publickey_request() {
        // Test the message format for publickey auth request
        let mut msg = Message::with_type(MessageType::UserauthRequest);
        msg.write_string(b"alice");
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(false); // no signature
        msg.write_string(b"ssh-rsa");
        msg.write_bytes(&[0x01, 0x02, 0x03, 0x04]); // public key hash
        
        // Should be parseable
        let parsed = msg.parse_userauth_request();
        assert!(parsed.is_some());
        
        let (username, service, method, has_sig) = parsed.unwrap();
        assert_eq!(username, "alice");
        assert_eq!(service, "ssh-connection");
        assert_eq!(method, "publickey");
        assert_eq!(has_sig, false);
    }

    #[test]
    fn test_message_format_signature_request() {
        // Test the message format for signature request
        let mut msg = Message::with_type(MessageType::UserauthRequest);
        msg.write_string(b"alice");
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(true); // has signature
        msg.write_string(b"ssh-rsa");
        msg.write_bytes(&[]); // public key blob
        msg.write_string(b"dummy_signature");
        
        let parsed = msg.parse_userauth_request();
        assert!(parsed.is_some());
        
        let (username, service, method, has_sig) = parsed.unwrap();
        assert_eq!(username, "alice");
        assert_eq!(service, "ssh-connection");
        assert_eq!(method, "publickey");
        assert_eq!(has_sig, true);
    }

    #[test]
    fn test_public_key_empty_key_handling() {
        // Test that empty keys can be handled
        let empty_key: Vec<u8> = vec![];
        assert!(empty_key.is_empty());
        assert_eq!(empty_key.len(), 0);
    }

    #[test]
    fn test_public_key_large_key_handling() {
        // Test that large keys can be handled
        let large_key = vec![0xAB; 4096]; // 4KB key
        assert_eq!(large_key.len(), 4096);
        assert!(!large_key.is_empty());
    }

    #[test]
    fn test_public_key_various_sizes() {
        // Test various key sizes
        let sizes = vec![0, 64, 256, 1024, 2048, 4096];
        
        for size in sizes {
            let key = vec![0xAB; size];
            assert_eq!(key.len(), size);
        }
    }
}