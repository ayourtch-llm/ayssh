//! Password Authentication Tests (TDD)

use bytes::BytesMut;
use ayssh::auth::password::PasswordAuthenticator;
use ayssh::protocol::message::Message;
use ayssh::protocol::messages::MessageType;

#[test]
fn test_password_auth_request_format() {
    // RED: Write test that defines expected message format
    let mut msg = Message::with_type(MessageType::UserauthRequest);
    
    // According to RFC 4252 Section 5.2:
    // byte      SSH_MSG_USERAUTH_REQUEST
    // string    username
    // string    service
    // string    method
    // boolean   first_attempt
    // string    password
    
    msg.write_string(b"alice");
    msg.write_string(b"ssh-connection");
    msg.write_string(b"password");
    msg.write_bool(false); // first attempt
    msg.write_string(b"secret_password");
    
    // Verify the message can be parsed correctly
    let parsed = msg.parse_userauth_request();
    assert!(parsed.is_some());
    
    let (username, service, method, first_attempt) = parsed.unwrap();
    assert_eq!(username, "alice");
    assert_eq!(service, "ssh-connection");
    assert_eq!(method, "password");
    assert_eq!(first_attempt, false);
}

#[test]
fn test_password_auth_multiple_attempts() {
    // Test that subsequent attempts set first_attempt to false
    let mut msg = Message::with_type(MessageType::UserauthRequest);
    
    msg.write_string(b"alice");
    msg.write_string(b"ssh-connection");
    msg.write_string(b"password");
    msg.write_bool(true); // first attempt
    msg.write_string(b"password1");
    
    let parsed = msg.parse_userauth_request().unwrap();
    assert_eq!(parsed.0, "alice");
    assert_eq!(parsed.3, true); // first attempt is true
    
    // Second attempt
    let mut msg2 = Message::with_type(MessageType::UserauthRequest);
    msg2.write_string(b"alice");
    msg2.write_string(b"ssh-connection");
    msg2.write_string(b"password");
    msg2.write_bool(false); // not first attempt
    msg2.write_string(b"password2");
    
    let parsed2 = msg2.parse_userauth_request().unwrap();
    assert_eq!(parsed2.3, false); // not first attempt
}

#[test]
fn test_password_auth_response_success() {
    // Test parsing SSH_MSG_USERAUTH_SUCCESS
    let mut msg = Message::with_type(MessageType::UserauthSuccess);
    
    // SUCCESS message has no additional data
    assert_eq!(msg.len(), 1); // Just the message type byte
    
    let parsed = msg.parse_userauth_request();
    assert!(parsed.is_none()); // Should not be parseable as request
}

#[test]
fn test_password_auth_response_failure() {
    // Test parsing SSH_MSG_USERAUTH_FAILURE
    // Format: byte SSH_MSG_USERAUTH_FAILURE, string partial_success, string methods
    let mut msg = Message::with_type(MessageType::UserauthFailure);
    msg.write_string(b"publickey"); // partial success
    msg.write_string(b"password,publickey"); // available methods
    
    let parsed = msg.parse_userauth_failure();
    assert!(parsed.is_some());
    
    let (partial_success, available_methods) = parsed.unwrap();
    assert_eq!(partial_success, vec!["publickey".to_string()]);
    assert_eq!(available_methods, vec!["password".to_string(), "publickey".to_string()]);
}

#[test]
fn test_password_encoding_with_special_characters() {
    // Test that passwords with special characters are encoded correctly
    let special_password = "p@ssw0rd!#$%&*()";
    
    let mut buf = BytesMut::new();
    ayssh::utils::string::write_string(&mut buf, special_password);
    
    // Should encode as length-prefixed string
    assert!(buf.len() > special_password.len());
    
    // Decode and verify - create a new buf from the data
    let mut decode_buf = &buf[..];
    let decoded = ayssh::protocol::types::SshString::decode(&mut decode_buf).unwrap();
    assert_eq!(decoded.to_str().unwrap(), special_password);
}

#[test]
fn test_password_auth_empty_password() {
    // Test that empty passwords are handled (they should be allowed in SSH)
    let mut msg = Message::with_type(MessageType::UserauthRequest);
    
    msg.write_string(b"alice");
    msg.write_string(b"ssh-connection");
    msg.write_string(b"password");
    msg.write_bool(false);
    msg.write_string(b""); // Empty password
    
    let parsed = msg.parse_userauth_request().unwrap();
    assert_eq!(parsed.1, "ssh-connection");
    // Empty password should still be parseable
}

#[test]
fn test_password_auth_unicode_password() {
    // Test that unicode passwords are handled correctly
    let unicode_password = "пароль密码🔐";
    
    let mut msg = Message::with_type(MessageType::UserauthRequest);
    msg.write_string(b"alice");
    msg.write_string(b"ssh-connection");
    msg.write_string(b"password");
    msg.write_bool(false);
    msg.write_string(unicode_password.as_bytes());
    
    let parsed = msg.parse_userauth_request().unwrap();
    assert_eq!(parsed.0, "alice");
    assert_eq!(parsed.1, "ssh-connection");
    assert_eq!(parsed.2, "password");
    assert_eq!(parsed.3, false); // first attempt
}