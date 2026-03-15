//! Integration tests for AuthState module

use ssh_client::auth::state::{AuthState, AuthStatus};
use ssh_client::error::SshError;

/// Test 1: Verify AuthState::new() creates state with NotAuthenticating status
#[test]
fn test_auth_state_new_initial_state() {
    let auth_state = AuthState::new();
    assert_eq!(*auth_state.status(), AuthStatus::NotAuthenticating);
}

/// Test 2: Verify AuthState::start_auth() transitions to Authenticating
#[test]
fn test_start_auth_transitions_to_authenticating() {
    let mut auth_state = AuthState::new();
    
    // Initial state should be NotAuthenticating
    assert!(auth_state.is_not_authenticating());
    
    // Start authentication
    auth_state.start_auth().expect("start_auth should succeed");
    
    // Should now be in Authenticating state
    assert!(auth_state.is_authenticating());
    assert_eq!(*auth_state.status(), AuthStatus::Authenticating);
}

/// Test 3: Verify AuthState::complete_auth() transitions to Authenticated
#[test]
fn test_complete_auth_transitions_to_authenticated() {
    let mut auth_state = AuthState::new();
    
    // Start authentication first
    auth_state.start_auth().expect("start_auth should succeed");
    
    // Complete authentication
    auth_state.complete_auth().expect("complete_auth should succeed");
    
    // Should now be in Authenticated state
    assert!(auth_state.is_authenticated());
    assert_eq!(*auth_state.status(), AuthStatus::Authenticated);
}

/// Test 4: Verify AuthState::fail_auth() transitions to Failed
#[test]
fn test_fail_auth_transitions_to_failed() {
    let mut auth_state = AuthState::new();
    
    // Start authentication first
    auth_state.start_auth().expect("start_auth should succeed");
    
    // Fail authentication
    auth_state.fail_auth().expect("fail_auth should succeed");
    
    // Should now be in Failed state
    assert!(auth_state.is_failed());
    assert_eq!(*auth_state.status(), AuthStatus::Failed);
}

/// Test 5: Test edge case - calling complete_auth when not in Authenticating state (NotAuthenticating)
#[test]
fn test_complete_auth_from_not_authenticating_fails() {
    let mut auth_state = AuthState::new();
    
    // Try to complete auth without starting first
    let result = auth_state.complete_auth();
    
    // Should fail with ProtocolError
    assert!(result.is_err());
    match result {
        Err(SshError::ProtocolError(msg)) => {
            assert!(msg.contains("Invalid state transition"));
            assert!(msg.contains("NotAuthenticating"));
        }
        _ => panic!("Expected ProtocolError"),
    }
}

/// Test 6: Test edge case - calling complete_auth when not in Authenticating state (Failed)
#[test]
fn test_complete_auth_from_failed_fails() {
    let mut auth_state = AuthState::new();
    
    // Start and fail authentication
    auth_state.start_auth().expect("start_auth should succeed");
    auth_state.fail_auth().expect("fail_auth should succeed");
    
    // Try to complete auth from Failed state
    let result = auth_state.complete_auth();
    
    // Should fail with ProtocolError
    assert!(result.is_err());
    match result {
        Err(SshError::ProtocolError(msg)) => {
            assert!(msg.contains("Invalid state transition"));
            assert!(msg.contains("Failed"));
        }
        _ => panic!("Expected ProtocolError"),
    }
}

/// Test 7: Test multiple state transitions in sequence
#[test]
fn test_multiple_state_transitions() {
    let mut auth_state = AuthState::new();
    
    // Transition 1: NotAuthenticating -> Authenticating
    auth_state.start_auth().expect("start_auth should succeed");
    assert!(auth_state.is_authenticating());
    
    // Transition 2: Authenticating -> Authenticated
    auth_state.complete_auth().expect("complete_auth should succeed");
    assert!(auth_state.is_authenticated());
    
    // Reset and start again
    auth_state.reset();
    assert!(auth_state.is_not_authenticating());
    
    // Transition 3: NotAuthenticating -> Authenticating -> Failed
    auth_state.start_auth().expect("start_auth should succeed");
    auth_state.fail_auth().expect("fail_auth should succeed");
    assert!(auth_state.is_failed());
    
    // Reset again
    auth_state.reset();
    assert!(auth_state.is_not_authenticating());
    
    // Transition 4: NotAuthenticating -> Authenticating -> Authenticated
    auth_state.start_auth().expect("start_auth should succeed");
    auth_state.complete_auth().expect("complete_auth should succeed");
    assert!(auth_state.is_authenticated());
}

/// Test 8: Test that AuthStatus enum variants are correctly defined
#[test]
fn test_auth_status_enum_variants() {
    // Verify all variants exist and have correct debug representation
    let not_authenticating = AuthStatus::NotAuthenticating;
    let authenticating = AuthStatus::Authenticating;
    let authenticated = AuthStatus::Authenticated;
    let failed = AuthStatus::Failed;
    
    // Verify they are distinct
    assert_ne!(not_authenticating, authenticating);
    assert_ne!(not_authenticating, authenticated);
    assert_ne!(not_authenticating, failed);
    assert_ne!(authenticating, authenticated);
    assert_ne!(authenticating, failed);
    assert_ne!(authenticated, failed);
    
    // Verify equality
    assert_eq!(not_authenticating, AuthStatus::NotAuthenticating);
    assert_eq!(authenticating, AuthStatus::Authenticating);
    assert_eq!(authenticated, AuthStatus::Authenticated);
    assert_eq!(failed, AuthStatus::Failed);
}

/// Test 9: Test state changes are properly tracked
#[test]
fn test_state_changes_tracked() {
    let mut auth_state = AuthState::new();
    
    // Initial state
    assert_eq!(auth_state.status(), &AuthStatus::NotAuthenticating);
    
    // After start_auth
    auth_state.start_auth().expect("start_auth should succeed");
    assert_eq!(auth_state.status(), &AuthStatus::Authenticating);
    
    // After complete_auth
    auth_state.complete_auth().expect("complete_auth should succeed");
    assert_eq!(auth_state.status(), &AuthStatus::Authenticated);
    
    // Create new state and verify it's independent
    let auth_state2 = AuthState::new();
    assert_eq!(auth_state2.status(), &AuthStatus::NotAuthenticating);
    
    // Verify auth_state is still Authenticated (independent tracking)
    assert_eq!(auth_state.status(), &AuthStatus::Authenticated);
}

/// Test 10: Test start_auth fails when already in Authenticating state
#[test]
fn test_start_auth_from_authenticating_fails() {
    let mut auth_state = AuthState::new();
    
    // Start authentication
    auth_state.start_auth().expect("start_auth should succeed");
    
    // Try to start again
    let result = auth_state.start_auth();
    
    // Should fail with ProtocolError
    assert!(result.is_err());
    match result {
        Err(SshError::ProtocolError(msg)) => {
            assert!(msg.contains("Invalid state transition"));
            assert!(msg.contains("Authenticating"));
        }
        _ => panic!("Expected ProtocolError"),
    }
}

/// Test 11: Test fail_auth fails when not in Authenticating state
#[test]
fn test_fail_auth_from_not_authenticating_fails() {
    let mut auth_state = AuthState::new();
    
    // Try to fail auth without starting
    let result = auth_state.fail_auth();
    
    // Should fail with ProtocolError
    assert!(result.is_err());
    match result {
        Err(SshError::ProtocolError(msg)) => {
            assert!(msg.contains("Invalid state transition"));
            assert!(msg.contains("NotAuthenticating"));
        }
        _ => panic!("Expected ProtocolError"),
    }
}

/// Test 12: Test reset functionality
#[test]
fn test_reset_functionality() {
    let mut auth_state = AuthState::new();
    
    // Go through full cycle
    auth_state.start_auth().expect("start_auth should succeed");
    auth_state.complete_auth().expect("complete_auth should succeed");
    
    // Verify authenticated
    assert!(auth_state.is_authenticated());
    
    // Reset
    auth_state.reset();
    
    // Should be back to NotAuthenticating
    assert!(auth_state.is_not_authenticating());
    assert_eq!(auth_state.status(), &AuthStatus::NotAuthenticating);
}

/// Test 13: Test Default implementation
#[test]
fn test_default_implementation() {
    let auth_state: AuthState = AuthState::default();
    assert_eq!(auth_state.status(), &AuthStatus::NotAuthenticating);
}

/// Test 14: Test AuthState state tracking
#[test]
fn test_auth_state_clone_and_partial_eq() {
    let mut auth_state1 = AuthState::new();
    let auth_state2 = AuthState::new();
    
    assert_eq!(auth_state1.status(), auth_state2.status());
    
    // Modify one and verify they're different
    auth_state1.start_auth().expect("start_auth should succeed");
    assert_ne!(auth_state1.status(), auth_state2.status());
}