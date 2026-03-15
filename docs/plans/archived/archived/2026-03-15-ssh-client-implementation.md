# SSH Client Library Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a production-ready SSH client library with test-first approach, architected for future server support, with code quality as a primary concern.

**Architecture:** Client-first approach with clean protocol layer abstraction. Test-driven development with integration tests against real servers. Code refactoring happens in parallel with feature work.

**Tech Stack:** Rust, Tokio (async), `bytes` (buffering), `ring`/`aws-lc-rs` (crypto), `thiserror` (errors), `testcontainers` (integration tests)

**Date:** 2026-03-15

---

## Phase 0: Foundation & Test Infrastructure

### Task 0.1: Fix Cargo.toml Dependencies

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add missing dependencies**

```toml
[dependencies]
# Existing dependencies...
bytes = "1.5"           # Buffer operations for SSH protocol
zeroize = "1.7"         # Secure memory zeroing
anyhow = "1.0"          # Error handling
hex = "0.4"             # Hex encoding (already listed, verify version)

# Crypto (add for implementation)
ring = "0.17"           # Low-level crypto primitives
subtle = "2.5"          # Constant-time operations

# Testing (dev-dependencies)
[dev-dependencies]
# Existing...
tokio-test = "0.4"
tempfile = "3.9"        # Temp files for key testing
```

**Step 2: Verify project compiles**

Run: `cargo check`
Expected: No errors, all dependencies resolve

**Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "build: add missing dependencies for SSH implementation"
```

---

### Task 0.2: Consolidate Error Types

**Files:**
- Create: `src/error.rs` (unified error types)
- Delete: `src/errors.rs`
- Modify: `src/protocol/types.rs` (remove duplicate SshError)
- Modify: All files referencing errors

**Step 1: Create unified error type**

```rust
// src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SshError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    #[error("Channel error: {0}")]
    ChannelError(String),
    
    #[error("Session error: {0}")]
    SessionError(String),
    
    #[error("Crypto error: {0}")]
    CryptoError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

// Protocol-specific errors
#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),
    
    #[error("Invalid message format: {0}")]
    InvalidMessageFormat(String),
    
    #[error("Algorithm negotiation failed: {0}")]
    AlgorithmNegotiationFailed(String),
    
    #[error("Protocol state error: {0}")]
    ProtocolStateError(String),
    
    #[error("Unexpected message type {0} in state {1}")]
    UnexpectedMessage(u8, String),
}

// Connection-specific errors
#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("Connection disconnected")]
    Disconnected,
    
    #[error("Connection timeout")]
    Timeout,
    
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Channel operation failed: {0}")]
    ChannelError(String),
}
```

**Step 2: Remove duplicate error files**

Run: `rm src/errors.rs`

**Step 3: Update protocol/types.rs**

Remove the duplicate `SshError` enum and use `crate::error::SshError` instead.

**Step 4: Update all imports**

Search for and update: `use crate::errors::SshError` → `use crate::error::SshError`

**Step 5: Test compilation**

Run: `cargo check`
Expected: No errors

**Step 6: Commit**

```bash
git add src/error.rs src/protocol/types.rs
git rm src/errors.rs
git commit -m "refactor: consolidate error types into single source of truth"
```

---

### Task 0.3: Fix Module Structure Issues

**Files:**
- Modify: `src/protocol/mod.rs` (add AuthMethod)
- Modify: `src/auth/methods.rs` (use correct AuthMethod)
- Modify: `src/lib.rs` (export all modules)

**Step 1: Add AuthMethod to protocol/types.rs**

```rust
// Add to src/protocol/types.rs
/// Authentication methods (RFC 4252)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    None,
    Password,
    PublicKey,
    KeyboardInteractive,
}
```

**Step 2: Update auth/methods.rs**

Change `protocol::AuthMethod` to use the new definition.

**Step 3: Update lib.rs exports**

Ensure all modules are properly exported:

```rust
pub mod auth;
pub mod channel;
pub mod client;
pub mod config;
pub mod connection;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod protocol;
pub mod session;
pub mod transport;
pub mod utils;

pub use config::Config;
pub use connection::Connection;
pub use error::SshError;
pub use protocol::{AuthMethod, MessageType};
pub use session::Session;
```

**Step 4: Test compilation**

Run: `cargo check`
Expected: No errors

**Step 5: Commit**

```bash
git add src/protocol/mod.rs src/protocol/types.rs src/auth/methods.rs src/lib.rs
git commit -m "refactor: fix module structure and AuthMethod definition"
```

---

### Task 0.4: Create Integration Test Infrastructure

**Files:**
- Create: `tests/integration/mod.rs`
- Create: `tests/integration/helpers.rs`
- Create: `tests/integration/fixtures/` directory

**Step 1: Create test module structure**

```rust
// tests/integration/mod.rs
mod helpers;
mod handshake_tests;
mod auth_tests;
mod connection_tests;

use helpers::*;
```

**Step 2: Create helper utilities**

```rust
// tests/integration/helpers.rs
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Start a test SSH server using sshd
pub fn start_test_server() -> TestServer {
    let temp_dir = TempDir::new().unwrap();
    let auth_key_path = temp_dir.path().join("id_ed25519");
    
    // Generate test key
    Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f", &auth_key_path, "-N", ""])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .expect("Failed to generate test key");
    
    // Setup authorized_keys
    let auth_file = temp_dir.path().join("authorized_keys");
    Command::new("cat")
        .arg(&auth_key_path)
        .arg(".pub")
        .output()
        .expect("Failed to read public key");
    
    // Start sshd
    let mut child = Command::new("sshd")
        .arg("-f")
        .arg(temp_dir.path().join("sshd_config"))
        .arg("-d") // Debug mode
        .spawn()
        .expect("Failed to start sshd");
    
    TestServer {
        temp_dir,
        child,
        port: 2222,
    }
}

pub struct TestServer {
    temp_dir: TempDir,
    child: std::process::Child,
    port: u16,
}

impl TestServer {
    pub fn port(&self) -> u16 {
        self.port
    }
    
    pub fn auth_key_path(&self) -> std::path::PathBuf {
        self.temp_dir.path().join("id_ed25519")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
```

**Step 3: Create first integration test skeleton**

```rust
// tests/integration/handshake_tests.rs
use crate::helpers::*;

#[tokio::test]
async fn test_protocol_version_exchange() {
    let server = start_test_server();
    
    // TODO: Implement actual test
    panic!("Test not yet implemented");
}
```

**Step 4: Test test infrastructure**

Run: `cargo test --test integration -- --nocapture`
Expected: Test framework loads, tests show "not yet implemented"

**Step 5: Commit**

```bash
git add tests/
git commit -m "test: add integration test infrastructure with test server helpers"
```

---

## Phase 1: Protocol Foundation (Test-First)

### Task 1.1: Test SSH String Encoding

**Files:**
- Create: `tests/integration/encoding_tests.rs`
- Modify: `src/protocol/types.rs` (implement SshString)

**Step 1: Write failing test**

```rust
// tests/integration/encoding_tests.rs
use bytes::{BufMut, BytesMut};
use ssh_client::protocol::{SshString, SshUint32};

#[test]
fn test_ssh_string_encode_decode() {
    let original = SshString::from_str("hello world");
    let mut buf = BytesMut::with_capacity(20);
    original.encode(&mut buf);
    
    let mut read_buf = &buf[..];
    let decoded = SshString::decode(&mut read_buf).unwrap();
    
    assert_eq!(original, decoded);
}

#[test]
fn test_ssh_string_with_null_bytes() {
    // SSH strings can contain null bytes
    let original = SshString::new(bytes::Bytes::from_static(b"hello\x00world"));
    let mut buf = BytesMut::new();
    original.encode(&mut buf);
    
    let mut read_buf = &buf[..];
    let decoded = SshString::decode(&mut read_buf).unwrap();
    
    assert_eq!(original.as_bytes(), decoded.as_bytes());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test integration test_ssh_string_encode_decode`
Expected: Test fails (function not implemented or wrong behavior)

**Step 3: Implement minimal code to pass**

Verify `src/protocol/types.rs` has working `SshString` implementation (it should already be there from the partial implementation).

**Step 4: Run test to verify it passes**

Run: `cargo test --test integration test_ssh_string_encode_decode`
Expected: PASS

**Step 5: Commit**

```bash
git add tests/integration/encoding_tests.rs src/protocol/types.rs
git commit -m "test: add SSH string encoding tests"
```

---

### Task 1.2: Test Transport State Machine

**Files:**
- Create: `tests/integration/state_machine_tests.rs`
- Modify: `src/transport/state.rs` (ensure tests exist)

**Step 1: Write integration test**

```rust
// tests/integration/state_machine_tests.rs
use ssh_client::transport::state::{State, TransportStateMachine};
use ssh_client::protocol::MessageType;

#[tokio::test]
async fn test_complete_handshake_flow() {
    let mut sm = TransportStateMachine::new();
    
    // Start in Handshake
    assert_eq!(sm.current_state(), State::Handshake);
    
    // Receive server KEXINIT
    sm.process_message(MessageType::KexInit).unwrap();
    assert_eq!(sm.current_state(), State::KeyExchange);
    
    // Key exchange messages
    sm.process_message(MessageType::KexInit).unwrap();
    assert_eq!(sm.current_state(), State::KeyExchange);
    
    // Receive NEWKEYS
    sm.process_message(MessageType::Newkeys).unwrap();
    assert_eq!(sm.current_state(), State::Established);
    
    // Now can process channel messages
    sm.process_message(MessageType::ChannelOpen).unwrap();
    assert_eq!(sm.current_state(), State::Established);
}

#[tokio::test]
async fn test_invalid_state_transitions() {
    let mut sm = TransportStateMachine::new();
    
    // Cannot skip KeyExchange
    let result = sm.process_message(MessageType::Newkeys);
    assert!(result.is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test integration test_complete_handshake_flow`
Expected: FAIL (if state machine has issues) or PASS (if already correct)

**Step 3: Fix any issues found**

**Step 4: Commit**

```bash
git add tests/integration/state_machine_tests.rs
git commit -m "test: add transport state machine integration tests"
```

---

## Phase 2: Transport Layer Implementation

### Task 2.1: Implement Version Exchange

**Files:**
- Modify: `src/transport/handshake.rs`
- Create: `tests/integration/version_tests.rs`

**Step 1: Write test for version parsing**

```rust
// tests/integration/version_tests.rs
#[test]
fn test_parse_server_version() {
    let version = b"SSH-2.0-libssh_0.9.6";
    let (proto, software) = ssh_client::transport::handshake::parse_version_string(version).unwrap();
    
    assert_eq!(proto, 2);
    assert_eq!(software, "libssh_0.9.6");
}
```

**Step 2: Implement version exchange**

Ensure `src/transport/handshake.rs` has working `parse_version_string` and `SSH_VERSION_STRING` constant.

**Step 3: Commit**

```bash
git add src/transport/handshake.rs tests/integration/version_tests.rs
git commit -m "feat: implement SSH version exchange"
```

---

### Task 2.2: Implement Algorithm Negotiation

**Files:**
- Modify: `src/protocol/algorithms.rs`
- Modify: `src/transport/handshake.rs`
- Create: `tests/integration/algo_tests.rs`

**Step 1: Write test**

```rust
#[test]
fn test_algorithm_selection() {
    let client = ssh_client::protocol::AlgorithmProposal::client_proposal();
    let server = ssh_client::protocol::AlgorithmProposal::server_proposal();
    
    let negotiated = client.select_common_algorithms(&server).unwrap();
    
    assert!(!negotiated.kex_algorithm.is_empty());
}
```

**Step 2: Implement**

**Step 3: Commit**

```bash
git add src/protocol/algorithms.rs src/transport/handshake.rs tests/integration/algo_tests.rs
git commit -m "feat: implement algorithm negotiation"
```

---

## Phase 3: Cryptographic Primitives

### Task 3.1: Implement HMAC-SHA256

**Files:**
- Create: `src/crypto/hmac.rs`
- Create: `tests/integration/crypto_tests.rs`

**Step 1: Write test with known vectors**

```rust
#[test]
fn test_hmac_sha256_known_vector() {
    // RFC 4253 test vector
    let key = b"01234567890123456789012345678901";
    let data = b"abc";
    let expected = hex::decode("...").unwrap(); // Known HMAC value
    
    let result = ssh_client::crypto::hmac::hmac_sha256(key, data);
    assert_eq!(result, expected);
}
```

**Step 2: Implement using `ring` crate**

**Step 3: Commit**

```bash
git add src/crypto/hmac.rs tests/integration/crypto_tests.rs
git commit -m "feat: implement HMAC-SHA256"
```

---

## Phase 4: Key Exchange

### Task 4.1: Implement ECDH Key Exchange

**Files:**
- Modify: `src/transport/kex.rs`
- Create: `src/crypto/ecdh.rs`
- Create: `tests/integration/kex_tests.rs`

**Step 1: Write test**

**Step 2: Implement**

**Step 3: Commit**

---

## Phase 5: Authentication

### Task 5.1: Implement Public Key Authentication

**Files:**
- Modify: `src/auth/publickey.rs`
- Create: `tests/integration/auth_tests.rs`

**Step 1: Write integration test with real server**

**Step 2: Implement**

**Step 3: Commit**

---

## Phase 6: Connection & Channels

### Task 6.1: Implement Channel Management

**Files:**
- Modify: `src/channel.rs`
- Modify: `src/connection/mod.rs`
- Create: `tests/integration/channel_tests.rs`

**Step 1: Write test**

**Step 2: Implement**

**Step 3: Commit**

---

## Phase 7: Client Integration

### Task 7.1: Implement Main Client API

**Files:**
- Modify: `src/client.rs`
- Modify: `src/session.rs`
- Create: `tests/integration/client_tests.rs`

**Step 1: Write integration test**

```rust
#[tokio::test]
async fn test_full_client_flow() {
    let server = start_test_server();
    
    let config = Config::new()
        .with_host("localhost")
        .with_port(server.port())
        .with_username("testuser");
    
    let mut client = Client::new(config);
    client.connect().await.unwrap();
    client.authenticate(AuthMethod::PublicKey).await.unwrap();
    
    // Session is now established
    assert!(client.is_authenticated());
}
```

**Step 2: Implement**

**Step 3: Commit**

---

## Phase 8: Server Example

### Task 8.1: Create Server Example Binary

**Files:**
- Create: `examples/server.rs`
- Modify: `Cargo.toml` (add example)

**Step 1: Create minimal server**

**Step 2: Test against client**

**Step 3: Commit**

---

## Execution Notes

**Workflow:** TDD (Test-Driven Development) for each task

**Testing Strategy:**
1. Write failing test first
2. Run test to confirm failure
3. Implement minimal code to pass
4. Run test to confirm pass
5. Commit

**Code Quality Requirements:**
- All code must pass `cargo clippy`
- All code must pass `cargo fmt`
- Integration tests must pass against real SSH servers
- No duplicate code between client and future server

**Server Architecture Principle:**
- Protocol layer (`ssh_protocol`) is shared
- Client and server are separate crates/binaries
- Both use the same underlying primitives

---

## Execution Handoff

**Plan saved to:** `docs/plans/2026-03-15-ssh-client-implementation.md`

**Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**