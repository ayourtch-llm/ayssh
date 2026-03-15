# End-to-End SSH Authentication & Channel Operations Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement complete SSH authentication (password + publickey) and channel operations (shell, exec, subsystem) with real sshd integration tests.

**Architecture:** 
- Extend TestServer infrastructure to support authentication testing
- Implement password authentication handler in client
- Implement publickey authentication with signature verification
- Implement channel operations for shell, exec, and subsystem commands
- Write comprehensive TDD tests for each feature

**Tech Stack:**
- Rust, Tokio (async runtime)
- Real `sshd` process for testing
- Ed25519, RSA, ECDSA key types
- ChaCha20-Poly1305, AES-GCM, AES-CBC ciphers
- SHA2, HMAC-SHA2-256/512 for authentication

---

## Task 1: Create Password Authentication Test

**Files:**
- Create: `tests/integration/e2e_password_auth_tests.rs`
- Modify: `tests/integration/mod.rs` (add module)

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn test_e2e_password_auth_basic() -> Result<(), Box<dyn std::error::Error>> {
    // Create server with test user
    let server = TestServerBuilder::new()
        .with_keys(vec![KeyType::Ed25519])
        .build()?;

    // Create user with password "test123"
    let user = "testuser";
    let password = "test123";
    let public_key = /* extract from server's public key */;
    create_test_user_with_password(&server, user, password, &public_key)?;

    // Attempt password authentication
    let client = ClientBuilder::new()
        .host("127.0.0.1")
        .port(server.port())
        .user(user)
        .build();

    let result = client.auth_password(password).await;
    
    assert!(result.is_ok(), "Password auth should succeed");
    
    Ok(())
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test --test mod e2e_password_auth_basic -- --nocapture`
Expected: FAIL with "password authentication not implemented"

**Step 3: Implement minimal password authentication**

Create `src/auth/password.rs` with minimal implementation.

**Step 4: Run test to verify it passes**

Run: `cargo test --test mod e2e_password_auth_basic -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add tests/integration/e2e_password_auth_tests.rs src/auth/password.rs tests/integration/mod.rs
git commit -m "feat: add password authentication test infrastructure"
```

---

## Task 2: Implement Password Authentication Handler

**Files:**
- Create: `src/auth/password.rs`
- Modify: `src/auth/mod.rs` (export module)
- Modify: `src/transport/encrypted.rs` (add auth handler)

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn test_password_auth_message_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Test the exact message exchange:
    // 1. Client sends USERAUTH_REQUEST with PASSWORD service
    // 2. Server responds with USERAUTH_FAILURE or SUCCESS
    // 3. Client receives response
    // Verify message encoding/decoding
}
```

**Step 2: Run test to verify it fails**

Expected: FAIL with "password auth module not found"

**Step 3: Implement password auth handler**

```rust
pub struct PasswordAuthenticator {
    username: String,
    password: String,
}

impl PasswordAuthenticator {
    pub fn new(username: &str, password: &str) -> Self { ... }
    
    pub fn build_request(&self) -> Message { ... }
    
    pub fn parse_response(&self, msg: &Message) -> Result<(), SshError> { ... }
}
```

**Step 4: Run test to verify it passes**

Expected: PASS

**Step 5: Commit**

```bash
git add src/auth/password.rs src/auth/mod.rs
git commit -m "feat: implement password authentication handler"
```

---

## Task 3: Implement Publickey Authentication

**Files:**
- Create: `src/auth/publickey.rs` (extend existing)
- Modify: `src/auth/mod.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn test_publickey_auth_ed25519() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new()
        .with_keys(vec![KeyType::Ed25519])
        .build()?;

    let user = "testuser";
    let public_key = /* server's public key */;
    let private_key = /* extract private key bytes */;
    
    create_test_user(&server, user, &public_key)?;

    let client = ClientBuilder::new()
        .host("127.0.0.1")
        .port(server.port())
        .user(user)
        .auth_method(AuthMethod::PublicKey(private_key))
        .build();

    let result = client.auth_publickey().await;
    assert!(result.is_ok(), "Publickey auth should succeed");
    
    Ok(())
}
```

**Step 2: Run test to verify it fails**

Expected: FAIL with "publickey signature verification not implemented"

**Step 3: Implement publickey auth**

```rust
pub struct PublickeyAuthenticator {
    username: String,
    private_key: PrivateKey,
    key_type: KeyType,
}

impl PublickeyAuthenticator {
    pub fn sign(&self, session_id: &[u8], service: &str) -> Result<SshSignature, SshError> { ... }
    
    pub fn build_request(&self, signature: &SshSignature) -> Message { ... }
}
```

**Step 4: Run test to verify it passes**

Expected: PASS

**Step 5: Commit**

```bash
git add src/auth/publickey.rs
git commit -m "feat: implement publickey authentication with signature"
```

---

## Task 4: Test Publickey Auth with Multiple Key Types

**Files:**
- Modify: `tests/integration/e2e_password_auth_tests.rs`

**Step 1: Write failing tests**

```rust
#[tokio::test]
async fn test_publickey_rsa_2048() -> Result<(), Box<dyn std::error::Error>> { ... }

#[tokio::test]
async fn test_publickey_ecdsa_p256() -> Result<(), Box<dyn std::error::Error>> { ... }

#[tokio::test]
async fn test_publickey_ecdsa_p384() -> Result<(), Box<dyn std::error::Error>> { ... }
```

**Step 2: Run tests to verify they fail**

Expected: FAIL with "key type not supported" or "signature algorithm unknown"

**Step 3: Implement key type support**

Add support for RSA, ECDSA P-256/384/521 in `src/auth/publickey.rs`

**Step 4: Run tests to verify they pass**

Expected: All 3 tests PASS

**Step 5: Commit**

```bash
git add tests/integration/e2e_password_auth_tests.rs src/auth/publickey.rs
git commit -m "feat: add publickey auth tests for RSA and ECDSA key types"
```

---

## Task 5: Implement Session Channel Opening

**Files:**
- Create: `src/channel/session.rs`
- Modify: `src/channel/mod.rs`
- Modify: `src/channel/types.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn test_open_session_channel() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new().build()?;
    let client = authenticate_client(&server).await?;

    let channel = client.open_session().await?;
    
    assert_eq!(channel.channel_type, "session");
    assert!(channel.id > 0);
    
    Ok(())
}
```

**Step 2: Run test to verify it fails**

Expected: FAIL with "session channel not implemented"

**Step 3: Implement session channel**

```rust
pub struct SessionChannel {
    id: ChannelId,
    window_size: u32,
    max_packet_size: u32,
}

impl SessionChannel {
    pub async fn open(client: &mut Client) -> Result<Self, SshError> { ... }
    
    pub fn send_request(&mut self, request: &str, want_reply: bool) -> Result<(), SshError> { ... }
}
```

**Step 4: Run test to verify it passes**

Expected: PASS

**Step 5: Commit**

```bash
git add src/channel/session.rs src/channel/mod.rs
git commit -m "feat: implement session channel opening"
```

---

## Task 6: Implement Shell Command Execution

**Files:**
- Modify: `src/channel/session.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn test_shell_command() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new().build()?;
    let mut client = authenticate_client(&server).await?;
    let mut channel = client.open_session().await?;

    channel.request_shell()?;
    
    // Give shell time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Shell should be ready
    assert!(channel.is_active());
    
    Ok(())
}
```

**Step 2: Run test to verify it fails**

Expected: FAIL with "shell request not implemented"

**Step 3: Implement shell request**

```rust
impl SessionChannel {
    pub fn request_shell(&mut self) -> Result<(), SshError> {
        self.send_request("shell", true)
    }
}
```

**Step 4: Run test to verify it passes**

Expected: PASS

**Step 5: Commit**

```bash
git add src/channel/session.rs
git commit -m "feat: implement shell request in session channel"
```

---

## Task 7: Implement Exec Command

**Files:**
- Modify: `src/channel/session.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn test_exec_command() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new().build()?;
    let mut client = authenticate_client(&server).await?;
    let mut channel = client.open_session().await?;

    let output = channel.exec("echo hello").await?;
    
    assert_eq!(output, "hello\n");
    
    Ok(())
}
```

**Step 2: Run test to verify it fails**

Expected: FAIL with "exec not implemented"

**Step 3: Implement exec**

```rust
impl SessionChannel {
    pub async fn exec(&mut self, command: &str) -> Result<String, SshError> {
        self.send_request("exec", true, command)?;
        self.read_output().await
    }
}
```

**Step 4: Run test to verify it passes**

Expected: PASS

**Step 5: Commit**

```bash
git add src/channel/session.rs
git commit -m "feat: implement exec command in session channel"
```

---

## Task 8: Implement Subsystem Request

**Files:**
- Modify: `src/channel/session.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn test_subsystem_sftp() -> Result<(), Box<dyn std::error::Error>> {
    let server = TestServerBuilder::new().build()?;
    let mut client = authenticate_client(&server).await?;
    let mut channel = client.open_session().await?;

    let result = channel.request_subsystem("sftp").await;
    assert!(result.is_ok(), "SFTP subsystem should start");
    
    Ok(())
}
```

**Step 2: Run test to verify it fails**

Expected: FAIL with "subsystem request not implemented"

**Step 3: Implement subsystem**

```rust
impl SessionChannel {
    pub async fn request_subsystem(&mut self, name: &str) -> Result<(), SshError> {
        self.send_request("subsystem", true, name)?;
        Ok(())
    }
}
```

**Step 4: Run test to verify it passes**

Expected: PASS

**Step 5: Commit**

```bash
git add src/channel/session.rs
git commit -m "feat: implement subsystem request"
```

---

## Task 9: Create Comprehensive E2E Test Suite

**Files:**
- Create: `tests/integration/e2e_auth_channel_tests.rs`

**Step 1: Write comprehensive tests**

```rust
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_full_auth_shell_flow() { ... }

    #[tokio::test]
    async fn test_full_auth_exec_flow() { ... }

    #[tokio::test]
    async fn test_multiple_channels_same_session() { ... }

    #[tokio::test]
    async fn test_channel_close_after_shell() { ... }

    #[tokio::test]
    async fn test_auth_failure_handling() { ... }
}
```

**Step 2: Run tests to verify they fail**

Expected: Multiple failures showing missing implementations

**Step 3: Implement all missing pieces**

Fill in all gaps from Tasks 1-8

**Step 4: Run tests to verify they pass**

Expected: All tests PASS

**Step 5: Commit**

```bash
git add tests/integration/e2e_auth_channel_tests.rs
git commit -m "feat: add comprehensive e2e auth and channel tests"
```

---

## Task 10: Final Verification and Documentation

**Files:**
- Modify: `README.md` (update with new features)
- Modify: `docs/IMPLEMENTATION_STATUS.md`

**Step 1: Run all tests**

```bash
cargo test --test mod 2>&1 | tail -20
```

Expected: All 500+ tests PASS

**Step 2: Update documentation**

Document new authentication methods and channel operations

**Step 3: Final commit**

```bash
git add README.md docs/IMPLEMENTATION_STATUS.md
git commit -m "docs: update implementation status with auth and channel features"
```

---

**Plan complete and saved to `docs/plans/2026-03-15-e2e-auth-channel.md`. Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**