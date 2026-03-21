# Meta-Learnings from ayssh Development Sessions

Generalized rules and patterns discovered during development that should be applied universally in future work.

## Testing

### Never accept flaky tests
- A "rarely fails" test WILL fail at the worst time. Treat any intermittent failure as a real bug.
- Root cause analysis is always worth it — the fix is usually simple once understood.
- **Mutex poisoning cascade**: one panicking test poisons a shared mutex, causing ALL subsequent tests to fail with `PoisonError`. Use `lock().unwrap_or_else(|e| e.into_inner())` to recover.
- **TCP listen race**: binding a port in a spawned thread + tokio runtime means the port might not be ready when the client connects. Bind the `std::net::TcpListener` on the **calling thread** (synchronous), then convert to tokio inside the spawned thread. The race is then structurally impossible.
- **Server close race**: if the server sends data and immediately drops the connection, the client may get TCP RST before reading the data. Wait for the client's CLOSE acknowledgment before dropping.

### Test error paths especially thoroughly
- Error paths are exercised least in production — that's exactly where bugs hide.
- Every `Result::Err` return, every `match` arm, every default trait method should have a test.
- "Minor edge case" is not a reason to skip testing — it's a reason to prioritize it.

### Interop testing is invaluable
- Self-tests (our client ↔ our server) only prove they agree with each other. If both have the same encoding bug, the test passes silently.
- Always test against real implementations (OpenSSH sshd, ssh, sftp CLIs).
- Start sshd/ssh in the test process with full control over config — don't depend on system sshd.
- Use `LogLevel DEBUG3` on test sshd to diagnose protocol issues.

### Use stress testing to find races
- `stress --cpu 16 --io 4` while running tests reveals timing-dependent bugs that normal runs miss.
- Run at least 10 iterations under stress before declaring "no flakiness."

## Protocol Implementation

### Read the RFC, but test against real implementations
- The RFC tells you the format. The real implementation tells you what actually happens.
- OpenSSH has extensions and behaviors not in any RFC (kex-strict, pipelining, etc.).

### SSH channel window management is critical
- **Client must send WINDOW_ADJUST** after consuming CHANNEL_DATA — without it, the server stops sending after the initial window (~1MB). Large file transfers will silently truncate.
- **Server must send WINDOW_ADJUST** to the client after receiving data — same issue in reverse.
- **During uploads, drain incoming WINDOW_ADJUST messages** between send chunks to prevent the upload from stalling.

### kex-strict (CVE-2023-48795) is mandatory for modern OpenSSH
- Modern OpenSSH (9.6+) advertises `kex-strict-s-v00@openssh.com` and resets sequence numbers after NEWKEYS.
- If you don't implement kex-strict, chacha20-poly1305 will fail because the nonce (derived from sequence number) will be wrong.
- The fix is simple: advertise `kex-strict-c-v00@openssh.com`, detect the server's extension, reset send/recv sequence numbers to 0 after NEWKEYS.

### SFTP packet pipelining
- Real SFTP clients (OpenSSH's sftp) pipeline multiple requests in a single CHANNEL_DATA message.
- The server MUST process ALL complete SFTP packets in its buffer, not just one per SSH message.
- Failing to do this causes the server to block on `recv_message()` waiting for data that's already in the buffer.

### Padding alignment differs by cipher
- For standard ciphers: total packet (4 + packet_length) must be block-aligned.
- For ChaCha20-Poly1305: just packet_length must be block-aligned (length is encrypted separately).
- For AES-GCM/ETM: the encrypted portion alignment (without the cleartext length field).

### Signature encoding varies by key type
- RSA: `SshSignature.data` = raw signature bytes. `encode()` wraps with algorithm prefix.
- Ed25519: `SshSignature.data` = raw 64-byte signature. Same wrapping.
- ECDSA: `SshSignature.data` = `mpint(r) || mpint(s)`. Must include 0x00 prefix when high bit is set.
- **Never double-encode**: if `data` already contains the algorithm prefix, `encode()` will add it again.

## Rust / Async Patterns

### Handler closures need Send + Sync for async contexts
- `Box<dyn Fn(...) + Send>` is NOT enough — `&Box<dyn Fn + Send>` requires `Sync` to be `Send`.
- Always use `Box<dyn Fn(...) + Send + Sync>` for closures stored in structs that cross `.await` points.
- This affects `async_trait` and `tokio::spawn` — the future must be `Send`.

### Async-in-sync-trait is hard
- Don't try to implement `tokio::io::AsyncRead` by polling a `receive()` future inside `poll_read()` — it doesn't work without unsafe pinning gymnastics.
- Instead, provide a chunk-based async API (`read_chunk() -> Vec<u8>`) and let callers wrap it.

### Server thread panics poison shared state
- Never let server threads in tests panic — use error channels instead.
- Report errors via `mpsc::channel`, check after the client finishes.
- This prevents mutex poisoning and gives clearer error messages.

## API Design

### Make security decisions explicit
- No default host key verifier — force the caller to choose `AcceptAll`, `TofuStore`, etc.
- "Accept all" should be the explicit choice for testing, not the implicit default.
- Never modify `~/.ssh/known_hosts` in tests — use temp files or in-memory stores.

### Streaming APIs alongside buffered ones
- Always provide both `Vec<u8>` convenience methods AND streaming variants.
- Streaming prevents OOM on large files and enables progress tracking.
- The streaming API should return content_length when known, for progress bars.

### Separate policy from storage
- Host key verification: the **verifier** (AcceptAll, TOFU, Strict) is separate from the **store** (memory, file).
- SFTP server: the **protocol handler** is separate from the **backend** (MemoryFs, FilesystemFs).

### Debug impls should hide sensitive data
- Use `finish_non_exhaustive()` for types containing passwords, keys, or crypto state.
- Show booleans like `has_password: true` instead of the actual password.

## Development Process

### TDD for bug fixes
- Reproduce the bug with a failing test FIRST, then fix the code.
- The test becomes the regression guard.
- Example: the WINDOW_ADJUST bug was reproduced with a 2MB upload test before fixing.

### Subagents for parallel independent work
- Use background agents for features that touch different files (e.g., port forwarding + connection type).
- Verify combined results after both complete — check for conflicts.

### Keep compiler warnings at zero
- Run `unset RUSTFLAGS && cargo test --no-run` to catch warnings that RUSTFLAGS might suppress.
- Fix warnings immediately — they accumulate fast and hide real issues.
- Use `_prefix` for intentionally unused variables, `#[allow(dead_code)]` for intentionally unused constants/fields.

### Coverage is a signal, not a target
- High coverage doesn't mean good tests — but uncovered code definitely has no tests.
- Error paths and edge cases are MORE important to test than happy paths.
- async_trait can cause tarpaulin artifacts (1 line showing uncovered when it's actually exercised).
