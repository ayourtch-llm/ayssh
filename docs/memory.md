# Session Memory — ayssh Development

## Current State (as of 2026-03-21)

### Coverage & Tests
- **Overall coverage: 83.79% (6861/8188 lines)**
- **951 lib tests, 1580+ total across all binaries**
- **0 failures, 0 flaky tests, 0 compiler warnings**
- Verified under `stress --cpu 16 --io 4` — 10/10 clean

### Architecture Overview

```
ayssh/
├── src/
│   ├── agent.rs           — SSH agent client (98% coverage, fully working)
│   ├── auth/
│   │   ├── mod.rs         — Authenticator with fallback + callback (79%)
│   │   ├── key.rs         — Key parsing: RSA/Ed25519/ECDSA P-256/384/521 (83%)
│   │   ├── keyboard.rs    — Keyboard-interactive auth (65%)
│   │   ├── signature.rs   — Signature encoding for all key types
│   │   ├── methods.rs     — Auth method management
│   │   └── state.rs       — Auth state machine
│   ├── channel/           — SSH channel types and management
│   ├── cisco_conn.rs      — Cisco-specific connection (12%, needs live device)
│   ├── cisco_ssh.rs       — Cisco SSH wrapper (14%, needs live device)
│   ├── client.rs          — SshClient (82%)
│   ├── config.rs          — Configuration (85%)
│   ├── connection/
│   │   ├── mod.rs         — SshConnection + SshConnectionBuilder (99%)
│   │   └── state.rs       — Connection state machine (77%)
│   ├── crypto/            — All crypto primitives (87-100%)
│   ├── error.rs           — Error types (80%)
│   ├── host_key_verify.rs — Host key verification trait + impls (98%)
│   ├── known_hosts.rs     — Known hosts parsing (85%)
│   ├── multiplex.rs       — Connection multiplexing (87%)
│   ├── port_forward.rs    — TCP port forwarding (100%)
│   ├── raw_session.rs     — RawSshSession vendor-neutral API (84%)
│   ├── server/
│   │   ├── encrypted_io.rs — Server-side encrypted I/O
│   │   ├── host_key.rs    — Host keys: Ed25519/RSA/ECDSA P-256/384/521
│   │   ├── sftp_server.rs — SFTP server with trait-based handler (86%)
│   │   └── test_server.rs — Test SSH server with auth behaviors
│   ├── session/           — Session management, PTY, shell, exec
│   ├── sftp.rs            — SCP + SFTP client with streaming APIs (87%)
│   ├── transport/
│   │   ├── mod.rs         — Core transport with all cipher modes (86%)
│   │   ├── handshake.rs   — SSH handshake + algorithm negotiation
│   │   ├── kex.rs         — Key exchange for all algorithms
│   │   └── ...            — packet, state, version, cipher, etc.
│   └── unix_conn.rs       — Unix SSH connection (4%, needs live server)
├── tests/
│   ├── ssh_client_interop.rs — Real OpenSSH client → our server (19 tests)
│   ├── sshd_interop.rs      — Our client → real OpenSSH sshd (26 tests)
│   └── integration/         — 565 integration tests
└── tests/keys/              — Test keypairs (Ed25519, RSA 2048/4096/8192, ECDSA P-256/384/521)
```

### Features Implemented

#### Core SSH
- **All 8 ciphers**: aes128/192/256-cbc, aes128/192/256-ctr, aes128/256-gcm, chacha20-poly1305
- **All 6 MACs**: hmac-sha1, hmac-sha2-256, hmac-sha2-512, + ETM variants
- **All 7 KEX**: DH group1/14 (SHA-1/SHA-256), curve25519, ECDH P-256/384/521
- **kex-strict (CVE-2023-48795)**: Terrapin mitigation implemented
- **WINDOW_ADJUST**: Both client and server sides for large file transfers

#### Authentication
- **7 key types**: Ed25519, RSA-2048/4096/8192, ECDSA P-256/384/521
- **SSH agent**: Full client connecting via SSH_AUTH_SOCK
- **Auth fallback**: Ordered method list with callback handler
- **Keyboard-interactive**: Challenge-response support
- **Password auth**: Standard password authentication

#### Host Key Verification
- `HostKeyVerifier` async trait — mandatory, no default
- `AcceptAll` / `RejectAll` / `TofuStore` / `TofuFileStore` / `StrictFileStore` / `CallbackVerifier`
- Wired into `Transport::handshake_with_verifier()`

#### File Transfer
- **SCP**: upload/download with password and pubkey auth
- **SCP streaming**: `download_stream()` → `SshChannelReader`, `upload_stream()` from AsyncRead
- **SFTP client**: open/read/write/close/stat/remove + `read_file()`/`write_file()`/`write_file_stream()`
- **SFTP server**: `SftpHandler` trait + `MemoryFs` backend, handles all SFTP v3 operations including REALPATH, FSTAT, OPENDIR, READDIR

#### High-Level APIs
- **RawSshSession**: Vendor-neutral byte-stream over SSH channel
- **SshConnection**: Builder pattern with `connect()`, `send()`, `receive()`, `exec()`, `disconnect()`
- **MultiplexedConnection**: Multiple sessions over one transport

#### Other
- **TCP port forwarding**: LocalForward (direct-tcpip), RemoteForwardRequest
- **Re-key byte counting**: `bytes_encrypted()`, `should_rekey()`, `set_rekey_threshold()`
- **Multiple channels**: `allocate_channel_id()` for sequential channel IDs
- **Debug for all pub types**: Sensitive data hidden via `finish_non_exhaustive()`
- **Send + Sync handlers**: All closures are Send + Sync for async_trait compatibility

### Bug Fixes Applied
1. **Ed25519 key parsing** — wrong offset in OpenSSH blob
2. **Ed25519 signature double-encoding** — data contained pre-encoded blob
3. **ECDSA k256→p256** — wrong curve (Bitcoin's secp256k1 vs NIST P-256)
4. **ECDSA signature mpint encoding** — r/s need 0x00 prefix when high bit set
5. **ChaCha20 padding alignment** — packet_length must be block-aligned
6. **kex-strict missing** — sequence number reset after NEWKEYS
7. **WINDOW_ADJUST missing** — client never replenished server's send window
8. **SFTP server pipelining** — process all buffered SFTP packets, not just one
9. **SFTP packet type constants** — LSTAT=7, STAT=17 (were swapped)
10. **Test flakiness** — mutex poisoning cascade, TCP listen race, server close race

### Test Infrastructure
- **Test SSH server**: Full server with configurable auth behaviors (AcceptAll, RejectPassword, KeyboardInteractive, AcceptPublicKey, RejectFirstThenAccept)
- **SCP server handlers**: `handle_scp_upload()` / `handle_scp_download()`
- **SFTP server**: `SftpServerSession` with `MemoryFs` backend
- **sshd interop**: Starts real OpenSSH sshd with test keys
- **ssh client interop**: Spawns real `ssh`/`sftp` CLI against our server
- **Stability**: Mutex poisoning recovery, std::net listener (no tokio race), server waits for client CLOSE

### Known Limitations
- `cisco_conn.rs` / `unix_conn.rs` / `cisco_ssh.rs` — need live devices for testing
- `main.rs` — CLI entry point, 0% coverage
- `connection/mod.rs` state.rs — 77% (state machine edge cases)
- Re-key initiation not implemented (only byte counting)
- SFTP server `read()` capped at 30KB to prevent TCP deadlock (no bidirectional I/O split)

### Design Decisions
- `connection/mod.rs` kept as future generic Connection abstraction (now implemented as SshConnection)
- `HostKeyVerifier` is mandatory (no default) — explicit security decision required
- `TofuFileStore` never touches `~/.ssh/known_hosts` by default
- Handler closures are `Send + Sync` for async_trait compatibility
- SshChannelReader uses chunk-based API (not AsyncRead) to avoid async-in-sync-trait issues

### Upstream Integration
- **ayclic crate** uses `RawSshSession` for vendor-neutral device interaction
- **ayurl crate** uses SCP/SFTP streaming APIs for file transfer
- `+ Sync` fix on handler closures was requested by ayurl user
- `SftpClient::connect_with_password()` added for ayurl user
- Streaming SCP/SFTP APIs inspired by ayurl's `SchemeHandler` trait

### Files of Interest
- `docs/restart.md` — Original dead code cleanup checklist
- `docs/plans/test-coverage-gaps.md` — Test improvement plan (mostly completed)
- `docs/debug-sessions/003-chacha20-poly1305-wip.md` — ChaCha20 interop debugging (RESOLVED)
- `tests/keys/` — All test keypairs (Ed25519, RSA, ECDSA)
