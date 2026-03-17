# Restart Context for Dead Code Cleanup

## What we were doing

Running `RUSTFLAGS="" cargo build` to find dead code, then removing it one item
at a time, running `cargo test` after each change.

## Dead code items identified (from compiler warnings)

### Already fixed:
1. `src/channel/types.rs:684` — unused `offset` assignment → changed to `_offset`

### Still to fix:
2. `src/auth/key.rs:659` — `strip_mpint_leading_zero()` never used → remove
3. `src/auth/publickey.rs:24` — field `private_key_pem` never read → remove
4. `src/auth/signature.rs:124` — `to_positive_mpint()` never used → remove
5. `src/channel/mod.rs:29` — fields `default_window_size`, `default_max_packet_size` never read → remove
6. `src/protocol/algorithms.rs:182` — `select_first_matching()` and `select_first_matching_in_category()` never used → remove
7. `src/transport/mod.rs:817` — `encrypt_packet()` and `decrypt_packet()` methods never used → remove
8. `src/transport/mod.rs` — `decrypt_packet_cbc()` standalone function never used → remove

### Bigger cleanup candidates:
9. `src/transport/packet.rs` — entire `Encryptor`/`Decryptor`/`CipherType` infrastructure is dead code
   (real encryption lives in `transport/mod.rs` with `EncryptionState`/`DecryptionState`)
10. `src/crypto/packet.rs` — entire module dead code (Packet struct duplicate, PacketWriter/Reader unused)
11. `src/transport/encrypted.rs` — `EncryptedTransport`/`CipherState` only used by `transport/session.rs`
    and `transport/state.rs` but may not be in any real code path
12. `src/keys/rsa.rs` — 0% coverage, may be dead

### Other warnings to fix:
- Unused imports: `Sha256`, `Digest`, `BufMut`, `BytesMut`, `RngCore`, `Buf`
- Unused variables: `shell`, `rng`, `originator_port/address`, `username`, `stdin_write`, `stdout_rx`, etc.
- Mutable variables that don't need to be: 7 instances
- Ambiguous glob re-exports: 5 instances
- Deprecated function usage: `base64::decode`, `generate_session_hash`

## Current test state
- 371 tests passing, 1 ignored (dead code placeholder in test_server.rs)
- Coverage: 68.16% (4519/6630 lines)
- Crypto matrix: 28/28 combinations pass

## Key architectural notes
- The REAL encryption path is in `transport/mod.rs`:
  - `EncryptionState`/`DecryptionState` structs
  - `encrypt_packet_cbc()` function (handles CBC, CTR, GCM, ChaCha20, ETM)
  - `recv_message()` method on Transport (handles all decrypt paths)
- The DEAD encryption path is in `transport/packet.rs`:
  - `Encryptor`/`Decryptor`/`CipherType` — never wired into Transport
- `crypto/packet.rs` has a duplicate `Packet` struct (the real one is `transport/packet.rs::Packet`)

## Recent important fixes
- `recv_version()` BufReader data loss — root cause of flaky tests
- `thread_rng()` → `OsRng` everywhere — enables Send for async
- NIST P-256: k256→p256 crate, removed curve name prefix from encode_public_key
- Group1 and Group14 DH primes corrected
- HMAC-SHA1 poly1305-donna implementation
- KDF multi-block fix (K2 no longer includes X byte)

## Files of interest
- `src/cisco_conn.rs` — newly public `send()` and `receive()` methods
- `src/server/test_server.rs` — test server + crypto matrix
- `src/transport/mod.rs` — core transport with all cipher modes
- `docs/plans/test-coverage-gaps.md` — planned test improvements
- `docs/debug-sessions/003-chacha20-poly1305-wip.md` — ChaCha20 interop WIP
