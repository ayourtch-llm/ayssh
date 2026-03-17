# Test Coverage Gaps and Planned Improvements

## Current State

As of 2026-03-17, the test suite has 379 tests covering:

- **Crypto matrix (28 combos):** All KEX × cipher × MAC combinations exercised
  end-to-end via our test SSH server (`test_crypto_matrix`)
- **Unit tests:** HMAC, AES-CBC/CTR/GCM, DH primes, Poly1305, exchange hash,
  mpint encoding, key derivation, packet framing, ETM/AEAD helpers
- **Integration tests:** 566 tests covering protocol types, channel management,
  auth flows, key parsing, etc.

## Priority 1: Quick Wins

### 1.1 RSA Host Key in Server Tests ✅ DONE
**Effort:** Small
**Files:** `src/server/test_server.rs`

Currently all 28 crypto matrix tests use Ed25519 host keys. Add a test
using RSA host key (load from `tests/keys/test_rsa_2048`):

```rust
#[test]
fn test_rsa_host_key() {
    // Same as run_crypto_test but with RSA host key
    run_crypto_test_with_host_key(
        HostKeyPair::load_openssh_rsa("tests/keys/test_rsa_2048"),
        Some("diffie-hellman-group14-sha256"),
        Some("aes128-ctr"),
        Some("hmac-sha1"),
    );
}
```

Why: Exercises RSA signature verification path (SHA-1 PKCS1v15) which
differs from Ed25519. Ensures `host_key.sign()` and `host_key.public_key_blob()`
work for RSA keys.

### 1.2 P-256 ECDH Shared Secret Consistency ✅ DONE
**Effort:** Small
**Files:** `src/crypto/ecdh.rs`

Add a unit test that generates two P-256 keypairs, exchanges public keys,
and verifies both sides compute the same shared secret:

```rust
#[test]
fn test_nistp256_shared_secret_matches() {
    let alice = EcdhKeyPair::generate(CurveType::Nistp256, &mut OsRng);
    let bob = EcdhKeyPair::generate(CurveType::Nistp256, &mut OsRng);
    let alice_secret = alice.compute_shared_secret(&bob.public_key);
    let bob_secret = bob.compute_shared_secret(&alice.public_key);
    assert_eq!(alice_secret, bob_secret);
}
```

Why: Prevents regression of the k256→p256 bug. The fix changed the curve
used for P-256 operations; this test ensures both sides agree on the
shared secret using the correct curve.

### 1.3 P-384 and P-521 Shared Secret Consistency ✅ DONE
**Effort:** Small
**Files:** `src/crypto/ecdh.rs`

Same as 1.2 but for the other NIST curves.

### 1.4 Curve25519 Shared Secret Consistency
**Status:** Already existed (`test_curve25519_shared_secret`)
**Files:** `src/crypto/ecdh.rs`

Was already covered by existing test.

## Priority 2: Auth Method Coverage

### 2.1 RSA Public Key Authentication via Server ✅ DONE
**Effort:** Medium
**Files:** `src/server/test_server.rs`, `src/auth/mod.rs`

Currently the server always accepts password auth. Add a test where:
- Server requires publickey auth (respond with USERAUTH_FAILURE for password,
  USERAUTH_PK_OK + USERAUTH_SUCCESS for valid public key)
- Client authenticates with RSA key from `tests/keys/test_rsa_2048`
- Verify the signature verification path works

This would test: RSA key parsing → public key blob extraction → mpint encoding
→ signature creation (SHA-1 or rsa-sha2-256) → signature wire format → server
verification.

### 2.2 Keyboard-Interactive Authentication via Server ✅ DONE
**Effort:** Medium
**Files:** `src/server/test_server.rs`, `src/auth/keyboard.rs`

Add a test where:
- Server sends SSH_MSG_USERAUTH_INFO_REQUEST with one prompt
- Client responds with password via keyboard-interactive handler
- Server verifies response and sends USERAUTH_SUCCESS

This would test: KB-interactive message format (RFC 4256), challenge parsing,
response encoding, correct message type (60/61).

### 2.3 Auth Method Fallback
**Effort:** Medium
**Files:** `src/auth/mod.rs`
**Status:** BLOCKED — Authenticator::authenticate() returns on first method failure
instead of trying the next method. Needs code fix before test can be written.

Test that the Authenticator correctly falls back from one method to another:
- Server rejects publickey, offers password
- Client tries publickey first, gets USERAUTH_FAILURE, then tries password
- Verify successful auth after fallback

## Priority 3: Error Cases and Robustness

### 3.1 Wrong Password Rejection ✅ DONE
**Effort:** Small
**Files:** `src/server/test_server.rs`

Modify server to reject a specific password and verify the client receives
`AuthenticationResult::Failure` with available methods list.

### 3.2 MAC Verification Failure
**Effort:** Medium
**Files:** `src/transport/mod.rs`

Test that a corrupted encrypted packet is properly rejected:
- Send a valid encrypted packet, flip a bit, verify MAC error
- This is partially covered by unit tests but not end-to-end

### 3.3 Invalid Host Key Rejection
**Effort:** Medium

Test that the client detects a host key change (MITM scenario).
Requires known_hosts integration.

### 3.4 Connection Timeout Handling
**Effort:** Small

Test that the client properly times out when the server doesn't respond
(e.g., server accepts TCP but never sends version string).

## Priority 4: Protocol Edge Cases

### 4.1 Large Data Transfer
**Effort:** Medium

Test sending/receiving data larger than one SSH packet (>32KB) to
exercise the channel windowing and multi-packet data paths.

### 4.2 Multiple Channels
**Effort:** Medium

Test opening multiple channels on the same connection (e.g., two
shell sessions). Verifies channel ID management.

### 4.3 Rekey (Key Exchange During Session)
**Effort:** Large

Test initiating a new key exchange after a certain amount of data,
as required by SSH for long-lived connections. This is a significant
protocol feature not currently implemented.

### 4.4 ChaCha20-Poly1305 Interop
**Effort:** Medium
**Status:** WIP (see `docs/debug-sessions/003-chacha20-poly1305-wip.md`)

The chacha20-poly1305@openssh.com cipher works in our own server↔client
tests but not against OpenSSH. The test server could help debug this by
comparing the exact bytes both sides produce.

## Priority 5: Additional Algorithms

### 5.1 ECDSA Host Keys
**Effort:** Medium
**Files:** `src/server/host_key.rs`

Add `HostKeyPair::Ecdsa` variant for ecdsa-sha2-nistp256/384/521 host keys.
This would allow testing host key algorithm negotiation with different key types.

### 5.2 Ed25519 Client Key Authentication
**Effort:** Medium

Add support for Ed25519 user authentication keys (in addition to RSA).
Requires extending the Authenticator to detect Ed25519 keys and use
the appropriate signature algorithm.

### 5.3 ECDSA Client Key Authentication
**Effort:** Medium

Same as 5.2 but for ECDSA keys.

## Test Infrastructure Improvements

### T.1 Test Server Port Configuration
**Effort:** Small

Allow CiscoConn/UnixConn to specify a port (currently hardcoded to 22).
This would enable integration tests that connect the high-level API
to our test server.

### T.2 Captured Packet Replay Tests
**Effort:** Large

Record the exact bytes from a successful OpenSSH connection (using tcpdump
or wireshark) and create tests that replay those bytes, verifying our
parsing and crypto produce the expected results. This would catch subtle
encoding differences without needing a live server.

### T.3 Fuzz Testing
**Effort:** Large

Use cargo-fuzz to fuzz the packet parsing, version string parsing, and
KEXINIT parsing code paths. These handle untrusted input and should be
robust against malformed data.
