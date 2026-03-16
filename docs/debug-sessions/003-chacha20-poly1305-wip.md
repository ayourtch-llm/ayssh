# Debug Session 003: ChaCha20-Poly1305@openssh.com — Work In Progress

**Date:** 2026-03-16
**Status:** WIP — unit tests pass, interop with OpenSSH pending

## Summary

The `chacha20-poly1305@openssh.com` AEAD cipher is implemented but not yet
interoperating with OpenSSH 9.6. All internal unit tests pass (encrypt/decrypt
round-trip, RFC 7539 Poly1305 test vector, tamper detection).

## What's Implemented

- **SSH-specific ChaCha20-Poly1305** (`src/crypto/ssh_chacha20.rs`):
  - 64-byte key split: main_key(32B) for payload, header_key(32B) for length
  - Packet length encrypted with header_key (unlike AES-GCM where it's cleartext)
  - Poly1305 key derived from block 0 of main_key keystream
  - Payload encrypted with main_key starting at block 1
  - Poly1305 MAC over concatenated encrypted_length + encrypted_payload

- **Standard Poly1305 (poly1305-donna)**: The `poly1305` crate's `UniversalHash`
  API (`update_padded`) does NOT produce standard Poly1305 output — it zero-pads
  partial blocks without proper hibit handling. Replaced with a direct
  poly1305-donna implementation that passes RFC 7539 Section 2.5.2 test vector.

- **Transport integration**: Both encrypt and decrypt paths handle the
  chacha20-poly1305 packet format (encrypted length + encrypted payload + tag).

## What Was Tried

1. **DJB ChaCha20** (8-byte nonce, `ChaCha20Legacy`): matches OpenSSH's native
   `cipher-chachapoly.c` variant. Failed against server.

2. **IETF ChaCha20** (12-byte nonce, `ChaCha20`): matches OpenSSH's
   `cipher-chachapoly-libcrypto.c` variant which uses OpenSSL's `EVP_chacha20`.
   Also failed against server.

3. Both variants produce the same ChaCha20 state for SSH's use case (nonce bytes
   land in the same state positions when zero-padded).

## Suspected Root Cause

The remaining issue is likely in one of:

1. **64-byte key derivation (K2)**: The KDF multi-block fix was applied (removing
   the X byte from K2), but this needs verification against OpenSSH's exact output.
   A captured key exchange trace comparing derived keys would confirm.

2. **OpenSSL EVP_chacha20 state mapping**: OpenSSL's 16-byte IV format
   `[counter(4 LE) || nonce(12)]` might be interpreted differently than expected
   by the `chacha20` Rust crate.

3. **Poly1305 block processing edge case**: While our poly1305-donna passes the
   RFC test vector, there might be a subtle difference for specific message lengths
   used in SSH packets.

## How to Debug Further

- Capture an OpenSSH key exchange and extract the derived 64-byte encryption key
  for chacha20-poly1305. Compare byte-by-byte with our KDF output.
- Use OpenSSH's `-o "LogLevel=DEBUG3"` to get packet-level traces.
- Create a test that uses known keys/nonces and compares ChaCha20 keystream output
  between our implementation and OpenSSL's EVP_chacha20.
- Build a test SSH server (next task) that can exercise this cipher in a controlled
  environment where we can inspect both sides.

## Files

- `src/crypto/ssh_chacha20.rs` — ChaCha20-Poly1305 implementation + poly1305-donna
- `src/transport/mod.rs` — AEAD encrypt/decrypt paths
- `src/crypto/kdf.rs` — Multi-block KDF fix (K2 no longer includes X byte)
