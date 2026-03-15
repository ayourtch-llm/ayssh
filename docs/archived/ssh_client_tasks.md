# SSH Client Implementation - Detailed Task List

This document breaks down the SSH client implementation into manageable, testable tasks following TDD principles.

---

## Phase 1: Foundation (Weeks 1-2)

### Task 1.1: Initialize Cargo Project
**Goal:** Set up the Rust project structure with necessary dependencies

**Files to create:**
- `Cargo.toml` - Project configuration with dependencies
- `src/lib.rs` - Library entry point
- `src/main.rs` - Binary entry point

**Dependencies:**
- tokio (async runtime)
- tokio-util (async utilities)
- async-trait (async trait support)
- thiserror (error handling)
- log (logging)

**Acceptance Criteria:**
- [ ] Project compiles without errors
- [ ] Basic module structure exists
- [ ] All dependencies resolve

---

### Task 1.2: Define Protocol Types
**Goal:** Create SSH protocol type definitions

**Files to create:**
- `src/protocol/mod.rs` - Module exports
- `src/protocol/messages.rs` - SSH message type constants
- `src/protocol/algorithms.rs` - Supported algorithm names
- `src/protocol/errors.rs` - Protocol error types

**Message Types (RFC 4250):**
- SSH_MSG_DISCONNECT = 1
- SSH_MSG_IGNORE = 2
- SSH_MSG_UNIMPLEMENTED = 3
- SSH_MSG_DEBUG = 4
- SSH_MSG_SERVICE_REQUEST = 5
- SSH_MSG_SERVICE_ACCEPT = 6
- SSH_MSG_KEXINIT = 20
- SSH_MSG_NEWKEYS = 21
- SSH_MSG_KEX_ECDH_INIT = 30
- SSH_MSG_KEX_ECDH_REPLY = 31
- ... (all other message types)

**Acceptance Criteria:**
- [ ] All SSH message types defined as constants
- [ ] Algorithm names defined (kex, cipher, mac, hostkey)
- [ ] Error types cover all protocol error cases
- [ ] Unit tests for type definitions

---

### Task 1.3: Implement Data Type Representations
**Goal:** Implement SSH string encoding/decoding

**Files to create:**
- `src/protocol/types.rs` - Data type implementations
- `src/utils/buffer.rs` - Buffer operations
- `src/utils/string.rs` - String encoding utilities

**Data Types:**
- `string<N>` - Length-prefixed string
- `uint32` - 32-bit unsigned integer (big-endian)
- `uint64` - 64-bit unsigned integer (big-endian)
- `boolean` - Single byte (0 = false, 1 = true)
- `mpint` - Multiple-precision integer

**Acceptance Criteria:**
- [ ] String encoding/decoding works correctly
- [ ] uint32/uint64 serialization/deserialization correct
- [ ] MPINT handles positive integers
- [ ] Round-trip tests for all types
- [ ] Error handling for malformed data

---

### Task 1.4: Implement Binary Packet Protocol
**Goal:** Implement SSH packet structure

**Files to create:**
- `src/transport/packet.rs` - Packet implementation

**Packet Structure:**
- 4 bytes: payload length (excluding padding length and MAC)
- 1 byte: padding length
- N bytes: payload
- M bytes: padding (minimum 4, max 255)
- Variable: MAC (if authenticated)

**Acceptance Criteria:**
- [ ] Packet serialization works
- [ ] Packet deserialization works
- [ ] Padding validation correct
- [ ] Max packet size enforced (32768 bytes default)
- [ ] Unit tests for packet operations

---

## Phase 2: Transport Layer - Handshake (Weeks 3-4)

### Task 2.1: Protocol Version Exchange
**Goal:** Implement SSH version string exchange

**Files to modify:**
- `src/transport/handshake.rs` - Version exchange logic

**Protocol:**
- Client sends: "SSH-2.0-ayssh_x.x.x\r\n"
- Server responds with version string
- Both must support protocol version 2

**Acceptance Criteria:**
- [ ] Client sends correct version string
- [ ] Server version parsed correctly
- [ ] Protocol version 2 enforced
- [ ] Old version compatibility handling
- [ ] Integration test with mock server

---

### Task 2.2: Algorithm Negotiation
**Goal:** Implement algorithm proposal exchange

**Files to modify:**
- `src/transport/handshake.rs` - Algorithm negotiation

**Client Proposal (sent in KEXINIT):**
- kex_algorithms: list of key exchange methods
- server_host_key_algorithms: list of host key types
- encryption_algorithms_c2s: client-to-server ciphers
- encryption_algorithms_s2c: server-to-client ciphers
- mac_algorithms_c2s: client-to-server MACs
- mac_algorithms_s2c: server-to-client MACs
- compression_algorithms: compression methods
- languages_c2s: languages (empty)
- languages_s2c: languages (empty)

**Acceptance Criteria:**
- [ ] Client proposal formatted correctly
- [ ] Server proposal parsed correctly
- [ ] Common algorithm selection works
- [ ] Priority-based selection implemented
- [ ] Unit tests for algorithm selection

---

### Task 2.3: Diffie-Hellman Key Exchange (Group14)
**Goal:** Implement diffie-hellman-group14-sha256/384/512

**Files to create:**
- `src/transport/kex.rs` - Key exchange implementations
- `src/crypto/dh.rs` - DH primitives

**Algorithm:**
- Use MODP group 14 (2048-bit)
- Hash: SHA-256/384/512
- Client generates random x, computes X = g^x mod p
- Server sends Y = g^y mod p
- Both compute K = Y^x mod p

**Acceptance Criteria:**
- [ ] DH parameters correctly defined
- [ ] Client X computation correct
- [ ] Server Y parsing works
- [ ] Shared secret K computed correctly
- [ ] MPINT encoding/decoding for large numbers
- [ ] Unit tests with known test vectors

---

### Task 2.4: Diffie-Hellman Group Exchange
**Goal:** Implement diffie-hellman-group-exchange-sha256

**Files to modify:**
- `src/transport/kex.rs` - Add group exchange support

**Protocol:**
- Client sends preferred group sizes (min, preferred, max)
- Server selects group and sends G, p
- Client computes X = g^x mod p, sends X
- Server sends Y = g^y mod p, signature
- Both compute shared secret

**Acceptance Criteria:**
- [ ] Group exchange request formatted
- [ ] Server group parameters parsed
- [ ] Signature verification implemented
- [ ] Shared secret computed
- [ ] Integration tests

---

### Task 2.5: ECDH Key Exchange
**Goal:** Implement ECDH key exchange (RFC 5656)

**Files to create:**
- `src/transport/kex.rs` - ECDH support
- `src/crypto/ecdh.rs` - ECDH primitives

**Curves:**
- ecdh-sha2-nistp256
- ecdh-sha2-nistp384
- ecdh-sha2-nistp521

**Acceptance Criteria:**
- [ ] Curve parameters defined
- [ ] Client public key generation works
- [ ] Server public key parsed
- [ ] Shared secret computed via ECDH
- [ ] Curve-specific hash functions used
- [ ] Unit tests with test vectors

---

### Task 2.6: Session Identifier Computation
**Goal:** Compute SSH session identifier (H)

**Files to modify:**
- `src/transport/kex.rs` - Session ID computation

**Algorithm:**
- H = hash(K || V_C || V_S || I_C || I_S || K_S || X_C || Y_S)
- Used for key derivation and host key verification

**Acceptance Criteria:**
- [ ] All components concatenated correctly
- [ ] Hash computed with selected hash algorithm
- [ ] Session ID stored for later use
- [ ] Unit tests for hash computation

---

### Task 2.7: Host Key Verification
**Goal:** Verify server host key signature

**Files to modify:**
- `src/transport/handshake.rs` - Host key verification

**Process:**
- Server sends host key (public key)
- Server signs (K || H) with host key
- Client verifies signature
- Host key algorithm matches proposal

**Acceptance Criteria:**
- [ ] Host key parsed (RSA, ECDSA, Ed25519)
- [ ] Signature verification implemented
- [ ] Algorithm match verified
- [ ] Unit tests for signature verification

---

### Task 2.8: Transport State Machine
**Goal:** Implement transport layer state machine

**Files to create:**
- `src/transport/state.rs` - State machine implementation

**States:**
- Handshake
- KeyExchange
- Established

**Transitions:**
- Handshake -> KeyExchange (after KEXINIT)
- KeyExchange -> Established (after NEWKEYS)
- Established -> KeyExchange (re-key)

**Acceptance Criteria:**
- [ ] State transitions correct
- [ ] Invalid transitions rejected
- [ ] Re-keying handled
- [ ] Unit tests for state machine

---

## Phase 3: Transport Layer - Encryption (Weeks 5-6)

### Task 3.1: AES Cipher Implementation
**Goal:** Implement AES-CTR and AES-CBC

**Files to create:**
- `src/crypto/cipher.rs` - Cipher implementations

**Ciphers:**
- aes128-ctr
- aes192-ctr
- aes256-ctr
- aes128-cbc (deprecated)
- aes192-cbc (deprecated)
- aes256-cbc (deprecated)

**Acceptance Criteria:**
- [ ] AES-CTR encryption/decryption works
- [ ] AES-CBC encryption/decryption works (for compatibility)
- [ ] Key lengths validated (128, 192, 256 bits)
- [ ] IV handling correct
- [ ] Unit tests with test vectors

---

### Task 3.2: ChaCha20-Poly1305 Implementation
**Goal:** Implement AEAD cipher (RFC 8731)

**Files to create:**
- `src/crypto/chacha20.rs` - ChaCha20 implementation

**Cipher:**
- chacha20-poly1305@openssh.com

**Acceptance Criteria:**
- [ ] ChaCha20 stream cipher works
- [ ] Poly1305 MAC works
- [ ] AEAD encryption/decryption works
- [ ] Nonce handling correct
- [ ] Unit tests with test vectors

---

### Task 3.3: HMAC Implementations
**Goal:** Implement message authentication codes

**Files to create:**
- `src/crypto/hmac.rs` - HMAC implementations

**MACs:**
- hmac-sha2-256
- hmac-sha2-256-etm (encrypt-then-MAC)
- hmac-sha2-512
- hmac-sha2-512-etm
- hmac-sha1 (deprecated)

**Acceptance Criteria:**
- [ ] HMAC-SHA256 works
- [ ] HMAC-SHA512 works
- [ ] ETM variants implemented
- [ ] MAC verification works
- [ ] Unit tests with test vectors

---

### Task 3.4: Key Derivation Function
**Goal:** Implement SSH KDF (RFC 4253)

**Files to create:**
- `src/crypto/kdf.rs` - Key derivation

**Algorithm:**
- K1 = hash(K || H || 0x00)
- K2 = hash(K || H || 0x01)
- ... (continue until all keys derived)

**Uses:**
- Encryption keys (client to server, server to client)
- MAC keys (client to server, server to client)
- IVs (if needed)

**Acceptance Criteria:**
- [ ] KDF produces correct key material
- [ ] Key lengths match cipher requirements
- [ ] IV derivation works
- [ ] Unit tests for KDF

---

### Task 3.5: Encrypted Packet Protocol
**Goal:** Implement encrypted packet sending/receiving

**Files to modify:**
- `src/transport/packet.rs` - Add encryption/decryption

**Packet Flow:**
- Encrypt: payload -> cipher(payload) + MAC
- Decrypt: cipher + MAC -> verify MAC -> decrypt

**Acceptance Criteria:**
- [ ] Packet encryption works
- [ ] Packet decryption works
- [ ] MAC verification correct
- [ ] Sequence number handling
- [ ] Integration tests

---

### Task 3.6: Compression Support
**Goal:** Implement zlib compression

**Files to create:**
- `src/transport/compression.rs` - Compression implementation

**Compression:**
- zlib@openssh.com
- none (default)

**Acceptance Criteria:**
- [ ] zlib compression works
- [ ] zlib decompression works
- [ ] Compression negotiation works
- [ ] Performance benchmarks

---

## Phase 4: Authentication (Weeks 7-8)

### Task 4.1: Authentication State Machine
**Goal:** Implement authentication protocol framework

**Files to create:**
- `src/auth/mod.rs` - Auth module
- `src/auth/state.rs` - Authentication state machine

**States:**
- NotAuthenticating
- Authenticating
- Authenticated

**Acceptance Criteria:**
- [ ] State machine works correctly
- [ ] Service request sent
- [ ] Service accept parsed
- [ ] Unit tests for state machine

---

### Task 4.2: Public Key Authentication
**Goal:** Implement public key authentication (RFC 4252, Section 7)

**Files to create:**
- `src/auth/publickey.rs` - Public key auth

**Protocol:**
1. Client sends "publickey" request with key
2. Server responds with success or signature request
3. If signature request, client signs (session_id || user || service || "publickey" || "publickey")
4. Client sends signature

**Acceptance Criteria:**
- [ ] Public key request formatted
- [ ] Signature request parsed
- [ ] Signature computation works
- [ ] Signature sent correctly
- [ ] Unit tests

---

### Task 4.3: Password Authentication
**Goal:** Implement password authentication (RFC 4252, Section 8)

**Files to create:**
- `src/auth/password.rs` - Password auth

**Protocol:**
- Client sends username, service, "password", password
- Server responds with success/failure

**Acceptance Criteria:**
- [ ] Password request formatted
- [ ] Response parsed
- [ ] Multiple attempt handling
- [ ] Unit tests

---

### Task 4.4: Authentication Method Negotiation
**Goal:** Handle authentication method selection

**Files to modify:**
- `src/auth/methods.rs` - Method negotiation

**Protocol:**
- Server sends list of accepted methods
- Client tries methods in order
- Handle partial success

**Acceptance Criteria:**
- [ ] Method list parsed
- [ ] Method selection works
- [ ] Partial success handled
- [ ] Unit tests

---

## Phase 5: Connection Layer (Weeks 9-10)

### Task 5.1: Connection Service Request
**Goal:** Request ssh-connection service

**Files to create:**
- `src/connection/mod.rs` - Connection module

**Protocol:**
- Send service request "ssh-connection"
- Parse service accept

**Acceptance Criteria:**
- [ ] Service request sent
- [ ] Service accept parsed
- [ ] Unit tests

---

### Task 5.2: Channel Management
**Goal:** Implement channel state machine

**Files to create:**
- `src/connection/channels.rs` - Channel management

**Channel States:**
- Closed
- OpenSent
- OpenConfirm
- Extended

**Channel Types:**
- session
- forward-tcpip
- forward-agent
- x11

**Acceptance Criteria:**
- [ ] Channel allocation works
- [ ] Channel open request formatted
- [ ] Channel open confirm parsed
- [ ] Channel close handled
- [ ] Unit tests

---

## Phase 6: Sessions & Commands (Weeks 11-12)

### Task 6.1: Session Channel
**Goal:** Open and manage session channels

**Files to create:**
- `src/connection/session.rs` - Session implementation

**Acceptance Criteria:**
- [ ] Session channel opened
- [ ] Session confirmation parsed
- [ ] Unit tests

---

### Task 6.2: PTY Allocation
**Goal:** Request pseudo-terminal

**Files to modify:**
- `src/connection/session.rs` - PTY support

**Terminal Modes:**
- AWT, Baud, Column, Delete, Erase, Intr, Kill, Linican, Nl, Oflag, Parity, Quit, Raw, Row, Status, Stop, Suspend, Vmin, Vtime, Word

**Acceptance Criteria:**
- [ ] PTY request formatted
- [ ] Terminal modes encoded
- [ ] Unit tests

---

### Task 6.3: Command Execution
**Goal:** Execute remote commands

**Files to create:**
- `src/connection/exec.rs` - Command execution

**Acceptance Criteria:**
- [ ] Exec request sent
- [ ] Command output received
- [ ] Exit status received
- [ ] Unit tests

---

## Phase 7: Port Forwarding (Weeks 13-14)

### Task 7.1: TCP/IP Forwarding
**Goal:** Implement port forwarding

**Files to create:**
- `src/connection/forward.rs` - Port forwarding

**Types:**
- Remote forwarding
- Local forwarding
- Dynamic (SOCKS) forwarding

**Acceptance Criteria:**
- [ ] Forwarding request formatted
- [ ] Forwarding channel opened
- [ ] Data forwarded correctly
- [ ] Unit tests

---

## Phase 8: Key Handling (Weeks 15-16)

### Task 8.1: OpenSSH Key Format
**Goal:** Parse OpenSSH private key format

**Files to create:**
- `src/keys/formats.rs` - Key format parsing

**Acceptance Criteria:**
- [ ] OpenSSH format parsed
- [ ] Encrypted keys supported
- [ ] Unencrypted keys supported
- [ ] Unit tests

---

### Task 8.2: RSA Key Handling
**Goal:** Handle RSA keys

**Files to create:**
- `src/keys/rsa.rs` - RSA key handling

**Acceptance Criteria:**
- [ ] RSA key parsed
- [ ] RSA signature works
- [ ] Unit tests

---

### Task 8.3: ECDSA Key Handling
**Goal:** Handle ECDSA keys

**Files to create:**
- `src/keys/ecdsa.rs` - ECDSA key handling

**Acceptance Criteria:**
- [ ] ECDSA key parsed
- [ ] ECDSA signature works
- [ ] Unit tests

---

### Task 8.4: Ed25519 Key Handling
**Goal:** Handle Ed25519 keys

**Files to create:**
- `src/keys/ed25519.rs` - Ed25519 key handling

**Acceptance Criteria:**
- [ ] Ed25519 key parsed
- [ ] Ed25519 signature works
- [ ] Unit tests

---

## Phase 9: Known Hosts (Weeks 17-18)

### Task 9.1: Known Hosts Database
**Goal:** Implement known_hosts file handling

**Files to create:**
- `src/auth/known_hosts.rs` - Known hosts

**Acceptance Criteria:**
- [ ] Known hosts file parsed
- [ ] Host key lookup works
- [ ] Host key verification works
- [ ] Unit tests

---

## Phase 10: CLI (Weeks 19-20)

### Task 10.1: CLI Interface
**Goal:** Create command-line interface

**Files to create:**
- `src/main.rs` - CLI entry point

**Options:**
- host, port, user
- identity file
- known_hosts file
- verbose/debug mode

**Acceptance Criteria:**
- [ ] Arguments parsed
- [ ] Connection options work
- [ ] Unit tests

---

## Testing Checklist for Each Task

For each task above, ensure:
1. **Unit Tests** - Test individual components in isolation
2. **Integration Tests** - Test components working together
3. **Edge Cases** - Test error conditions and boundary values
4. **Documentation** - Document public APIs

---

## TDD Workflow for Each Task

1. **Write Test First** - Create test that fails
2. **Run Test** - Confirm failure
3. **Write Minimal Code** - Make test pass
4. **Refactor** - Improve code quality
5. **Verify** - Ensure all tests pass

---

## Summary

Total Tasks: 40+
Estimated Timeline: 20 weeks (2 tasks per week)

Each task should be:
- Implemented using TDD
- Tested thoroughly
- Documented
- Reviewed before merging
