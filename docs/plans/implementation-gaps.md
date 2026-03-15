# SSH Client Implementation Gaps & Next Steps

**Generated:** 2026-03-15  
**Current Status:** Framework Complete, Core Crypto Missing

---

## 🚨 Critical Implementation Gaps

### 1. Key Exchange (KEX) - 0% Complete

**File:** `src/transport/kex.rs` (Empty placeholder)

**Required by RFC 4253 Section 7**

**Missing Implementations:**
- [ ] `diffie-hellman-group14-sha256` (RFC 8731)
- [ ] `diffie-hellman-group-exchange-sha256` (RFC 4462)
- [ ] `ecdh-sha2-nistp256` (RFC 5656)
- [ ] `ecdh-sha2-nistp384` (RFC 5656)
- [ ] `ecdh-sha2-nistp521` (RFC 5656)
- [ ] `curve25519-sha256` (OpenSSH extension)
- [ ] `curve25519-sha256@libssh.org` (OpenSSH extension)

**Implementation Steps:**
1. Implement DH group parameters (G, p, q)
2. Implement modular exponentiation
3. Implement ECDH operations (NIST curves, Curve25519)
4. Implement session ID computation (H = HASH(K | ...))
5. Implement key derivation from shared secret

**Dependencies:**
- `num-bigint` for big integer arithmetic
- `ecdsa` crate for ECDSA operations
- `x25519-dalek` for Curve25519

---

### 2. Cipher Implementations - 0% Complete

**Files:** `src/crypto/cipher.rs`, `src/crypto/chacha20_poly1305.rs` (Stubs only)

**Required by RFC 4253 Section 6**

**Missing Implementations:**
- [ ] **AES-128-CTR** (RFC 4344)
- [ ] **AES-192-CTR** (RFC 4344)
- [ ] **AES-256-CTR** (RFC 4344)
- [ ] **AES-128-GCM** (RFC 5647)
- [ ] **AES-256-GCM** (RFC 5647)
- [ ] **ChaCha20-Poly1305** (RFC 8439)
- [ ] **AES-128-CBC** (RFC 4470, deprecated but required)
- [ ] **AES-256-CBC** (RFC 4470, deprecated but required)

**Implementation Steps:**
1. Implement AES block cipher (RustCrypto `aes` crate)
2. Implement CTR mode wrapping
3. Implement GCM mode wrapping
4. Implement ChaCha20 stream cipher (`chacha20` crate)
5. Implement Poly1305 MAC (`poly1305` crate)
6. Implement cipher initialization from keys

**Dependencies:**
- `aes` crate (RustCrypto)
- `ctr` crate (RustCrypto)
- `aes-gcm` crate (RustCrypto)
- `chacha20` crate (RustCrypto)
- `poly1305` crate (RustCrypto)

---

### 3. MAC Implementations - 0% Complete

**File:** `src/crypto/hmac.rs` (Stub only)

**Required by RFC 4253 Section 6**

**Missing Implementations:**
- [ ] **hmac-sha2-256** (RFC 6668)
- [ ] **hmac-sha2-512** (RFC 6668)
- [ ] **hmac-sha2-256-etm@openssh.com** (RFC 6668)
- [ ] **hmac-sha2-512-etm@openssh.com** (RFC 6668)
- [ ] **hmac-sha1** (RFC 4335, deprecated)
- [ ] **umac-64@openssh.com** (RFC 4462, optional)
- [ ] **umac-128@openssh.com** (RFC 4462, optional)
- [ ] **poly1305** (for AEAD ciphers)

**Implementation Steps:**
1. Implement HMAC-SHA2-256 (`hmac` + `sha2` crates)
2. Implement HMAC-SHA2-512
3. Implement ETM (Encrypt-then-MAC) variants
4. Implement Poly1305 for AEAD ciphers

**Dependencies:**
- `hmac` crate (RustCrypto)
- `sha2` crate (RustCrypto)
- `poly1305` crate

---

### 4. KDF Implementation - 30% Complete

**File:** `src/crypto/kdf.rs` (Partial stub)

**Required by RFC 4253 Section 7**

**Missing Implementations:**
- [ ] SSH KDF function (RFC 4253 Section 7)
- [ ] Key derivation for encryption keys
- [ ] Key derivation for MAC keys
- [ ] Key derivation for IVs

**Current State:**
```rust
// src/crypto/kdf.rs - Only stub exists
pub fn ssh_kdf(_hash: &mut impl Digest, _key: &[u8], _label: &[u8], _counter: u32) -> Vec<u8> {
    // TODO: Implement SSH KDF
    Vec::new()
}
```

**Implementation Steps:**
1. Implement SSH KDF as per RFC 4253 Section 7
2. Derive encryption keys from K
3. Derive MAC keys from K
4. Derive IVs from K

---

### 5. Packet Encryption/Decryption - 0% Complete

**File:** `src/transport/packet.rs` (Stub only)

**Required by RFC 4253 Section 6**

**Missing Implementations:**
- [ ] Packet length encoding (4 bytes)
- [ ] Padding length field
- [ ] Payload encryption
- [ ] MAC computation and verification
- [ ] Sequence number handling
- [ ] Packet reassembly
- [ ] Padding generation

**Current State:**
```rust
// src/transport/packet.rs - Only stub
pub struct Packet {
    pub length: u32,
    pub padding_length: u8,
    pub payload: Vec<u8>,
    pub padding: Vec<u8>,
    pub mac: Option<Vec<u8>>,
}
```

**Implementation Steps:**
1. Implement packet serialization
2. Implement packet deserialization
3. Implement encryption wrapper
4. Implement MAC verification
5. Implement sequence number increment

---

### 6. Public Key Cryptography - 0% Complete

**File:** `src/keys/` (All files missing)

**Required by RFC 4252, RFC 4716, RFC 6668, RFC 7465, RFC 8332**

**Missing Implementations:**
- [ ] **RSA key generation** (RFC 8017)
- [ ] **RSA signing** (RFC 8017, RFC 7465)
- [ ] **RSA verification**
- [ ] **ECDSA key generation** (RFC 6668)
- [ ] **ECDSA signing** (RFC 6668)
- [ ] **ECDSA verification**
- [ ] **Ed25519 key generation** (RFC 8332)
- [ ] **Ed25519 signing** (RFC 8332)
- [ ] **Ed25519 verification**
- [ ] **OpenSSH key format parsing** (RFC 4716)
- [ ] **PEM format parsing**
- [ ] **PKCS#8 support**

**Implementation Steps:**
1. Create `src/keys/rsa.rs` - RSA operations
2. Create `src/keys/ecdsa.rs` - ECDSA operations
3. Create `src/keys/ed25519.rs` - Ed25519 operations
4. Create `src/keys/formats.rs` - Key format parsing
5. Implement key loading from files
6. Implement key serialization

**Dependencies:**
- `rsa` crate (RustCrypto)
- `ecdsa` crate (RustCrypto)
- `ed25519-dalek` crate
- `pem` crate
- `pkcs8` crate

---

### 7. Channel Data Transfer - 0% Complete

**File:** `src/channel/types.rs` (Types defined, no implementation)

**Required by RFC 4254 Section 5**

**Missing Implementations:**
- [ ] Channel open message handling
- [ ] Channel open confirmation
- [ ] Channel data send
- [ ] Channel data receive
- [ ] Channel EOF
- [ ] Channel close
- [ ] Channel window adjust
- [ ] Backpressure handling

**Current State:**
```rust
// src/channel/types.rs - Only type definitions
pub struct Channel {
    pub id: ChannelId,
    pub state: ChannelState,
    pub remote_window_size: u32,
    pub remote_max_packet_size: u32,
    // ... but no actual send/receive methods
}
```

**Implementation Steps:**
1. Implement channel open message encoding
2. Implement channel data encoding
3. Implement channel close encoding
4. Implement message dispatching
5. Implement flow control

---

### 8. Session Channel - 0% Complete

**File:** `src/session/mod.rs` (Does not exist)

**Required by RFC 4254 Section 6**

**Missing Implementations:**
- [ ] Session channel opening
- [ ] exec request handling
- [ ] shell request handling
- [ ] PTY allocation (RFC 4254 Section 6.2)
- [ ] Environment variable requests
- [ ] Window size change requests
- [ ] Signal requests

**Implementation Steps:**
1. Create `src/session/mod.rs`
2. Create `src/session/exec.rs` - Command execution
3. Create `src/session/pty.rs` - PTY handling
4. Implement session channel methods

---

### 9. Port Forwarding - 0% Complete

**Files:** `src/connection/forward.rs` (Does not exist)

**Required by RFC 4254 Section 7**

**Missing Implementations:**
- [ ] Remote port forwarding (RFC 4254 Section 7.2)
- [ ] Local port forwarding (RFC 4254 Section 7.3)
- [ ] Dynamic SOCKS proxy (RFC 4254 Section 7.4)
- [ ] X11 forwarding (RFC 4254 Section 6.3)
- [ ] Agent forwarding (RFC 4254 Section 6.5)

**Implementation Steps:**
1. Create `src/connection/forward.rs`
2. Implement TCP forwarding
3. Implement X11 forwarding
4. Implement agent forwarding

---

### 10. Known Hosts Database - 0% Complete

**File:** `src/known_hosts.rs` (Does not exist)

**Required by RFC 4253 Section 7**

**Missing Implementations:**
- [ ] known_hosts file parsing
- [ ] Host key verification
- [ ] Host key storage
- [ ] Host key addition
- [ ] Host key matching

---

## 📋 Implementation Priority Order

### Phase 1: Core Protocol (Critical - Blocker)
**Estimated Effort:** 40-60 hours

1. **Key Exchange** (20 hours)
   - Implement DH group14-sha256
   - Implement ECDH
   - Implement session ID computation

2. **Cipher Implementations** (15 hours)
   - AES-CTR
   - ChaCha20-Poly1305

3. **MAC Implementations** (5 hours)
   - HMAC-SHA2-256
   - HMAC-SHA2-512

4. **KDF** (5 hours)
   - SSH KDF function

5. **Packet Encryption** (10 hours)
   - Packet serialization
   - Encryption/decryption
   - MAC verification

**Expected Outcome:** Secure channel establishment working

---

### Phase 2: Authentication (High - Functional)
**Estimated Effort:** 30-40 hours

1. **Public Key Cryptography** (20 hours)
   - RSA signing
   - ECDSA signing
   - Ed25519 signing

2. **Key Format Parsing** (10 hours)
   - OpenSSH format
   - PEM format

3. **Auth Integration** (10 hours)
   - Public key auth flow
   - Password auth flow
   - Signature exchange

**Expected Outcome:** Authentication working

---

### Phase 3: Connection Protocol (High - Functional)
**Estimated Effort:** 25-35 hours

1. **Channel Management** (15 hours)
   - Channel open
   - Channel data transfer
   - Channel close

2. **Session Channel** (10 hours)
   - exec()
   - shell()
   - PTY allocation

3. **Service Request** (5 hours)
   - ssh-connection service

**Expected Outcome:** Basic SSH connection working

---

### Phase 4: Features (Medium - Nice to Have)
**Estimated Effort:** 20-30 hours

1. **Port Forwarding** (10 hours)
2. **X11 Forwarding** (5 hours)
3. **Agent Forwarding** (5 hours)
4. **Known Hosts** (5 hours)
5. **CLI Improvements** (5 hours)

**Expected Outcome:** Full-featured SSH client

---

## 🧪 Testing Strategy

### Unit Tests (Priority: HIGH)
- [ ] Test KEX algorithms individually
- [ ] Test cipher encryption/decryption
- [ ] Test MAC computation/verification
- [ ] Test KDF output
- [ ] Test packet serialization
- [ ] Test key signing/verification

### Integration Tests (Priority: HIGH)
- [ ] Test full handshake with mock server
- [ ] Test authentication flow
- [ ] Test channel data transfer
- [ ] Test session commands

### Fuzz Testing (Priority: MEDIUM)
- [ ] Fuzz packet parsing
- [ ] Fuzz key exchange
- [ ] Fuzz channel messages

---

## 📊 Current vs. Target Metrics

| Metric | Current | Target | Gap |
|--------|---------|--------|-----|
| **RFC 4253 Compliance** | 50% | 100% | 50% |
| **RFC 4252 Compliance** | 60% | 100% | 40% |
| **RFC 4254 Compliance** | 40% | 100% | 60% |
| **Cryptographic Ops** | 0% | 100% | 100% |
| **Key Exchange** | 0% | 100% | 100% |
| **Encryption** | 0% | 100% | 100% |
| **Authentication** | 60% | 100% | 40% |
| **Channel Transfer** | 0% | 100% | 100% |

---

## 🔧 Recommended Next Steps

### Immediate (This Week)
1. **Implement KDF** - 5 hours
2. **Implement DH Key Exchange** - 20 hours
3. **Implement AES-CTR** - 10 hours

### Short-Term (Next 2 Weeks)
4. **Implement ChaCha20-Poly1305** - 10 hours
5. **Implement HMAC-SHA2** - 5 hours
6. **Implement Packet Encryption** - 10 hours

### Medium-Term (Next Month)
7. **Implement RSA/ECDSA/Ed25519** - 20 hours
8. **Implement Key Format Parsing** - 10 hours
9. **Implement Channel Transfer** - 15 hours

---

## 📚 Reference Implementations

### Rust SSH Libraries to Study
- **ssh2** - Mature SSH library (C bindings)
- **russh** - Pure Rust SSH server/client
- **libssh2** - C library with Rust bindings
- **openssh** - Reference implementation

### RFC Documents
- [RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253) - Transport Layer
- [RFC 4252](https://datatracker.ietf.org/doc/html/rfc4252) - Authentication
- [RFC 4254](https://datatracker.ietf.org/doc/html/rfc4254) - Connection
- [RFC 8731](https://datatracker.ietf.org/doc/html/rfc8731) - DH Group Exchange
- [RFC 5656](https://datatracker.ietf.org/doc/html/rfc5656) - ECDH
- [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) - ChaCha20

---

**Report Generated:** 2026-03-15  
**Analysis Method:** Gap analysis against RFC specifications  
**Recommendation:** Focus on Phase 1 (Core Protocol) before proceeding to authentication features