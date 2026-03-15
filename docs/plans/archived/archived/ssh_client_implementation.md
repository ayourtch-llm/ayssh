# SSH Client Implementation Plan

## Overview

This document outlines the implementation plan for building a secure SSH client using the async Tokio framework in Rust. The implementation follows the SSH protocol specifications defined in RFC 4250-4254, 4335, 4462, 4344, 4470, 4471, 4716, 5656, 6668, 7465, 8332, 8731, and 8879.

## Architecture Overview

The SSH protocol consists of three major components:
1. **Transport Layer Protocol** (RFC 4253) - Provides server authentication, confidentiality, and integrity with perfect forward secrecy
2. **User Authentication Protocol** (RFC 4252) - Authenticates the client to the server
3. **Connection Protocol** (RFC 4254) - Multiplexes the encrypted tunnel into several logical channels

## Project Structure

```
ayssh/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── main.rs
│   ├── client.rs          # Main SSH client struct
│   ├── transport/         # Transport layer implementation
│   │   ├── mod.rs
│   │   ├── handshake.rs   # Protocol version exchange, key exchange
│   │   ├── crypto.rs      # Cryptographic operations
│   │   ├── packet.rs      # Binary packet protocol
│   │   └── kex.rs         # Key exchange methods (DH, ECDH)
│   ├── auth/              # Authentication layer implementation
│   │   ├── mod.rs
│   │   ├── publickey.rs   # Public key authentication
│   │   ├── password.rs    # Password authentication
│   │   └── methods.rs     # Authentication method negotiation
│   ├── connection/        # Connection layer implementation
│   │   ├── mod.rs
│   │   ├── channels.rs    # Channel management
│   │   ├── session.rs     # Interactive sessions
│   │   ├── exec.rs        # Remote command execution
│   │   └── forward.rs     # Port forwarding
│   ├── protocol/          # Protocol constants and types
│   │   ├── mod.rs
│   │   ├── messages.rs    # SSH message types
│   │   ├── algorithms.rs  # Supported algorithms
│   │   └── errors.rs      # Error types
│   ├── crypto/            # Cryptographic primitives
│   │   ├── mod.rs
│   │   ├── kdf.rs         # Key derivation functions
│   │   ├── hmac.rs        # HMAC implementations
│   │   ├── cipher.rs      # Cipher implementations (AES, ChaCha20)
│   │   └── hash.rs        # Hash functions (SHA-1, SHA-2, SHA-3)
│   ├── keys/              # Key handling
│   │   ├── mod.rs
│   │   ├── formats.rs     # Key formats (PEM, OpenSSH)
│   │   ├── rsa.rs         # RSA key handling
│   │   ├── ecdsa.rs       # ECDSA key handling
│   │   └── ed25519.rs     # Ed25519 key handling
│   └── utils/             # Utility functions
│       ├── mod.rs
│       ├── buffer.rs      # SSH buffer types
│       └── string.rs      # SSH string encoding
```

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)
**Goal:** Set up project structure, protocol types, and basic utilities

#### Tasks:
1. **Initialize Cargo project**
   - Create Cargo.toml with Tokio, async-trait, and other dependencies
   - Set up basic project structure

2. **Implement SSH Protocol Types**
   - Define SSH message types (RFC 4250)
   - Define data type representations (string, uint32, uint64, boolean)
   - Create error types for protocol errors

3. **Implement SSH String Encoding**
   - SSH string encoding/decoding (length-prefixed strings)
   - Buffer types for reading/writing SSH data

4. **Implement Binary Packet Protocol**
   - Packet structure (length, padding length, payload, padding, MAC)
   - Packet encryption and decryption
   - Compression support (optional for MVP)

**Deliverables:**
- Project skeleton with all modules
- Protocol type definitions
- String encoding utilities
- Basic packet protocol implementation
- Unit tests for all components

---

### Phase 2: Transport Layer - Handshake (Weeks 3-4)
**Goal:** Implement SSH transport layer handshake and key exchange

#### Tasks:
1. **Protocol Version Exchange**
   - Send and parse SSH protocol version strings
   - Handle compatibility with old SSH versions
   - Negotiate protocol version

2. **Algorithm Negotiation**
   - Send client proposals for algorithms
   - Parse server proposals
   - Select common algorithms for:
     - Key exchange methods
     - Server host key algorithms
     - Encryption algorithms (client to server, server to client)
     - MAC algorithms
     - Compression algorithms

3. **Diffie-Hellman Key Exchange**
   - Implement diffie-hellman-group14-sha256/384/512 (RFC 8731)
   - Implement diffie-hellman-group-exchange-sha256 (RFC 4462)
   - Implement ECDH key exchange (RFC 5656)
   - Generate key exchange values (G, X, Y, K)
   - Compute session identifier (H)

4. **Server Host Key Verification**
   - Parse server host key (RSA, ECDSA, Ed25519)
   - Verify host key signature
   - Store and verify known hosts (optional for MVP)

5. **Transport Layer State Machine**
   - Implement state machine for transport layer
   - Handle key re-exchange
   - Handle disconnect, ignore, and debug messages

**Deliverables:**
- Version exchange implementation
- Algorithm negotiation
- Diffie-Hellman key exchange
- ECDH key exchange
- Host key verification
- Transport layer state machine
- Integration tests for handshake

---

### Phase 3: Transport Layer - Encryption & MAC (Weeks 5-6)
**Goal:** Implement encrypted packet protocol

#### Tasks:
1. **Symmetric Cipher Implementations**
   - AES-CTR (RFC 4344)
   - AES-CBC (RFC 4470) - deprecated but required for compatibility
   - ChaCha20-Poly1305 (RFC 8731)
   - Implement cipher initialization from keys

2. **Message Authentication**
   - HMAC-SHA2-256/384/512
   - HMAC-SHA1 (deprecated)
   - UMAC (optional)
   - Poly1305 (for AEAD ciphers)

3. **Key Derivation**
   - Implement SSH KDF (RFC 4253)
   - Derive encryption keys, MAC keys, IVs from K
   - Handle key length requirements for each cipher

4. **Packet Protocol Implementation**
   - Encrypt/decrypt packets
   - Compute and verify MACs
   - Handle packet fragmentation
   - Implement sequence number handling

5. **Compression**
   - zlib compression (RFC 4253)
   - No compression (default)

**Deliverables:**
- Cipher implementations
- MAC implementations
- Key derivation functions
- Encrypted packet protocol
- Compression support
- Performance benchmarks

---

### Phase 4: Authentication Layer (Weeks 7-8)
**Goal:** Implement user authentication

#### Tasks:
1. **Authentication Protocol Framework**
   - Implement authentication state machine
   - Handle service request ("ssh-userauth")
   - Parse authentication success/failure messages

2. **Public Key Authentication** (RFC 4252, Section 7)
   - Send public key algorithm and key
   - Handle signature request
   - Verify server's signature request
   - Sign challenge with client key
   - Support RSA (RFC 7465), ECDSA (RFC 6668), Ed25519 (RFC 8332)

3. **Password Authentication** (RFC 4252, Section 8)
   - Send password authentication request
   - Handle success/failure responses
   - Handle keyboard-interactive (optional)

4. **Authentication Method Negotiation**
   - Parse list of accepted methods
   - Try multiple authentication methods
   - Handle partial success

5. **Banner Message**
   - Parse and display server banner

**Deliverables:**
- Authentication state machine
- Public key authentication
- Password authentication
- Method negotiation
- Integration tests for authentication

---

### Phase 5: Connection Layer - Channels (Weeks 9-10)
**Goal:** Implement SSH connection protocol and channel management

#### Tasks:
1. **Service Request**
   - Send service request ("ssh-connection")
   - Parse service acceptance

2. **Channel Management**
   - Implement channel ID allocation
   - Channel state machine (open, open confirmation, extended, closed)
   - Handle channel opening requests
   - Parse channel open messages (session, forward-tcpip, forward-agent, x11)

3. **Channel Data Transfer**
   - Send and receive channel data
   - Handle backpressure
   - Implement channel flow control

4. **Channel Close**
   - Handle channel close messages
   - Graceful channel shutdown

5. **Channel Extended Data**
   - Handle stderr channel extended data
   - Route extended data appropriately

**Deliverables:**
- Channel management system
- Channel state machine
- Data transfer implementation
- Flow control
- Integration tests

---

### Phase 6: Connection Layer - Sessions & Commands (Weeks 11-12)
**Goal:** Implement interactive sessions and command execution

#### Tasks:
1. **Session Channel**
   - Open session channel
   - Parse session channel confirmation

2. **PTY Allocation** (RFC 4254, Section 6.2)
   - Request pseudo-terminal
   - Parse terminal modes
   - Handle terminal mode encoding/decoding

3. **Command Execution**
   - Send exec request
   - Execute remote commands
   - Handle command output
   - Handle exit status

4. **Shell Request**
   - Request interactive shell
   - Handle shell output

5. **Environment Variables**
   - Send environment variable requests
   - Parse received environment variables

6. **Window Size Changes**
   - Handle terminal resize events
   - Send window change messages

**Deliverables:**
- Session channel implementation
- PTY allocation
- Command execution
- Interactive shell
- Environment variable handling
- Window size changes

---

### Phase 7: Connection Layer - Port Forwarding (Weeks 13-14)
**Goal:** Implement TCP/IP and X11 forwarding

#### Tasks:
1. **TCP/IP Port Forwarding**
   - Request remote port forwarding
   - Handle forwarded connection requests
   - Implement local port forwarding
   - Handle dynamic SOCKS proxy (optional)

2. **X11 Forwarding**
   - Request X11 forwarding
   - Handle X11 channel connections
   - Forward X11 authentication data

3. **Agent Forwarding**
   - Request agent forwarding
   - Forward SSH agent requests
   - Handle agent channel connections

4. **Forwarding State Management**
   - Track forwarded ports
   - Handle port binding and cleanup

**Deliverables:**
- TCP/IP port forwarding
- X11 forwarding
- Agent forwarding
- Forwarding state management

---

### Phase 8: Key Handling & Formats (Weeks 15-16)
**Goal:** Implement SSH key formats and loading

#### Tasks:
1. **OpenSSH Key Format**
   - Parse OpenSSH private key format (RFC 4716)
   - Support encrypted private keys (passphrase)
   - Support unencrypted private keys

2. **PEM Format**
   - Parse PEM-encoded keys
   - Support traditional SSH key format

3. **Key Type Support**
   - RSA keys (PKCS#1, PKCS#8)
   - ECDSA keys (NIST P-256, P-384, P-521)
   - Ed25519 keys
   - Ed448 keys (RFC 8879)

4. **Key Generation** (optional)
   - Generate new SSH key pairs
   - Support different key sizes

**Deliverables:**
- OpenSSH key format parser
- PEM format parser
- RSA key handling
- ECDSA key handling
- Ed25519 key handling
- Key generation (optional)

---

### Phase 9: Known Hosts & Security (Weeks 17-18)
**Goal:** Implement host key verification and security features

#### Tasks:
1. **Known Hosts Database**
   - Load known_hosts file
   - Parse known_hosts format
   - Verify server host keys against known hosts
   - Add new hosts to known_hosts

2. **Host Key Algorithms**
   - Support RSA (with SHA-2, RFC 7465)
   - Support ECDSA (RFC 6668)
   - Support Ed25519 (RFC 8332)

3. **Security Enhancements**
   - Implement timing attack mitigation
   - Validate all cryptographic parameters
   - Reject weak algorithms
   - Implement strict key verification

**Deliverables:**
- Known hosts database
- Host key verification
- Security hardening
- Weak algorithm rejection

---

### Phase 10: CLI Interface & Integration (Weeks 19-20)
**Goal:** Create command-line interface and integration

#### Tasks:
1. **CLI Implementation**
   - Parse command-line arguments
   - Support connection options (host, port, user)
   - Support identity file options
   - Support known_hosts file option

2. **Interactive Mode**
   - Implement interactive shell mode
   - Handle terminal input/output
   - Support Ctrl+C, Ctrl+D signals

3. **Command Execution Mode**
   - Execute single remote command
   - Return exit status
   - Handle output streaming

4. **Logging & Debugging**
   - Implement detailed logging
   - Support debug mode
   - Add connection diagnostics

5. **Examples & Documentation**
   - Create example code
   - Document API
   - Write usage guide

**Deliverables:**
- CLI application
- Interactive shell mode
- Command execution mode
- Logging system
- Documentation

---

## Dependencies

### Core Dependencies
- `tokio` - Async runtime
- `tokio-util` - Tokio utilities
- `async-trait` - Async trait support
- `thiserror` - Error handling
- `log` - Logging framework

### Cryptographic Dependencies
- `ring` or `aws-lc-rs` - Low-level crypto
- `rsa` - RSA operations
- `ecdsa` - ECDSA operations
- `ed25519-dalek` - Ed25519 operations
- `subtle` - Constant-time operations
- `zeroize` - Memory zeroing

### Encoding Dependencies
- `hex` - Hex encoding
- `base64` - Base64 encoding
- `pem` - PEM parsing

### CLI Dependencies
- `clap` - Command-line argument parsing
- `anyhow` - Error handling

### Testing Dependencies
- `criterion` - Benchmarking
- `mockall` - Mocking for tests

---

## Testing Strategy

### Unit Tests
- Test each module independently
- Test protocol encoding/decoding
- Test cryptographic operations
- Test edge cases

### Integration Tests
- Test full handshake with reference implementations
- Test authentication flows
- Test channel operations
- Test end-to-end connections

### Fuzz Testing
- Fuzz protocol message parsing
- Fuzz key exchange implementations

---

## Security Considerations

1. **Constant-Time Operations**: All cryptographic comparisons must be constant-time
2. **Memory Safety**: Use `zeroize` to clear sensitive data from memory
3. **Algorithm Selection**: Reject weak/deprecated algorithms by default
4. **Key Verification**: Always verify host keys, never trust without verification
5. **Replay Protection**: Use sequence numbers correctly
6. **Timing Attacks**: Mitigate timing attacks in protocol handling

---

## Performance Goals

1. **Handshake Time**: < 200ms for local connection
2. **Throughput**: > 100 MB/s for file transfer
3. **Memory Usage**: < 50MB for idle connection
4. **CPU Usage**: Minimal when idle

---

## Future Enhancements (Out of Scope for MVP)

1. SSH agent protocol implementation
2. SSH config file parsing
3. Connection multiplexing (like SSH control master)
4. SCP/SFTP protocol implementation
5. Compression algorithm negotiation
6. GSSAPI authentication
7. Kerberos authentication

---

## Verification Checklist

- [ ] All RFC 4250-4254 requirements met
- [ ] All unit tests passing
- [ ] All integration tests passing
- [ ] Security audit completed
- [ ] Performance benchmarks within goals
- [ ] Documentation complete
- [ ] CLI working for basic use cases

---

## References

- RFC 4250: The Secure Shell (SSH) Protocol Architecture
- RFC 4251: The Secure Shell (SSH) Protocol Architecture (updated)
- RFC 4252: SSH Authentication Protocol
- RFC 4253: SSH Transport Layer Protocol
- RFC 4254: SSH Connection Protocol
- RFC 4255: Using SSH Public Keys
- RFC 4335: SHA-1 in SSH
- RFC 4344: AES in SSH
- RFC 4462: Diffie-Hellman Group Exchange
- RFC 4470: CBC Mode in SSH
- RFC 4471: Extension Mechanism
- RFC 4716: SSH Public Key Format
- RFC 5656: Extension Negotiation
- RFC 6668: ECDSA Keys in SSH
- RFC 7465: RSA SHA-2 in SSH
- RFC 8332: Ed25519 Keys in SSH
- RFC 8731: Extended Encryption Algorithms
- RFC 8879: Ed448 Keys in SSH
