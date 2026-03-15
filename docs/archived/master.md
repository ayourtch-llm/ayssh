Master plan of implementation

Each step of the plan MUST be implemented by a subagent.

1) Download and check in all RFCs related to SSH protocol
   ✅ COMPLETED: All 19 SSH RFCs downloaded to docs/rfc/

2) Read the RFCs and build an implementation plan for implementing a ssh client
   using async tokio framework.
   ✅ COMPLETED: Implementation plan created at docs/plans/ssh_client_implementation.md

3) Split the implementation plan into the manageable tasks.
   ✅ COMPLETED: Detailed task list created at docs/plans/ssh_client_tasks.md

4) Use TDD from superpowers to oversee the implementation of each task.
   🔄 PENDING: Implementation using TDD workflow

5) Verify all the tests pass.
   🔄 PENDING: Test verification

---

## Implementation Details

### Phase 1: Foundation (Weeks 1-2)
- Initialize Cargo project
- Define protocol types and data representations
- Implement SSH string encoding and binary packet protocol

### Phase 2: Transport Layer - Handshake (Weeks 3-4)
- Protocol version exchange
- Algorithm negotiation
- Diffie-Hellman key exchange (Group14 and GroupExchange)
- ECDH key exchange
- Session identifier computation
- Host key verification
- Transport state machine

### Phase 3: Transport Layer - Encryption (Weeks 5-6)
- AES cipher implementation (CTR and CBC)
- ChaCha20-Poly1305 AEAD
- HMAC implementations (SHA256, SHA512)
- Key derivation function
- Encrypted packet protocol
- Compression support

### Phase 4: Authentication (Weeks 7-8)
- Authentication state machine
- Public key authentication
- Password authentication
- Method negotiation

### Phase 5: Connection Layer (Weeks 9-10)
- Connection service request
- Channel management

### Phase 6: Sessions & Commands (Weeks 11-12)
- Session channel
- PTY allocation
- Command execution

### Phase 7: Port Forwarding (Weeks 13-14)
- TCP/IP forwarding

### Phase 8: Key Handling (Weeks 15-16)
- OpenSSH key format parsing
- RSA, ECDSA, Ed25519 key handling

### Phase 9: Known Hosts (Weeks 17-18)
- Known hosts database

### Phase 10: CLI (Weeks 19-20)
- Command-line interface

---

## References

- Implementation Plan: docs/plans/ssh_client_implementation.md
- Detailed Task List: docs/plans/ssh_client_tasks.md
- RFCs: docs/rfc/ (19 files)

---

## Notes

- Each task should be implemented using TDD (Test-Driven Development)
- Tests must fail first, then implementation code is written
- Code review required before merging each task
- All tests must pass before moving to next phase
