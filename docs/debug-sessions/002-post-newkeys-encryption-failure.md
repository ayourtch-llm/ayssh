# Debug Session 002: Post-NEWKEYS Encryption Failure — Multiple Bugs

**Date:** 2026-03-16
**Status:** Resolved
**Affected Components:** `src/transport/kex.rs`, `src/transport/mod.rs`
**Root Cause:** Session hash computed without RFC 4253 §8 SSH string/mpint encoding; plus 6 additional bugs in the encrypted transport layer

---

## 1. Symptom

After fixing the NEWKEYS packet framing bug (session 001), the NEWKEYS
exchange now completes successfully:

```
SSH2 4: SSH2_MSG_NEWKEYS received   ← NEWKEYS exchange works!
```

But the **first encrypted packet** after NEWKEYS produces garbage on the
Cisco IOS server:

```
SSH2 4: ssh_receive: 52 bytes received
SSH2 4: input: packet len -1648749987    ← Garbage!
SSH2 4: Bad packet length -1648749991.
```

And the client also fails decrypting the server's response:

```
Extracted packet length: 4017544833
Error: ProtocolError("Invalid packet length: 4017544833")
```

---

## 2. Debug Logs

### 2.1 Cisco IOS Server (`debug ip ssh`)

```
SSH2 4: SSH2_MSG_NEWKEYS sent
SSH2 4: waiting for SSH2_MSG_NEWKEYS
SSH2 4: ssh_receive: 16 bytes received        ← NEWKEYS correctly 16 bytes
SSH2 4: input: padlen 10
SSH2 4: newkeys: mode 0
SSH2 4: received packet type 21
SSH2 4: SSH2_MSG_NEWKEYS received              ← NEWKEYS accepted ✓
SSH2 4: ssh_receive: 52 bytes received         ← First encrypted packet
SSH2 4: input: packet len -1648749987          ← Decryption produces garbage
SSH2 4: Bad packet length -1648749991.
SSH2 4: send: len 64 (includes padlen 16)      ← Server sends DISCONNECT
SSH2 4: done calc MAC out #3
SSH4: Session disconnected - error 0x07
```

### 2.2 Client Log

```
INFO  ssh_client::transport: SSH handshake completed
DEBUG ssh_client::transport: Sending SERVICE_REQUEST for 'ssh-connection'
DEBUG ssh_client::transport: Encrypting message of 19 bytes
DEBUG ssh_client::transport: Encrypted to 52 bytes     ← Correct size: 32 enc + 20 MAC
DEBUG ssh_client::transport: SERVICE_REQUEST sent successfully
DEBUG ssh_client::transport: Waiting for SERVICE_ACCEPT...
DEBUG ssh_client::transport: Decrypted first block: [239, 118, 222, 129, ...]  ← Garbage
DEBUG ssh_client::transport: Extracted packet length: 4017544833
Error: ProtocolError("Invalid packet length: 4017544833")
```

**Key observation:** Both sides receive data but decrypt to garbage.
This means the encryption keys are different on each side — the session
hash used for key derivation is wrong.

---

## 3. Root Cause Analysis

### 3.1 Bug 1 (ROOT CAUSE): Session Hash Missing SSH Encoding

Per RFC 4253 Section 8, the exchange hash H for `diffie-hellman-group1-sha1`
is computed as:

```
H = hash(string V_C || string V_S || string I_C || string I_S ||
         string K_S || mpint e || mpint f || mpint K)
```

Where `string` means **SSH string encoding** (4-byte big-endian length prefix
followed by the data), and `mpint` means **SSH mpint encoding** (4-byte
length prefix + value bytes with sign-bit handling).

**The bug:** `update_session_hash()` in `kex.rs` was feeding raw bytes into
the hash WITHOUT the 4-byte length prefixes:

```rust
// BEFORE (WRONG)
hasher.update(vc_clean);        // V_C: raw bytes, no length prefix
hasher.update(vs_clean);        // V_S: raw bytes, no length prefix
hasher.update(ic);              // I_C: raw bytes, no length prefix
hasher.update(is);              // I_S: raw bytes, no length prefix
hasher.update(hs);              // K_S: raw bytes, no length prefix
hasher.update(ec);              // e:   raw MPINT, no length prefix

// AFTER (CORRECT)
hasher.update(&(vc_clean.len() as u32).to_be_bytes());
hasher.update(vc_clean);        // V_C: SSH string
hasher.update(&(vs_clean.len() as u32).to_be_bytes());
hasher.update(vs_clean);        // V_S: SSH string
// ... same pattern for I_C, I_S, K_S, e
```

Only `f` (server_ephemeral) and `K` (shared secret) were already correctly
length-prefixed. All other fields were raw — producing a different hash
than what the Cisco server computes, leading to different derived keys.

### 3.2 Bug 2: Sequence Numbers Initialized to 0

Per RFC 4253 Section 6.4, sequence numbers start at 0 for the **first
packet** and increment for **every** packet, including unencrypted ones.
They do NOT reset after NEWKEYS.

During the handshake:
- Client sends: KEXINIT (seq 0), KEXDH_INIT (seq 1), NEWKEYS (seq 2)
- Client receives: KEXINIT (seq 0), KEXDH_REPLY (seq 1), NEWKEYS (seq 2)

So the first encrypted packet must use sequence number **3**, not 0.

```rust
// BEFORE (WRONG)
sequence_number: 0,

// AFTER (CORRECT)
sequence_number: 3,  // After KEXINIT(0) + KEXDH_INIT(1) + NEWKEYS(2)
```

Wrong sequence numbers would cause MAC verification failure even with
correct encryption keys.

### 3.3 Bug 3: Padding Alignment (8 vs 16)

RFC 4253 Section 6 requires the total packet size to be a multiple of
`max(cipher_block_size, 8)`. For AES-128-CBC, the block size is 16.

The code used 8-byte alignment, which for some payload sizes would
produce packets that aren't multiples of 16 bytes — causing
`aes_128_cbc_encrypt_raw` to reject the input.

### 3.4 Bug 4: recv_message Total Bytes Off by 4

In CBC mode, the 4-byte `packet_length` field is itself encrypted.
So the total encrypted data on the wire is `4 + packet_length`, not
just `packet_length`. The code was reading 4 fewer bytes than needed:

```rust
// BEFORE (WRONG)
let total_bytes = packet_length + mac_len;
let encrypted = &buffer[..packet_length];

// AFTER (CORRECT)
let total_encrypted = 4 + packet_length;
// ... read total_encrypted + mac_len bytes total ...
```

### 3.5 Bug 5: recv_message Using PKCS#7 Decrypt

The code called `aes_128_cbc_decrypt()` which removes PKCS#7 padding.
SSH packets use their own padding scheme (specified in the packet header).
Using PKCS#7 removal would corrupt the decrypted data by stripping
legitimate SSH padding bytes.

Fixed to use `aes_128_cbc_decrypt_raw()` (no padding removal).

### 3.6 Bug 6: recv_message Returning Wrong Data

`recv_message` was returning the full decrypted packet (including the
4-byte length field and 1-byte padding_length), but callers (like
`recv_service_accept`) expected just the payload.

Fixed to extract the payload by parsing the packet structure:
```
decrypted: [packet_length(4)][padding_length(1)][payload][padding]
return: payload only
```

### 3.7 Bug 7: decrypt_packet_cbc Using PKCS#7 Decrypt

Same as Bug 5 but in the standalone `decrypt_packet_cbc` function.

---

## 4. Fix Summary

| Bug | File | Line | Description |
|-----|------|------|-------------|
| 1 | `kex.rs` | `update_session_hash()` | Add SSH string encoding (4-byte length prefix) for V_C, V_S, I_C, I_S, K_S, e |
| 2 | `mod.rs` | Encryption state init | Set `sequence_number: 3` instead of `0` |
| 3 | `mod.rs` | `encrypt_packet_cbc()` | Align to `max(cipher_block, 8) = 16` for AES |
| 4 | `mod.rs` | `recv_message()` | Total encrypted = `4 + packet_length` |
| 5 | `mod.rs` | `recv_message()` | Use `aes_128_cbc_decrypt_raw` |
| 6 | `mod.rs` | `recv_message()` | Extract payload from decrypted packet |
| 7 | `mod.rs` | `decrypt_packet_cbc()` | Use `aes_128_cbc_decrypt_raw` |

---

## 5. Tests Added

### 5.1 Session Hash Tests (`kex.rs`)

- `test_session_hash_includes_length_prefixes`: Verifies different version
  strings produce different hashes (proving they're included in the hash).

- `test_session_hash_encoding_manual_verification`: Constructs the hash
  input manually with proper SSH encoding and verifies `KexContext` produces
  the same hash. This is the definitive test that would have caught Bug 1.

### 5.2 Encrypt/Decrypt Tests (`mod.rs`)

- `test_encrypt_decrypt_roundtrip`: Full encrypt → decrypt cycle with
  payload recovery.

- `test_encrypt_packet_alignment`: Verifies all payload sizes produce
  16-byte-aligned encrypted data for AES-128.

- `test_sequence_number_in_mac`: Proves wrong sequence number causes MAC
  failure; correct sequence number succeeds.

- `test_multiple_packets_iv_chaining`: Sends 5 packets with CBC IV
  chaining and sequence number tracking.

---

## 6. Verification

All tests pass after the fix:
- 319 lib tests (313 existing + 6 new)
- 566 integration tests
- 3 ignored tests
- 9 doc tests

---

## 7. Lessons Learned

1. **RFC 4253 §8 specifies SSH encoding, not raw bytes.** When the RFC
   says `string V_C`, it means the SSH `string` type — a 4-byte length
   prefix followed by the data. This is easy to miss because the
   surrounding text describes the *semantic* meaning of each field, not
   its encoding.

2. **Both sides compute the same hash.** If the session hash is wrong,
   ALL derived keys are wrong, and EVERY encrypted packet is garbage. The
   "Bad packet length" error is a red herring — the actual problem is
   that decryption produces random-looking bytes.

3. **Sequence numbers don't reset on NEWKEYS.** They are a transport-layer
   counter that increments for every packet sent/received, regardless of
   encryption state. The first encrypted packet has `seq = 3`, not `seq = 0`.

4. **SSH uses its own padding, not PKCS#7.** The SSH binary packet format
   includes a `padding_length` field that specifies the padding. Using
   PKCS#7 padding removal would corrupt the data by stripping bytes that
   might look like valid PKCS#7 padding but are actually SSH padding.

5. **The 4-byte length field is encrypted in CBC mode.** This means the
   total encrypted data on the wire is `4 + packet_length`, not just
   `packet_length`. The receive side must account for this when reading
   and splitting the buffer.

6. **Padding must align to the cipher block size.** For AES-128 (16-byte
   blocks), the total packet must be a multiple of 16. Using 8-byte
   alignment (which is correct for unencrypted packets) would produce
   non-16-aligned packets that AES rejects.
