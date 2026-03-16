# Debug Session 001: Cisco IOS SSH Connection Failure — NEWKEYS Packet Framing Bug

**Date:** 2026-03-16
**Status:** Resolved
**Affected Component:** `src/transport/kex.rs`, `src/transport/mod.rs`, `src/transport/handshake.rs`
**Root Cause:** `encode_newkeys()` sent a bare message-type byte instead of a properly framed SSH binary packet

---

## 1. Symptom

Attempting to connect to a Cisco IOS device (`SSH-1.99-Cisco-1.25`) using
`cisco_ssh` resulted in a **timeout error** on the client side:

```
Error: TimeoutError
```

The Cisco device logged:

```
%SSH-4-SSH2_UNEXPECTED_MSG: Unexpected message type has arrived. Terminating the connection
```

The connection completed the version exchange, KEXINIT negotiation, and
Diffie-Hellman key exchange (KEXDH_INIT / KEXDH_REPLY) successfully, but
failed immediately after the shared secret and session ID were computed —
right at the NEWKEYS exchange step.

---

## 2. Debug Logs

### 2.1 Client-Side Log (ayssh)

```
Connecting to Cisco device at 192.168.0.130...
DEBUG ssh_client::transport::handshake: Sending version string: Ok("SSH-2.0-OpenSSH_7.4\r\n")
DEBUG ssh_client::transport::handshake: Cleaned version string: "SSH-1.99-Cisco-1.25"
DEBUG ssh_client::transport: Server version: SSH-1.99-Cisco-1.25
DEBUG ssh_client::transport: Generated client KEXINIT (771 bytes)
DEBUG ssh_client::transport: KEXINIT: sending 784 bytes total
DEBUG ssh_client::transport: Server KEXINIT packet length: 276 bytes
DEBUG ssh_client::transport: Negotiated KEX algorithm: diffie-hellman-group1-sha1
DEBUG ssh_client::transport: Sending KEXDH_INIT packet (payload=133, padding=6, total=144)
DEBUG ssh_client::transport: KEXDH_REPLY packet length: 444 bytes
DEBUG ssh_client::transport::kex: Session ID (first 16 bytes): [23, 127, 34, ...]
DEBUG ssh_client::transport::kex: Shared secret (first 16 bytes): [187, 50, 105, ...]
Error: TimeoutError
```

**Key observation:** The log ends right after computing the shared secret.
There is no log line about sending or receiving NEWKEYS. The client computes
the shared secret, then silently times out.

### 2.2 Server-Side Log (Cisco IOS `debug ip ssh`)

```
SSH2 4: SSH2_MSG_KEXINIT sent
SSH2 4: SSH2_MSG_KEXINIT received
SSH2: kex: client->server aes128-cbc hmac-sha1 none
SSH2: kex: server->client aes128-cbc hmac-sha1 none
SSH2 4: expecting SSH2_MSG_KEXDH_INIT
SSH2 4: SSH2_MSG_KEXDH_INIT received
SSH2 4: signature length 143
SSH2 4: send: len 448 (includes padlen 8)       ← KEXDH_REPLY sent
SSH2: kex_derive_keys complete
SSH2 4: send: len 16 (includes padlen 10)       ← NEWKEYS sent (16 bytes)
SSH2 4: SSH2_MSG_NEWKEYS sent
SSH2 4: waiting for SSH2_MSG_NEWKEYS             ← Waiting for client NEWKEYS
SSH2 4: ssh_receive: 1 bytes received            ← *** Only 1 byte received! ***
...
%SSH-4-SSH2_UNEXPECTED_MSG: Unexpected message type has arrived.
                            Terminating the connection
```

**Critical clue:** The server received exactly **1 byte** when it expected a
full NEWKEYS packet. A properly framed NEWKEYS packet should be **16 bytes**
(4-byte length + 1-byte padding length + 1-byte payload + 10-byte padding).

---

## 3. Investigation

### 3.1 Following the Packet Through the Code

The handshake flow in `TransportSession::handshake()` (file `src/transport/mod.rs`)
proceeds as:

1. Version exchange ✅
2. KEXINIT exchange ✅
3. KEXDH_INIT / KEXDH_REPLY exchange ✅
4. Compute shared secret and session ID ✅
5. **Send NEWKEYS** ← Problem here
6. Receive NEWKEYS from server

Step 5 is implemented as:

```rust
// src/transport/mod.rs, line 472-474
let newkeys_msg = crate::transport::kex::encode_newkeys();
self.stream_mut().write_all(&newkeys_msg).await?;
```

### 3.2 The `encode_newkeys()` Function

```rust
// src/transport/kex.rs (BEFORE fix)
pub fn encode_newkeys() -> Vec<u8> {
    // SSH_MSG_NEWKEYS is just a single-byte message type (RFC 4253 Section 7)
    vec![protocol::MessageType::Newkeys.value()]
}
```

This returns `vec![21]` — a **single byte**. The function's comment even
mentions the SSH binary packet format but then ignores it.

### 3.3 Comparing with Correctly Framed Packets

Looking at how KEXDH_INIT is sent (same file, same handshake function), it
uses correct SSH binary packet framing:

```rust
// KEXDH_INIT — correctly framed (src/transport/mod.rs, lines 330-354)
let packet_length = payload_len as u32 + padding_length as u32 + 1;
let mut kexdh_init_msg = bytes::BytesMut::new();
kexdh_init_msg.put_u32(packet_length);      // 4-byte packet length
kexdh_init_msg.put_u8(padding_length);       // 1-byte padding length
kexdh_init_msg.put_slice(&kexdh_init_payload); // payload
for _ in 0..padding_length {                 // padding bytes
    kexdh_init_msg.put_u8(0);
}
```

The Cisco IOS correctly received this as 144 bytes. But the NEWKEYS
message was just sent as a raw byte, without any framing.

### 3.4 What the Server Expected

Per RFC 4253 Section 6, **every** SSH message must be sent as a binary packet:

```
uint32    packet_length
byte      padding_length
byte[n1]  payload; n1 = packet_length - padding_length - 1
byte[n2]  random padding; n2 = padding_length
```

For a NEWKEYS message (1-byte payload = `[21]`):

| Field | Value | Bytes |
|-------|-------|-------|
| packet_length | 12 | `00 00 00 0C` |
| padding_length | 10 | `0A` |
| payload (SSH_MSG_NEWKEYS) | 21 | `15` |
| random padding | 10 bytes | `xx xx xx xx xx xx xx xx xx xx` |
| **Total** | | **16 bytes** |

Alignment check: `4 + 1 + 1 + 10 = 16` → multiple of 8 ✓
Minimum padding: `10 ≥ 4` ✓
Minimum packet size: `16 ≥ 16` ✓

Instead, the client sent just `[21]` (1 byte). The Cisco device read this
single byte, could not parse it as a valid SSH packet, and disconnected.

---

## 4. Additional Bugs Found

### 4.1 Off-by-One in NEWKEYS Receive Check (`src/transport/mod.rs`)

```rust
// BEFORE (line 496)
if newkeys_bytes.len() >= 5 && newkeys_bytes[5] == ...
```

Accessing `newkeys_bytes[5]` (byte index 5) requires `len >= 6`, not `>= 5`.
If the server happened to send exactly 5 bytes, this would panic with an
index-out-of-bounds error.

### 4.2 Wrong Byte Index in `handshake.rs` NEWKEYS Validation

```rust
// BEFORE (handshake.rs, line 446)
if newkeys_bytes[0] != protocol::MessageType::Newkeys as u8 { ... }
```

After reading the 4-byte `packet_length` and then `packet_length` bytes of
packet body, the packet body starts with the `padding_length` byte, NOT the
payload. The message type byte is at index **1**, not index **0**:

```
packet body: [padding_length (1 byte)] [payload...] [padding...]
              index 0                   index 1
```

---

## 5. Fix

### 5.1 `encode_newkeys()` (`src/transport/kex.rs`)

Rewrote to return a properly framed SSH binary packet with:
- Correct `packet_length` field (includes padding_length byte + payload + padding)
- Proper 8-byte alignment
- Minimum 4 bytes of random padding (per RFC 4253 Section 6)
- Total packet size of 16 bytes

### 5.2 NEWKEYS Receive Bounds Check (`src/transport/mod.rs`)

Changed `>= 5` to `>= 6` for safe access of `newkeys_bytes[5]`.

### 5.3 NEWKEYS Parse Index (`src/transport/handshake.rs`)

Changed `newkeys_bytes[0]` to `newkeys_bytes[1]` with a `len < 2` guard,
so the message type byte is read from the correct position after the
`padding_length` byte.

---

## 6. Tests Added

### `test_encode_newkeys` (updated)

Validates the NEWKEYS packet structure:
- Total size ≥ 16 bytes (minimum SSH packet)
- Total size is 8-byte aligned
- `packet_length` field matches actual wire size
- Message type byte (21) is at the correct position (byte index 5)
- Padding ≥ 4 bytes

### `test_encode_newkeys_rfc4253_compliance` (new)

Comprehensive RFC 4253 Section 6 compliance test:
- 8-byte alignment of total packet
- Minimum packet size of 16 bytes
- Padding in range [4, 255]
- Wire size = 4 + packet_length
- Payload is exactly 1 byte (message type 21)
- Correct relationship: `packet_length = 1 + payload_len + padding_len`

---

## 7. Verification

All 891 tests pass after the fix (313 lib tests + 566 integration tests +
3 debug tests + 9 doc-tests).

---

## 8. Lessons Learned

1. **Every SSH message must be a properly framed binary packet.** The SSH
   protocol has no concept of sending raw message-type bytes on the wire.
   Even single-byte messages like NEWKEYS must be wrapped in the standard
   packet format.

2. **Compare with working code paths.** The KEXINIT and KEXDH_INIT packets
   were correctly framed in the same file. The NEWKEYS encoding was an
   outlier that didn't follow the same pattern.

3. **Cross-reference client and server logs.** The server log showing
   "ssh_receive: 1 bytes received" was the critical clue that pinpointed
   the packet size as the issue. Without the Cisco `debug ip ssh` output,
   the client-side "TimeoutError" alone would have been much harder to
   diagnose.

4. **Validate packet structure in tests.** The original test only checked
   that the output was 1 byte with the correct message type — which
   validated the *wrong* behavior. Tests should validate the wire format,
   not just the payload content.
