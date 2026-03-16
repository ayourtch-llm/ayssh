# Debug Session 002: Cisco IOS SSH — Encrypted Transport Bugs

**Date:** 2026-03-16
**Status:** Resolved
**Affected Components:** `src/transport/mod.rs`, `src/crypto/dh.rs`, `src/crypto/hmac.rs`, `src/transport/kex.rs`, `src/client.rs`, `src/session/mod.rs`
**Root Cause:** Twelve distinct bugs across TCP buffering, cryptographic primitives, packet framing, and protocol compliance prevented encrypted communication with Cisco IOS devices

---

## 1. Overview

After fixing the NEWKEYS framing bug (see [Debug Session 001](001-cisco-ios-newkeys-framing.md)), the SSH handshake progressed past the NEWKEYS exchange but failed to establish encrypted communication. Twelve bugs were found and fixed across multiple layers of the SSH implementation, ranging from TCP buffering issues to incorrect cryptographic constants and malformed channel open messages.

The bugs are documented in the order they were discovered during debugging. Several bugs masked each other — fixing one revealed the next.

---

## 2. Bug 1: TCP Buffering — NEWKEYS Consumed During KEXDH_REPLY Read (Critical)

**File:** `src/transport/mod.rs`

### 2.1 Symptom

```
Error: TimeoutError
```

The client timed out waiting for the server's NEWKEYS message, even though the server had already sent it.

### 2.2 Investigation

The Cisco IOS server sends KEXDH_REPLY (448 bytes) and NEWKEYS (16 bytes) in quick succession, often in the same TCP segment. The client used a 1024-byte read buffer for the KEXDH_REPLY read, which consumed both packets in a single `read()` call. The code processed only the KEXDH_REPLY payload and discarded the remaining 16 bytes in the buffer — which were the NEWKEYS packet.

The client then issued another `read()` call waiting for NEWKEYS, but those bytes had already been consumed and thrown away.

### 2.3 Root Cause

No buffering mechanism existed between TCP reads and SSH packet parsing. Each `read()` call assumed it would receive exactly one SSH packet, which is not how TCP works — TCP is a stream protocol with no message boundaries.

### 2.4 Fix

Added a `read_buffer: Vec<u8>` field to the `Transport` struct and created a `read_unencrypted_packet()` helper method. This method:

1. Checks `read_buffer` for leftover bytes from a previous read before issuing a new TCP `read()`.
2. After extracting one complete packet, stores any remaining bytes back into `read_buffer` for the next call.

---

## 3. Bug 2: Wrong DH Group 1 Prime (Critical)

**File:** `src/crypto/dh.rs`

### 3.1 Symptom

After enabling encryption, decrypted `packet_length` values were garbage (e.g., 298334213).

### 3.2 Investigation

The shared secret `K` was wrong because the Diffie-Hellman computation used the wrong prime. This meant the client and server derived different encryption keys, so decryption produced gibberish.

### 3.3 Root Cause

The constant `GROUP1_P` contained the first 1024 bits of the 1536-bit Group 5 prime from RFC 3526, not the actual 1024-bit Oakley Group 2 prime from RFC 2409 (which is what `diffie-hellman-group1-sha1` requires).

The incorrect prime ended with:

```
...ECE45B3D C2007CB8 A163BF05
```

The correct prime from RFC 2409 ends with:

```
...ECE65381 FFFFFFFF FFFFFFFF
```

The correct prime is defined by the formula `p = 2^1024 - 2^960 - 1 + 2^64 * {floor(2^894 * pi) + 129093}`, which mathematically guarantees the last 64 bits are all 1s (`FFFFFFFFFFFFFFFF`). The trailing bytes were a clear indicator that the wrong constant had been used.

### 3.4 Fix

Replaced `GROUP1_P` with the correct 1024-bit prime from RFC 2409 Section 6.2.

---

## 4. Bug 3: HMAC-SHA1 Implementation Bug (Critical)

**File:** `src/crypto/hmac.rs`

### 4.1 Symptom

MAC verification failed in both directions — the server rejected the client's MACs and the client rejected the server's MACs.

### 4.2 Investigation

Even with the correct shared secret and encryption keys, integrity checks failed. This pointed to a bug in the HMAC computation itself, independent of key derivation.

### 4.3 Root Cause

`HmacSha1::finish()` computed `H(K' XOR opad || H(K' XOR ipad || SHA1(text)))` instead of the correct `H(K' XOR opad || H(K' XOR ipad || text))`.

The `update()` method accumulated data in a SHA1 hasher. When `finish()` called `finalize_reset()`, it produced `SHA1(text)` — an intermediate hash. The inner HMAC computation then hashed `ipad || intermediate_hash` instead of `ipad || raw_text`.

Per RFC 2104, HMAC is defined as:

```
HMAC(K, text) = H(K XOR opad || H(K XOR ipad || text))
```

The `text` must be the raw input, not a hash of the input.

### 4.4 Fix

Changed `HmacSha1` to accumulate raw data in a `Vec<u8>` instead of a SHA1 hasher. The `finish()` method now properly computes:

1. Inner hash: `SHA1(K' XOR ipad || raw_text)`
2. Outer hash: `SHA1(K' XOR opad || inner_hash)`

---

## 5. Bug 4: Exchange Hash Missing SSH String Encoding

**File:** `src/transport/kex.rs`

### 5.1 Symptom

Derived encryption keys did not match the server's keys, causing decryption failures.

### 5.2 Investigation

Even with the correct DH prime and HMAC implementation, the encryption keys were wrong. The key derivation starts from the exchange hash `H`, so if `H` is wrong, all derived keys are wrong.

### 5.3 Root Cause

The exchange hash computation concatenated raw bytes without SSH string encoding:

```
H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
```

Per RFC 4253 Section 8, each field in this concatenation must be encoded using SSH data types — strings with a 4-byte length prefix, and mpints with a 4-byte length prefix and proper sign-bit handling. The code was writing raw bytes without any length prefixes, producing a different hash than the server.

### 5.4 Fix

Wrapped all fields with proper SSH encoding:

- `V_C`, `V_S`, `I_C`, `I_S`, `K_S`: encoded as SSH strings (`[4-byte length][data]`)
- `e`, `f`, `K`: encoded as SSH mpints (`[4-byte length][sign-extended data]`)

---

## 6. Bug 5: Sequence Numbers Reset After NEWKEYS

**File:** `src/transport/mod.rs`

### 6.1 Symptom

MAC mismatch after transitioning to encrypted transport. (This bug was masked by earlier bugs and would have manifested once those were fixed.)

### 6.2 Root Cause

When the encryption/decryption state was initialized after the NEWKEYS exchange, the sequence numbers were set to 0. Per RFC 4253 Section 6.4:

> The sequence number is initialized to zero for the first packet, and is incremented after every packet (regardless of whether encryption or MAC is in use).

After the unencrypted handshake phase (KEXINIT at seq=0, KEXDH_INIT at seq=1, NEWKEYS at seq=2), the first encrypted packet should use seq=3, not seq=0.

### 6.3 Fix

Added `send_sequence_number` and `recv_sequence_number` fields to the `Transport` struct. These counters persist across the NEWKEYS transition and are passed to the encryption/decryption state during initialization.

---

## 7. Bug 6: `recv_message()` Packet Length Calculation Off By 4

**File:** `src/transport/mod.rs`

### 7.1 Symptom

The client read the wrong number of bytes from the stream, resulting in an incorrect split between ciphertext and MAC.

### 7.2 Root Cause

The encrypted packet reading code computed:

```rust
total_bytes = packet_length + mac_len
```

But `packet_length` does not include the 4-byte `packet_length` field itself, and in SSH's encrypted mode, those 4 bytes are also encrypted. The correct calculation is:

```rust
total_bytes = 4 + packet_length + mac_len
```

### 7.3 Fix

Rewrote `recv_message()` to properly handle AES-CBC decryption:

1. Read and decrypt the first AES block (16 bytes) to extract `packet_length`.
2. Calculate `total_encrypted = 4 + packet_length` (must be block-aligned).
3. Read the remaining ciphertext bytes: `total_encrypted - 16` (first block already read).
4. Read the MAC: `mac_len` bytes after the ciphertext.
5. Decrypt remaining ciphertext blocks.
6. Verify the MAC over the entire plaintext.

---

## 8. Bug 7: AES-CBC Padding Alignment Wrong

**File:** `src/transport/mod.rs`

### 8.1 Symptom

Some payload sizes produced non-block-aligned ciphertext, causing AES-CBC encryption to fail or produce corrupted output.

### 8.2 Root Cause

The padding alignment calculation used modulo 8, but AES-128-CBC has a 16-byte block size. Per RFC 4253 Section 6:

> random padding
>   Arbitrary-length padding, such that the total length of (packet_length || padding_length || payload || random padding) is a multiple of the cipher block size or 8, whichever is larger.

For AES-128-CBC, the cipher block size is 16, which is larger than 8.

### 8.3 Fix

Changed `encrypt_packet_cbc()` to use `block_size = 16` for AES-CBC ciphers, ensuring the total packet (excluding MAC) is always a multiple of 16 bytes.

---

## 9. Bug 8: PKCS#7 Padding Removal on SSH Packets

**File:** `src/transport/mod.rs`

### 9.1 Symptom

Decrypted packet data was corrupted — the last few bytes of the plaintext were missing or wrong.

### 9.2 Root Cause

The code called `aes_128_cbc_decrypt()`, which automatically removes PKCS#7 padding after decryption. However, SSH does not use PKCS#7 padding — it uses its own padding scheme where random padding bytes are appended, and the `padding_length` field tells the receiver how many to strip.

PKCS#7 removal inspects the last byte of the decrypted plaintext, interprets it as a padding count, and removes that many bytes. Since SSH's random padding bytes have arbitrary values, this would strip a random number of bytes from the end of the packet.

### 9.3 Fix

Changed to `aes_128_cbc_decrypt_raw()`, which returns the raw decrypted bytes without stripping any padding. The SSH padding is then removed by the SSH packet parsing logic using the `padding_length` field.

---

## 10. Bug 9: Payload Extraction Off By 1

**File:** `src/transport/mod.rs`

### 10.1 Symptom

The server's KEXINIT payload (`I_S`) included one extra padding byte at the end, causing the exchange hash `H` to be wrong and all derived keys to be wrong.

### 10.2 Root Cause

The payload extraction calculation was:

```rust
payload_end = 5 + packet_len - padding_len
```

The SSH binary packet structure is:

```
[4 bytes: packet_length] [1 byte: padding_length] [payload] [padding]
```

Where `packet_length = 1 (padding_length field) + payload_length + padding_length`.

The payload starts at byte offset 5 (after the 4-byte length and 1-byte padding length). The payload length is `packet_length - 1 - padding_length`. So:

```
payload_end = 5 + (packet_length - 1 - padding_length)
            = 4 + packet_length - padding_length
```

The original code used `5 +` instead of `4 +`, making `payload_end` one byte too large and including the first padding byte as part of the payload.

### 10.3 Fix

Changed to `payload_end = 4 + packet_len - padding_len`.

---

## 11. Bug 10: Wrong Service Name

**File:** `src/client.rs`

### 11.1 Symptom

The server might reject the SSH_MSG_SERVICE_REQUEST, preventing authentication from starting.

### 11.2 Root Cause

The client sent a service request for `"ssh-connection"` instead of `"ssh-userauth"`. Per RFC 4252 Section 2, the authentication protocol is initiated by the client requesting the `"ssh-userauth"` service. The `"ssh-connection"` service is requested later, after authentication succeeds.

### 11.3 Fix

Changed the service name from `"ssh-connection"` to `"ssh-userauth"`.

---

## 12. Bug 11: SERVICE_ACCEPT Parsing

**File:** `src/transport/mod.rs`

### 12.1 Symptom

```
Buffer too small: need 100663296 bytes
```

### 12.2 Root Cause

When parsing the SSH_MSG_SERVICE_ACCEPT response (message type 6), the code called `SshString::decode()` starting at byte 0 of the payload. Byte 0 is the message type byte (`0x06`), not the start of the service name string.

`SshString::decode()` interprets the first 4 bytes as a length prefix. Reading from byte 0, it consumed `[0x06, ...]` as part of the length field, producing a nonsensical string length (100663296 = `0x06000000` on a big-endian read).

### 12.3 Fix

Skip the message type byte before decoding the service name — start `SshString::decode()` at byte 1 of the payload.

---

## 13. Bug 12: CHANNEL_OPEN Message Format

**File:** `src/session/mod.rs`

### 13.1 Symptom

The server responded with SSH_MSG_CHANNEL_OPEN_FAILURE (message type 92) instead of SSH_MSG_CHANNEL_OPEN_CONFIRMATION.

### 13.2 Root Cause

The SSH_MSG_CHANNEL_OPEN message had two problems:

1. **Wrong field order:** The fields were not in the order specified by RFC 4254 Section 5.1.
2. **Malformed channel type string:** The string length prefix was incorrect.

Per RFC 4254 Section 5.1, the format is:

```
byte      SSH_MSG_CHANNEL_OPEN (90)
string    channel type ("session")
uint32    sender channel
uint32    initial window size
uint32    maximum packet size
```

### 13.3 Fix

Reordered the fields to match RFC 4254 and fixed the string length prefix for the channel type.

---

## 14. Lessons Learned

1. **TCP is a stream protocol.** Never assume a single `read()` call returns exactly one SSH packet. Always buffer incoming data and parse complete packets from the buffer. Leftover bytes belong to the next packet.

2. **Verify cryptographic constants against the RFC.** The DH prime was subtly wrong — it came from the right family of primes but was the wrong size. The last 64 bits being all 1s is a mathematical property of the Group 2 prime that serves as a quick visual check.

3. **HMAC is not hash-of-hash.** The HMAC construction requires the raw message as input to the inner hash, not a pre-hashed version. Wrapping data in a SHA1 hasher during `update()` and then hashing again in `finish()` adds an extra layer of hashing that breaks the HMAC specification.

4. **SSH string encoding is pervasive.** The exchange hash computation requires every field to be SSH-encoded with length prefixes. Raw byte concatenation produces a different (incorrect) hash even if all the field values are correct.

5. **Sequence numbers are connection-global.** They count every packet from connection start, not from the last key exchange. Resetting them at NEWKEYS causes MAC verification failures.

6. **SSH has its own padding scheme.** Do not use PKCS#7 padding removal with SSH packets. SSH's `padding_length` field handles padding explicitly, and PKCS#7 removal will corrupt the plaintext.

7. **Off-by-one errors compound.** A single byte offset error in payload extraction (Bug 9) propagates through the exchange hash computation into key derivation, making every subsequent encrypted operation fail. These errors are difficult to diagnose because the symptom (decryption failure) is far removed from the cause (wrong payload boundary).

8. **Read the RFC field order carefully.** Both the SERVICE_ACCEPT parsing (Bug 11) and CHANNEL_OPEN formatting (Bug 12) were caused by not following the exact byte layout specified in the RFC. When in doubt, write out the expected wire format byte-by-byte.
