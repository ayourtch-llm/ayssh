# SSH Client Implementation Plan - Complete Guide

**Target:** Build a fully functional SSH client in Rust following RFC 4250-4254  
**Current Status:** Framework complete (71.86% coverage), Core crypto missing  
**Estimated Effort:** 120-160 hours for a single engineer  
**Timeline:** 4-6 weeks (part-time), 2-3 weeks (full-time)

---

## 📋 Prerequisites

### Knowledge Requirements
- Rust programming (async/await, traits, generics)
- SSH protocol basics (RFC 4250-4254)
- Cryptography basics (DH, AES, HMAC, KDF)
- Async Rust (Tokio runtime)

### Dependencies to Add

Add these to `Cargo.toml`:

```toml
[dependencies]
# Async runtime
tokio = { version = "1.35", features = ["full"] }
tokio-util = { version = "0.7", features = ["codec"] }

# Cryptography (RustCrypto crates)
aes = "0.8"
ctr = "0.9"
aes-gcm = "0.10"
chacha20 = "0.9"
poly1305 = "0.8"
hmac = "0.12"
sha2 = "0.10"
digest = "0.10"
blake2 = "0.10"

# Elliptic curves
ecdsa = "0.16"
elliptic-curve = "0.13"
k256 = "0.13" # NIST P-256
x25519-dalek = "2.0"

# RSA
rsa = "0.9"

# Ed25519
ed25519-dalek = "2.1"

# Error handling
thiserror = "1.0"
anyhow = "1.0"

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"

# Utilities
bytes = "1.5"
hex = "0.4"
base64 = "0.21"
zeroize = "1.7"

# Big integers for DH
num-bigint = "0.4"
num-traits = "0.2"

# CLI
clap = { version = "4.4", features = ["derive"] }
```

---

## 🏗️ Architecture Overview

```
ayssh/
├── src/
│   ├── lib.rs
│   ├── main.rs
│   ├── protocol/          # ✅ Complete
│   │   ├── messages.rs    # All 31 message types
│   │   ├── types.rs       # SSH data types
│   │   ├── algorithms.rs  # Algorithm negotiation
│   │   └── errors.rs      # Error types
│   ├── transport/         # ⚠️ Partial (50%)
│   │   ├── version.rs     # ✅ Complete
│   │   ├── handshake.rs   # ⚠️ Partial (KEXINIT only)
│   │   ├── state.rs       # ✅ Complete
│   │   ├── kex.rs         # ❌ Missing (implement this!)
│   │   ├── packet.rs      # ⚠️ Partial (stub)
│   │   ├── encrypted.rs   # ⚠️ Partial (stub)
│   │   └── cipher.rs      # ❌ Missing (implement this!)
│   ├── crypto/            # ❌ Missing (implement all!)
│   │   ├── mod.rs
│   │   ├── kdf.rs         # ⚠️ Partial (stub)
│   │   ├── hmac.rs        # ❌ Missing
│   │   ├── cipher.rs      # ❌ Missing
│   │   ├── dh.rs          # ❌ Missing
│   │   └── chacha20_poly1305.rs # ❌ Missing
│   ├── auth/              # ⚠️ Partial (60%)
│   │   ├── state.rs       # ✅ Complete
│   │   ├── methods.rs     # ✅ Complete
│   │   ├── mod.rs         # ⚠️ Partial (framework)
│   │   ├── publickey.rs   # ❌ Missing (crypto)
│   │   └── password.rs    # ❌ Missing (crypto)
│   ├── connection/        # ⚠️ Partial (40%)
│   │   ├── mod.rs         # ⚠️ Partial (basic connect)
│   │   ├── state.rs       # ✅ Complete
│   │   ├── channels.rs    # ❌ Missing
│   │   ├── session.rs     # ❌ Missing
│   │   ├── exec.rs        # ❌ Missing
│   │   └── forward.rs     # ❌ Missing
│   ├── channel/           # ✅ Types complete
│   │   ├── types.rs       # ✅ Complete
│   │   ├── state.rs       # ✅ Complete
│   │   └── mod.rs         # ⚠️ Partial (no data transfer)
│   ├── keys/              # ❌ Missing (implement all!)
│   │   ├── mod.rs
│   │   ├── formats.rs     # ❌ Missing
│   │   ├── rsa.rs         # ❌ Missing
│   │   ├── ecdsa.rs       # ❌ Missing
│   │   └── ed25519.rs     # ❌ Missing
│   ├── utils/             # ✅ Mostly complete
│   │   ├── buffer.rs      # ✅ Complete
│   │   └── string.rs      # ✅ Complete
│   └── error.rs           # ✅ Complete
└── tests/                 # ✅ 533 tests passing
```

---

## 📅 Phase 1: Key Exchange (KEX) - 25 hours

**Goal:** Implement Diffie-Hellman and ECDH key exchange  
**RFC:** 4253 Section 7, 4462, 5656, 8731

### Task 1.1: Implement BigInt Helper (2 hours)

**File:** `src/crypto/dh.rs` (Create new)

```rust
//! Diffie-Hellman Key Exchange
//!
//! Implements DH and ECDH key exchange algorithms.

use num_bigint::BigUint;
use num_traits::One;
use num_traits::Zero;
use sha2::{Sha256, Sha512, Digest};
use std::convert::TryInto;

/// DH Group 14 (2048-bit MODP) - RFC 8731
pub struct DhGroup14Sha256;

impl DhGroup14Sha256 {
    /// Generator G
    pub const G: &'static str = "2";
    
    /// Prime P (2048-bit)
    pub const P: &'static str = 
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
         29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
         EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
         E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
         EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381\
         FFFFFFFFFFFFFFFFFF";
    
    /// Convert hex string to BigUint
    fn hex_to_biguint(hex: &str) -> BigUint {
        BigUint::parse_bytes(hex.as_bytes(), 16).unwrap()
    }
    
    /// Get prime P as BigUint
    pub fn get_p() -> BigUint {
        Self::hex_to_biguint(Self::P)
    }
    
    /// Get generator G as BigUint
    pub fn get_g() -> BigUint {
        BigUint::parse_bytes(Self::G.as_bytes(), 16).unwrap()
    }
    
    /// Generate private key (random number 1 < x < p-1)
    pub fn generate_private_key(rng: &mut impl rand::RngCore) -> BigUint {
        let p = Self::get_p();
        let mut x = BigUint::from(2u64);
        
        while x >= p - 1u64.into() {
            let random_bytes = rng.gen::<[u8; 256]>();
            x = BigUint::from_bytes_be(&random_bytes);
        }
        
        x
    }
    
    /// Compute public key: y = g^x mod p
    pub fn compute_public_key(x: &BigUint) -> BigUint {
        let g = Self::get_g();
        let p = Self::get_p();
        
        g.modpow(x, &p)
    }
    
    /// Compute shared secret: K = y^x mod p
    pub fn compute_shared_secret(private_x: &BigUint, public_y: &BigUint) -> BigUint {
        let p = Self::get_p();
        public_y.modpow(private_x, &p)
    }
    
    /// Compute session identifier H = HASH(K | ... )
    pub fn compute_session_id(
        k: &BigUint,
        client_kexinit: &[u8],
        server_kexinit: &[u8],
        server_host_key: &[u8],
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        
        // K in big-endian, minimum 16 bytes
        let k_bytes = k.to_bytes_be();
        let k_padded = if k_bytes.len() < 16 {
            vec![0u8; 16 - k_bytes.len()].into_iter()
                .chain(k_bytes.into_iter())
                .collect::<Vec<_>>()
        } else {
            k_bytes
        };
        
        hasher.update(&k_padded);
        hasher.update(client_kexinit);
        hasher.update(server_kexinit);
        hasher.update(server_host_key);
        
        hasher.finalize().to_vec()
    }
}

/// ECDH with NIST P-256 curve - RFC 5656
pub struct EcdhNistp256;

impl EcdhNistp256 {
    /// Compute ECDH shared secret
    pub fn compute_shared_secret(
        private_key: &k256::SecretKey,
        public_key: &k256::PublicKey,
    ) -> k256::SharedSecret {
        k256::SharedSecret::new(public_key)
    }
    
    /// Convert shared secret to bytes
    pub fn shared_secret_to_bytes(secret: &k256::SharedSecret) -> Vec<u8> {
        secret.to_bytes()
    }
}

/// ECDH with Curve25519
pub struct Curve25519;

impl Curve25519 {
    /// Generate private key (32 random bytes)
    pub fn generate_private_key(rng: &mut impl rand::RngCore) -> x25519_dalek::StaticSecret {
        x25519_dalek::StaticSecret::random_from_rng(rng)
    }
    
    /// Convert private key to public key
    pub fn compute_public_key(private_key: &x25519_dalek::StaticSecret) -> x25519_dalek::PublicKey {
        let public_key: x25519_dalek::PublicKey = private_key.into();
        public_key
    }
    
    /// Compute shared secret
    pub fn compute_shared_secret(
        private_key: &x25519_dalek::StaticSecret,
        public_key: &x25519_dalek::PublicKey,
    ) -> x25519_dalek::SharedSecret {
        private_key.diffie_hellman(public_key)
    }
}
```

### Task 1.2: Implement DH Key Exchange Function (5 hours)

**File:** `src/transport/kex.rs` (Update existing)

```rust
//! Key Exchange (KEX) Implementation
//!
//! Implements various key exchange algorithms.

use crate::crypto::dh::{DhGroup14Sha256, EcdhNistp256, Curve25519};
use crate::protocol::KexAlgorithm;
use rand::rngs::OsRng;
use num_bigint::BigUint;

/// Key exchange context
#[derive(Debug)]
pub struct KexContext {
    /// Selected algorithm
    pub algorithm: KexAlgorithm,
    /// Client's ephemeral key
    pub client_ephemeral: Option<Vec<u8>>,
    /// Server's ephemeral key
    pub server_ephemeral: Option<Vec<u8>>,
    /// Shared secret (if computed)
    pub shared_secret: Option<Vec<u8>>,
    /// Session ID (if computed)
    pub session_id: Option<Vec<u8>>,
}

impl KexContext {
    /// Create a new KEX context
    pub fn new(algorithm: KexAlgorithm) -> Self {
        Self {
            algorithm,
            client_ephemeral: None,
            server_ephemeral: None,
            shared_secret: None,
            session_id: None,
        }
    }
    
    /// Perform Diffie-Hellman key exchange
    pub async fn perform_dh(&mut self) -> anyhow::Result<()> {
        let mut rng = OsRng;
        
        match self.algorithm {
            KexAlgorithm::DiffieHellmanGroup14Sha256 => {
                // Generate client private key
                let client_x = DhGroup14Sha256::generate_private_key(&mut rng);
                
                // Compute client public key
                let client_y = DhGroup14Sha256::compute_public_key(&client_x);
                
                // Serialize client public key (big-endian, minimal encoding)
                let client_pub_bytes = client_y.to_bytes_be();
                self.client_ephemeral = Some(client_pub_bytes);
                
                // TODO: Send client KEX_INIT and wait for server response
                // TODO: Receive server public key
                // TODO: Compute shared secret
                // TODO: Compute session ID
                
                Ok(())
            }
            KexAlgorithm::EcdhSha2Nistp256 => {
                // Generate ECDH private key
                let private_key = k256::SecretKey::random(&mut rng);
                let public_key = k256::PublicKey::from(&private_key);
                
                let pub_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
                self.client_ephemeral = Some(pub_bytes);
                
                // TODO: Receive server public key
                // TODO: Compute shared secret
                // TODO: Compute session ID
                
                Ok(())
            }
            KexAlgorithm::Curve25519Sha256 => {
                // Generate Curve25519 private key
                let private_key = Curve25519::generate_private_key(&mut rng);
                let public_key = Curve25519::compute_public_key(&private_key);
                
                let pub_bytes = public_key.as_bytes().to_vec();
                self.client_ephemeral = Some(pub_bytes);
                
                // TODO: Receive server public key
                // TODO: Compute shared secret
                // TODO: Compute session ID
                
                Ok(())
            }
        }
    }
    
    /// Compute shared secret from received server key
    pub fn compute_shared_secret(&mut self, server_ephemeral: &[u8]) -> anyhow::Result<()> {
        match self.algorithm {
            KexAlgorithm::DiffieHellmanGroup14Sha256 => {
                let server_y = BigUint::from_bytes_be(server_ephemeral);
                // TODO: Get client private key
                // TODO: Compute K = server_y^client_x mod p
                self.shared_secret = Some(vec![0u8; 32]); // Placeholder
                Ok(())
            }
            KexAlgorithm::EcdhSha2Nistp256 => {
                // TODO: Implement ECDH shared secret computation
                self.shared_secret = Some(vec![0u8; 32]); // Placeholder
                Ok(())
            }
            KexAlgorithm::Curve25519Sha256 => {
                // TODO: Implement Curve25519 shared secret computation
                self.shared_secret = Some(vec![0u8; 32]); // Placeholder
                Ok(())
            }
        }
    }
}

/// Perform key exchange with given algorithm
pub async fn perform_kex(
    algorithm: KexAlgorithm,
    context: &mut KexContext,
    client_kexinit: &[u8],
    server_kexinit: &[u8],
    server_host_key: &[u8],
) -> anyhow::Result<()> {
    // Step 1: Generate client ephemeral key
    context.perform_dh().await?;
    
    // Step 2: Send KEX_DH_GEX_REQUEST (if applicable) or ECDH public key
    // TODO: Send client ephemeral key to server
    
    // Step 3: Receive server ephemeral key
    // TODO: Read server response
    
    // Step 4: Compute shared secret
    // TODO: context.compute_shared_secret(server_ephemeral)?;
    
    // Step 5: Compute session ID H
    // TODO: context.session_id = Some(DhGroup14Sha256::compute_session_id(...));
    
    Ok(())
}
```

### Task 1.3: Add Tests (3 hours)

**File:** `tests/integration/kex_tests.rs` (Create new)

```rust
//! Key Exchange Tests
//!
//! Tests for DH and ECDH key exchange implementations.

#[cfg(test)]
mod tests {
    use ssh_client::crypto::dh::{DhGroup14Sha256, EcdhNistp256, Curve25519};
    use rand::rngs::OsRng;
    
    #[test]
    fn test_dh_group14_prime_p() {
        let p = DhGroup14Sha256::get_p();
        assert!(p.to_bytes_be().len() == 256); // 2048 bits
    }
    
    #[test]
    fn test_dh_generate_private_key() {
        let mut rng = OsRng;
        let x = DhGroup14Sha256::generate_private_key(&mut rng);
        
        assert!(x > num_bigint::BigUint::from(1u64));
        assert!(x < DhGroup14Sha256::get_p() - num_bigint::BigUint::from(1u64));
    }
    
    #[test]
    fn test_dh_compute_public_key() {
        let mut rng = OsRng;
        let x = DhGroup14Sha256::generate_private_key(&mut rng);
        let y = DhGroup14Sha256::compute_public_key(&x);
        
        assert!(y > num_bigint::BigUint::from(1u64));
        assert!(y < DhGroup14Sha256::get_p());
    }
    
    #[test]
    fn test_dh_shared_secret_symmetry() {
        let mut rng = OsRng;
        
        // Client generates key
        let client_x = DhGroup14Sha256::generate_private_key(&mut rng);
        let client_y = DhGroup14Sha256::compute_public_key(&client_x);
        
        // Server generates key
        let server_x = DhGroup14Sha256::generate_private_key(&mut rng);
        let server_y = DhGroup14Sha256::compute_public_key(&server_x);
        
        // Both compute shared secret
        let client_k = DhGroup14Sha256::compute_shared_secret(&client_x, &server_y);
        let server_k = DhGroup14Sha256::compute_shared_secret(&server_x, &client_y);
        
        // Secrets should match
        assert_eq!(client_k.to_bytes_be(), server_k.to_bytes_be());
    }
    
    #[test]
    fn test_curve25519_key_exchange() {
        let mut rng = OsRng;
        
        // Client generates key
        let client_private = Curve25519::generate_private_key(&mut rng);
        let client_public = Curve25519::compute_public_key(&client_private);
        
        // Server generates key
        let server_private = Curve25519::generate_private_key(&mut rng);
        let server_public = Curve25519::compute_public_key(&server_private);
        
        // Both compute shared secret
        let client_secret = Curve25519::compute_shared_secret(&client_private, &server_public);
        let server_secret = Curve25519::compute_shared_secret(&server_private, &client_public);
        
        // Secrets should match
        assert_eq!(client_secret.to_bytes(), server_secret.to_bytes());
    }
    
    #[test]
    fn test_session_id_computation() {
        let mut rng = OsRng;
        let x = DhGroup14Sha256::generate_private_key(&mut rng);
        let y = DhGroup14Sha256::compute_public_key(&x);
        let k = DhGroup14Sha256::compute_shared_secret(&x, &y);
        
        let client_kexinit = vec![0x00, 0x01, 0x02, 0x03];
        let server_kexinit = vec![0x04, 0x05, 0x06, 0x07];
        let server_host_key = vec![0x08, 0x09, 0x0a, 0x0b];
        
        let session_id = DhGroup14Sha256::compute_session_id(
            &k,
            &client_kexinit,
            &server_kexinit,
            &server_host_key,
        );
        
        assert_eq!(session_id.len(), 32); // SHA-256 output
    }
}
```

---

## 📅 Phase 2: Cipher Implementations - 20 hours

**Goal:** Implement AES and ChaCha20 ciphers  
**RFC:** 4253 Section 6, 4344, 8439

### Task 2.1: Implement AES-CTR (8 hours)

**File:** `src/crypto/cipher.rs` (Create new)

```rust
//! Cipher Implementations
//!
//! Implements AES-CTR, AES-GCM, and ChaCha20-Poly1305.

use aes::Aes256;
use ctr::Ctr128BE;
use typenum::U32;
use zeroize::Zeroize;
use std::marker::PhantomData;

/// AES-256-CTR cipher
pub struct Aes256Ctr;

impl Aes256Ctr {
    /// Key size: 32 bytes
    pub const KEY_SIZE: usize = 32;
    
    /// Block size: 16 bytes
    pub const BLOCK_SIZE: usize = 16;
    
    /// Initialize cipher with key
    pub fn new(key: &[u8]) -> anyhow::Result<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(anyhow::anyhow!(
                "Invalid key length: expected {}, got {}",
                Self::KEY_SIZE,
                key.len()
            ));
        }
        
        Ok(Self)
    }
    
    /// Encrypt data using AES-CTR
    pub fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let cipher = Ctr128BE::<Aes256>::from_key_iv(key, iv)?;
        
        let mut result = plaintext.to_vec();
        for (i, chunk) in result.chunks_mut(Self::BLOCK_SIZE).enumerate() {
            let mut counter = [0u8; 16];
            counter[..12].copy_from_slice(iv);
            counter[12..].copy_from_slice(&(i as u64).to_be_bytes());
            
            let mut keystream = [0u8; 16];
            keystream.copy_from_slice(&counter);
            
            // XOR with keystream (simplified - proper implementation uses cipher)
            for (j, byte) in chunk.iter_mut().enumerate().take(chunk.len()) {
                *byte ^= keystream[j % 16];
            }
        }
        
        Ok(result)
    }
    
    /// Decrypt data using AES-CTR (same as encrypt due to CTR mode)
    pub fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.encrypt(key, iv, ciphertext)
    }
}

/// AES-128-GCM cipher
pub struct Aes128Gcm;

impl Aes128Gcm {
    pub const KEY_SIZE: usize = 16;
    pub const TAG_SIZE: usize = 16;
    pub const NONCE_SIZE: usize = 12;
    
    pub fn new(key: &[u8]) -> anyhow::Result<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(anyhow::anyhow!(
                "Invalid key length: expected {}, got {}",
                Self::KEY_SIZE,
                key.len()
            ));
        }
        
        Ok(Self)
    }
    
    /// Encrypt with GCM mode
    pub fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
        
        let cipher = Aes128Gcm::new_from_slice(key)?;
        let nonce = Nonce::from_slice(nonce);
        
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
        Ok(ciphertext)
    }
    
    /// Decrypt with GCM mode
    pub fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
        
        let cipher = Aes128Gcm::new_from_slice(key)?;
        let nonce = Nonce::from_slice(nonce);
        
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
        Ok(plaintext)
    }
}

/// AES-256-GCM cipher
pub struct Aes256Gcm;

impl Aes256Gcm {
    pub const KEY_SIZE: usize = 32;
    pub const TAG_SIZE: usize = 16;
    pub const NONCE_SIZE: usize = 12;
    
    pub fn new(key: &[u8]) -> anyhow::Result<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(anyhow::anyhow!(
                "Invalid key length: expected {}, got {}",
                Self::KEY_SIZE,
                key.len()
            ));
        }
        
        Ok(Self)
    }
    
    /// Encrypt with GCM mode
    pub fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        
        let cipher = Aes256Gcm::new_from_slice(key)?;
        let nonce = Nonce::from_slice(nonce);
        
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
        Ok(ciphertext)
    }
    
    /// Decrypt with GCM mode
    pub fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        
        let cipher = Aes256Gcm::new_from_slice(key)?;
        let nonce = Nonce::from_slice(nonce);
        
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
        Ok(plaintext)
    }
}
```

### Task 2.2: Implement ChaCha20-Poly1305 (7 hours)

**File:** `src/crypto/chacha20_poly1305.rs` (Create new)

```rust
//! ChaCha20-Poly1305 AEAD Cipher
//!
//! Implements RFC 8439.

use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Aead};
use zeroize::Zeroize;

/// ChaCha20-Poly1305 cipher
pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    /// Key size: 32 bytes
    pub const KEY_SIZE: usize = 32;
    
    /// Nonce size: 12 bytes
    pub const NONCE_SIZE: usize = 12;
    
    /// Tag size: 16 bytes
    pub const TAG_SIZE: usize = 16;
    
    /// Initialize cipher with key
    pub fn new(key: &[u8]) -> anyhow::Result<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(anyhow::anyhow!(
                "Invalid key length: expected {}, got {}",
                Self::KEY_SIZE,
                key.len()
            ));
        }
        
        Ok(Self)
    }
    
    /// Encrypt with ChaCha20-Poly1305
    pub fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce);
        
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())?;
        Ok(ciphertext)
    }
    
    /// Decrypt with ChaCha20-Poly1305
    pub fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce);
        
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
        Ok(plaintext)
    }
}
```

### Task 2.3: Add Cipher Tests (5 hours)

**File:** `tests/integration/cipher_tests.rs` (Create new)

```rust
//! Cipher Tests

#[cfg(test)]
mod tests {
    use ssh_client::crypto::cipher::{Aes256Ctr, Aes256Gcm, ChaCha20Poly1305};
    
    #[test]
    fn test_aes256ctr_encrypt_decrypt() {
        let cipher = Aes256Ctr::new(&[0x00; 32]).unwrap();
        let key = [0x00; 32];
        let iv = [0x00; 16];
        let plaintext = b"Hello, World!";
        
        let ciphertext = cipher.encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = cipher.decrypt(&key, &iv, &ciphertext).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_aes256gcm_encrypt_decrypt() {
        let cipher = Aes256Gcm::new(&[0x00; 32]).unwrap();
        let key = [0x00; 32];
        let nonce = [0x00; 12];
        let aad = b"additional data";
        let plaintext = b"Secret message";
        
        let ciphertext = cipher.encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_chacha20poly1305_encrypt_decrypt() {
        let cipher = ChaCha20Poly1305::new(&[0x00; 32]).unwrap();
        let key = [0x00; 32];
        let nonce = [0x00; 12];
        let aad = b"header";
        let plaintext = b"Top secret";
        
        let ciphertext = cipher.encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_chacha20poly1305_invalid_tag() {
        let cipher = ChaCha20Poly1305::new(&[0x00; 32]).unwrap();
        let key = [0x00; 32];
        let nonce = [0x00; 12];
        let aad = b"header";
        let plaintext = b"Secret";
        
        let ciphertext = cipher.encrypt(&key, &nonce, plaintext, aad).unwrap();
        
        // Corrupt the ciphertext
        let mut corrupted = ciphertext.clone();
        corrupted[0] ^= 0xFF;
        
        // Decryption should fail
        assert!(cipher.decrypt(&key, &nonce, &corrupted, aad).is_err());
    }
}
```

---

## 📅 Phase 3: MAC & KDF - 10 hours

**Goal:** Implement HMAC and KDF  
**RFC:** 4253 Section 6-7

### Task 3.1: Implement HMAC-SHA2 (5 hours)

**File:** `src/crypto/hmac.rs` (Create new)

```rust
//! HMAC Implementations
//!
//! Implements HMAC-SHA2-256 and HMAC-SHA2-512.

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// HMAC-SHA2-256
pub struct HmacSha256;

impl HmacSha256 {
    pub const KEY_SIZE: usize = 32;
    pub const TAG_SIZE: usize = 32;
    
    /// Compute HMAC-SHA2-256
    pub fn compute(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
    
    /// Verify HMAC-SHA2-256
    pub fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(data);
        mac.verify_slice(tag).is_ok()
    }
}

/// HMAC-SHA2-512
pub struct HmacSha512;

impl HmacSha512 {
    pub const KEY_SIZE: usize = 64;
    pub const TAG_SIZE: usize = 64;
    
    /// Compute HMAC-SHA2-512
    pub fn compute(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha512::new_from_slice(key).unwrap();
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
    
    /// Verify HMAC-SHA2-512
    pub fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        let mut mac = HmacSha512::new_from_slice(key).unwrap();
        mac.update(data);
        mac.verify_slice(tag).is_ok()
    }
}

/// ETM (Encrypt-then-MAC) variants
pub struct HmacSha256EtM;

impl HmacSha256EtM {
    /// Compute HMAC-SHA2-256-ETM
    pub fn compute(key: &[u8], data: &[u8]) -> Vec<u8> {
        HmacSha256::compute(key, data)
    }
}

pub struct HmacSha512EtM;

impl HmacSha512EtM {
    /// Compute HMAC-SHA2-512-ETM
    pub fn compute(key: &[u8], data: &[u8]) -> Vec<u8> {
        HmacSha512::compute(key, data)
    }
}
```

### Task 3.2: Implement KDF (3 hours)

**File:** `src/crypto/kdf.rs` (Update existing)

```rust
//! Key Derivation Function
//!
//! Implements SSH KDF as per RFC 4253 Section 7.

use sha2::{Sha256, Sha512, Digest};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// SSH KDF function
///
/// Derives key material from shared secret K.
///
/// # Arguments
///
/// * `hash` - Hash function to use (SHA-256 or SHA-512)
/// * `key` - Shared secret K
/// * `label` - Label string (e.g., "session key")
/// * `counter` - Counter value (1, 2, 3, ...)
///
/// # Returns
///
/// * `Vec<u8>` - Derived key material (up to 32/64 bytes)
pub fn ssh_kdf(hash: &mut impl Digest, key: &[u8], label: &[u8], counter: u32) -> Vec<u8> {
    let mut result = Vec::new();
    let mut current_hash = Vec::new();
    
    // A0 = 0x00000000 || counter
    let mut a0 = Vec::new();
    a0.extend_from_slice(&counter.to_be_bytes());
    
    // Hash = H(K || A0)
    let mut hasher = hash.clone();
    hasher.update(key);
    hasher.update(&a0);
    current_hash = hasher.finalize_reset();
    
    // Result = Hash
    result.extend_from_slice(&current_hash);
    
    result
}

/// Derive encryption key
pub fn derive_encryption_key(
    hash: &mut impl Digest,
    k: &[u8],
    key_length: usize,
) -> Vec<u8> {
    ssh_kdf(hash, k, b"encryption key", 1)
}

/// Derive MAC key
pub fn derive_mac_key(
    hash: &mut impl Digest,
    k: &[u8],
    key_length: usize,
) -> Vec<u8> {
    ssh_kdf(hash, k, b"MAC key", 2)
}

/// Derive IV
pub fn derive_iv(
    hash: &mut impl Digest,
    k: &[u8],
    iv_length: usize,
) -> Vec<u8> {
    ssh_kdf(hash, k, b"IV", 3)
}
```

### Task 3.3: Add MAC & KDF Tests (2 hours)

**File:** `tests/integration/mac_kdf_tests.rs` (Create new)

```rust
//! MAC and KDF Tests

#[cfg(test)]
mod tests {
    use ssh_client::crypto::hmac::{HmacSha256, HmacSha512};
    use ssh_client::crypto::kdf::derive_encryption_key;
    use sha2::Sha256;
    
    #[test]
    fn test_hmac_sha256() {
        let key = b"secret_key";
        let data = b"Hello, World!";
        
        let tag = HmacSha256::compute(key, data);
        assert_eq!(tag.len(), 32);
        
        assert!(HmacSha256::verify(key, data, &tag));
        assert!(!HmacSha256::verify(key, b"different", &tag));
    }
    
    #[test]
    fn test_hmac_sha512() {
        let key = b"secret_key";
        let data = b"Hello, World!";
        
        let tag = HmacSha512::compute(key, data);
        assert_eq!(tag.len(), 64);
        
        assert!(HmacSha512::verify(key, data, &tag));
    }
    
    #[test]
    fn test_derive_encryption_key() {
        let mut hash = Sha256::new();
        let k = b"shared_secret";
        
        let key = derive_encryption_key(&mut hash, k, 32);
        assert_eq!(key.len(), 32);
    }
}
```

---

## 📅 Phase 4: Packet Protocol - 15 hours

**Goal:** Implement encrypted packet protocol  
**RFC:** 4253 Section 6

### Task 4.1: Implement Packet Structure (5 hours)

**File:** `src/transport/packet.rs` (Update existing)

```rust
//! Packet Protocol Implementation
//!
//! Implements SSH binary packet protocol.

use bytes::{Buf, BufMut, BytesMut};
use crate::crypto::cipher::{Aes256Gcm, ChaCha20Poly1305};
use crate::crypto::hmac::{HmacSha256, HmacSha512};

/// SSH Packet
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet length (excluding length field and padding length)
    pub length: u32,
    /// Padding length
    pub padding_length: u8,
    /// Payload (including message type)
    pub payload: Vec<u8>,
    /// Padding
    pub padding: Vec<u8>,
    /// MAC (if using non-AEAD cipher)
    pub mac: Option<Vec<u8>>,
}

impl Packet {
    /// Encode packet to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(
            4 + 1 + self.length as usize + 1 + self.padding.len()
        );
        
        // Length (4 bytes)
        buf.put_u32(self.length);
        
        // Padding length (1 byte)
        buf.put_u8(self.padding_length);
        
        // Payload
        buf.extend_from_slice(&self.payload);
        
        // Padding
        buf.extend_from_slice(&self.padding);
        
        buf.to_vec()
    }
    
    /// Decode packet from bytes
    pub fn decode(data: &mut &[u8]) -> anyhow::Result<Self> {
        if data.len() < 5 {
            return Err(anyhow::anyhow!("Packet too short"));
        }
        
        let length = data.get_u32();
        let padding_length = data.get_u8();
        
        let payload_len = length as usize;
        let total_len = 1 + payload_len + padding_length as usize;
        
        if data.len() < total_len + 1 {
            return Err(anyhow::anyhow!("Packet data too short"));
        }
        
        let payload = data.split_to(payload_len).to_vec();
        let padding = data.split_to(padding_length as usize).to_vec();
        
        Ok(Self {
            length,
            padding_length,
            payload,
            padding,
            mac: None,
        })
    }
    
    /// Compute padding length (must make total length multiple of 8 or 16)
    pub fn compute_padding_length(payload_len: usize) -> u8 {
        let min_padding = 4; // Minimum padding
        let block_size = 8; // AES block size
        
        let total = 1 + payload_len + min_padding;
        let padding = (block_size - (total % block_size)) % block_size;
        
        padding as u8
    }
}

/// Encrypted packet handler
pub struct PacketHandler {
    /// Encryption cipher
    cipher: CipherType,
    /// MAC algorithm
    mac: MacType,
    /// Sequence number
    sequence_number: u32,
}

enum CipherType {
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

enum MacType {
    HmacSha256,
    HmacSha512,
}

impl PacketHandler {
    /// Create new packet handler
    pub fn new(
        cipher: CipherType,
        mac: MacType,
        encryption_key: &[u8],
        mac_key: &[u8],
    ) -> Self {
        Self {
            cipher,
            mac,
            sequence_number: 0,
        }
    }
    
    /// Encrypt packet
    pub fn encrypt_packet(&self, packet: &Packet) -> anyhow::Result<Vec<u8>> {
        let mut plaintext = packet.encode();
        
        // Add MAC if using non-AEAD cipher
        if let MacType::HmacSha256 = self.mac {
            let mac = HmacSha256::compute(
                &self.sequence_number.to_be_bytes(),
                &plaintext
            );
            plaintext.extend_from_slice(&mac);
        }
        
        // Encrypt
        // TODO: Implement actual encryption
        
        self.sequence_number = self.sequence_number.wrapping_add(1);
        
        Ok(plaintext)
    }
    
    /// Decrypt packet
    pub fn decrypt_packet(&self, ciphertext: &[u8]) -> anyhow::Result<Packet> {
        // TODO: Implement actual decryption
        
        self.sequence_number = self.sequence_number.wrapping_add(1);
        
        Ok(Packet {
            length: 0,
            padding_length: 0,
            payload: Vec::new(),
            padding: Vec::new(),
            mac: None,
        })
    }
}
```

---

## 📅 Phase 5: Public Key Cryptography - 25 hours

**Goal:** Implement RSA, ECDSA, Ed25519 signing  
**RFC:** 4716, 6668, 7465, 8332

### Task 5.1: Implement RSA Keys (10 hours)

**File:** `src/keys/rsa.rs` (Create new)

```rust
//! RSA Key Operations
//!
//! Implements RSA signing and verification.

use rsa::{RsaPrivateKey, RsaPublicKey, PaddingScheme, Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Sha256, Sha512, Digest};

/// RSA key pair
pub struct RsaKeyPair {
    /// Private key
    private_key: RsaPrivateKey,
    /// Public key
    public_key: RsaPublicKey,
}

impl RsaKeyPair {
    /// Create new RSA key pair
    pub fn new(private_key: RsaPrivateKey) -> Self {
        let public_key = RsaPublicKey::from(&private_key);
        
        Self {
            private_key,
            public_key,
        }
    }
    
    /// Sign data using RSA-SHA256
    pub fn sign_sha256(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        let signature = self.private_key
            .sign(PaddingScheme::new_pkcs1v15_sign::<Sha256>(), &hash)?;
        
        Ok(signature.to_vec())
    }
    
    /// Sign data using RSA-SHA512
    pub fn sign_sha512(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        let signature = self.private_key
            .sign(PaddingScheme::new_pkcs1v15_sign::<Sha512>(), &hash)?;
        
        Ok(signature.to_vec())
    }
    
    /// Verify signature using RSA-SHA256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        self.public_key
            .verify(PaddingScheme::new_pkcs1v15_sign::<Sha256>(), &hash, signature)?;
        
        Ok(())
    }
    
    /// Verify signature using RSA-SHA512
    pub fn verify_sha512(&self, data: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        let mut hasher = Sha512::new();
        hasher.update(data);
        let hash = hasher.finalize();
        
        self.public_key
            .verify(PaddingScheme::new_pkcs1v15_sign::<Sha512>(), &hash, signature)?;
        
        Ok(())
    }
    
    /// Get public key blob (OpenSSH format)
    pub fn public_key_blob(&self) -> Vec<u8> {
        // Format: string "ssh-rsa", string exponent, string modulus
        // TODO: Implement proper encoding
        Vec::new()
    }
}

/// Load RSA private key from PEM file
pub fn load_rsa_key_from_pem(pem_data: &[u8]) -> anyhow::Result<RsaKeyPair> {
    let private_key = RsaPrivateKey::from_pkcs1_pem(pem_data)?;
    Ok(RsaKeyPair::new(private_key))
}

/// Load RSA private key from OpenSSH format
pub fn load_rsa_key_from_openssh(openssh_data: &[u8]) -> anyhow::Result<RsaKeyPair> {
    // TODO: Implement OpenSSH format parsing
    unimplemented!()
}
```

### Task 5.2: Implement ECDSA Keys (7 hours)

**File:** `src/keys/ecdsa.rs` (Create new)

```rust
//! ECDSA Key Operations
//!
//! Implements ECDSA signing and verification.

use ecdsa::{SigningKey, VerifyingKey, Signature, SignatureSize};
use elliptic_curve::{sec1::FromEncodedPoint, PrimeField};
use k256::{ecdsa, Secp256r1};

/// ECDSA key pair (NIST P-256)
pub struct EcdsaKeyPair {
    /// Private key
    signing_key: SigningKey<Secp256r1>,
    /// Public key
    verifying_key: VerifyingKey<Secp256r1>,
}

impl EcdsaKeyPair {
    /// Create new ECDSA key pair
    pub fn new(signing_key: SigningKey<Secp256r1>) -> Self {
        let verifying_key = VerifyingKey::from(&signing_key);
        
        Self {
            signing_key,
            verifying_key,
        }
    }
    
    /// Sign data using ECDSA-SHA256
    pub fn sign_sha256(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use ecdsa::SignatureEncoding;
        
        let signature: Signature<Secp256r1> = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
    
    /// Verify signature using ECDSA-SHA256
    pub fn verify_sha256(&self, data: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        let signature = Signature::<Secp256r1>::try_from(signature)?;
        
        self.verifying_key
            .verify(data, &signature)?;
        
        Ok(())
    }
    
    /// Get public key blob (OpenSSH format)
    pub fn public_key_blob(&self) -> Vec<u8> {
        // Format: string "ecdsa-sha2-nistp256", string curve name, EC point
        // TODO: Implement proper encoding
        Vec::new()
    }
}

/// Load ECDSA private key from PEM
pub fn load_ecdsa_key_from_pem(pem_data: &[u8]) -> anyhow::Result<EcdsaKeyPair> {
    use elliptic_curve::pkcs8::DecodePrivateKey;
    
    let signing_key = SigningKey::<Secp256r1>::from_pkcs8_pem(pem_data)?;
    Ok(EcdsaKeyPair::new(signing_key))
}
```

### Task 5.3: Implement Ed25519 Keys (8 hours)

**File:** `src/keys/ed25519.rs` (Create new)

```rust
//! Ed25519 Key Operations
//!
//! Implements Ed25519 signing and verification.

use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
use rand::rngs::OsRng;

/// Ed25519 key pair
pub struct Ed25519KeyPair {
    /// Private key
    signing_key: SigningKey,
    /// Public key
    verifying_key: VerifyingKey,
}

impl Ed25519KeyPair {
    /// Generate new Ed25519 key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        
        Self {
            signing_key,
            verifying_key,
        }
    }
    
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        
        Self {
            signing_key,
            verifying_key,
        }
    }
    
    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }
    
    /// Verify signature
    pub fn verify(&self, data: &[u8], signature: &Signature) -> anyhow::Result<()> {
        self.verifying_key
            .verify(data, signature)?;
        Ok(())
    }
    
    /// Get public key blob (OpenSSH format)
    pub fn public_key_blob(&self) -> Vec<u8> {
        // Format: string "ssh-ed25519", string public key
        let mut buf = Vec::new();
        
        // Algorithm name
        buf.extend_from_slice(&("ssh-ed25519".len() as u32).to_be_bytes());
        buf.extend_from_slice(b"ssh-ed25519");
        
        // Public key (32 bytes)
        buf.extend_from_slice(self.verifying_key.as_bytes());
        
        buf
    }
}

/// Load Ed25519 private key from OpenSSH format
pub fn load_ed25519_key_from_openssh(openssh_data: &[u8]) -> anyhow::Result<Ed25519KeyPair> {
    // TODO: Implement OpenSSH format parsing
    unimplemented!()
}
```

---

## 📅 Phase 6: Integration & Testing - 20 hours

### Task 6.1: Create Integration Tests (10 hours)

**File:** `tests/integration/complete_handshake.rs` (Create new)

```rust
//! Complete SSH Handshake Integration Test
//!
//! Tests the full handshake from connection to authentication.

#[cfg(test)]
mod tests {
    use ssh_client::transport::kex::KexContext;
    use ssh_client::protocol::KexAlgorithm;
    
    #[tokio::test]
    async fn test_dh_key_exchange() {
        let mut context = KexContext::new(KexAlgorithm::DiffieHellmanGroup14Sha256);
        
        // This would require a mock server
        // For now, test the crypto components
        assert!(context.algorithm == KexAlgorithm::DiffieHellmanGroup14Sha256);
    }
    
    #[tokio::test]
    async fn test_cipher_encryption() {
        use ssh_client::crypto::cipher::ChaCha20Poly1305;
        
        let cipher = ChaCha20Poly1305::new(&[0x00; 32]).unwrap();
        let key = [0x00; 32];
        let nonce = [0x00; 12];
        let plaintext = b"Test message";
        
        let ciphertext = cipher.encrypt(&key, &nonce, plaintext, b"").unwrap();
        let decrypted = cipher.decrypt(&key, &nonce, &ciphertext, b"").unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
}
```

### Task 6.2: Run Full Test Suite (5 hours)

```bash
# Run all tests
cargo test --all

# Run with coverage
cargo tarpaulin --out Html --out Terminal

# Check coverage
cargo tarpaulin --out Html
```

### Task 6.3: Performance Testing (5 hours)

**File:** `benches/kex_benchmark.rs` (Create new)

```rust
//! Key Exchange Benchmark

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ssh_client::crypto::dh::DhGroup14Sha256;
use rand::rngs::OsRng;

fn benchmark_dh_key_exchange(c: &mut Criterion) {
    c.bench_function("dh_group14_key_exchange", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            let client_x = DhGroup14Sha256::generate_private_key(&mut rng);
            let client_y = DhGroup14Sha256::compute_public_key(&client_x);
            black_box(client_y)
        })
    });
}

criterion_group!(benches, benchmark_dh_key_exchange);
criterion_main!(benches);
```

---

## 📊 Verification Checklist

After implementing each phase, verify:

### Phase 1: KEX
- [ ] DH group14 parameters correct
- [ ] ECDH NIST P-256 working
- [ ] Curve25519 working
- [ ] Session ID computation correct
- [ ] All KEX tests passing

### Phase 2: Ciphers
- [ ] AES-256-CTR encrypt/decrypt working
- [ ] AES-256-GCM encrypt/decrypt working
- [ ] ChaCha20-Poly1305 encrypt/decrypt working
- [ ] All cipher tests passing

### Phase 3: MAC & KDF
- [ ] HMAC-SHA2-256 computing correctly
- [ ] HMAC-SHA2-512 computing correctly
- [ ] KDF producing correct output
- [ ] All MAC/KDF tests passing

### Phase 4: Packet Protocol
- [ ] Packet encoding/decoding working
- [ ] Encryption/decryption working
- [ ] MAC verification working
- [ ] Sequence number handling correct

### Phase 5: Public Keys
- [ ] RSA signing/verification working
- [ ] ECDSA signing/verification working
- [ ] Ed25519 signing/verification working
- [ ] Key format parsing working

### Phase 6: Integration
- [ ] Full handshake test passing
- [ ] Authentication test passing
- [ ] Channel data transfer test passing
- [ ] All 533 existing tests still passing
- [ ] Coverage >= 90%

---

## 🚀 Quick Start Commands

```bash
# 1. Clone repository
git clone <repo-url>
cd ayssh

# 2. Add dependencies
cargo add tokio --features full
cargo add tokio-util
cargo add aes ctr aes-gcm chacha20poly1305
cargo add hmac sha2 digest
cargo add ecdsa elliptic-curve k256
cargo add rsa
cargo add ed25519-dalek
cargo add num-bigint num-traits
cargo add rand
cargo add bytes
cargo add zeroize

# 3. Run tests (should pass)
cargo test --all

# 4. Implement Phase 1 (KEX)
# Follow Phase 1 tasks above
cargo test --all

# 5. Implement Phase 2 (Ciphers)
# Follow Phase 2 tasks above
cargo test --all

# ... continue through all phases
```

---

## 📚 References

- [RFC 4253](https://datatracker.ietf.org/doc/html/rfc4253) - Transport Layer Protocol
- [RFC 4252](https://datatracker.ietf.org/doc/html/rfc4252) - Authentication Protocol
- [RFC 4254](https://datatracker.ietf.org/doc/html/rfc4254) - Connection Protocol
- [RFC 8731](https://datatracker.ietf.org/doc/html/rfc8731) - DH Group Exchange
- [RFC 5656](https://datatracker.ietf.org/doc/html/rfc5656) - ECDH
- [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) - ChaCha20
- [RustCrypto](https://github.com/RustCrypto) - Cryptographic crates

---

**Plan Generated:** 2026-03-15  
**Estimated Total Time:** 120-160 hours  
**Difficulty:** Intermediate to Advanced  
**Prerequisites:** Rust, async programming, cryptography basics