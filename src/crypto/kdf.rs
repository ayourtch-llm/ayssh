//! Key Derivation Function (KDF) for SSH
//!
//! This module implements the Key Derivation Function as defined in RFC 4253 Section 7.
//! The KDF is used to derive cryptographic keys from the shared secret (DH exchange output).
//!
//! # SSH KDF Specification
//!
//! The KDF takes the following inputs:
//! - `shared_secret` (Z): The shared secret from Diffie-Hellman exchange
//! - `session_id`: The session ID (hash of exchange)
//! - `counter`: The counter value (1 for encryption key, 2 for MAC key, etc.)
//! - `desired_length`: The length of the output key in bytes
//!
//! The KDF function is defined as:
//! ```text
//! KDF(N, S, H, C, L) =
//!     K[1] = H(S || C || N || 0x00000001)
//!     K[2] = H(S || C || N || 0x00000002)
//!     ...
//!     KDF = K[1] || K[2] || ... || K[m]
//! ```
//!
//! Where:
//! - H = SHA-256 (in our implementation)
//! - S = shared secret
//! - C = session ID
//! - N = counter (1, 2, 3, ...)
//! - L = desired output length
//! - m = ceil(L / H.len)

use ring::digest::{self, SHA256};

/// Derive cryptographic keys using the SSH KDF
///
/// This function implements the Key Derivation Function as defined in RFC 4253 Section 7.
/// It derives keys from the shared secret using SHA-256 as the hash function.
///
/// # Arguments
///
/// * `shared_secret` - The shared secret from Diffie-Hellman exchange (Z)
/// * `session_id` - The session ID (hash of exchange)
/// * `counter` - The counter value (1 for encryption key, 2 for MAC key, etc.)
/// * `desired_length` - The length of the output key in bytes
///
/// # Returns
///
/// A vector containing the derived key of the specified length.
///
/// # Example
///
/// ```
/// use ssh_client::crypto::kdf::kdf;
///
/// // Derive an AES-256 encryption key
/// let shared_secret = b"dh_shared_secret";
/// let session_id = b"session_id";
/// let counter = 1u32;
/// let key = kdf(shared_secret, session_id, counter, 32);
/// assert_eq!(key.len(), 32);
/// ```
///
/// # Security Considerations
///
/// - The shared secret should be securely erased after key derivation
/// - Different counters produce different keys from the same inputs
/// - The session ID ensures keys are unique per session
pub fn kdf(shared_secret: &[u8], session_id: &[u8], counter: u32, desired_length: usize) -> Vec<u8> {
    if desired_length == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(desired_length);
    const HASH_LEN: usize = 32; // SHA-256 produces 32 bytes
    let num_blocks = (desired_length + HASH_LEN - 1) / HASH_LEN;

    for i in 1..=num_blocks {
        let mut hasher = digest::Context::new(&SHA256);
        
        // Concatenate: session_id || counter || shared_secret || counter
        // Note: RFC 4253 uses: H(S || C || N || 0x00000001)
        // where S=session_id, C=counter, N=shared_secret
        hasher.update(session_id);
        hasher.update(&counter.to_be_bytes());
        hasher.update(shared_secret);
        hasher.update(&i.to_be_bytes());
        
        let digest = hasher.finish();
        let digest_bytes = digest.as_ref();
        
        // Add full block or truncate to desired length
        let remaining = desired_length - result.len();
        if remaining >= HASH_LEN {
            result.extend_from_slice(digest_bytes);
        } else {
            result.extend_from_slice(&digest_bytes[..remaining]);
        }
    }

    result.truncate(desired_length);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_simple() {
        let shared_secret = b"shared_secret_data";
        let session_id = b"session_id_data";
        let counter = 1u32;
        let desired_length = 32;
        
        let result = kdf(shared_secret, session_id, counter, desired_length);
        assert_eq!(result.len(), desired_length);
    }

    #[test]
    fn test_kdf_multiblock() {
        let shared_secret = b"shared_secret_data";
        let session_id = b"session_id_data";
        let counter = 1u32;
        let desired_length = 64; // More than one SHA256 block
        
        let result = kdf(shared_secret, session_id, counter, desired_length);
        assert_eq!(result.len(), desired_length);
    }

    #[test]
    fn test_kdf_empty_secret() {
        let shared_secret = b"";
        let session_id = b"session_id";
        let counter = 1u32;
        let desired_length = 32;
        
        let result = kdf(shared_secret, session_id, counter, desired_length);
        assert_eq!(result.len(), desired_length);
    }

    #[test]
    fn test_kdf_counter_increment() {
        let shared_secret = b"secret";
        let session_id = b"session";
        let result1 = kdf(shared_secret, session_id, 1, 32);
        let result2 = kdf(shared_secret, session_id, 2, 32);
        
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_kdf_determinism() {
        let shared_secret = b"secret";
        let session_id = b"session";
        let counter = 1u32;
        let desired_length = 32;
        
        let result1 = kdf(shared_secret, session_id, counter, desired_length);
        let result2 = kdf(shared_secret, session_id, counter, desired_length);
        
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_kdf_zero_length() {
        let shared_secret = b"secret";
        let session_id = b"session";
        let counter = 1u32;
        let desired_length = 0;
        
        let result = kdf(shared_secret, session_id, counter, desired_length);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_kdf_one_byte() {
        let shared_secret = b"secret";
        let session_id = b"session";
        let counter = 1u32;
        let desired_length = 1;
        
        let result = kdf(shared_secret, session_id, counter, desired_length);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_kdf_different_session_id() {
        let shared_secret = b"secret";
        let session_id1 = b"session1";
        let session_id2 = b"session2";
        let counter = 1u32;
        let desired_length = 32;
        
        let result1 = kdf(shared_secret, session_id1, counter, desired_length);
        let result2 = kdf(shared_secret, session_id2, counter, desired_length);
        
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_kdf_non_zero_output() {
        let shared_secret = b"secret";
        let session_id = b"session";
        let counter = 1u32;
        let desired_length = 32;
        
        let result = kdf(shared_secret, session_id, counter, desired_length);
        
        // Should not be all zeros
        assert!(!result.iter().all(|&b| b == 0));
    }
}