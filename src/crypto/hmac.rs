//! HMAC-SHA256 and HMAC-SHA512 implementation for SSH
//!
//! This module implements HMAC-SHA256 and HMAC-SHA512 as defined in RFC 2104 and used in SSH (RFC 4253).
//! HMAC (Hash-based Message Authentication Code) is a mechanism for message authentication
//! using cryptographic hash functions.

use ring::hmac;

/// HMAC-SHA256 state machine for streaming computation
///
/// This struct allows incremental computation of HMAC-SHA256, which is useful
/// when processing data in chunks or when the data source is a stream.
///
/// # Example
///
/// ```
/// use ssh_client::crypto::hmac::{HmacSha256, compute};
///
/// // Streaming computation
/// let key = b"secret";
/// let data = b"Hello, World!";
///
/// let mut hmac = HmacSha256::new(key);
/// hmac.update(&data[..5]);
/// hmac.update(&data[5..]);
/// let result = hmac.finish();
///
/// // Or use the convenience function
/// let result2 = compute(key, data);
/// ```
pub struct HmacSha256 {
    context: hmac::Context,
}

impl HmacSha256 {
    /// Create a new HMAC-SHA256 instance with the given key
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key for HMAC computation
    ///
    /// # Panics
    ///
    /// Panics if the key is empty.
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "HMAC key must not be empty");
        
        let key = hmac::Key::new(hmac::HMAC_SHA256, key);
        Self {
            context: hmac::Context::with_key(&key),
        }
    }

    /// Update the HMAC computation with additional data
    ///
    /// This method can be called multiple times to incrementally compute
    /// the HMAC over a stream of data.
    ///
    /// # Arguments
    ///
    /// * `data` - Additional data to include in the HMAC computation
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Finalize the HMAC computation and return the result
    ///
    /// This consumes the `HmacSha256` instance and returns the 32-byte
    /// HMAC-SHA256 authentication tag.
    ///
    /// # Returns
    ///
    /// A 32-element array containing the HMAC-SHA256 result.
    pub fn finish(self) -> [u8; 32] {
        let tag = self.context.sign();
        tag.as_ref().try_into().expect("HMAC-SHA256 produces 32 bytes")
    }
}

/// HMAC-SHA512 state machine for streaming computation
pub struct HmacSha512 {
    context: hmac::Context,
}

impl HmacSha512 {
    /// Create a new HMAC-SHA512 instance with the given key
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty(), "HMAC key must not be empty");
        
        let key = hmac::Key::new(hmac::HMAC_SHA512, key);
        Self {
            context: hmac::Context::with_key(&key),
        }
    }

    /// Update the HMAC computation with additional data
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Finalize the HMAC computation and return the result
    pub fn finish(self) -> [u8; 64] {
        let tag = self.context.sign();
        tag.as_ref().try_into().expect("HMAC-SHA512 produces 64 bytes")
    }
}

/// Compute HMAC-SHA256 for the given key and data
///
/// This is a convenience function that creates a new `HmacSha256` instance,
/// updates it with the data, and returns the result.
///
/// # Arguments
///
/// * `key` - The secret key for HMAC computation
/// * `data` - The data to authenticate
///
/// # Returns
///
/// A 32-element array containing the HMAC-SHA256 result.
///
/// # Example
///
/// ```
/// use ssh_client::crypto::hmac::compute;
///
/// let key = b"secret";
/// let data = b"Hello, World!";
/// let hmac = compute(key, data);
/// ```
pub fn compute(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hmac = HmacSha256::new(key);
    hmac.update(data);
    hmac.finish()
}

/// Compute HMAC-SHA512 for the given key and data
pub fn compute_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut hmac = HmacSha512::new(key);
    hmac.update(data);
    hmac.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_basic() {
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let result = compute(&key, data);
        
        // RFC 4231 Section 4.2 test vector
        // Key: 20 bytes of 0x0b
        // Data: "Hi There"
        // Expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
        let expected = hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();
        
        assert_eq!(result.as_slice(), expected.as_slice());
    }

    #[test]
    #[should_panic(expected = "HMAC key must not be empty")]
    fn test_empty_key_panics() {
        let _ = HmacSha256::new(b"");
    }

    #[test]
    fn test_streaming_computation() {
        let key = b"key";
        let data = b"Hi There";
        
        let mut hmac = HmacSha256::new(key);
        hmac.update(&data[..4]);
        hmac.update(&data[4..]);
        
        let result = hmac.finish();
        let expected = compute(key, data);
        
        assert_eq!(result, expected);
    }

    #[test]
    fn test_different_keys_different_results() {
        let key1 = b"key1";
        let key2 = b"key2";
        let data = b"same data";
        
        let result1 = compute(key1, data);
        let result2 = compute(key2, data);
        
        assert_ne!(result1, result2);
    }
}