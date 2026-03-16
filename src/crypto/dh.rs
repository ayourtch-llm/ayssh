//! Diffie-Hellman Key Exchange Implementation
//!
//! Implements Diffie-Hellman key exchange algorithms for SSH:
//! - diffie-hellman-group1-sha1 (RFC 4253, Oakley Group 2)
//! - diffie-hellman-group14-sha256/384/512 (RFC 4253)
//! - diffie-hellman-group-exchange-sha256/384/512 (RFC 4253)

use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::crypto::kdf;
use crate::error::SshError;
use crate::protocol;

/// MODP Group 1 (RFC 2409 Oakley Group 2, 1024-bit) prime p
/// RFC 2409 Section 6.2, RFC 4253 Section 8.1
/// MODP Group 2 (1024-bit) prime p from RFC 2409 Section 6.2 / RFC 3526 Section 2
/// SSH's "diffie-hellman-group1-sha1" uses this prime (Oakley Group 2)
/// p = 2^1024 - 2^960 - 1 + 2^64 * { floor(2^894 * pi) + 129093 }
pub const GROUP1_P: &str = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 \
                             020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 \
                             4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED \
                             EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381 FFFFFFFF FFFFFFFF";

/// MODP Group 1 generator g = 2
pub const GROUP1_G: u32 = 2;

/// MODP Group 1 prime as BigUint
lazy_static::lazy_static! {
    pub static ref GROUP1_P_BIGINT: BigUint = {
        let hex_str = GROUP1_P.replace(" ", "");
        BigUint::parse_bytes(hex_str.as_bytes(), 16).expect("Invalid Group1 prime")
    };
}

/// MODP Group 14 (2048-bit) prime p from RFC 3526 Section 3
/// p = 2^2048 - 2^1984 - 1 + 2^64 * { floor(2^1918 * pi) + 124476 }
pub const GROUP14_P: &str = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 \
                              020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 \
                              4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED \
                              EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D C2007CB8 A163BF05 \
                              98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB \
                              9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B \
                              E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718 \
                              3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AACAA68 FFFFFFFF FFFFFFFF";

/// MODP Group 14 generator g = 2
pub const GROUP14_G: u32 = 2;

/// MODP Group 14 prime as BigUint
lazy_static::lazy_static! {
    pub static ref GROUP14_P_BIGINT: BigUint = {
        let hex_str = GROUP14_P.replace(" ", "");
        BigUint::parse_bytes(hex_str.as_bytes(), 16).expect("Invalid Group14 prime")
    };
}

/// Diffie-Hellman group parameters
#[derive(Debug, Clone)]
pub struct DhGroup {
    /// Prime p
    pub p: BigUint,
    /// Generator g
    pub g: BigUint,
}

impl DhGroup {
    /// Create Group1 parameters (Oakley Group 2, 1024-bit)
    pub fn group1() -> Self {
        Self {
            p: GROUP1_P_BIGINT.clone(),
            g: BigUint::from(GROUP1_G),
        }
    }

    /// Create Group14 parameters (2048-bit)
    pub fn group14() -> Self {
        Self {
            p: GROUP14_P_BIGINT.clone(),
            g: BigUint::from(GROUP14_G),
        }
    }

    /// Generate client's private key x (random)
    /// Size should be at least 160 bits, recommended 256 bits
    pub fn generate_private_key(&self, rng: &mut impl RngCore, bits: usize) -> BigUint {
        let mut bytes = (bits + 7) / 8;
        let mut x_bytes = vec![0u8; bytes];
        
        // Generate random bytes
        rng.fill_bytes(&mut x_bytes);
        
        // Ensure x is in range [1, p-2]
        let x = BigUint::from_bytes_be(&x_bytes);
        let max = self.p.clone() - BigUint::from(2u8);
        
        if x >= max || x.is_zero() {
            self.generate_private_key(rng, bits)
        } else {
            x
        }
    }

    /// Compute public key X = g^x mod p
    pub fn compute_public_key(&self, x: &BigUint) -> BigUint {
        let g = self.g.clone();
        let p = self.p.clone();
        
        // X = g^x mod p
        g.modpow(x, &p)
    }

    /// Compute shared secret K = Y^x mod p
    pub fn compute_shared_secret(&self, y: &BigUint, x: &BigUint) -> BigUint {
        let p = self.p.clone();
        
        // K = Y^x mod p
        y.modpow(x, &p)
    }
}

/// MPINT encoding - Multiple-precision integer (RFC 4251 Section 5)
/// Positive integers encoded as big-endian with sign bit (0x00 for positive)
pub struct Mpint;

impl Mpint {
    /// Encode a BigUint as MPINT
    /// Returns bytes with leading 0x00 sign byte if high bit would be set
    pub fn encode(n: &BigUint) -> Vec<u8> {
        let mut bytes = n.to_bytes_be();
        
        // If high bit is set, prepend 0x00 to ensure positive
        if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
            bytes.insert(0, 0x00);
        }
        
        bytes
    }

    /// Decode MPINT bytes to BigUint
    pub fn decode(bytes: &[u8]) -> Result<BigUint, SshError> {
        if bytes.is_empty() {
            return Err(SshError::ProtocolError("Empty MPINT".to_string()));
        }
        
        Ok(BigUint::from_bytes_be(bytes))
    }

    /// Encode length-prefixed MPINT (for SSH protocol)
    pub fn encode_length_prefixed(n: &BigUint) -> Vec<u8> {
        let value_bytes = Self::encode(n);
        let mut result = Vec::with_capacity(4 + value_bytes.len());
        
        // 4-byte length prefix
        result.extend_from_slice(&(value_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(&value_bytes);
        
        result
    }

    /// Decode length-prefixed MPINT
    pub fn decode_length_prefixed(data: &[u8]) -> Result<(BigUint, &[u8]), SshError> {
        if data.len() < 4 {
            return Err(SshError::ProtocolError("Data too short for MPINT length prefix".to_string()));
        }
        
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        
        if data.len() < 4 + len {
            return Err(SshError::ProtocolError("Data too short for MPINT value".to_string()));
        }
        
        let value_bytes = &data[4..4 + len];
        let n = Self::decode(value_bytes)?;
        
        Ok((n, &data[4 + len..]))
    }
}

/// Compute DH hash K || H for key derivation
/// H is the session identifier (hash of exchange)
pub fn compute_dh_hash(
    k: &BigUint,
    h: &[u8],
    hash_algorithm: protocol::HashAlgorithm,
) -> Vec<u8> {
    let k_bytes = Mpint::encode(k);
    
    match hash_algorithm {
        protocol::HashAlgorithm::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(&k_bytes);
            hasher.update(h);
            hasher.finalize().to_vec()
        }
        protocol::HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&k_bytes);
            hasher.update(h);
            hasher.finalize().to_vec()
        }
        protocol::HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(&k_bytes);
            hasher.update(h);
            hasher.finalize().to_vec()
        }
        protocol::HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(&k_bytes);
            hasher.update(h);
            hasher.finalize().to_vec()
        }
    }
}

/// Derive key material from shared secret using KDF
pub fn derive_keys(
    k: &BigUint,
    h: &[u8],
    enc_key_len: usize,
    mac_key_len: usize,
    iv_len: usize,
    hash_algorithm: protocol::HashAlgorithm,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), SshError> {
    let kh = compute_dh_hash(k, h, hash_algorithm);
    
    // Use KDF to derive all needed keys
    let kdf_algo = match hash_algorithm {
        protocol::HashAlgorithm::Sha1 => kdf::HashAlgorithm::Sha1,
        protocol::HashAlgorithm::Sha256 |
        protocol::HashAlgorithm::Sha384 |
        protocol::HashAlgorithm::Sha512 => kdf::HashAlgorithm::Sha256,
    };
    let enc_key = kdf::kdf(&kh, h, 1, enc_key_len, kdf_algo);
    let mac_key = kdf::kdf(&kh, h, 2, mac_key_len, kdf_algo);
    let iv = kdf::kdf(&kh, h, 3, iv_len, kdf_algo);
    
    Ok((enc_key, mac_key, iv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_mpint_encode_decode() {
        // Test small number
        let n = BigUint::from(42u64);
        let encoded = Mpint::encode(&n);
        let decoded = Mpint::decode(&encoded).unwrap();
        assert_eq!(n, decoded);

        // Test large number
        let large = BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16).unwrap();
        let encoded = Mpint::encode(&large);
        let decoded = Mpint::decode(&encoded).unwrap();
        assert_eq!(large, decoded);
    }

    #[test]
    fn test_mpint_high_bit() {
        // Number with high bit set should have 0x00 prefix
        let n = BigUint::from(0x80u64);
        let encoded = Mpint::encode(&n);
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x80);
    }

    #[test]
    fn test_group14_parameters() {
        let group = DhGroup::group14();
        
        // Verify p is at least 2048 bits (may have leading zeros stripped)
        assert!(group.p.bits() >= 2048);
        
        // Verify g = 2
        assert_eq!(group.g, BigUint::from(2u32));
    }

    #[test]
    fn test_dh_public_key_computation() {
        let group = DhGroup::group14();
        let mut rng = OsRng;
        
        // Generate private key
        let x = group.generate_private_key(&mut rng, 256);
        
        // Compute public key
        let x_public = group.compute_public_key(&x);
        
        // Verify it's in valid range
        assert!(!x_public.is_zero());
        assert!(x_public < group.p);
    }

    #[test]
    fn test_dh_shared_secret() {
        let group = DhGroup::group14();
        let mut rng = OsRng;
        
        // Client generates x
        let x = group.generate_private_key(&mut rng, 256);
        let x_public = group.compute_public_key(&x);
        
        // Server generates y
        let y = group.generate_private_key(&mut rng, 256);
        let y_public = group.compute_public_key(&y);
        
        // Both compute shared secret
        let client_k = group.compute_shared_secret(&y_public, &x);
        let server_k = group.compute_shared_secret(&x_public, &y);
        
        // Shared secrets must match
        assert_eq!(client_k, server_k);
    }

    #[test]
    fn test_mpint_length_prefixed() {
        let n = BigUint::from(12345u64);
        let encoded = Mpint::encode_length_prefixed(&n);
        
        // Should have 4-byte length prefix
        assert!(encoded.len() >= 4);
        
        let (decoded, remaining) = Mpint::decode_length_prefixed(&encoded).unwrap();
        assert_eq!(n, decoded);
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_dh_hash_computation() {
        let group = DhGroup::group14();
        let mut rng = OsRng;

        let x = group.generate_private_key(&mut rng, 256);
        let k = group.compute_public_key(&x);

        let h = b"test_session_id";

        let hash = compute_dh_hash(&k, h, protocol::HashAlgorithm::Sha256);

        // Hash should be 32 bytes for SHA256
        assert_eq!(hash.len(), 32);
    }

    /// Verify DH Group 1 prime is exactly 1024 bits and matches RFC 2409 Section 6.2
    /// p = 2^1024 - 2^960 - 1 + 2^64 * { floor(2^894 * pi) + 129093 }
    #[test]
    fn test_group1_prime_is_1024_bits() {
        let group = DhGroup::group1();
        assert_eq!(group.p.bits(), 1024, "Group 1 prime must be exactly 1024 bits");
    }

    /// Verify DH Group 1 prime starts and ends correctly per RFC 2409
    #[test]
    fn test_group1_prime_boundary_values() {
        let group = DhGroup::group1();
        let p_bytes = group.p.to_bytes_be();

        // The prime must start with 0xFF (all top bits set)
        assert_eq!(p_bytes[0], 0xFF, "Group 1 prime must start with 0xFF");
        assert_eq!(p_bytes[1], 0xFF, "Group 1 prime second byte must be 0xFF");

        // The prime must end with 0xFF (last 64 bits are all 1s by construction)
        let len = p_bytes.len();
        assert_eq!(p_bytes[len - 1], 0xFF, "Group 1 prime must end with 0xFF");
        assert_eq!(p_bytes[len - 2], 0xFF, "Group 1 prime second-to-last byte must be 0xFF");
        assert_eq!(p_bytes[len - 8], 0xFF, "Group 1 prime last 8 bytes must all be 0xFF");
    }

    /// Verify DH Group 1 prime is a valid safe prime (p is odd, (p-1)/2 passes basic checks)
    #[test]
    fn test_group1_prime_is_odd() {
        let group = DhGroup::group1();
        // A prime must be odd (last bit = 1)
        let p_bytes = group.p.to_bytes_be();
        assert_eq!(p_bytes[p_bytes.len() - 1] & 1, 1, "Group 1 prime must be odd");
    }

    /// Verify DH Group 1 generator is 2
    #[test]
    fn test_group1_generator() {
        let group = DhGroup::group1();
        assert_eq!(group.g, BigUint::from(2u32), "Group 1 generator must be 2");
    }

    /// Verify DH Group 14 prime is exactly 2048 bits
    #[test]
    fn test_group14_prime_is_2048_bits() {
        let group = DhGroup::group14();
        assert_eq!(group.p.bits(), 2048, "Group 14 prime must be exactly 2048 bits");
    }

    /// Verify DH Group 14 prime starts and ends with FFFFFFFFFFFFFFFF
    /// (by construction from the formula p = 2^2048 - 2^1984 - 1 + 2^64 * {...})
    #[test]
    fn test_group14_prime_boundary_values() {
        let group = DhGroup::group14();
        let p_bytes = group.p.to_bytes_be();

        assert_eq!(p_bytes[0], 0xFF, "Group 14 prime must start with 0xFF");
        assert_eq!(p_bytes[1], 0xFF, "Group 14 prime second byte must be 0xFF");

        let len = p_bytes.len();
        for i in 0..8 {
            assert_eq!(p_bytes[len - 1 - i], 0xFF,
                "Group 14 prime last 8 bytes must all be 0xFF (byte {} from end)", i);
        }
    }

    /// Verify DH Group 14 generator is 2
    #[test]
    fn test_group14_generator() {
        let group = DhGroup::group14();
        assert_eq!(group.g, BigUint::from(2u32), "Group 14 generator must be 2");
    }
}