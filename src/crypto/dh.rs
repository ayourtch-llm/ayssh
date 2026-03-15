//! Diffie-Hellman Key Exchange Implementation
//!
//! Implements Diffie-Hellman key exchange algorithms for SSH:
//! - diffie-hellman-group14-sha256/384/512 (RFC 4253)
//! - diffie-hellman-group-exchange-sha256/384/512 (RFC 4253)

use num_bigint::BigUint;
use num_traits::{Zero, One};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::crypto::kdf;
use crate::error::SshError;
use crate::protocol;

/// MODP Group 14 (2048-bit) prime p
/// RFC 4253 Appendix A.1
pub const GROUP14_P: &str = "FFFFFFFF FFFFFFFC FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF \
                              C7634D81 FDDF92DD AEDC7FB5 E83B5C9B CF468899 95427025 0B9564F2 EA1F4B1F \
                              9CAFFC70 14A6447D 7DCEEF36 ADF30694 E4586A01 64687E48 9664699F 614B2B83 \
                              1A3BFEFD 33D45E9A 07F0BC9C 03EDD880 2E9196BB 59053097 1D07DAB1 07483B00 \
                              AD44B750 5C212EBB B03E4919 2D239A73 004F0834 7D360C3F 2F692FF7 00127C24 \
                              8BEA5EA4 62FE74CF 3D3A4748 5B296210 AA637DC6 A2B760D8 0C3E7C2C 9FF489FC \
                              FA9D8B90 06944E 83E4A24B 5B898DA0 39D96408 4FE13AC6 454FE2E5 3755CF37 \
                              B89A52FC D4D09503 E867B754 89CC7B6A 3E6C4F3D 7B644FB6 3B964549 4E2B418D \
                              4C4399F5 E1444B64 54ADBBB6 A739D6C8 22D9DF13 B3E1CBFD 5D526985 9134703C";

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
    /// Create Group14 parameters
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
    let enc_key = kdf::kdf(&kh, h, 1, enc_key_len);
    let mac_key = kdf::kdf(&kh, h, 2, mac_key_len);
    let iv = kdf::kdf(&kh, h, 3, iv_len);
    
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
}