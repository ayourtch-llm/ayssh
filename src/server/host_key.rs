//! SSH server host key management
//!
//! Supports generating, loading, and signing with host keys.
//! Used by the test SSH server for KEXDH_REPLY signatures.

use crate::error::SshError;
use bytes::{BufMut, BytesMut};

/// A server host key pair (private + public)
#[derive(Clone)]
pub enum HostKeyPair {
    /// Ed25519 host key (fast generation, recommended for testing)
    Ed25519(ed25519_dalek::SigningKey),
    /// RSA host key
    Rsa(Box<rsa::RsaPrivateKey>),
}

impl HostKeyPair {
    /// Generate a new Ed25519 host key pair (instant, no entropy concerns)
    pub fn generate_ed25519() -> Self {
        use ed25519_dalek::SigningKey;
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        Self::Ed25519(signing_key)
    }

    /// Generate a new RSA host key pair (slow - ~100ms for 2048 bits)
    pub fn generate_rsa(bits: usize) -> Result<Self, SshError> {
        use rand::rngs::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| SshError::CryptoError(format!("RSA key generation failed: {}", e)))?;
        Ok(Self::Rsa(Box::new(private_key)))
    }

    /// Load an RSA key from OpenSSH private key format
    pub fn load_openssh_rsa(path: &std::path::Path) -> Result<Self, SshError> {
        let key_data = std::fs::read(path)
            .map_err(|e| SshError::IoError(e))?;
        let pem_content = String::from_utf8_lossy(&key_data);
        let private_key = crate::auth::key::PrivateKey::parse_pem(&pem_content)?;
        match private_key {
            crate::auth::key::PrivateKey::Rsa(rsa_key) => Ok(Self::Rsa(Box::new(rsa_key))),
            _ => Err(SshError::CryptoError("Expected RSA key".to_string())),
        }
    }

    /// Get the SSH algorithm name for this key type
    pub fn algorithm_name(&self) -> &str {
        match self {
            Self::Ed25519(_) => "ssh-ed25519",
            Self::Rsa(_) => "ssh-rsa",
        }
    }

    /// Encode the public key in SSH wire format (for KEXDH_REPLY K_S field)
    /// Format: string(algorithm_name) || key-specific-data
    pub fn public_key_blob(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        match self {
            Self::Ed25519(signing_key) => {
                let algorithm = b"ssh-ed25519";
                buf.put_u32(algorithm.len() as u32);
                buf.put_slice(algorithm);
                let public_key = signing_key.verifying_key();
                let pk_bytes = public_key.to_bytes();
                buf.put_u32(pk_bytes.len() as u32);
                buf.put_slice(&pk_bytes);
            }
            Self::Rsa(private_key) => {
                use rsa::traits::PublicKeyParts;
                let algorithm = b"ssh-rsa";
                buf.put_u32(algorithm.len() as u32);
                buf.put_slice(algorithm);
                // Exponent e (as mpint)
                let e = private_key.e().to_bytes_be();
                put_mpint(&mut buf, &e);
                // Modulus n (as mpint)
                let n = private_key.n().to_bytes_be();
                put_mpint(&mut buf, &n);
            }
        }
        buf.to_vec()
    }

    /// Sign data with this host key, returning SSH wire-format signature.
    /// For KEXDH_REPLY, the data is the exchange hash H.
    /// Returns: string(algorithm) || string(signature_blob)
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SshError> {
        let mut buf = BytesMut::new();
        match self {
            Self::Ed25519(signing_key) => {
                use ed25519_dalek::Signer;
                let signature = signing_key.sign(data);
                let sig_bytes = signature.to_bytes();

                let algorithm = b"ssh-ed25519";
                buf.put_u32(algorithm.len() as u32);
                buf.put_slice(algorithm);
                buf.put_u32(sig_bytes.len() as u32);
                buf.put_slice(&sig_bytes);
            }
            Self::Rsa(private_key) => {
                // ssh-rsa uses PKCS1v15 with SHA-1
                use sha1::Digest;
                let hash = sha1::Sha1::digest(data);
                use rsa::Pkcs1v15Sign;
                let scheme = Pkcs1v15Sign::new::<sha1::Sha1>();
                let sig_bytes = private_key.sign(scheme, &hash)
                    .map_err(|e| SshError::CryptoError(format!("RSA signing failed: {}", e)))?;

                let algorithm = b"ssh-rsa";
                buf.put_u32(algorithm.len() as u32);
                buf.put_slice(algorithm);
                buf.put_u32(sig_bytes.len() as u32);
                buf.put_slice(&sig_bytes);
            }
        }
        Ok(buf.to_vec())
    }
}

impl std::fmt::Debug for HostKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519(_) => write!(f, "HostKeyPair::Ed25519(...)"),
            Self::Rsa(_) => write!(f, "HostKeyPair::Rsa(...)"),
        }
    }
}

/// Encode a big-endian byte array as SSH mpint (with 0x00 prefix if high bit set)
fn put_mpint(buf: &mut BytesMut, value: &[u8]) {
    if !value.is_empty() && (value[0] & 0x80) != 0 {
        buf.put_u32((value.len() + 1) as u32);
        buf.put_u8(0x00);
        buf.put_slice(value);
    } else {
        buf.put_u32(value.len() as u32);
        buf.put_slice(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519() {
        let key = HostKeyPair::generate_ed25519();
        assert_eq!(key.algorithm_name(), "ssh-ed25519");

        let blob = key.public_key_blob();
        // ssh-ed25519 blob: [4+11 algorithm] + [4+32 key] = 51 bytes
        assert_eq!(blob.len(), 4 + 11 + 4 + 32);
        assert_eq!(&blob[4..15], b"ssh-ed25519");
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let key = HostKeyPair::generate_ed25519();
        let data = b"test exchange hash data for signing";
        let sig = key.sign(data).unwrap();

        // Verify signature structure: string("ssh-ed25519") || string(64-byte sig)
        let alg_len = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]) as usize;
        assert_eq!(alg_len, 11);
        assert_eq!(&sig[4..15], b"ssh-ed25519");
        let sig_len = u32::from_be_bytes([sig[15], sig[16], sig[17], sig[18]]) as usize;
        assert_eq!(sig_len, 64); // Ed25519 signature is 64 bytes
    }

    #[test]
    fn test_ed25519_different_keys_different_sigs() {
        let key1 = HostKeyPair::generate_ed25519();
        let key2 = HostKeyPair::generate_ed25519();
        let data = b"same data different keys";
        let sig1 = key1.sign(data).unwrap();
        let sig2 = key2.sign(data).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_load_rsa_from_test_keys() {
        let path = std::path::Path::new("tests/keys/test_rsa_2048");
        if !path.exists() {
            return; // Skip if keys not available
        }
        let key = HostKeyPair::load_openssh_rsa(path).unwrap();
        assert_eq!(key.algorithm_name(), "ssh-rsa");

        let blob = key.public_key_blob();
        // RSA blob starts with string("ssh-rsa")
        let alg_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        assert_eq!(alg_len, 7);
        assert_eq!(&blob[4..11], b"ssh-rsa");
    }

    #[test]
    fn test_rsa_sign() {
        let path = std::path::Path::new("tests/keys/test_rsa_2048");
        if !path.exists() {
            return;
        }
        let key = HostKeyPair::load_openssh_rsa(path).unwrap();
        let data = b"test exchange hash";
        let sig = key.sign(data).unwrap();

        // Verify structure: string("ssh-rsa") || string(256-byte sig)
        let alg_len = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]) as usize;
        assert_eq!(alg_len, 7);
        assert_eq!(&sig[4..11], b"ssh-rsa");
        let sig_len = u32::from_be_bytes([sig[11], sig[12], sig[13], sig[14]]) as usize;
        assert_eq!(sig_len, 256); // RSA-2048 signature
    }

    #[test]
    fn test_ed25519_public_key_blob_deterministic() {
        let key = HostKeyPair::generate_ed25519();
        let blob1 = key.public_key_blob();
        let blob2 = key.public_key_blob();
        assert_eq!(blob1, blob2);
    }
}
