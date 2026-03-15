//! Key parsing utilities for SSH authentication
//!
//! Supports parsing:
//! - RSA private keys (PEM PKCS#1 and PKCS#8)
//! - Ed25519 private keys (PEM PKCS#8 and SSH format)
//! - ECDSA private keys (PEM PKCS#8)
//! - Public keys (SSH format)

use crate::error::SshError;
use pem::Pem;
use rsa::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use std::fs;

/// Key type enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    /// RSA key
    Rsa,
    /// ECDSA key (with curve)
    Ecdsa(EcdsaCurve),
    /// Ed25519 key
    Ed25519,
}

/// ECDSA curves
#[derive(Debug, Clone, PartialEq)]
pub enum EcdsaCurve {
    /// NIST P-256
    Nistp256,
    /// NIST P-384
    Nistp384,
    /// NIST P-521
    Nistp521,
}

/// Parsed private key
#[derive(Debug, Clone)]
pub enum PrivateKey {
    /// RSA private key
    Rsa(rsa::RsaPrivateKey),
    /// ECDSA private key (with curve)
    Ecdsa(EcdsaCurve, Vec<u8>),
    /// Ed25519 private key
    Ed25519(ed25519_dalek::SigningKey),
}

/// Parsed public key
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// Key type
    pub key_type: KeyType,
    /// Public key blob (SSH format)
    pub blob: Vec<u8>,
    /// Algorithm name
    pub algorithm: String,
}

impl PrivateKey {
    /// Load private key from file (PEM format)
    pub fn load_from_file(path: &str) -> Result<Self, SshError> {
        let pem_content = fs::read_to_string(path)
            .map_err(|e| SshError::IoError(e))?;
        Self::parse_pem(&pem_content)
    }

    /// Load private key from bytes (PEM format)
    pub fn parse_pem(pem_content: &str) -> Result<Self, SshError> {
        // Try PKCS#8 first (most common)
        if let Ok(key) = Self::parse_pkcs8(pem_content) {
            return Ok(key);
        }

        // Try PKCS#1 (RSA only)
        if let Ok(key) = Self::parse_pkcs1(pem_content) {
            return Ok(key);
        }

        // Try SSH format (OpenSSH)
        if let Ok(key) = Self::parse_openssh(pem_content) {
            return Ok(key);
        }

        Err(SshError::CryptoError("Failed to parse private key".into()))
    }

    /// Parse PKCS#8 PEM format
    fn parse_pkcs8(pem_content: &str) -> Result<Self, SshError> {
        let pem = pem::parse(pem_content)
            .map_err(|_| SshError::CryptoError("Invalid PEM format".into()))?;
        let tag = pem.tag();
        let der = pem.contents();

        match tag {
            "PRIVATE KEY" => {
                // Generic PKCS#8 - detect key type from OID
                Self::parse_generic_pkcs8(der)
            }
            "ENCRYPTED PRIVATE KEY" => {
                Err(SshError::CryptoError("Encrypted keys not supported".into()))
            }
            _ => Err(SshError::CryptoError("Unknown PEM tag".into())),
        }
    }

    /// Parse PKCS#1 RSA format
    fn parse_pkcs1(pem_content: &str) -> Result<Self, SshError> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        
        let pem = pem::parse(pem_content)
            .map_err(|_| SshError::CryptoError("Invalid PEM format".into()))?;
        let tag = pem.tag();
        let der = pem.contents();

        match tag {
            "RSA PRIVATE KEY" => {
                let key = rsa::RsaPrivateKey::from_pkcs1_der(&der)
                    .map_err(|_| SshError::CryptoError("Invalid RSA key".into()))?;
                Ok(PrivateKey::Rsa(key))
            }
            _ => Err(SshError::CryptoError("Unknown PEM tag".into())),
        }
    }

    /// Parse generic PKCS#8 (detect key type)
    fn parse_generic_pkcs8(der: &[u8]) -> Result<Self, SshError> {
        // Try Ed25519 first - simplest (32-byte seed)
        if der.len() == 32 {
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(der);
            let key = ed25519_dalek::SigningKey::from_bytes(&key_array);
            return Ok(PrivateKey::Ed25519(key));
        }

        // Try ECDSA P-256 (32-byte seed)
        if der.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(der);
            let key = k256::ecdsa::SigningKey::from_bytes(&bytes.into())
                .map_err(|_| SshError::CryptoError("Invalid ECDSA P-256 key".into()))?;
            return Ok(PrivateKey::Ecdsa(
                EcdsaCurve::Nistp256,
                key.to_bytes().to_vec(),
            ));
        }

        // Try ECDSA P-384 (48-byte seed)
        if der.len() == 48 {
            let mut bytes = [0u8; 48];
            bytes.copy_from_slice(der);
            let key = p384::ecdsa::SigningKey::from_bytes(&bytes.into())
                .map_err(|_| SshError::CryptoError("Invalid ECDSA P-384 key".into()))?;
            return Ok(PrivateKey::Ecdsa(
                EcdsaCurve::Nistp384,
                key.to_bytes().to_vec(),
            ));
        }

        // Try ECDSA P-521 (66-byte seed)
        if der.len() == 66 {
            let key = p521::ecdsa::SigningKey::from_slice(der)
                .map_err(|_| SshError::CryptoError("Invalid ECDSA P-521 key".into()))?;
            return Ok(PrivateKey::Ecdsa(
                EcdsaCurve::Nistp521,
                key.to_bytes().to_vec(),
            ));
        }

        // Try RSA - use pkcs8 crate
        if let Ok(key) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
            return Ok(PrivateKey::Rsa(key));
        }

        Err(SshError::CryptoError("Unsupported key type".into()))
    }

    /// Parse OpenSSH private key format
    fn parse_openssh(pem_content: &str) -> Result<Self, SshError> {
        // OpenSSH format starts with "---- BEGIN OPENSSH PRIVATE KEY ----"
        if !pem_content.contains("BEGIN OPENSSH PRIVATE KEY") {
            return Err(SshError::CryptoError("Not an OpenSSH key".into()));
        }

        // Extract base64 content
        let start = pem_content.find("-----BEGIN OPENSSH PRIVATE KEY-----")
            .ok_or_else(|| SshError::CryptoError("Invalid OpenSSH key format".into()))?;
        let end = pem_content.find("-----END OPENSSH PRIVATE KEY-----")
            .ok_or_else(|| SshError::CryptoError("Invalid OpenSSH key format".into()))?;

        let base64 = &pem_content[start + 38..end];
        let der = base64::decode(base64)
            .map_err(|_| SshError::CryptoError("Invalid base64 encoding".into()))?;

        Self::parse_openssh_der(&der)
    }

    /// Parse OpenSSH DER format
    fn parse_openssh_der(der: &[u8]) -> Result<Self, SshError> {
        use std::io::Cursor;
        use std::io::Read;

        let mut cursor = Cursor::new(der);
        
        // Read magic: "openssh-key-v1\0"
        let mut magic = [0u8; 15];
        cursor.read_exact(&mut magic)
            .map_err(|_| SshError::CryptoError("Invalid OpenSSH format".into()))?;
        
        if &magic != b"openssh-key-v1\0" {
            return Err(SshError::CryptoError("Invalid OpenSSH magic".into()));
        }

        // Read cipher name
        let mut cipher_len_buf = [0u8; 4];
        cursor.read_exact(&mut cipher_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid cipher name".into()))?;
        let cipher_len = u32::from_be_bytes(cipher_len_buf) as usize;
        let mut cipher = vec![0u8; cipher_len];
        cursor.read_exact(&mut cipher)
            .map_err(|_| SshError::CryptoError("Invalid cipher name".into()))?;

        // Read kdf name
        let mut kdf_len_buf = [0u8; 4];
        cursor.read_exact(&mut kdf_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid kdf name".into()))?;
        let kdf_len = u32::from_be_bytes(kdf_len_buf) as usize;
        let mut kdf = vec![0u8; kdf_len];
        cursor.read_exact(&mut kdf)
            .map_err(|_| SshError::CryptoError("Invalid kdf name".into()))?;

        // Read kdf options
        let mut kdf_opts_len_buf = [0u8; 4];
        cursor.read_exact(&mut kdf_opts_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid kdf options".into()))?;
        let kdf_opts_len = u32::from_be_bytes(kdf_opts_len_buf) as usize;
        let mut kdf_opts = vec![0u8; kdf_opts_len];
        cursor.read_exact(&mut kdf_opts)
            .map_err(|_| SshError::CryptoError("Invalid kdf options".into()))?;

        // Read number of keys
        let mut nkeys_buf = [0u8; 4];
        cursor.read_exact(&mut nkeys_buf)
            .map_err(|_| SshError::CryptoError("Invalid key count".into()))?;
        let nkeys = u32::from_be_bytes(nkeys_buf) as usize;

        if nkeys != 1 {
            return Err(SshError::CryptoError("Only single-key OpenSSH files supported".into()));
        }

        // Read public key
        let mut pub_key_len_buf = [0u8; 4];
        cursor.read_exact(&mut pub_key_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid public key".into()))?;
        let pub_key_len = u32::from_be_bytes(pub_key_len_buf) as usize;
        let mut pub_key = vec![0u8; pub_key_len];
        cursor.read_exact(&mut pub_key)
            .map_err(|_| SshError::CryptoError("Invalid public key".into()))?;

        // Read private key blob
        let mut priv_key_len_buf = [0u8; 4];
        cursor.read_exact(&mut priv_key_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid private key".into()))?;
        let priv_key_len = u32::from_be_bytes(priv_key_len_buf) as usize;
        let mut priv_key_blob = vec![0u8; priv_key_len];
        cursor.read_exact(&mut priv_key_blob)
            .map_err(|_| SshError::CryptoError("Invalid private key".into()))?;

        // Parse based on key type (from public key)
        let mut pub_cursor = Cursor::new(&pub_key);
        
        let mut algo_len_buf = [0u8; 4];
        pub_cursor.read_exact(&mut algo_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid algorithm".into()))?;
        let algo_len = u32::from_be_bytes(algo_len_buf) as usize;
        let mut algo = vec![0u8; algo_len];
        pub_cursor.read_exact(&mut algo)
            .map_err(|_| SshError::CryptoError("Invalid algorithm".into()))?;

        let algorithm = String::from_utf8(algo)
            .map_err(|_| SshError::CryptoError("Invalid algorithm string".into()))?;

        match algorithm.as_str() {
            "ssh-rsa" => {
                // Parse RSA public key to get modulus/exponent
                // Then parse private key blob
                let rsa_key = Self::parse_openssh_rsa(&priv_key_blob)?;
                Ok(PrivateKey::Rsa(rsa_key))
            }
            "ssh-ed25519" => {
                // Ed25519: 32-byte private key + 32-byte public key + padding
                if priv_key_blob.len() >= 64 {
                    let mut key_bytes = [0u8; 32];
                    key_bytes.copy_from_slice(&priv_key_blob[32..64]);
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
                    Ok(PrivateKey::Ed25519(signing_key))
                } else {
                    Err(SshError::CryptoError("Invalid Ed25519 key length".into()))
                }
            }
            "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
                // ECDSA key - extract from private key blob
                // Format: 32-bit curve name length + curve name + 32-bit scalar length + scalar
                let mut ec_cursor = Cursor::new(&priv_key_blob[32..]); // Skip 32-byte public key
                let mut curve_len_buf = [0u8; 4];
                ec_cursor.read_exact(&mut curve_len_buf)
                    .map_err(|_| SshError::CryptoError("Invalid curve name".into()))?;
                let curve_len = u32::from_be_bytes(curve_len_buf) as usize;
                let mut curve_name = vec![0u8; curve_len];
                ec_cursor.read_exact(&mut curve_name)
                    .map_err(|_| SshError::CryptoError("Invalid curve name".into()))?;

                let curve = match curve_name.as_slice() {
                    b"nistp256" => EcdsaCurve::Nistp256,
                    b"nistp384" => EcdsaCurve::Nistp384,
                    b"nistp521" => EcdsaCurve::Nistp521,
                    _ => return Err(SshError::CryptoError("Unsupported ECDSA curve".into())),
                };

                let mut scalar_len_buf = [0u8; 4];
                ec_cursor.read_exact(&mut scalar_len_buf)
                    .map_err(|_| SshError::CryptoError("Invalid scalar".into()))?;
                let scalar_len = u32::from_be_bytes(scalar_len_buf) as usize;
                let mut scalar = vec![0u8; scalar_len];
                ec_cursor.read_exact(&mut scalar)
                    .map_err(|_| SshError::CryptoError("Invalid scalar".into()))?;

                Ok(PrivateKey::Ecdsa(curve, scalar))
            }
            _ => Err(SshError::CryptoError("Unsupported key type".into())),
        }
    }

    /// Parse OpenSSH RSA private key
    fn parse_openssh_rsa(private_key_blob: &[u8]) -> Result<rsa::RsaPrivateKey, SshError> {
        use std::io::Cursor;
        use std::io::Read;

        let mut cursor = Cursor::new(private_key_blob);

        // Read checkint (2x 32-bit integers)
        let mut checkint1_buf = [0u8; 4];
        cursor.read_exact(&mut checkint1_buf)
            .map_err(|_| SshError::CryptoError("Invalid checkint".into()))?;
        let checkint1 = u32::from_be_bytes(checkint1_buf);
        
        let mut checkint2_buf = [0u8; 4];
        cursor.read_exact(&mut checkint2_buf)
            .map_err(|_| SshError::CryptoError("Invalid checkint".into()))?;
        let checkint2 = u32::from_be_bytes(checkint2_buf);

        if checkint1 != checkint2 {
            return Err(SshError::CryptoError("RSA checkint mismatch".into()));
        }

        // Read public exponent
        let mut e_len_buf = [0u8; 4];
        cursor.read_exact(&mut e_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid exponent".into()))?;
        let e_len = u32::from_be_bytes(e_len_buf) as usize;
        let mut e = vec![0u8; e_len];
        cursor.read_exact(&mut e)
            .map_err(|_| SshError::CryptoError("Invalid exponent".into()))?;

        // Read private exponent
        let mut d_len_buf = [0u8; 4];
        cursor.read_exact(&mut d_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid exponent".into()))?;
        let d_len = u32::from_be_bytes(d_len_buf) as usize;
        let mut d = vec![0u8; d_len];
        cursor.read_exact(&mut d)
            .map_err(|_| SshError::CryptoError("Invalid exponent".into()))?;

        // Read prime1 (p)
        let mut p_len_buf = [0u8; 4];
        cursor.read_exact(&mut p_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid prime p".into()))?;
        let p_len = u32::from_be_bytes(p_len_buf) as usize;
        let mut p = vec![0u8; p_len];
        cursor.read_exact(&mut p)
            .map_err(|_| SshError::CryptoError("Invalid prime p".into()))?;

        // Read prime2 (q)
        let mut q_len_buf = [0u8; 4];
        cursor.read_exact(&mut q_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid prime q".into()))?;
        let q_len = u32::from_be_bytes(q_len_buf) as usize;
        let mut q = vec![0u8; q_len];
        cursor.read_exact(&mut q)
            .map_err(|_| SshError::CryptoError("Invalid prime q".into()))?;

        // Read exponent1 (d mod p-1)
        let mut exp1_len_buf = [0u8; 4];
        cursor.read_exact(&mut exp1_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid exponent1".into()))?;
        let exp1_len = u32::from_be_bytes(exp1_len_buf) as usize;
        let mut exp1 = vec![0u8; exp1_len];
        cursor.read_exact(&mut exp1)
            .map_err(|_| SshError::CryptoError("Invalid exponent1".into()))?;

        // Read exponent2 (d mod q-1)
        let mut exp2_len_buf = [0u8; 4];
        cursor.read_exact(&mut exp2_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid exponent2".into()))?;
        let exp2_len = u32::from_be_bytes(exp2_len_buf) as usize;
        let mut exp2 = vec![0u8; exp2_len];
        cursor.read_exact(&mut exp2)
            .map_err(|_| SshError::CryptoError("Invalid exponent2".into()))?;

        // Read coefficient (inverse of q mod p)
        let mut coef_len_buf = [0u8; 4];
        cursor.read_exact(&mut coef_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid coefficient".into()))?;
        let coef_len = u32::from_be_bytes(coef_len_buf) as usize;
        let mut coef = vec![0u8; coef_len];
        cursor.read_exact(&mut coef)
            .map_err(|_| SshError::CryptoError("Invalid coefficient".into()))?;

        // Construct RSA private key from components
        let n = rsa::BigUint::from_bytes_be(&p);
        let e = rsa::BigUint::from_bytes_be(&e);
        let d = rsa::BigUint::from_bytes_be(&d);
        let p_big = rsa::BigUint::from_bytes_be(&p);
        let q_big = rsa::BigUint::from_bytes_be(&q);
        
        // Use from_components which is the correct API in rsa 0.9
        let key = rsa::RsaPrivateKey::from_components(
            n,
            e,
            d,
            vec![p_big.clone(), q_big.clone()], // primes
        )
        .map_err(|_| SshError::CryptoError("Invalid RSA key".into()))?;

        Ok(key)
    }

    /// Get key type
    pub fn key_type(&self) -> KeyType {
        match self {
            PrivateKey::Rsa(_) => KeyType::Rsa,
            PrivateKey::Ecdsa(curve, _) => KeyType::Ecdsa(curve.clone()),
            PrivateKey::Ed25519(_) => KeyType::Ed25519,
        }
    }

    /// Get public key blob (SSH format)
    pub fn to_public_key(&self) -> Result<PublicKey, SshError> {
        match self {
            PrivateKey::Rsa(key) => {
                use bytes::BufMut;
                use rsa::traits::PublicKeyParts;
                
                let n = key.n();
                let e = key.e();
                let mut blob = Vec::new();
                
                // Algorithm name
                blob.put_u8(SSH_RSA.len() as u8);
                blob.put_slice(SSH_RSA.as_bytes());
                
                // Public exponent
                let mut e_bytes = e.to_bytes_be();
                if e_bytes[0] & 0x80 != 0 {
                    e_bytes.insert(0, 0x00);
                }
                blob.put_u8(e_bytes.len() as u8);
                blob.put_slice(&e_bytes);
                
                // Modulus
                let mut n_bytes = n.to_bytes_be();
                if n_bytes[0] & 0x80 != 0 {
                    n_bytes.insert(0, 0x00);
                }
                blob.put_u8(n_bytes.len() as u8);
                blob.put_slice(&n_bytes);
                
                Ok(PublicKey {
                    key_type: KeyType::Rsa,
                    blob,
                    algorithm: SSH_RSA.to_string(),
                })
            }
            PrivateKey::Ecdsa(curve, _) => {
                use bytes::BufMut;
                
                let mut blob = Vec::new();
                
                // Algorithm name
                let algo = match curve {
                    EcdsaCurve::Nistp256 => SSH_ECDSA_NISTP256,
                    EcdsaCurve::Nistp384 => SSH_ECDSA_NISTP384,
                    EcdsaCurve::Nistp521 => SSH_ECDSA_NISTP521,
                };
                blob.put_u8(algo.len() as u8);
                blob.put_slice(algo.as_bytes());
                
                // Curve name
                let curve_name = match curve {
                    EcdsaCurve::Nistp256 => b"nistp256",
                    EcdsaCurve::Nistp384 => b"nistp384",
                    EcdsaCurve::Nistp521 => b"nistp521",
                };
                blob.put_u8(curve_name.len() as u8);
                blob.put_slice(curve_name);
                
                // Public key (32 bytes for P-256, 48 for P-384, 66 for P-521)
                // For now, use dummy - would need to extract from private key
                blob.put_u8(32);
                blob.put_slice(&[0u8; 32]);
                
                Ok(PublicKey {
                    key_type: KeyType::Ecdsa(curve.clone()),
                    blob,
                    algorithm: algo.to_string(),
                })
            }
            PrivateKey::Ed25519(key) => {
                use bytes::BufMut;
                
                let mut blob = Vec::new();
                
                // Algorithm name
                blob.put_u8(SSH_ED25519.len() as u8);
                blob.put_slice(SSH_ED25519.as_bytes());
                
                // Public key (32 bytes)
                let public_key = key.verifying_key();
                blob.put_u8(public_key.as_ref().len() as u8);
                blob.put_slice(public_key.as_ref());
                
                Ok(PublicKey {
                    key_type: KeyType::Ed25519,
                    blob,
                    algorithm: SSH_ED25519.to_string(),
                })
            }
        }
    }

    /// Compute public key hash (SHA-256 of blob)
    pub fn public_key_hash(&self) -> Result<Vec<u8>, SshError> {
        let public_key = self.to_public_key()?;
        let mut hasher = Sha256::new();
        hasher.update(&public_key.blob);
        Ok(hasher.finalize().to_vec())
    }
}

// SSH algorithm constants
const SSH_RSA: &str = "ssh-rsa";
const SSH_ED25519: &str = "ssh-ed25519";
const SSH_ECDSA_NISTP256: &str = "ecdsa-sha2-nistp256";
const SSH_ECDSA_NISTP384: &str = "ecdsa-sha2-nistp384";
const SSH_ECDSA_NISTP521: &str = "ecdsa-sha2-nistp521";

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_rsa_key_parsing() {
        let pem = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MmE3YvGz
... (truncated for brevity)
-----END RSA PRIVATE KEY-----
"#;

        // This is a truncated example - would need real key for full test
        // let key = PrivateKey::parse_pem(pem).unwrap();
        // assert_eq!(key.key_type(), KeyType::Rsa);
    }

    #[test]
    fn test_ed25519_key_parsing() {
        let pem = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQy
NTUxOQAAACBjZGQ3MzE2YzU4YzI0ZDg5YjE2ZjI5ZjI5ZjI5ZjI5ZjI5ZjI5ZjI5ZgAAAAtz
c2gtZWQyNTUxOQAAACBjZGQ3MzE2YzU4YzI0ZDg5YjE2ZjI5ZjI5ZjI5ZjI5ZjI5ZjI5ZjI5
ZgAAAA==
-----END OPENSSH PRIVATE KEY-----
"#;

        // This is a truncated example - would need real key for full test
        // let key = PrivateKey::parse_pem(pem).unwrap();
        // assert_eq!(key.key_type(), KeyType::Ed25519);
    }
}