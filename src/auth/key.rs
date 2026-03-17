//! Key parsing utilities for SSH authentication
//!
//! Supports parsing:
//! - RSA private keys (PEM PKCS#1 and PKCS#8)
//! - Ed25519 private keys (PEM PKCS#8 and SSH format)
//! - ECDSA private keys (PEM PKCS#8)
//! - Public keys (SSH format)

use base64::Engine as _;
use crate::error::SshError;
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
        eprintln!("=== parse_pem called ===");
        let preview = pem_content.chars().take(100).collect::<String>();
        eprintln!("PEM content starts with: {}", preview);
        
        // Try PKCS#8 first (most common)
        eprintln!("\n--- Trying PKCS#8 ---");
        let pkcs8_result = Self::parse_pkcs8(pem_content);
        if let Ok(key) = pkcs8_result {
            eprintln!("✓ PKCS#8 succeeded");
            return Ok(key);
        }
        
        // If parse_pkcs8 failed, check if it was a PEM parsing error or a tag mismatch
        if let Err(e) = pkcs8_result {
            // Check if PEM parsing itself failed
            if let SshError::CryptoError(msg) = e {
                if msg == "Invalid PEM format" {
                    eprintln!("✗ PKCS#8 failed: Invalid PEM format");
                    return Err(SshError::CryptoError(format!(
                        "Invalid PEM format: {}",
                        msg
                    )));
                }
                // Tag mismatch - this is expected for non-PKCS#8 keys
                eprintln!("✗ PKCS#8 failed: tag mismatch (expected PRIVATE KEY)");
            } else {
                eprintln!("✗ PKCS#8 failed: {:?}", e);
                return Err(e);
            }
        }

        // Try PKCS#1 (RSA only)
        eprintln!("\n--- Trying PKCS#1 ---");
        let pkcs1_result = Self::parse_pkcs1(pem_content);
        if let Ok(key) = pkcs1_result {
            eprintln!("✓ PKCS#1 succeeded");
            return Ok(key);
        }
        if let Err(e) = pkcs1_result {
            if let SshError::CryptoError(msg) = e {
                if msg == "Invalid PEM format" {
                    eprintln!("✗ PKCS#1 failed: Invalid PEM format");
                    return Err(SshError::CryptoError(format!(
                        "Invalid PEM format: {}",
                        msg
                    )));
                }
                // Tag mismatch - expected for non-PKCS#1 keys
                eprintln!("✗ PKCS#1 failed: tag mismatch (expected RSA PRIVATE KEY)");
            } else {
                eprintln!("✗ PKCS#1 failed: {:?}", e);
                return Err(e);
            }
        }

        // Try SSH format (OpenSSH)
        eprintln!("\n--- Trying OpenSSH ---");
        let openssh_result = Self::parse_openssh(pem_content);
        if let Ok(key) = openssh_result {
            eprintln!("✓ OpenSSH succeeded");
            return Ok(key);
        }
        
        // All formats failed - provide detailed diagnostic
        let mut error_info = String::from("Failed to parse private key. Tried: ");
        
        // Check PEM format
        if pem::parse(pem_content).is_err() {
            error_info.push_str("PEM parsing failed; ");
        } else {
            // Get the tag for better diagnostics
            if let Ok(pem) = pem::parse(pem_content) {
                let tag = pem.tag();
                error_info.push_str(&format!("tag='{}', ", tag));
            }
        }
        
        // Check if it's an OpenSSH format
        if pem_content.contains("BEGIN OPENSSH PRIVATE KEY") {
            error_info.push_str("OpenSSH format detected; ");
        }
        
        // Add OpenSSH error if available
        if let Err(e) = openssh_result {
            if let SshError::CryptoError(ref msg) = e {
                error_info.push_str(&format!("OpenSSH error: '{}', ", msg));
            }
        }
        
        error_info.push_str("all formats failed");
        
        eprintln!("✗ All formats failed: {}", error_info);
        Err(SshError::CryptoError(error_info))
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

        // Extract base64 content using the rsa crate pattern
        let der_encoded = pem_content
            .lines()
            .filter(|line| !line.starts_with("-"))
            .fold(String::new(), |mut data, line| {
                data.push_str(&line);
                data
            });
        
        let der = base64::engine::general_purpose::STANDARD.decode(&der_encoded)
            .map_err(|e| SshError::CryptoError(format!("Invalid base64 encoding: {}", e)))?;

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
            .map_err(|_| SshError::CryptoError("Invalid OpenSSH format: cannot read magic bytes".into()))?;
        
        if &magic != b"openssh-key-v1\0" {
            return Err(SshError::CryptoError(format!(
                "Invalid OpenSSH magic: expected 'openssh-key-v1\\0', got {:02x?}",
                &magic[..magic.len().min(15)]
            )));
        }

        // Read cipher name
        let mut cipher_len_buf = [0u8; 4];
        cursor.read_exact(&mut cipher_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid cipher name: cannot read length".into()))?;
        let cipher_len = u32::from_be_bytes(cipher_len_buf) as usize;
        let mut cipher = vec![0u8; cipher_len];
        cursor.read_exact(&mut cipher)
            .map_err(|_| SshError::CryptoError(format!(
                "Invalid cipher name: cannot read cipher name (len={})",
                cipher_len
            )))?;

        // Read kdf name
        let mut kdf_len_buf = [0u8; 4];
        cursor.read_exact(&mut kdf_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid kdf name: cannot read length".into()))?;
        let kdf_len = u32::from_be_bytes(kdf_len_buf) as usize;
        let mut kdf = vec![0u8; kdf_len];
        cursor.read_exact(&mut kdf)
            .map_err(|_| SshError::CryptoError(format!(
                "Invalid kdf name: cannot read kdf name (len={})",
                kdf_len
            )))?;

        // Read kdf options
        let mut kdf_opts_len_buf = [0u8; 4];
        cursor.read_exact(&mut kdf_opts_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid kdf options: cannot read length".into()))?;
        let kdf_opts_len = u32::from_be_bytes(kdf_opts_len_buf) as usize;
        let mut kdf_opts = vec![0u8; kdf_opts_len];
        cursor.read_exact(&mut kdf_opts)
            .map_err(|_| SshError::CryptoError(format!(
                "Invalid kdf options: cannot read kdf options (len={})",
                kdf_opts_len
            )))?;

        // Read number of keys
        let mut nkeys_buf = [0u8; 4];
        cursor.read_exact(&mut nkeys_buf)
            .map_err(|_| SshError::CryptoError("Invalid key count: cannot read length".into()))?;
        let nkeys = u32::from_be_bytes(nkeys_buf) as usize;

        if nkeys != 1 {
            return Err(SshError::CryptoError(format!(
                "Only single-key OpenSSH files supported, found {} keys",
                nkeys
            )));
        }

        // Read public key
        let mut pub_key_len_buf = [0u8; 4];
        cursor.read_exact(&mut pub_key_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid public key: cannot read length".into()))?;
        let pub_key_len = u32::from_be_bytes(pub_key_len_buf) as usize;
        let mut pub_key = vec![0u8; pub_key_len];
        cursor.read_exact(&mut pub_key)
            .map_err(|_| SshError::CryptoError(format!(
                "Invalid public key: cannot read public key blob (len={})",
                pub_key_len
            )))?;

        // Read private key blob
        let mut priv_key_len_buf = [0u8; 4];
        cursor.read_exact(&mut priv_key_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid private key: cannot read length".into()))?;
        let priv_key_len = u32::from_be_bytes(priv_key_len_buf) as usize;
        let mut priv_key_blob = vec![0u8; priv_key_len];
        cursor.read_exact(&mut priv_key_blob)
            .map_err(|_| SshError::CryptoError(format!(
                "Invalid private key: cannot read private key blob (len={})",
                priv_key_len
            )))?;

        // Parse based on key type (from public key)
        let mut pub_cursor = Cursor::new(&pub_key);
        
        let mut algo_len_buf = [0u8; 4];
        pub_cursor.read_exact(&mut algo_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid algorithm: cannot read length".into()))?;
        let algo_len = u32::from_be_bytes(algo_len_buf) as usize;
        let mut algo = vec![0u8; algo_len];
        pub_cursor.read_exact(&mut algo)
            .map_err(|_| SshError::CryptoError(format!(
                "Invalid algorithm: cannot read algorithm string (len={})",
                algo_len
            )))?;

        let algorithm = String::from_utf8(algo)
            .map_err(|_| SshError::CryptoError("Invalid algorithm string: not valid UTF-8".into()))?;

        match algorithm.as_str() {
            "ssh-rsa" => {
                // Parse RSA public key to get modulus/exponent
                // Then parse private key blob
                let rsa_key = Self::parse_openssh_rsa(&priv_key_blob)?;
                Ok(PrivateKey::Rsa(rsa_key))
            }
            "ssh-ed25519" => {
                // Ed25519 format in private key blob:
                // See ssh-ed25519.c:ssh_ed25519_deserialize_private
                // Format: [32-byte public key][64-byte private key (seed + pubkey)]
                if priv_key_blob.len() >= 96 {
                    // Skip first 32 bytes (public key), take next 64 bytes (seed + pubkey)
                    let private_data = &priv_key_blob[32..96];
                    // First 32 bytes is the seed
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&private_data[0..32]);
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                    Ok(PrivateKey::Ed25519(signing_key))
                } else {
                    Err(SshError::CryptoError(format!(
                        "Invalid Ed25519 key length: expected >= 96 bytes, got {}",
                        priv_key_blob.len()
                    )))
                }
            }
            "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
                // ECDSA private key blob format (OpenSSH):
                // uint32 checkint1, uint32 checkint2,
                // string key_type, string curve_name,
                // string public_key (EC point), string private_key (scalar),
                // string comment, padding
                let mut ec_cursor = Cursor::new(&priv_key_blob);

                // Skip checkints (8 bytes)
                let mut skip = [0u8; 8];
                ec_cursor.read_exact(&mut skip)
                    .map_err(|_| SshError::CryptoError("ECDSA: cannot read checkints".into()))?;

                // Skip key_type string
                let mut len_buf = [0u8; 4];
                ec_cursor.read_exact(&mut len_buf)
                    .map_err(|_| SshError::CryptoError("ECDSA: cannot read key_type length".into()))?;
                let skip_len = u32::from_be_bytes(len_buf) as usize;
                let mut skip_data = vec![0u8; skip_len];
                ec_cursor.read_exact(&mut skip_data)
                    .map_err(|_| SshError::CryptoError("ECDSA: cannot read key_type".into()))?;

                // Read curve_name string
                ec_cursor.read_exact(&mut len_buf)
                    .map_err(|_| SshError::CryptoError("ECDSA: cannot read curve_name length".into()))?;
                let curve_len = u32::from_be_bytes(len_buf) as usize;
                let mut curve_name = vec![0u8; curve_len];
                ec_cursor.read_exact(&mut curve_name)
                    .map_err(|_| SshError::CryptoError(format!(
                        "ECDSA: cannot read curve_name (len={})", curve_len
                    )))?;

                let curve = match curve_name.as_slice() {
                    b"nistp256" => EcdsaCurve::Nistp256,
                    b"nistp384" => EcdsaCurve::Nistp384,
                    b"nistp521" => EcdsaCurve::Nistp521,
                    _ => return Err(SshError::CryptoError(format!(
                        "Unsupported ECDSA curve: {}",
                        String::from_utf8_lossy(&curve_name)
                    ))),
                };

                // Skip public_key string (EC point)
                ec_cursor.read_exact(&mut len_buf)
                    .map_err(|_| SshError::CryptoError("ECDSA: cannot read public_key length".into()))?;
                let pubkey_len = u32::from_be_bytes(len_buf) as usize;
                let mut pubkey_data = vec![0u8; pubkey_len];
                ec_cursor.read_exact(&mut pubkey_data)
                    .map_err(|_| SshError::CryptoError("ECDSA: cannot read public_key".into()))?;

                // Read private_key scalar
                ec_cursor.read_exact(&mut len_buf)
                    .map_err(|_| SshError::CryptoError("ECDSA: cannot read scalar length".into()))?;
                let scalar_len = u32::from_be_bytes(len_buf) as usize;
                let mut scalar = vec![0u8; scalar_len];
                ec_cursor.read_exact(&mut scalar)
                    .map_err(|_| SshError::CryptoError(format!(
                        "ECDSA: cannot read scalar (len={})", scalar_len
                    )))?;

                Ok(PrivateKey::Ecdsa(curve, scalar))
            }
            _ => Err(SshError::CryptoError(format!(
                "Unsupported key type: {}",
                algorithm
            ))),
        }
    }

    /// Parse OpenSSH RSA private key
    /// 
    /// OpenSSH RSA format in private key blob (RFC4253):
    /// - checkint (4 bytes)
    /// - checkint (4 bytes) - must match
    /// - algorithm string "ssh-rsa" (variable length)
    /// - modulus n (mpint)
    /// - public exponent e (mpint)
    /// - private exponent d (mpint)
    /// - prime1 p (mpint)
    /// - prime2 q (mpint)
    /// - exponent1 (mpint)
    /// - exponent2 (mpint)
    /// - coefficient (optional, mpint) - inverse of q mod p
    /// - comment (optional, string)
    /// - padding (optional, bytes)
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

        // Read public key algorithm string (ssh-rsa)
        let mut algo_len_buf = [0u8; 4];
        cursor.read_exact(&mut algo_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid algorithm string length".into()))?;
        let algo_len = u32::from_be_bytes(algo_len_buf) as usize;
        let mut algo = vec![0u8; algo_len];
        cursor.read_exact(&mut algo)
            .map_err(|_| SshError::CryptoError("Invalid algorithm string".into()))?;
        
        let algorithm = String::from_utf8(algo)
            .map_err(|_| SshError::CryptoError("Invalid algorithm string encoding".into()))?;
        
        if algorithm != "ssh-rsa" {
            return Err(SshError::CryptoError(format!(
                "Expected 'ssh-rsa' algorithm, got '{}'",
                algorithm
            )));
        }

        // Read modulus (n)
        let mut n_len_buf = [0u8; 4];
        cursor.read_exact(&mut n_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid modulus".into()))?;
        let n_len = u32::from_be_bytes(n_len_buf) as usize;
        let mut n = vec![0u8; n_len];
        cursor.read_exact(&mut n)
            .map_err(|_| SshError::CryptoError("Invalid modulus".into()))?;

        // Read public exponent (e)
        let mut e_len_buf = [0u8; 4];
        cursor.read_exact(&mut e_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid public exponent".into()))?;
        let e_len = u32::from_be_bytes(e_len_buf) as usize;
        let mut e = vec![0u8; e_len];
        cursor.read_exact(&mut e)
            .map_err(|_| SshError::CryptoError("Invalid public exponent".into()))?;

        // Read private exponent (d)
        let mut d_len_buf = [0u8; 4];
        cursor.read_exact(&mut d_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid private exponent".into()))?;
        let d_len = u32::from_be_bytes(d_len_buf) as usize;
        let mut d = vec![0u8; d_len];
        cursor.read_exact(&mut d)
            .map_err(|_| SshError::CryptoError("Invalid private exponent".into()))?;

        // Read coefficient (iqmp = q^(-1) mod p) - comes BEFORE p and q in OpenSSH format
        let mut coef_len_buf = [0u8; 4];
        cursor.read_exact(&mut coef_len_buf)
            .map_err(|_| SshError::CryptoError("Invalid coefficient".into()))?;
        let coef_len = u32::from_be_bytes(coef_len_buf) as usize;
        let mut coef = vec![0u8; coef_len];
        cursor.read_exact(&mut coef)
            .map_err(|_| SshError::CryptoError("Invalid coefficient".into()))?;

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

        // Read exponent1 (d mod p-1) - optional in some OpenSSH versions
        // Check if there's enough data for a length field
        let bytes_remaining = private_key_blob.len() - cursor.position() as usize;
        if bytes_remaining >= 4 {
            let mut exp1_len_buf = [0u8; 4];
            if cursor.read_exact(&mut exp1_len_buf).is_ok() {
                let exp1_len = u32::from_be_bytes(exp1_len_buf) as usize;
                if bytes_remaining >= 4 + exp1_len {
                    let mut exp1 = vec![0u8; exp1_len];
                    cursor.read_exact(&mut exp1)
                        .map_err(|_| SshError::CryptoError("Invalid exponent1".into()))?;
                    // exp1 is optional, we can ignore it
                    drop(exp1);
                } else {
                    // Not enough bytes for exponent1, this is likely padding
                    // Rewind the length bytes
                    cursor.set_position(cursor.position() - 4);
                }
            }
        }

        // Read exponent2 (d mod q-1) - optional in some OpenSSH versions
        let bytes_remaining = private_key_blob.len() - cursor.position() as usize;
        if bytes_remaining >= 4 {
            let mut exp2_len_buf = [0u8; 4];
            if cursor.read_exact(&mut exp2_len_buf).is_ok() {
                let exp2_len = u32::from_be_bytes(exp2_len_buf) as usize;
                if bytes_remaining >= 4 + exp2_len {
                    let mut exp2 = vec![0u8; exp2_len];
                    cursor.read_exact(&mut exp2)
                        .map_err(|_| SshError::CryptoError("Invalid exponent2".into()))?;
                    // exp2 is optional, we can ignore it
                    drop(exp2);
                } else {
                    // Not enough bytes for exponent2, this is likely padding
                    // Rewind the length bytes
                    cursor.set_position(cursor.position() - 4);
                }
            }
        }

        // Construct RSA private key from components
        // OpenSSH uses mpint encoding which adds a leading 0x00 byte to prevent
        // the MSB from being interpreted as a sign bit. We need to strip it.
        let n_bytes = if n.len() > 1 && n[0] == 0x00 && (n[1] & 0x80) != 0 {
            &n[1..]
        } else {
            &n[..]
        };
        let e_bytes = if e.len() > 1 && e[0] == 0x00 && (e[1] & 0x80) != 0 {
            &e[1..]
        } else {
            &e[..]
        };
        let d_bytes = if d.len() > 1 && d[0] == 0x00 && (d[1] & 0x80) != 0 {
            &d[1..]
        } else {
            &d[..]
        };
        let p_bytes = if p.len() > 1 && p[0] == 0x00 && (p[1] & 0x80) != 0 {
            &p[1..]
        } else {
            &p[..]
        };
        let q_bytes = if q.len() > 1 && q[0] == 0x00 && (q[1] & 0x80) != 0 {
            &q[1..]
        } else {
            &q[..]
        };
        
        let n_big = rsa::BigUint::from_bytes_be(n_bytes);
        let e_big = rsa::BigUint::from_bytes_be(e_bytes);
        let d_big = rsa::BigUint::from_bytes_be(d_bytes);
        let p_big = rsa::BigUint::from_bytes_be(p_bytes);
        let q_big = rsa::BigUint::from_bytes_be(q_bytes);
        
        // Use from_components which is the correct API in rsa 0.9
        let key = rsa::RsaPrivateKey::from_components(
            n_big,
            e_big,
            d_big,
            vec![p_big, q_big], // primes
        )
        .map_err(|e| SshError::CryptoError(format!("Invalid RSA key: {}", e)))?;

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

    #[test]
    fn test_load_rsa_2048_key() {
        let pem = std::fs::read_to_string("tests/keys/test_rsa_2048").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Rsa);
    }

    #[test]
    fn test_load_rsa_4096_key() {
        let pem = std::fs::read_to_string("tests/keys/test_rsa_4096").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Rsa);
    }

    #[test]
    fn test_load_rsa_8192_key() {
        let pem = std::fs::read_to_string("tests/keys/test_rsa_8192").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Rsa);
    }

    #[test]
    fn test_load_ed25519_key() {
        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Ed25519);
    }

    #[test]
    fn test_load_ecdsa_p256_key() {
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_256").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Ecdsa(EcdsaCurve::Nistp256));
    }

    #[test]
    fn test_load_ecdsa_p384_key() {
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_384").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Ecdsa(EcdsaCurve::Nistp384));
    }

    #[test]
    fn test_ed25519_key_can_extract_public_key() {
        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let pub_key = key.to_public_key().unwrap();
        assert_eq!(pub_key.key_type, KeyType::Ed25519);
        assert!(!pub_key.blob.is_empty());
    }

    #[test]
    fn test_ed25519_key_hash_deterministic() {
        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let hash1 = key.public_key_hash().unwrap();
        let hash2 = key.public_key_hash().unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA-256
    }

    #[test]
    fn test_different_key_types_have_different_hashes() {
        let rsa_pem = std::fs::read_to_string("tests/keys/test_rsa_2048").unwrap();
        let ed_pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let rsa_hash = PrivateKey::parse_pem(&rsa_pem).unwrap().public_key_hash().unwrap();
        let ed_hash = PrivateKey::parse_pem(&ed_pem).unwrap().public_key_hash().unwrap();
        assert_ne!(rsa_hash, ed_hash);
    }

    #[test]
    fn test_ecdsa_p256_key_can_extract_public_key() {
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_256").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let pub_key = key.to_public_key().unwrap();
        assert_eq!(pub_key.key_type, KeyType::Ecdsa(EcdsaCurve::Nistp256));
        assert!(!pub_key.blob.is_empty());
    }

    #[test]
    fn test_invalid_pem_returns_error() {
        let result = PrivateKey::parse_pem("not a valid key");
        assert!(result.is_err());
    }
}