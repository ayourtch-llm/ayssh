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
            let key = p256::ecdsa::SigningKey::from_bytes(&bytes.into())
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
                // OpenSSH Ed25519 private key blob format:
                // uint32 checkint1, uint32 checkint2,
                // string key_type ("ssh-ed25519"),
                // string pubkey (32 bytes),
                // string privkey (64 bytes: seed || pubkey),
                // string comment, padding
                let mut cursor = Cursor::new(&priv_key_blob);

                // Skip checkints (8 bytes)
                let mut skip = [0u8; 8];
                cursor.read_exact(&mut skip)
                    .map_err(|_| SshError::CryptoError("Ed25519: cannot read checkints".into()))?;

                // Skip key_type string
                let mut len_buf = [0u8; 4];
                cursor.read_exact(&mut len_buf)
                    .map_err(|_| SshError::CryptoError("Ed25519: cannot read key_type length".into()))?;
                let kt_len = u32::from_be_bytes(len_buf) as usize;
                let mut kt_data = vec![0u8; kt_len];
                cursor.read_exact(&mut kt_data)
                    .map_err(|_| SshError::CryptoError("Ed25519: cannot read key_type".into()))?;

                // Skip pubkey string (32 bytes)
                cursor.read_exact(&mut len_buf)
                    .map_err(|_| SshError::CryptoError("Ed25519: cannot read pubkey length".into()))?;
                let pk_len = u32::from_be_bytes(len_buf) as usize;
                let mut pk_data = vec![0u8; pk_len];
                cursor.read_exact(&mut pk_data)
                    .map_err(|_| SshError::CryptoError("Ed25519: cannot read pubkey".into()))?;

                // Read privkey string (64 bytes: seed || pubkey)
                cursor.read_exact(&mut len_buf)
                    .map_err(|_| SshError::CryptoError("Ed25519: cannot read privkey length".into()))?;
                let priv_len = u32::from_be_bytes(len_buf) as usize;
                if priv_len < 32 {
                    return Err(SshError::CryptoError(format!(
                        "Ed25519: privkey too short: {} bytes", priv_len
                    )));
                }
                let mut priv_data = vec![0u8; priv_len];
                cursor.read_exact(&mut priv_data)
                    .map_err(|_| SshError::CryptoError("Ed25519: cannot read privkey".into()))?;

                // First 32 bytes of privkey is the seed
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&priv_data[0..32]);
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                Ok(PrivateKey::Ed25519(signing_key))
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

    /// Get the SSH algorithm names to try for this key type.
    /// Returns a list in preference order (first is preferred).
    pub fn ssh_algorithm_names(&self) -> Vec<&'static str> {
        match self {
            PrivateKey::Rsa(_) => vec!["rsa-sha2-256", "ssh-rsa"],
            PrivateKey::Ed25519(_) => vec!["ssh-ed25519"],
            PrivateKey::Ecdsa(curve, _) => vec![match curve {
                EcdsaCurve::Nistp256 => "ecdsa-sha2-nistp256",
                EcdsaCurve::Nistp384 => "ecdsa-sha2-nistp384",
                EcdsaCurve::Nistp521 => "ecdsa-sha2-nistp521",
            }],
        }
    }

    /// Encode the public key as an SSH wire-format blob (4-byte length-prefixed strings).
    /// This is the blob sent in USERAUTH_REQUEST per RFC 4252 Section 7.
    pub fn ssh_public_key_blob(&self) -> Result<Vec<u8>, SshError> {
        use bytes::{BufMut, BytesMut};

        fn put_string(buf: &mut BytesMut, data: &[u8]) {
            buf.put_u32(data.len() as u32);
            buf.put_slice(data);
        }

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

        let mut buf = BytesMut::new();

        match self {
            PrivateKey::Rsa(key) => {
                use rsa::traits::PublicKeyParts;
                put_string(&mut buf, b"ssh-rsa");
                let e = key.e().to_bytes_be();
                put_mpint(&mut buf, &e);
                let n = key.n().to_bytes_be();
                put_mpint(&mut buf, &n);
            }
            PrivateKey::Ed25519(key) => {
                put_string(&mut buf, b"ssh-ed25519");
                let public_key = key.verifying_key();
                put_string(&mut buf, public_key.as_bytes());
            }
            PrivateKey::Ecdsa(curve, scalar) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                let (algo, curve_name, pubkey_bytes) = match curve {
                    EcdsaCurve::Nistp256 => {
                        let secret = p256::SecretKey::from_slice(scalar)
                            .map_err(|e| SshError::CryptoError(format!("P-256 key error: {}", e)))?;
                        let point = secret.public_key().to_encoded_point(false);
                        ("ecdsa-sha2-nistp256", "nistp256", point.as_bytes().to_vec())
                    }
                    EcdsaCurve::Nistp384 => {
                        use p384::elliptic_curve::sec1::ToEncodedPoint as _;
                        let secret = p384::SecretKey::from_slice(scalar)
                            .map_err(|e| SshError::CryptoError(format!("P-384 key error: {}", e)))?;
                        let point = secret.public_key().to_encoded_point(false);
                        ("ecdsa-sha2-nistp384", "nistp384", point.as_bytes().to_vec())
                    }
                    EcdsaCurve::Nistp521 => {
                        use p521::elliptic_curve::sec1::ToEncodedPoint as _;
                        let secret = p521::SecretKey::from_slice(scalar)
                            .map_err(|e| SshError::CryptoError(format!("P-521 key error: {}", e)))?;
                        let point = secret.public_key().to_encoded_point(false);
                        ("ecdsa-sha2-nistp521", "nistp521", point.as_bytes().to_vec())
                    }
                };
                put_string(&mut buf, algo.as_bytes());
                put_string(&mut buf, curve_name.as_bytes());
                put_string(&mut buf, &pubkey_bytes);
            }
        }

        Ok(buf.to_vec())
    }

    /// Sign data with this private key, returning an SshSignature.
    pub fn sign(&self, data: &[u8]) -> Result<crate::auth::signature::SshSignature, SshError> {
        use crate::auth::signature::*;
        match self {
            PrivateKey::Rsa(key) => RsaSignatureEncoder::encode_sha256(key, data),
            PrivateKey::Ed25519(key) => Ed25519SignatureEncoder::encode(key, data),
            PrivateKey::Ecdsa(curve, scalar) => match curve {
                EcdsaCurve::Nistp256 => {
                    let secret = p256::SecretKey::from_slice(scalar)
                        .map_err(|e| SshError::CryptoError(format!("P-256: {}", e)))?;
                    let signing_key = p256::ecdsa::SigningKey::from(secret);
                    EcdsaSignatureEncoder::encode_nistp256(&signing_key, data)
                }
                EcdsaCurve::Nistp384 => {
                    let secret = p384::SecretKey::from_slice(scalar)
                        .map_err(|e| SshError::CryptoError(format!("P-384: {}", e)))?;
                    let signing_key = p384::ecdsa::SigningKey::from(secret);
                    EcdsaSignatureEncoder::encode_nistp384(&signing_key, data)
                }
                EcdsaCurve::Nistp521 => {
                    let signing_key = p521::ecdsa::SigningKey::from_slice(scalar)
                        .map_err(|e| SshError::CryptoError(format!("P-521: {}", e)))?;
                    EcdsaSignatureEncoder::encode_nistp521(&signing_key, data)
                }
            },
        }
    }

    /// Sign data using a specific SSH algorithm name (e.g., "rsa-sha2-256" vs "ssh-rsa").
    /// For non-RSA keys, the algorithm parameter is ignored.
    pub fn sign_with_algorithm(&self, data: &[u8], algorithm: &str) -> Result<crate::auth::signature::SshSignature, SshError> {
        use crate::auth::signature::*;
        match self {
            PrivateKey::Rsa(key) => match algorithm {
                "rsa-sha2-256" => RsaSignatureEncoder::encode_sha256(key, data),
                _ => RsaSignatureEncoder::encode(key, data),
            },
            _ => self.sign(data),
        }
    }

    /// Get public key blob (SSH format)
    /// NOTE: Uses 1-byte length encoding (legacy). Prefer ssh_public_key_blob() for wire format.
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

    #[test]
    fn test_ed25519_ssh_public_key_blob_matches_ssh_keygen() {
        use base64::Engine;
        let pub_content = std::fs::read_to_string("tests/keys/test_ed25519.pub").unwrap();
        let parts: Vec<&str> = pub_content.trim().splitn(3, ' ').collect();
        let expected_blob = base64::engine::general_purpose::STANDARD.decode(parts[1]).unwrap();

        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let our_blob = key.ssh_public_key_blob().unwrap();

        assert_eq!(our_blob, expected_blob,
            "Ed25519 public key blob must match ssh-keygen output");
    }

    #[test]
    fn test_rsa_ssh_public_key_blob_matches_ssh_keygen() {
        use base64::Engine;
        let pub_content = std::fs::read_to_string("tests/keys/test_rsa_2048.pub").unwrap();
        let parts: Vec<&str> = pub_content.trim().splitn(3, ' ').collect();
        let expected_blob = base64::engine::general_purpose::STANDARD.decode(parts[1]).unwrap();

        let pem = std::fs::read_to_string("tests/keys/test_rsa_2048").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let our_blob = key.ssh_public_key_blob().unwrap();

        assert_eq!(our_blob, expected_blob,
            "RSA public key blob must match ssh-keygen output");
    }

    #[test]
    fn test_ecdsa_p256_ssh_public_key_blob_matches_ssh_keygen() {
        use base64::Engine;
        let pub_content = std::fs::read_to_string("tests/keys/test_ecdsa_256.pub").unwrap();
        let parts: Vec<&str> = pub_content.trim().splitn(3, ' ').collect();
        let expected_blob = base64::engine::general_purpose::STANDARD.decode(parts[1]).unwrap();

        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_256").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let our_blob = key.ssh_public_key_blob().unwrap();

        assert_eq!(our_blob, expected_blob,
            "ECDSA P-256 public key blob must match ssh-keygen output (uses p256 crate, not k256)");
    }

    #[test]
    fn test_ecdsa_p384_ssh_public_key_blob_matches_ssh_keygen() {
        use base64::Engine;
        let pub_content = std::fs::read_to_string("tests/keys/test_ecdsa_384.pub").unwrap();
        let parts: Vec<&str> = pub_content.trim().splitn(3, ' ').collect();
        let expected_blob = base64::engine::general_purpose::STANDARD.decode(parts[1]).unwrap();

        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_384").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let our_blob = key.ssh_public_key_blob().unwrap();

        assert_eq!(our_blob, expected_blob,
            "ECDSA P-384 public key blob must match ssh-keygen output");
    }

    #[test]
    fn test_key_type_rsa() {
        let pem = std::fs::read_to_string("tests/keys/test_rsa_2048").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Rsa);
    }

    #[test]
    fn test_key_type_ed25519() {
        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Ed25519);
    }

    #[test]
    fn test_key_type_ecdsa_p256() {
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_256").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Ecdsa(EcdsaCurve::Nistp256));
    }

    #[test]
    fn test_key_type_ecdsa_p384() {
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_384").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Ecdsa(EcdsaCurve::Nistp384));
    }

    #[test]
    fn test_ssh_algorithm_names_rsa() {
        let pem = std::fs::read_to_string("tests/keys/test_rsa_2048").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let names = key.ssh_algorithm_names();
        assert_eq!(names, vec!["rsa-sha2-256", "ssh-rsa"]);
    }

    #[test]
    fn test_ssh_algorithm_names_ed25519() {
        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let names = key.ssh_algorithm_names();
        assert_eq!(names, vec!["ssh-ed25519"]);
    }

    #[test]
    fn test_ssh_algorithm_names_ecdsa_p256() {
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_256").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let names = key.ssh_algorithm_names();
        assert_eq!(names, vec!["ecdsa-sha2-nistp256"]);
    }

    #[test]
    fn test_ssh_algorithm_names_ecdsa_p384() {
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_384").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let names = key.ssh_algorithm_names();
        assert_eq!(names, vec!["ecdsa-sha2-nistp384"]);
    }

    #[test]
    fn test_to_public_key_rsa_legacy() {
        let pem = std::fs::read_to_string("tests/keys/test_rsa_2048").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let pub_key = key.to_public_key().unwrap();
        assert_eq!(pub_key.key_type, KeyType::Rsa);
        assert_eq!(pub_key.algorithm, "ssh-rsa");
        assert!(!pub_key.blob.is_empty());
        // Legacy format uses 1-byte length prefix
        // First byte is length of "ssh-rsa" = 7
        assert_eq!(pub_key.blob[0], 7);
        assert_eq!(&pub_key.blob[1..8], b"ssh-rsa");
    }

    #[test]
    fn test_to_public_key_ecdsa_legacy() {
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_256").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let pub_key = key.to_public_key().unwrap();
        assert_eq!(pub_key.key_type, KeyType::Ecdsa(EcdsaCurve::Nistp256));
        assert_eq!(pub_key.algorithm, "ecdsa-sha2-nistp256");
        assert!(!pub_key.blob.is_empty());
        // Check 1-byte length prefix for algo name
        let algo_name = "ecdsa-sha2-nistp256";
        assert_eq!(pub_key.blob[0], algo_name.len() as u8);
    }

    #[test]
    fn test_to_public_key_ecdsa_p384_legacy() {
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_384").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let pub_key = key.to_public_key().unwrap();
        assert_eq!(pub_key.key_type, KeyType::Ecdsa(EcdsaCurve::Nistp384));
        assert_eq!(pub_key.algorithm, "ecdsa-sha2-nistp384");
    }

    #[test]
    fn test_to_public_key_ed25519_legacy() {
        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let pub_key = key.to_public_key().unwrap();
        assert_eq!(pub_key.key_type, KeyType::Ed25519);
        assert_eq!(pub_key.algorithm, "ssh-ed25519");
        // 1-byte length prefix + "ssh-ed25519" (11 bytes) + 1-byte length + 32-byte key
        assert_eq!(pub_key.blob[0], 11);
        assert_eq!(&pub_key.blob[1..12], b"ssh-ed25519");
    }

    #[test]
    fn test_public_key_hash_rsa() {
        let pem = std::fs::read_to_string("tests/keys/test_rsa_2048").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let hash = key.public_key_hash().unwrap();
        assert_eq!(hash.len(), 32); // SHA-256
    }

    #[test]
    fn test_sign_ed25519() {
        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let sig = key.sign(b"test data").unwrap();
        assert!(!sig.data.is_empty());
    }

    #[test]
    fn test_sign_rsa_sha256() {
        let pem = std::fs::read_to_string("tests/keys/test_rsa_2048").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let sig = key.sign(b"test data").unwrap();
        assert!(!sig.data.is_empty());
    }

    #[test]
    fn test_sign_with_algorithm_rsa_sha2_256() {
        let pem = std::fs::read_to_string("tests/keys/test_rsa_2048").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let sig = key.sign_with_algorithm(b"test data", "rsa-sha2-256").unwrap();
        assert!(!sig.data.is_empty());
    }

    #[test]
    fn test_sign_with_algorithm_ssh_rsa_legacy() {
        let pem = std::fs::read_to_string("tests/keys/test_rsa_2048").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let sig = key.sign_with_algorithm(b"test data", "ssh-rsa").unwrap();
        assert!(!sig.data.is_empty());
    }

    #[test]
    fn test_sign_with_algorithm_ed25519_ignores_algorithm() {
        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        // For non-RSA keys, algorithm parameter is ignored
        let sig = key.sign_with_algorithm(b"test data", "anything").unwrap();
        assert!(!sig.data.is_empty());
    }

    #[test]
    fn test_sign_ecdsa_p256() {
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_256").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let sig = key.sign(b"test data").unwrap();
        assert!(!sig.data.is_empty());
    }

    #[test]
    fn test_sign_ecdsa_p384() {
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_384").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let sig = key.sign(b"test data").unwrap();
        assert!(!sig.data.is_empty());
    }

    #[test]
    fn test_parse_pem_empty_string() {
        let result = PrivateKey::parse_pem("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pem_garbage() {
        let result = PrivateKey::parse_pem("-----BEGIN PRIVATE KEY-----\nnotbase64!!\n-----END PRIVATE KEY-----");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pem_encrypted_key_error() {
        // Construct a minimal PEM with ENCRYPTED PRIVATE KEY tag
        let result = PrivateKey::parse_pem(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_file_nonexistent() {
        let result = PrivateKey::load_from_file("/nonexistent/path/key.pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_ssh_public_key_blob_ed25519_format() {
        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let blob = key.ssh_public_key_blob().unwrap();

        // Parse the blob structure: 4-byte length + "ssh-ed25519" + 4-byte length + 32-byte key
        let algo_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        assert_eq!(algo_len, 11); // "ssh-ed25519"
        assert_eq!(&blob[4..15], b"ssh-ed25519");

        let key_len = u32::from_be_bytes([blob[15], blob[16], blob[17], blob[18]]) as usize;
        assert_eq!(key_len, 32); // Ed25519 public key is 32 bytes
        assert_eq!(blob.len(), 4 + 11 + 4 + 32);
    }

    #[test]
    fn test_ecdsa_p521_key_operations() {
        // Test P-521 key if available
        let pem = std::fs::read_to_string("tests/keys/test_ecdsa_521");
        if pem.is_err() {
            // Skip if key not available
            return;
        }
        let pem = pem.unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        assert_eq!(key.key_type(), KeyType::Ecdsa(EcdsaCurve::Nistp521));
        assert_eq!(key.ssh_algorithm_names(), vec!["ecdsa-sha2-nistp521"]);

        let blob = key.ssh_public_key_blob().unwrap();
        assert!(!blob.is_empty());

        let sig = key.sign(b"test data").unwrap();
        assert!(!sig.data.is_empty());
    }

    #[test]
    fn test_rsa_4096_ssh_public_key_blob() {
        let pem = std::fs::read_to_string("tests/keys/test_rsa_4096").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let blob = key.ssh_public_key_blob().unwrap();

        // Verify structure: "ssh-rsa" prefix
        let algo_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        assert_eq!(algo_len, 7);
        assert_eq!(&blob[4..11], b"ssh-rsa");

        // Compare against ssh-keygen output
        let pub_content = std::fs::read_to_string("tests/keys/test_rsa_4096.pub").unwrap();
        let parts: Vec<&str> = pub_content.trim().splitn(3, ' ').collect();
        let expected_blob = base64::engine::general_purpose::STANDARD.decode(parts[1]).unwrap();
        assert_eq!(blob, expected_blob);
    }

    #[test]
    fn test_private_key_clone() {
        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let cloned = key.clone();
        assert_eq!(key.key_type(), cloned.key_type());

        // Both should produce the same public key blob
        let blob1 = key.ssh_public_key_blob().unwrap();
        let blob2 = cloned.ssh_public_key_blob().unwrap();
        assert_eq!(blob1, blob2);
    }

    #[test]
    fn test_public_key_struct_clone() {
        let pem = std::fs::read_to_string("tests/keys/test_ed25519").unwrap();
        let key = PrivateKey::parse_pem(&pem).unwrap();
        let pub_key = key.to_public_key().unwrap();
        let cloned = pub_key.clone();
        assert_eq!(pub_key.key_type, cloned.key_type);
        assert_eq!(pub_key.blob, cloned.blob);
        assert_eq!(pub_key.algorithm, cloned.algorithm);
    }
}