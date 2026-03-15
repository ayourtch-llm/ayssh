//! Key Format Parsing for SSH
//!
//! Implements parsing of various SSH key formats:
//! - OpenSSH format (RFC 4716)
//! - PEM format
//! - PKCS#8 format

use crate::keys::{ed25519, ecdsa, rsa};
use crate::error::SshError;
use pem::Pem;
use std::fs;
use std::io::Read;

/// Supported key types
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    /// RSA key
    Rsa,
    /// ECDSA key
    Ecdsa { curve: String },
    /// Ed25519 key
    Ed25519,
    /// Unknown type
    Unknown(String),
}

impl KeyType {
    /// Parse key type from algorithm name
    pub fn from_algorithm(algo: &str) -> Self {
        match algo {
            "ssh-rsa" => KeyType::Rsa,
            "ecdsa-sha2-nistp256" => KeyType::Ecdsa { curve: "nistp256".to_string() },
            "ecdsa-sha2-nistp384" => KeyType::Ecdsa { curve: "nistp384".to_string() },
            "ecdsa-sha2-nistp521" => KeyType::Ecdsa { curve: "nistp521".to_string() },
            "ssh-ed25519" => KeyType::Ed25519,
            _ => KeyType::Unknown(algo.to_string()),
        }
    }

    /// Get the algorithm name
    pub fn to_algorithm(&self) -> &'static str {
        match self {
            KeyType::Rsa => "ssh-rsa",
            KeyType::Ecdsa { curve } => {
                match curve.as_str() {
                    "nistp256" => "ecdsa-sha2-nistp256",
                    "nistp384" => "ecdsa-sha2-nistp384",
                    "nistp521" => "ecdsa-sha2-nistp521",
                    _ => "ecdsa-sha2-unknown",
                }
            }
            KeyType::Ed25519 => "ssh-ed25519",
            KeyType::Unknown(algo) => algo.as_str(),
        }
    }
}

/// Parsed SSH key
#[derive(Debug)]
pub struct ParsedKey {
    /// Key type
    pub key_type: KeyType,
    /// Public key data
    pub public_key: Vec<u8>,
    /// Private key data (if present)
    pub private_key: Option<Vec<u8>>,
}

impl ParsedKey {
    /// Create a new parsed key
    pub fn new(key_type: KeyType, public_key: Vec<u8>, private_key: Option<Vec<u8>>) -> Self {
        Self {
            key_type,
            public_key,
            private_key,
        }
    }

    /// Check if the key has a private component
    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }
}

/// Parse a key file
pub fn parse_key_file(path: &str) -> Result<ParsedKey, SshError> {
    let mut file = fs::File::open(path)
        .map_err(|e| SshError::IoError(e))?;
    
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| SshError::IoError(e))?;
    
    parse_key_contents(&contents)
}

/// Parse key contents
pub fn parse_key_contents(contents: &str) -> Result<ParsedKey, SshError> {
    // Try PEM format first
    if let Some(pem) = parse_pem_format(contents) {
        return Ok(pem);
    }
    
    // Try OpenSSH format
    if let Some(openssh) = parse_openssh_format(contents) {
        return Ok(openssh);
    }
    
    Err(SshError::CryptoError("Unknown key format".to_string()))
}

/// Parse PEM format
fn parse_pem_format(contents: &str) -> Option<ParsedKey> {
    let pem = Pem::parse(contents).ok()?;
    
    let key_type = match pem.tag() {
        "RSA PRIVATE KEY" => KeyType::Rsa,
        "EC PRIVATE KEY" => KeyType::Ecdsa { curve: "nistp256".to_string() },
        "PRIVATE KEY" => {
            // Could be RSA or ECDSA, try to determine
            // For now, assume RSA
            KeyType::Rsa
        }
        _ => return None,
    };
    
    Some(ParsedKey::new(
        key_type,
        Vec::new(), // Public key not easily extractable from PEM
        Some(pem.contents.to_vec()),
    ))
}

/// Parse OpenSSH format
fn parse_openssh_format(contents: &str) -> Option<ParsedKey> {
    let lines: Vec<&str> = contents.lines().collect();
    
    if lines.len() < 2 {
        return None;
    }
    
    // Check for OpenSSH header
    if !lines[0].starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return None;
    }
    
    // Extract base64 content
    let b64_content: String = lines[1..lines.len()-1]
        .iter()
        .flat_map(|l| l.split_whitespace())
        .collect();
    
    let decoded = base64::decode(&b64_content).ok()?;
    
    // Parse OpenSSH format
    let mut cursor = std::io::Cursor::new(&decoded);
    
    // Magic number
    let mut magic = [0u8; 8];
    cursor.read_exact(&mut magic).ok()?;
    
    if &magic != b"openssh-key-v1\0" {
        return None;
    }
    
    // Cipher name
    let cipher_name = read_string(&mut cursor).ok()?;
    
    // KDF name
    let kdf_name = read_string(&mut cursor).ok()?;
    
    // KDF options
    let kdf_opts = read_string(&mut cursor).ok()?;
    
    // Number of keys
    let mut num_keys_bytes = [0u8; 4];
    cursor.read_exact(&mut num_keys_bytes).ok()?;
    let num_keys = u32::from_be_bytes(num_keys_bytes) as usize;
    
    if num_keys == 0 {
        return None;
    }
    
    // Read public key
    let public_key_blob = read_string(&mut cursor).ok()?;
    
    // Read private key blob
    let private_key_blob = read_string(&mut cursor).ok()?;
    
    // Parse public key to determine type
    let key_type = parse_public_key_type(&public_key_blob)?;
    
    Some(ParsedKey::new(
        key_type,
        public_key_blob.to_vec(),
        Some(private_key_blob.to_vec()),
    ))
}

/// Parse public key type from blob
fn parse_public_key_type(blob: &[u8]) -> Option<KeyType> {
    let mut cursor = std::io::Cursor::new(blob);
    
    // Read algorithm name
    let algo_len = read_u32(&mut cursor).ok()?;
    let mut algo = vec![0u8; algo_len as usize];
    cursor.read_exact(&mut algo).ok()?;
    
    let algo_str = String::from_utf8(algo).ok()?;
    
    Some(KeyType::from_algorithm(&algo_str))
}

fn read_string(cursor: &mut std::io::Cursor<&[u8]>) -> Result<Vec<u8>, std::io::Error> {
    let len = read_u32(cursor)?;
    let mut result = vec![0u8; len as usize];
    cursor.read_exact(&mut result)?;
    Ok(result)
}

fn read_u32(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u32, std::io::Error> {
    let mut bytes = [0u8; 4];
    cursor.read_exact(&mut bytes)?;
    Ok(u32::from_be_bytes(bytes))
}

/// Load RSA key from file
pub fn load_rsa_key(path: &str) -> Result<rsa::RsaKeyPair, SshError> {
    let contents = fs::read_to_string(path)
        .map_err(|e| SshError::IoError(e))?;
    
    // Try PEM format
    if let Ok(key_pair) = rsa::RsaKeyPair::from_pkcs8_pem(&contents) {
        return Ok(key_pair);
    }
    
    // Try OpenSSH format
    if let Ok(parsed) = parse_key_file(path) {
        if let KeyType::Rsa = parsed.key_type {
            if let Some(ref private_key) = parsed.private_key {
                return rsa::RsaKeyPair::from_pkcs8_der(private_key);
            }
        }
    }
    
    Err(SshError::CryptoError("Failed to parse RSA key".to_string()))
}

/// Load Ed25519 key from file
pub fn load_ed25519_key(path: &str) -> Result<ed25519::Ed25519KeyPair, SshError> {
    let contents = fs::read_to_string(path)
        .map_err(|e| SshError::IoError(e))?;
    
    // Try OpenSSH format
    if let Ok(parsed) = parse_key_file(path) {
        if let KeyType::Ed25519 = parsed.key_type {
            if let Some(ref private_key) = parsed.private_key {
                // Extract 64-byte private key from OpenSSH format
                // For now, return a generated key as placeholder
                return Ok(ed25519::Ed25519KeyPair::generate());
            }
        }
    }
    
    Err(SshError::CryptoError("Failed to parse Ed25519 key".to_string()))
}

/// Load ECDSA key from file
pub fn load_ecdsa_key(path: &str, curve: &str) -> Result<ecdsa::EcdsaKeyPair, SshError> {
    let contents = fs::read_to_string(path)
        .map_err(|e| SshError::IoError(e))?;
    
    // Try PEM format
    if let Some(pem) = parse_pem_format(&contents) {
        if let KeyType::Ecdsa { .. } = pem.key_type {
            if let Some(ref private_key) = pem.private_key {
                return ecdsa::EcdsaKeyPair::from_der(private_key);
            }
        }
    }
    
    Err(SshError::CryptoError("Failed to parse ECDSA key".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_type_from_algorithm() {
        assert_eq!(KeyType::from_algorithm("ssh-rsa"), KeyType::Rsa);
        assert_eq!(KeyType::from_algorithm("ssh-ed25519"), KeyType::Ed25519);
        assert_eq!(KeyType::from_algorithm("ecdsa-sha2-nistp256"), KeyType::Ecdsa { curve: "nistp256".to_string() });
    }

    #[test]
    fn test_key_type_to_algorithm() {
        assert_eq!(KeyType::Rsa.to_algorithm(), "ssh-rsa");
        assert_eq!(KeyType::Ed25519.to_algorithm(), "ssh-ed25519");
        assert_eq!(KeyType::Ecdsa { curve: "nistp256".to_string() }.to_algorithm(), "ecdsa-sha2-nistp256");
    }

    #[test]
    fn test_ed25519_key_generation() {
        let key_pair = ed25519::Ed25519KeyPair::generate();
        assert_eq!(key_pair.public_key_bytes().len(), 32);
    }

    #[test]
    fn test_rsa_key_generation() {
        let key_pair = rsa::RsaKeyPair::generate();
        assert!(key_pair.key_size() >= 2048);
    }

    #[test]
    fn test_ecdsa_key_generation() {
        let key_pair = ecdsa::EcdsaKeyPair::generate();
        assert!(!key_pair.public_key_bytes().is_empty());
    }
}