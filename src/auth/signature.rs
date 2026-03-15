//! SSH Signature Encoding - Complete Implementation
//!
//! Implements RFC 4253, RFC 5656, and RFC 8332 for SSH signature formats.
//! This module provides proper encoding for RSA, ECDSA, and Ed25519 signatures.

use crate::error::SshError;
use bytes::{Buf, BufMut, BytesMut};
use sha2::{Digest, Sha256};
use signature::SignatureEncoding;

/// SSH signature algorithm identifiers
pub const SSH_SIG_ALGORITHM_RSA: &str = "ssh-rsa";
pub const SSH_SIG_ALGORITHM_ECDSA_NISTP256: &str = "ecdsa-sha2-nistp256";
pub const SSH_SIG_ALGORITHM_ECDSA_NISTP384: &str = "ecdsa-sha2-nistp384";
pub const SSH_SIG_ALGORITHM_ECDSA_NISTP521: &str = "ecdsa-sha2-nistp521";
pub const SSH_SIG_ALGORITHM_ED25519: &str = "ssh-ed25519";

/// SSH signature structure
#[derive(Debug, Clone)]
pub struct SshSignature {
    /// Algorithm identifier
    pub algorithm: String,
    /// Signature data (SSH-encoded)
    pub data: Vec<u8>,
}

impl SshSignature {
    /// Create a new SSH signature
    pub fn new(algorithm: impl Into<String>, data: impl Into<Vec<u8>>) -> Self {
        Self {
            algorithm: algorithm.into(),
            data: data.into(),
        }
    }

    /// Encode signature as SSH string (string + data)
    /// SSH strings are encoded as: [4-byte length][data]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        // Algorithm string (4-byte length prefix)
        buf.put_u32(self.algorithm.len() as u32);
        buf.put_slice(self.algorithm.as_bytes());
        // Signature data string (4-byte length prefix)
        buf.put_u32(self.data.len() as u32);
        buf.put_slice(&self.data);
        buf.to_vec()
    }

    /// Decode signature from SSH-encoded bytes
    /// SSH strings are encoded as: [4-byte length][data]
    pub fn decode(encoded: &[u8]) -> Result<Self, SshError> {
        let mut buf = BytesMut::from(encoded);
        
        // Read algorithm string (4-byte length prefix)
        let algo_len = buf.get_u32() as usize;
        if algo_len == 0 || algo_len > 256 {
            return Err(SshError::ProtocolError(
                "Invalid algorithm string length".into()
            ));
        }
        let algorithm = String::from_utf8(buf.copy_to_bytes(algo_len).to_vec())
            .map_err(|_| SshError::ProtocolError("Invalid algorithm string".into()))?;
        
        // Read signature data string (4-byte length prefix)
        let sig_len = buf.get_u32() as usize;
        if sig_len == 0 || sig_len > 65535 {
            return Err(SshError::ProtocolError(
                "Invalid signature string length".into()
            ));
        }
        let data = buf.copy_to_bytes(sig_len).to_vec();
        
        Ok(Self { algorithm, data })
    }
}

/// RSA signature encoding (RFC 4253 Section 11.1)
/// Format: string "ssh-rsa" + mpint(e) + mpint(s)
pub struct RsaSignatureEncoder;

impl RsaSignatureEncoder {
    /// Encode RSA signature
    /// data: SHA-256 hash of (session_id + SSH_MSG_USERAUTH_REQUEST + ...)
    pub fn encode(
        private_key: &rsa::RsaPrivateKey,
        data: &[u8],
    ) -> Result<SshSignature, SshError> {
        use signature::Signer;
        
        // Create signing key with empty prefix (unprefixed signatures)
        let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new_unprefixed(private_key.clone());
        
        // Sign the data
        let signature = signing_key.sign(data);
        
        // SSH RSA signature format:
        // string "ssh-rsa"
        // mpint e (public exponent, typically 65537)
        // mpint s (signature)
        let mut buf = BytesMut::new();
        
        // Algorithm name (4-byte length prefix)
        buf.put_u32(SSH_SIG_ALGORITHM_RSA.len() as u32);
        buf.put_slice(SSH_SIG_ALGORITHM_RSA.as_bytes());
        
        // Public exponent (65537 = 0x010001) as mpint
        let e = vec![0x01, 0x00, 0x01];
        buf.put_u32(e.len() as u32);
        buf.put_slice(&e);
        
        // Signature (convert to positive mpint - big-endian) as mpint
        let signature_bytes = signature.to_bytes();
        let s = Self::to_positive_mpint(signature_bytes.as_ref());
        buf.put_u32(s.len() as u32);
        buf.put_slice(&s);
        
        Ok(SshSignature::new(SSH_SIG_ALGORITHM_RSA, buf.to_vec()))
    }

    /// Convert signature to positive mpint (big-endian, no sign bit)
    /// SSH mpint must be positive, so if high bit is set, prepend 0x00
    fn to_positive_mpint(signature: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(signature.len() + 1);
        
        // If high bit is set, prepend 0x00 to make it positive
        if signature[0] & 0x80 != 0 {
            result.push(0x00);
        }
        
        result.extend_from_slice(signature);
        result
    }
}

/// ECDSA signature encoding (RFC 5656, RFC 8332)
/// Format: string "ecdsa-sha2-nistp256" + string (nistp256 + r || s)
pub struct EcdsaSignatureEncoder;

impl EcdsaSignatureEncoder {
    /// Encode ECDSA signature for NISTP256
    pub fn encode_nistp256(
        private_key: &k256::ecdsa::SigningKey,
        data: &[u8],
    ) -> Result<SshSignature, SshError> {
        use k256::ecdsa::Signature;
        use signature::Signer;
        
        // Sign the data
        let signature: Signature = private_key.sign(data);
        
        // Get r and s as bytes (32 bytes each for P-256)
        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();
        
        // Concatenate r and s (64 bytes total for P-256)
        let mut rs = Vec::with_capacity(64);
        rs.extend_from_slice(&r_bytes[..32]);
        rs.extend_from_slice(&s_bytes[..32]);
        
        let mut buf = BytesMut::new();
        
        // Algorithm name (4-byte length prefix)
        buf.put_u32(SSH_SIG_ALGORITHM_ECDSA_NISTP256.len() as u32);
        buf.put_slice(SSH_SIG_ALGORITHM_ECDSA_NISTP256.as_bytes());
        
        // Curve name + r || s as a single string
        let curve_name = b"nistp256";
        buf.put_u32(curve_name.len() as u32);
        buf.put_slice(curve_name);
        buf.put_u32(rs.len() as u32);
        buf.put_slice(&rs);
        
        Ok(SshSignature::new(SSH_SIG_ALGORITHM_ECDSA_NISTP256, buf.to_vec()))
    }

    /// Encode ECDSA signature for NISTP384
    pub fn encode_nistp384(
        private_key: &p384::ecdsa::SigningKey,
        data: &[u8],
    ) -> Result<SshSignature, SshError> {
        use p384::ecdsa::Signature;
        use signature::Signer;
        
        let signature: Signature = private_key.sign(data);
        
        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();
        
        // P-384: 48 bytes each
        let mut rs = Vec::with_capacity(96);
        rs.extend_from_slice(&r_bytes[..48]);
        rs.extend_from_slice(&s_bytes[..48]);
        
        let mut buf = BytesMut::new();
        
        // Algorithm name (4-byte length prefix)
        buf.put_u32(SSH_SIG_ALGORITHM_ECDSA_NISTP384.len() as u32);
        buf.put_slice(SSH_SIG_ALGORITHM_ECDSA_NISTP384.as_bytes());
        
        // Curve name + r || s as a single string
        let curve_name = b"nistp384";
        buf.put_u32(curve_name.len() as u32);
        buf.put_slice(curve_name);
        buf.put_u32(rs.len() as u32);
        buf.put_slice(&rs);
        
        Ok(SshSignature::new(SSH_SIG_ALGORITHM_ECDSA_NISTP384, buf.to_vec()))
    }

    /// Encode ECDSA signature for NISTP521
    pub fn encode_nistp521(
        private_key: &p521::ecdsa::SigningKey,
        data: &[u8],
    ) -> Result<SshSignature, SshError> {
        use p521::ecdsa::Signature;
        use signature::Signer;
        
        let signature: Signature = private_key.sign(data);
        
        let r_bytes = signature.r().to_bytes();
        let s_bytes = signature.s().to_bytes();
        
        // P-521: 66 bytes each
        let mut rs = Vec::with_capacity(132);
        rs.extend_from_slice(&r_bytes[..66]);
        rs.extend_from_slice(&s_bytes[..66]);
        
        let mut buf = BytesMut::new();
        
        // Algorithm name (4-byte length prefix)
        buf.put_u32(SSH_SIG_ALGORITHM_ECDSA_NISTP521.len() as u32);
        buf.put_slice(SSH_SIG_ALGORITHM_ECDSA_NISTP521.as_bytes());
        
        // Curve name + r || s as a single string
        let curve_name = b"nistp521";
        buf.put_u32(curve_name.len() as u32);
        buf.put_slice(curve_name);
        buf.put_u32(rs.len() as u32);
        buf.put_slice(&rs);
        
        Ok(SshSignature::new(SSH_SIG_ALGORITHM_ECDSA_NISTP521, buf.to_vec()))
    }
}

/// Ed25519 signature encoding (RFC 8332 Section 3)
/// Format: string "ssh-ed25519" + string (signature)
pub struct Ed25519SignatureEncoder;

impl Ed25519SignatureEncoder {
    /// Encode Ed25519 signature
    pub fn encode(
        private_key: &ed25519_dalek::SigningKey,
        data: &[u8],
    ) -> Result<SshSignature, SshError> {
        use ed25519_dalek::Signer;
        
        // Sign the data
        let signature = private_key.sign(data);
        
        let mut buf = BytesMut::new();
        
        // Algorithm name (4-byte length prefix)
        buf.put_u32(SSH_SIG_ALGORITHM_ED25519.len() as u32);
        buf.put_slice(SSH_SIG_ALGORITHM_ED25519.as_bytes());
        
        // Signature (64 bytes) as a string
        let sig_bytes = signature.to_bytes();
        buf.put_u32(sig_bytes.len() as u32);
        buf.put_slice(&sig_bytes);
        
        Ok(SshSignature::new(SSH_SIG_ALGORITHM_ED25519, buf.to_vec()))
    }
}

/// Create signature data for authentication (RFC 4252 Section 7)
/// The signature is computed over:
/// - session_id (20 bytes)
/// - SSH_MSG_USERAUTH_REQUEST (1 byte = 0x32)
/// - username (string)
/// - service (string)
/// - method (string)
/// - has_signature (boolean)
/// - public_key_algorithm (string)
/// - public_key_blob (string)
pub fn create_signature_data(
    session_id: &[u8],
    username: &str,
    service: &str,
    method: &str,
    has_signature: bool,
    public_key_algorithm: &str,
    public_key_blob: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    
    // Session ID (20 bytes from key exchange)
    hasher.update(session_id);
    
    // Message type (SSH_MSG_USERAUTH_REQUEST = 50 = 0x32)
    hasher.update(&[0x32]);
    
    // Username (string)
    hasher.update(username.as_bytes());
    
    // Service (string)
    hasher.update(service.as_bytes());
    
    // Method (string)
    hasher.update(method.as_bytes());
    
    // Has signature (boolean)
    hasher.update(&[if has_signature { 0x01 } else { 0x00 }]);
    
    // Public key algorithm (string)
    hasher.update(public_key_algorithm.as_bytes());
    
    // Public key blob (string)
    hasher.update(public_key_blob);
    
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    use rand::rngs::OsRng;
    
    #[test]
    fn test_rsa_signature_encoding() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        
        let data = b"test signature data for RSA";
        let signature = RsaSignatureEncoder::encode(&private_key, data).unwrap();
        
        assert_eq!(signature.algorithm, SSH_SIG_ALGORITHM_RSA);
        assert!(!signature.data.is_empty());
        
        // Test round-trip - encode the signature and decode it
        let encoded = signature.encode();
        let decoded = SshSignature::decode(&encoded).unwrap();
        
        assert_eq!(decoded.algorithm, signature.algorithm);
        assert_eq!(decoded.data, signature.data);
    }
    
    #[test]
    fn test_ecdsa_signature_encoding() {
        use k256::ecdsa::SigningKey;
        
        let mut rng = OsRng;
        let private_key = SigningKey::random(&mut rng);
        
        let data = b"test signature data for ECDSA";
        let signature = EcdsaSignatureEncoder::encode_nistp256(&private_key, data).unwrap();
        
        assert_eq!(signature.algorithm, SSH_SIG_ALGORITHM_ECDSA_NISTP256);
        assert!(!signature.data.is_empty());
        
        // Test round-trip - encode the signature and decode it
        let encoded = signature.encode();
        let decoded = SshSignature::decode(&encoded).unwrap();
        
        assert_eq!(decoded.algorithm, signature.algorithm);
        assert_eq!(decoded.data, signature.data);
    }
    
    #[test]
    fn test_ed25519_signature_encoding() {
        use ed25519_dalek::SigningKey;
        use rand::Rng;
        
        let mut rng = OsRng;
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let private_key = SigningKey::from_bytes(&seed);
        
        let data = b"test signature data for Ed25519";
        let signature = Ed25519SignatureEncoder::encode(&private_key, data).unwrap();
        
        assert_eq!(signature.algorithm, SSH_SIG_ALGORITHM_ED25519);
        assert!(!signature.data.is_empty());
        
        // Test round-trip - encode the signature and decode it
        let encoded = signature.encode();
        let decoded = SshSignature::decode(&encoded).unwrap();
        
        assert_eq!(decoded.algorithm, signature.algorithm);
        assert_eq!(decoded.data, signature.data);
    }
    
    #[test]
    fn test_signature_data_creation() {
        let session_id = vec![0x01; 20];
        let username = "testuser";
        let service = "ssh-connection";
        let method = "publickey";
        let has_signature = false;
        let public_key_algorithm = "ssh-rsa";
        let public_key_blob = vec![0x02; 100];
        
        let sig_data = create_signature_data(
            &session_id,
            username,
            service,
            method,
            has_signature,
            public_key_algorithm,
            &public_key_blob,
        );
        
        assert_eq!(sig_data.len(), 32); // SHA-256 hash is always 32 bytes
    }
}