//! Key Exchange (KEX) Implementation
//!
//! Implements various key exchange algorithms as defined in RFC 4253 Section 7.
//! Supports:
//! - diffie-hellman-group14-sha256 (RFC 8731)
//! - diffie-hellman-group-exchange-sha256 (RFC 4253)

use crate::crypto::dh::{DhGroup, Mpint};
use crate::crypto::kdf;
use crate::protocol;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha384};

/// Key exchange context
#[derive(Debug)]
pub struct KexContext {
    /// Selected algorithm
    pub algorithm: protocol::KexAlgorithm,
    /// Client's ephemeral key
    pub client_ephemeral: Option<Vec<u8>>,
    /// Server's ephemeral key
    pub server_ephemeral: Option<Vec<u8>>,
    /// Client's private key (for DH)
    client_private: Option<num_bigint::BigUint>,
    /// Server's public key (for DH)
    server_public: Option<num_bigint::BigUint>,
    /// Shared secret (if computed)
    pub shared_secret: Option<Vec<u8>>,
    /// Session ID (if computed)
    pub session_id: Option<Vec<u8>>,
}

impl KexContext {
    /// Create a new KEX context
    pub fn new(algorithm: protocol::KexAlgorithm) -> Self {
        Self {
            algorithm,
            client_ephemeral: None,
            server_ephemeral: None,
            client_private: None,
            server_public: None,
            shared_secret: None,
            session_id: None,
        }
    }

    /// Generate client's ephemeral key for the selected algorithm
    pub fn generate_client_key(&mut self, rng: &mut impl RngCore) -> anyhow::Result<()> {
        match self.algorithm {
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha256 |
            protocol::KexAlgorithm::DiffieHellmanGroupExchangeSha256 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha384 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha512 |
            protocol::KexAlgorithm::DiffieHellmanGroup16Sha512 |
            protocol::KexAlgorithm::DiffieHellmanGroup18Sha512 => {
                let group = DhGroup::group14();
                let private_x = group.generate_private_key(rng, 256);
                let public_y = group.compute_public_key(&private_x);
                
                self.client_private = Some(private_x);
                self.client_ephemeral = Some(Mpint::encode(&public_y));
                Ok(())
            }
            protocol::KexAlgorithm::EcdhSha2Nistp256 |
            protocol::KexAlgorithm::EcdhSha2Nistp384 |
            protocol::KexAlgorithm::EcdhSha2Nistp521 |
            protocol::KexAlgorithm::Curve25519Sha256 => {
                // For ECDH/curve25519, generate random bytes (placeholder)
                let mut public_bytes = vec![0u8; 32];
                rng.fill_bytes(&mut public_bytes);
                
                self.client_ephemeral = Some(public_bytes);
                Ok(())
            }
        }
    }

    /// Process server's key exchange message
    pub fn process_server_kex_init(&mut self, server_ephemeral: &[u8]) -> anyhow::Result<()> {
        // Decode server's ephemeral key from MPINT
        let server_public = Mpint::decode(server_ephemeral)?;
        self.server_public = Some(server_public);
        self.server_ephemeral = Some(server_ephemeral.to_vec());
        Ok(())
    }

    /// Compute the shared secret
    pub fn compute_shared_secret(&mut self) -> anyhow::Result<()> {
        match self.algorithm {
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha256 |
            protocol::KexAlgorithm::DiffieHellmanGroupExchangeSha256 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha384 |
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha512 |
            protocol::KexAlgorithm::DiffieHellmanGroup16Sha512 |
            protocol::KexAlgorithm::DiffieHellmanGroup18Sha512 => {
                // For DH, compute shared secret: s = server_public^client_private mod p
                if let (Some(ref server_pub), Some(ref client_priv)) = 
                    (&self.server_public, &self.client_private) {
                    let group = DhGroup::group14();
                    let shared = group.compute_shared_secret(server_pub, client_priv);
                    self.shared_secret = Some(shared.to_bytes_be());
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Missing private or public key for DH"))
                }
            }
            protocol::KexAlgorithm::Curve25519Sha256 |
            protocol::KexAlgorithm::EcdhSha2Nistp256 |
            protocol::KexAlgorithm::EcdhSha2Nistp384 |
            protocol::KexAlgorithm::EcdhSha2Nistp521 => {
                // For ECDH/curve25519, compute shared secret using elliptic curve multiplication
                // This would require a proper elliptic curve implementation
                // Placeholder: derive from ephemeral keys
                if let (Some(ref client_eph), Some(ref server_eph)) = 
                    (&self.client_ephemeral, &self.server_ephemeral) {
                    // Simple placeholder: hash the concatenation
                    use sha2::Sha256;
                    let mut hasher = Sha256::new();
                    hasher.update(client_eph);
                    hasher.update(server_eph);
                    self.shared_secret = Some(hasher.finalize().to_vec());
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Missing ephemeral keys for ECDH"))
                }
            }
        }
    }

    /// Generate the session hash (H)
    pub fn generate_session_hash(&self, _session_id: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.algorithm {
            protocol::KexAlgorithm::DiffieHellmanGroup14Sha256 |
            protocol::KexAlgorithm::DiffieHellmanGroupExchangeSha256 => {
                // H = Hash(K_S || V_C || V_S || I_C || I_S || K_EXC || H_S)
                let mut hasher = Sha256::new();
                
                // K_S - shared secret
                if let Some(ref ss) = self.shared_secret {
                    hasher.update(ss);
                }
                
                // V_C - client version string
                hasher.update(b"SSH-2.0-OpenSSH_9.0");
                
                // V_S - server version string
                hasher.update(b"SSH-2.0-OpenSSH_9.0");
                
                // I_C - client initial kex packet
                hasher.update(&[]);
                
                // I_S - server initial kex packet
                hasher.update(&[]);
                
                // K_EXC - exchanged key exchange parameters
                if let Some(ref ce) = self.client_ephemeral {
                    hasher.update(ce);
                }
                if let Some(ref se) = self.server_ephemeral {
                    hasher.update(se);
                }
                
                // H_S - server host key (placeholder)
                hasher.update(&[]);
                
                Ok(hasher.finalize().to_vec())
            }
            _ => {
                // For other algorithms, use SHA256 as default
                let mut hasher = Sha256::new();
                
                if let Some(ref ss) = self.shared_secret {
                    hasher.update(ss);
                }
                
                hasher.update(b"SSH-2.0-OpenSSH_9.0");
                hasher.update(b"SSH-2.0-OpenSSH_9.0");
                hasher.update(&[]);
                hasher.update(&[]);
                
                if let Some(ref ce) = self.client_ephemeral {
                    hasher.update(ce);
                }
                if let Some(ref se) = self.server_ephemeral {
                    hasher.update(se);
                }
                
                Ok(hasher.finalize().to_vec())
            }
        }
    }

    /// Derive session keys from shared secret and session hash
    pub fn derive_session_keys(&mut self, hash: &[u8]) -> anyhow::Result<SessionKeys> {
        if let Some(ref shared_secret) = self.shared_secret {
            // Use the session hash as session_id for KDF
            let enc_key_len = 32; // AES-256
            let mac_key_len = 32; // SHA-256
            let iv_len = 12; // For GCM/ChaCha20
            
            let enc_key = kdf::kdf(shared_secret, hash, 1, enc_key_len);
            let mac_key = kdf::kdf(shared_secret, hash, 2, mac_key_len);
            let client_iv = kdf::kdf(shared_secret, hash, 3, iv_len);
            let server_iv = kdf::kdf(shared_secret, hash, 4, iv_len);
            
            Ok(SessionKeys {
                enc_key,
                mac_key,
                client_iv,
                server_iv,
            })
        } else {
            Err(anyhow::anyhow!("Shared secret not computed yet"))
        }
    }
}

/// Session keys derived from key exchange
#[derive(Debug)]
pub struct SessionKeys {
    /// Encryption key
    pub enc_key: Vec<u8>,
    /// MAC key
    pub mac_key: Vec<u8>,
    /// Client IV
    pub client_iv: Vec<u8>,
    /// Server IV
    pub server_iv: Vec<u8>,
}

/// Perform key exchange with given algorithm
pub async fn perform_kex(
    _algorithm: protocol::KexAlgorithm,
    _context: &mut KexContext,
    _client_kexinit: &[u8],
    _server_kexinit: &[u8],
    _server_host_key: &[u8],
) -> anyhow::Result<()> {
    // Placeholder for actual KEX implementation
    // This would involve:
    // 1. Generate client ephemeral key
    // 2. Send KEX_INIT to server
    // 3. Receive server KEX_INIT and server key
    // 4. Compute shared secret
    // 5. Compute session ID
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use crate::crypto::dh::{DhGroup, Mpint};
    use num_bigint::BigUint;

    #[test]
    fn test_kex_context_creation() {
        let context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        assert_eq!(context.algorithm, protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        assert!(context.client_ephemeral.is_none());
    }

    #[test]
    fn test_dh_group14_key_generation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        context.generate_client_key(&mut OsRng).unwrap();
        
        assert!(context.client_ephemeral.is_some());
        assert!(!context.client_ephemeral.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_curve25519_key_generation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::Curve25519Sha256);
        context.generate_client_key(&mut OsRng).unwrap();
        
        assert!(context.client_ephemeral.is_some());
        assert_eq!(context.client_ephemeral.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_dh_shared_secret_computation() {
        let group = DhGroup::group14();
        
        // Generate client's key pair
        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        
        // Generate server's key pair
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);
        
        // Compute shared secret from both sides
        let client_shared = group.compute_shared_secret(&server_public, &client_private);
        let server_shared = group.compute_shared_secret(&client_public, &server_private);
        
        // Both sides should compute the same shared secret
        assert_eq!(client_shared, server_shared);
        assert!(client_shared > BigUint::from(0u8));
    }

    #[test]
    fn test_dh_shared_secret_with_mpint() {
        let group = DhGroup::group14();
        
        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);
        
        // Encode public keys as MPINT (as sent over the wire)
        let client_mpint = Mpint::encode(&client_public);
        let server_mpint = Mpint::encode(&server_public);
        
        // Decode MPINTs back to BigUint
        let client_public_decoded = Mpint::decode(&client_mpint).unwrap();
        let server_public_decoded = Mpint::decode(&server_mpint).unwrap();
        
        // Compute shared secret using decoded values
        // Client computes: s = server_public^client_private mod p
        let client_shared = group.compute_shared_secret(&server_public_decoded, &client_private);
        // Server computes: s = client_public^server_private mod p
        let server_shared = group.compute_shared_secret(&client_public_decoded, &server_private);
        
        assert_eq!(client_shared, server_shared);
        assert!(client_shared > BigUint::from(0u8));
    }

    #[test]
    fn test_session_hash_generation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        
        // Generate key pairs
        let group = DhGroup::group14();
        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);
        
        // Set up context
        context.client_private = Some(client_private.clone());
        context.client_ephemeral = Some(Mpint::encode(&client_public));
        context.server_public = Some(server_public.clone());
        context.server_ephemeral = Some(Mpint::encode(&server_public));
        
        // Compute shared secret
        context.compute_shared_secret().unwrap();
        
        // Generate session hash
        let _session_id = b"test-session-id-12345";
        let hash = context.generate_session_hash(_session_id).unwrap();
        
        assert_eq!(hash.len(), 32); // SHA256 output
    }

    #[test]
    fn test_session_hash_deterministic() {
        let mut context1 = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        let mut context2 = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        
        // Use the same inputs for both
        let group = DhGroup::group14();
        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);
        
        context1.client_private = Some(client_private.clone());
        context1.client_ephemeral = Some(Mpint::encode(&client_public));
        context1.server_public = Some(server_public.clone());
        context1.server_ephemeral = Some(Mpint::encode(&server_public));
        
        context2.client_private = Some(client_private.clone());
        context2.client_ephemeral = Some(Mpint::encode(&client_public));
        context2.server_public = Some(server_public.clone());
        context2.server_ephemeral = Some(Mpint::encode(&server_public));
        
        context1.compute_shared_secret().unwrap();
        context2.compute_shared_secret().unwrap();
        
        let hash1 = context1.generate_session_hash(b"session-id").unwrap();
        let hash2 = context2.generate_session_hash(b"session-id").unwrap();
        
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_session_key_derivation() {
        let mut context = KexContext::new(protocol::KexAlgorithm::DiffieHellmanGroup14Sha256);
        
        // Generate key pairs
        let group = DhGroup::group14();
        let client_private = group.generate_private_key(&mut OsRng, 256);
        let client_public = group.compute_public_key(&client_private);
        let server_private = group.generate_private_key(&mut OsRng, 256);
        let server_public = group.compute_public_key(&server_private);
        
        // Set up context
        context.client_private = Some(client_private.clone());
        context.client_ephemeral = Some(Mpint::encode(&client_public));
        context.server_public = Some(server_public.clone());
        context.server_ephemeral = Some(Mpint::encode(&server_public));
        
        // Compute shared secret
        context.compute_shared_secret().unwrap();
        
        // Generate session hash
        let session_id = b"test-session-id";
        let hash = context.generate_session_hash(session_id).unwrap();
        
        // Derive session keys
        let keys = context.derive_session_keys(&hash).unwrap();
        
        assert_eq!(keys.enc_key.len(), 32); // AES-256
        assert_eq!(keys.mac_key.len(), 32); // SHA-256
        assert_eq!(keys.client_iv.len(), 12);
        assert_eq!(keys.server_iv.len(), 12);
    }
}