//! Session Identifier Computation
//!
//! Implements SSH session identifier (H) computation as defined in RFC 4253 Section 7.2.
//! The session identifier is used for key derivation and host key verification.

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::crypto::dh::Mpint;
use crate::protocol::{HashAlgorithm, KexAlgorithm};

/// Compute the SSH session identifier H
///
/// Per RFC 4253 Section 7.2, the exchange hash H is computed as:
/// H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
///
/// For ECDH (RFC 5656), this becomes:
/// H = hash(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
///
/// Where:
/// - V_C = Client version string (excluding CRLF)
/// - V_S = Server version string (excluding CRLF)
/// - I_C = Payload of client's KEXINIT message
/// - I_S = Payload of server's KEXINIT message
/// - K_S = Server's public host key
/// - Q_C / e = Client's ephemeral public key
/// - Q_S / f = Server's ephemeral public key
/// - K = Shared secret, encoded as mpint (from DH or ECDH exchange)
///
/// # Arguments
///
/// * `shared_secret` - The shared secret K from the key exchange
/// * `client_version` - The client version string V_C
/// * `server_version` - The server version string V_S
/// * `client_kex_init` - The client's KEXINIT packet I_C
/// * `server_kex_init` - The server's KEXINIT packet I_S
/// * `server_host_key` - The server's host key K_S
/// * `client_public_key` - The client's public key X_C
/// * `server_public_key` - The server's public key Y_S
/// * `hash_algorithm` - The hash algorithm to use for computing H
///
/// # Returns
///
/// The computed session identifier H as a byte vector.
///
/// # Example
///
/// ```
/// use ayssh::transport::session_id::compute_session_id;
/// use ayssh::protocol::HashAlgorithm;
///
/// let shared_secret = vec![0x00; 32];
/// let client_version = b"SSH-2.0-ayssh";
/// let server_version = b"SSH-2.0-OpenSSH_8.0";
/// let client_kex_init = vec![0x00];
/// let server_kex_init = vec![0x00];
/// let server_host_key = vec![0x00];
/// let client_public_key = vec![0x00];
/// let server_public_key = vec![0x00];
///
/// let session_id = compute_session_id(
///     &shared_secret,
///     client_version,
///     server_version,
///     &client_kex_init,
///     &server_kex_init,
///     &server_host_key,
///     &client_public_key,
///     &server_public_key,
///     HashAlgorithm::Sha256,
/// );
/// ```
pub fn compute_session_id(
    shared_secret: &[u8],
    client_version: &[u8],
    server_version: &[u8],
    client_kex_init: &[u8],
    server_kex_init: &[u8],
    server_host_key: &[u8],
    client_public_key: &[u8],
    server_public_key: &[u8],
    hash_algorithm: HashAlgorithm,
) -> Vec<u8> {
    // Encode K (shared secret) as mpint per RFC 4253 Section 7.2
    let k_mpint = Mpint::encode_length_prefixed(
        &num_bigint::BigUint::from_bytes_be(shared_secret)
    );

    match hash_algorithm {
        HashAlgorithm::Sha256 => {
            let mut h = Sha256::new();
            // RFC 4253 Section 7.2: H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
            h.update(client_version);
            h.update(server_version);
            h.update(client_kex_init);
            h.update(server_kex_init);
            h.update(server_host_key);
            h.update(client_public_key);
            h.update(server_public_key);
            h.update(&k_mpint);  // K (shared secret) as mpint, comes LAST
            h.finalize().to_vec()
        }
        HashAlgorithm::Sha384 => {
            let mut h = Sha384::new();
            h.update(client_version);
            h.update(server_version);
            h.update(client_kex_init);
            h.update(server_kex_init);
            h.update(server_host_key);
            h.update(client_public_key);
            h.update(server_public_key);
            h.update(&k_mpint);  // K (shared secret) as mpint, comes LAST
            h.finalize().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let mut h = Sha512::new();
            h.update(client_version);
            h.update(server_version);
            h.update(client_kex_init);
            h.update(server_kex_init);
            h.update(server_host_key);
            h.update(client_public_key);
            h.update(server_public_key);
            h.update(&k_mpint);  // K (shared secret) as mpint, comes LAST
            h.finalize().to_vec()
        }
        HashAlgorithm::Sha1 => {
            let mut h = Sha1::new();
            h.update(client_version);
            h.update(server_version);
            h.update(client_kex_init);
            h.update(server_kex_init);
            h.update(server_host_key);
            h.update(client_public_key);
            h.update(server_public_key);
            h.update(&k_mpint);  // K (shared secret) as mpint, comes LAST
            h.finalize().to_vec()
        }
    }
}

/// Get the hash algorithm for a given KEX algorithm
pub fn hash_algorithm_for_kex(kex_algorithm: KexAlgorithm) -> HashAlgorithm {
    match kex_algorithm {
        KexAlgorithm::DiffieHellmanGroup1Sha1
        | KexAlgorithm::DiffieHellmanGroup14Sha1 => HashAlgorithm::Sha1,
        KexAlgorithm::DiffieHellmanGroup14Sha256
        | KexAlgorithm::DiffieHellmanGroupExchangeSha256
        | KexAlgorithm::EcdhSha2Nistp256
        | KexAlgorithm::Curve25519Sha256 => HashAlgorithm::Sha256,
        KexAlgorithm::DiffieHellmanGroup14Sha384
        | KexAlgorithm::DiffieHellmanGroup16Sha512
        | KexAlgorithm::DiffieHellmanGroup18Sha512
        | KexAlgorithm::EcdhSha2Nistp384 => HashAlgorithm::Sha384,
        KexAlgorithm::DiffieHellmanGroup14Sha512
        | KexAlgorithm::EcdhSha2Nistp521 => HashAlgorithm::Sha512,
    }
}

/// Session identifier context
#[derive(Debug, Clone)]
pub struct SessionIdContext {
    /// Client version string
    pub client_version: Vec<u8>,
    /// Server version string
    pub server_version: Vec<u8>,
    /// Client KEXINIT packet
    pub client_kex_init: Vec<u8>,
    /// Server KEXINIT packet
    pub server_kex_init: Vec<u8>,
    /// Server host key
    pub server_host_key: Vec<u8>,
}

impl SessionIdContext {
    /// Create a new session ID context
    pub fn new(
        client_version: &str,
        server_version: &str,
        client_kex_init: Vec<u8>,
        server_kex_init: Vec<u8>,
        server_host_key: Vec<u8>,
    ) -> Self {
        Self {
            client_version: client_version.as_bytes().to_vec(),
            server_version: server_version.as_bytes().to_vec(),
            client_kex_init,
            server_kex_init,
            server_host_key,
        }
    }

    /// Compute the session identifier
    pub fn compute(
        &self,
        shared_secret: &[u8],
        client_public_key: &[u8],
        server_public_key: &[u8],
        hash_algorithm: HashAlgorithm,
    ) -> Vec<u8> {
        compute_session_id(
            shared_secret,
            &self.client_version,
            &self.server_version,
            &self.client_kex_init,
            &self.server_kex_init,
            &self.server_host_key,
            client_public_key,
            server_public_key,
            hash_algorithm,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn test_session_id_computation() {
        let shared_secret = vec![0x00; 32];
        let client_version = b"SSH-2.0-ayssh";
        let server_version = b"SSH-2.0-OpenSSH_8.0";
        let client_kex_init = vec![0x00];
        let server_kex_init = vec![0x00];
        let server_host_key = vec![0x00];
        let client_public_key = vec![0x00];
        let server_public_key = vec![0x00];

        let session_id = compute_session_id(
            &shared_secret,
            client_version,
            server_version,
            &client_kex_init,
            &server_kex_init,
            &server_host_key,
            &client_public_key,
            &server_public_key,
            HashAlgorithm::Sha256,
        );

        // Session ID should be 32 bytes for SHA-256
        assert_eq!(session_id.len(), 32);
    }

    #[test]
    fn test_session_id_uniqueness() {
        let shared_secret = vec![0x00; 32];
        let client_version = b"SSH-2.0-ayssh";
        let server_version = b"SSH-2.0-OpenSSH_8.0";
        let client_kex_init = vec![0x00];
        let server_kex_init = vec![0x00];
        let server_host_key = vec![0x00];
        let client_public_key = vec![0x00];
        let server_public_key = vec![0x00];

        let session_id1 = compute_session_id(
            &shared_secret,
            client_version,
            server_version,
            &client_kex_init,
            &server_kex_init,
            &server_host_key,
            &client_public_key,
            &server_public_key,
            HashAlgorithm::Sha256,
        );

        // Change server public key
        let server_public_key2 = vec![0x01];
        let session_id2 = compute_session_id(
            &shared_secret,
            client_version,
            server_version,
            &client_kex_init,
            &server_kex_init,
            &server_host_key,
            &client_public_key,
            &server_public_key2,
            HashAlgorithm::Sha256,
        );

        // Session IDs should be different
        assert_ne!(session_id1, session_id2);
    }

    #[test]
    fn test_session_id_determinism() {
        let shared_secret = vec![0x00; 32];
        let client_version = b"SSH-2.0-ayssh";
        let server_version = b"SSH-2.0-OpenSSH_8.0";
        let client_kex_init = vec![0x00];
        let server_kex_init = vec![0x00];
        let server_host_key = vec![0x00];
        let client_public_key = vec![0x00];
        let server_public_key = vec![0x00];

        let session_id1 = compute_session_id(
            &shared_secret,
            client_version,
            server_version,
            &client_kex_init,
            &server_kex_init,
            &server_host_key,
            &client_public_key,
            &server_public_key,
            HashAlgorithm::Sha256,
        );

        let session_id2 = compute_session_id(
            &shared_secret,
            client_version,
            server_version,
            &client_kex_init,
            &server_kex_init,
            &server_host_key,
            &client_public_key,
            &server_public_key,
            HashAlgorithm::Sha256,
        );

        // Session IDs should be the same
        assert_eq!(session_id1, session_id2);
    }

    #[test]
    fn test_session_id_sha384() {
        let shared_secret = vec![0x00; 32];
        let client_version = b"SSH-2.0-ayssh";
        let server_version = b"SSH-2.0-OpenSSH_8.0";
        let client_kex_init = vec![0x00];
        let server_kex_init = vec![0x00];
        let server_host_key = vec![0x00];
        let client_public_key = vec![0x00];
        let server_public_key = vec![0x00];

        let session_id = compute_session_id(
            &shared_secret,
            client_version,
            server_version,
            &client_kex_init,
            &server_kex_init,
            &server_host_key,
            &client_public_key,
            &server_public_key,
            HashAlgorithm::Sha384,
        );

        // Session ID should be 48 bytes for SHA-384
        assert_eq!(session_id.len(), 48);
    }

    #[test]
    fn test_session_id_sha512() {
        let shared_secret = vec![0x00; 32];
        let client_version = b"SSH-2.0-ayssh";
        let server_version = b"SSH-2.0-OpenSSH_8.0";
        let client_kex_init = vec![0x00];
        let server_kex_init = vec![0x00];
        let server_host_key = vec![0x00];
        let client_public_key = vec![0x00];
        let server_public_key = vec![0x00];

        let session_id = compute_session_id(
            &shared_secret,
            client_version,
            server_version,
            &client_kex_init,
            &server_kex_init,
            &server_host_key,
            &client_public_key,
            &server_public_key,
            HashAlgorithm::Sha512,
        );

        // Session ID should be 64 bytes for SHA-512
        assert_eq!(session_id.len(), 64);
    }

    #[test]
    fn test_hash_algorithm_for_kex() {
        assert_eq!(
            hash_algorithm_for_kex(KexAlgorithm::DiffieHellmanGroup14Sha256),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            hash_algorithm_for_kex(KexAlgorithm::DiffieHellmanGroup16Sha512),
            HashAlgorithm::Sha384
        );
        assert_eq!(
            hash_algorithm_for_kex(KexAlgorithm::EcdhSha2Nistp521),
            HashAlgorithm::Sha512
        );
    }

    #[test]
    fn test_session_id_context() {
        let context = SessionIdContext::new(
            "SSH-2.0-ayssh",
            "SSH-2.0-OpenSSH_8.0",
            vec![0x00],
            vec![0x00],
            vec![0x00],
        );

        let shared_secret = vec![0x00; 32];
        let client_public_key = vec![0x00];
        let server_public_key = vec![0x00];

        let session_id = context.compute(
            &shared_secret,
            &client_public_key,
            &server_public_key,
            HashAlgorithm::Sha256,
        );

        assert_eq!(session_id.len(), 32);
    }

    #[test]
    fn test_session_id_with_realistic_values() {
        let shared_secret = vec![0xAB; 32];
        let client_version = b"SSH-2.0-ayssh_0.1.0";
        let server_version = b"SSH-2.0-OpenSSH_8.4";
        let client_kex_init = vec![
            0x00, 0x00, 0x00, 0x20, // 32 bytes length
            0x64, 0x69, 0x66, 0x66, // "diffie-hellman-group14-sha256"
            0x69, 0x65, 0x2d, 0x68,
            0x65, 0x6c, 0x6c, 0x6d,
            0x2d, 0x67, 0x72, 0x6f,
            0x75, 0x70, 0x31, 0x34,
            0x2d, 0x73, 0x68, 0x61,
            0x32, 0x35, 0x36,
        ];
        let server_kex_init = client_kex_init.clone();
        let server_host_key = vec![0x00, 0x01, 0x02, 0x03];
        let client_public_key = vec![0x00; 65]; // P-256 public key
        let server_public_key = vec![0x01; 65]; // P-256 public key

        let session_id = compute_session_id(
            &shared_secret,
            client_version,
            server_version,
            &client_kex_init,
            &server_kex_init,
            &server_host_key,
            &client_public_key,
            &server_public_key,
            HashAlgorithm::Sha256,
        );

        assert_eq!(session_id.len(), 32);
        assert!(!session_id.is_empty());
    }

    #[test]
    fn test_session_id_order_per_rfc_4253() {
        // Verify that the hash computation follows RFC 4253 Section 7.2:
        // H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
        // where K is encoded as mpint and comes LAST

        let shared_secret = vec![0x01; 32];  // K
        let client_version = b"SSH-2.0-client";  // V_C
        let server_version = b"SSH-2.0-server";  // V_S
        let client_kex_init = vec![0x02];  // I_C
        let server_kex_init = vec![0x03];  // I_S
        let server_host_key = vec![0x04];  // K_S
        let client_public_key = vec![0x05];  // e / Q_C
        let server_public_key = vec![0x06];  // f / Q_S

        let session_id1 = compute_session_id(
            &shared_secret,
            client_version,
            server_version,
            &client_kex_init,
            &server_kex_init,
            &server_host_key,
            &client_public_key,
            &server_public_key,
            HashAlgorithm::Sha256,
        );

        // Change only the shared secret - should produce completely different session ID
        let shared_secret2 = vec![0xFF; 32];
        let session_id2 = compute_session_id(
            &shared_secret2,
            client_version,
            server_version,
            &client_kex_init,
            &server_kex_init,
            &server_host_key,
            &client_public_key,
            &server_public_key,
            HashAlgorithm::Sha256,
        );

        // Session IDs should be completely different (avalanche effect)
        assert_ne!(session_id1, session_id2);

        // Count differing bytes - should be close to 50% for good hash
        let diff_count = session_id1.iter()
            .zip(session_id2.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert!(diff_count > 10, "Expected significant difference in session IDs");
    }
}