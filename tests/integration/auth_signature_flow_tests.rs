//! Test for real RSA signature computation in authentication flow

use ayssh::auth::{create_signature_data, RsaSignatureEncoder, SshSignature};

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_rsa_signature_in_auth_flow() {
        // Generate a test RSA key pair
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

        // Create the signature data that SSH uses for authentication
        // Format: session_id || SSH_MSG_USERAUTH_REQUEST || username || service || method || has_signature || public_key_algorithm || public_key_blob
        let session_id = vec![0x01; 20];
        let username = "testuser";
        let service = "ssh-connection";
        let method = "publickey";
        let has_signature = true;
        let public_key_algorithm = "ssh-rsa";
        let public_key_blob = vec![0x02; 128]; // Dummy public key blob

        let sig_data = create_signature_data(
            &session_id,
            username,
            service,
            method,
            has_signature,
            public_key_algorithm,
            &public_key_blob,
        );

        // Sign the data with RSA
        let signature = RsaSignatureEncoder::encode(&private_key, &sig_data).unwrap();

        // Verify the signature was created
        assert_eq!(signature.algorithm, "ssh-rsa");
        assert!(!signature.data.is_empty());

        // Verify the encoded signature can be decoded back
        let encoded = signature.encode();
        let decoded = SshSignature::decode(&encoded).unwrap();
        assert_eq!(decoded.algorithm, "ssh-rsa");
        assert!(!decoded.data.is_empty());
    }

    #[test]
    fn test_rsa_signature_verification() {
        // Generate a test RSA key pair
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();

        // Create signature data
        let session_id = vec![0x01; 20];
        let username = "testuser";
        let service = "ssh-connection";
        let method = "publickey";
        let has_signature = true;
        let public_key_algorithm = "ssh-rsa";
        let public_key_blob = vec![0x02; 128];

        let sig_data = create_signature_data(
            &session_id,
            username,
            service,
            method,
            has_signature,
            public_key_algorithm,
            &public_key_blob,
        );

        // Sign the data
        let signature = RsaSignatureEncoder::encode(&private_key, &sig_data).unwrap();

        // Verify the encoded signature can be round-tripped
        let encoded = signature.encode();
        let decoded = SshSignature::decode(&encoded).unwrap();

        assert_eq!(decoded.algorithm, "ssh-rsa");
        assert!(!decoded.data.is_empty());

        // Verify the raw signature is the right size for RSA-2048 (256 bytes)
        assert_eq!(signature.data.len(), 256);
    }

    #[test]
    fn test_signature_data_format() {
        // Test that signature data is created correctly per RFC 4252 Section 7
        // create_signature_data returns SSH-encoded data to be signed, NOT a hash
        let session_id = vec![0x01; 20];
        let username = "testuser";
        let service = "ssh-connection";
        let method = "publickey";
        let has_signature = true;
        let public_key_algorithm = "ssh-rsa";
        let public_key_blob = vec![0x02; 128];

        let sig_data = create_signature_data(
            &session_id,
            username,
            service,
            method,
            has_signature,
            public_key_algorithm,
            &public_key_blob,
        );

        // Expected length: session_id(20+4) + msg_type(1) + username(8+4) + service(14+4) + method(9+4) + has_sig(1) + algo(7+4) + blob(128+4)
        let expected_len = 4 + 20 + 1 + 4 + 8 + 4 + 14 + 4 + 9 + 1 + 4 + 7 + 4 + 128;
        assert_eq!(sig_data.len(), expected_len);

        // Verify the structure: first 4 bytes should be session_id length
        assert_eq!(
            u32::from_be_bytes([sig_data[0], sig_data[1], sig_data[2], sig_data[3]]),
            20
        );

        // Verify message type byte
        assert_eq!(sig_data[24], 0x32); // SSH_MSG_USERAUTH_REQUEST
    }
}
