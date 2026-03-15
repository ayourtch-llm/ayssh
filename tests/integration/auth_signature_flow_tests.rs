//! Test for real RSA signature computation in authentication flow

use ssh_client::auth::{create_signature_data, RsaSignatureEncoder, SshSignature};

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    use rand::rngs::OsRng;
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
        
        // Verify the signature data is the correct length (SHA-256 hash)
        assert_eq!(sig_data.len(), 32); // SHA-256 hash
        
        // Test that the signature can be decoded
        let decoded = SshSignature::decode(&signature.data).unwrap();
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
        
        // Verify the signature
        let decoded = SshSignature::decode(&signature.data).unwrap();
        
        // Note: Full verification would require extracting the public key and verifying
        // For now, we just verify the signature can be decoded and has correct format
        assert_eq!(decoded.algorithm, "ssh-rsa");
        assert!(!decoded.data.is_empty());
    }

    #[test]
    fn test_signature_data_format() {
        // Test that signature data is created correctly
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
        
        // Signature data should be SHA-256 hash (32 bytes)
        assert_eq!(sig_data.len(), 32);
        
        // Verify the hash is computed correctly
        let mut hasher = Sha256::new();
        hasher.update(&session_id);
        hasher.update(&[0x32]); // SSH_MSG_USERAUTH_REQUEST
        hasher.update(username.as_bytes());
        hasher.update(service.as_bytes());
        hasher.update(method.as_bytes());
        hasher.update(&[0x01]); // has_signature = true
        hasher.update(public_key_algorithm.as_bytes());
        hasher.update(&public_key_blob);
        
        let expected = hasher.finalize();
        assert_eq!(sig_data, expected.as_slice());
    }
}