//! Authentication tests using real SSH keys

use ayssh::auth::{
    create_signature_data, Ed25519SignatureEncoder, EcdsaSignatureEncoder,
    PrivateKey, PublicKeyAuthenticator, RsaSignatureEncoder, SSH_SIG_ALGORITHM_ED25519,
    SSH_SIG_ALGORITHM_RSA,
};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::Message;
    use crate::protocol::messages::MessageType;
    use crate::transport::Transport;
    use bytes::BytesMut;
    use std::io::Cursor;

    #[test]
    fn test_ed25519_key_parsing() {
        let pem_content = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDye0bbrSGsotdwr4icJwRADJ/afJrfoBav6YdoYkpU0AAAAJgYjh9oGI4f
aAAAAAtzc2gtZWQyNTUxOQAAACDye0bbrSGsotdwr4icJwRADJ/afJrfoBav6YdoYkpU0A
AAAECoR1gOXudrcRYwcKRRRdHAdcivlSivKk76HhJMCUt3OfJ7RtutIayi13CviJwnBEAM
n9p8mt+gFq/ph2hiSlTQAAAADnRlc3RAbG9jYWxob3N0AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----"#;

        let key = PrivateKey::parse_pem(pem_content).unwrap();
        assert_eq!(key.key_type(), crate::auth::key::KeyType::Ed25519);
    }

    #[test]
    fn test_rsa_key_parsing() {
        let pem_content = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEApKskAVxvB/bN/SeqOmiMmqRHnoRF8TIk768Fp0QF0ky1mjrRcAbB
b4qhm/s5RIdDYOl/AszPy/Q6KoSyMIsjN1hcvxpOJnZdP5IEclQRRGzrfh9krDmU2n0oNp
SsYIzFjyQ2nQtL4yV4z9IVRurajLhWnAQuAhTnPrp2jAL/8mfFP6RFjxTCx8P0QwrkuX8p
WnCFKuU7lMpg+zEydtbnStJ9VJ17lnNkEgPWxwJmwFnhuAJWV+p8MuE5gf3Ovxl7sKff4R
C6BSCfppX1LbXcMTWEU00h5OpzXQ0N4FR2+g08z+mi3ev2MBdlcQIe8IFN75fsKCCCLfEh
bnVK/RPKVwAAA8jAFbyDwBW8gwAAAAdzc2gtcnNhAAABAQCkqyQBXG8H9s39J6o6aIyapE
eehEXxMiTvrwWnRAXSTLWaOtFwBsFviqGb+zlEh0Ng6X8CzM/L9DoqhLIwiyM3WFy/Gk4m
dl0/kgRyVBFEbOt+H2SsOZTafSg2lKxgjMWPJDadC0vjJXjP0hVG6tqMuFacBC4CFOc+un
aMAv/yZ8U/pEWPFMLHw/RDCuS5fylacIUq5TuUymD7MTJ21udK0n1UnXuWc2QSA9bHAmbA
WeG4AlZX6nwy4TmB/c6/GXuwp9/hELoFIJ+mlfUttdwxNYRTTSHk6nNdDQ3gVHb6DTzP6a
Ld6/YwF2VxAh7wgU3vl+woIIIt8SFudUr9E8pXAAAAAwEAAQAAAQEAjKkcUoVQ2u66Otud
D9Oq95YJD6FR1ZzN7GgHXkA+8MtR/XLs4NMEfXFgZ0uMObuJlMkgE5Y8kq4G2bcMN2dDJ8
21PBEOXNCTCvCCF98z+M1JxCyw5GUzgAeVSDprnPXi9Eks1a2Gn3us3WlJf5CyK65zXUY8
vs54Uh8ZkLQnSjp3WMKi1IDAAagsf1QribP0qSdfWD+OoZ3AWXLRGN529vjyPIyxYSG68V
HpwsSKxah4J5J7o86586ZjWM/AKvLcxGgE+iJR/HGzrQd9fwies8IbN5O72ulClRORNTX2
bl4AR+ueys7TR8lJ3CuUKJP3bPjKvqT2o4GHVn2Gic/3oQAAAIEAwId3DITlSZ1MHEnzvS
NFROo1VqrwYl1x3hLb2IYCmSOXzlt5UQSs4a/qReoAoulLjooW5Na8q2EL078V1ISuem3h
E4C1aL81F1Px2UzdRBiflkuQC1FSxez3UH8XmIsSPeDO5qvPNPCHPN9BbbTj3utBseitIt
nXp1XxEAlAUkgAAACBANOCdgVD7PFQ4P3JyPXLar2ARcuWX2FfmsRaDRtTNTsSL2SE6Ico
MWsyu0XGxBYXbmAT91ogH/LXLTcerFISFgjOXPcTOTbZYoQzWFFXf6lr4277Rcz9S0NhbV
KEo0vdZ+jRuMXtTmnEPaU72JLL4Ht36RZH8bNhZRXF38m16Gn/AAAAgQDHTlfECu+IXDUc
EK50EOHAfdJWcQPG3kDhFuNFiYk3tytrK+tvx+ZUt/iN1VkmpKSnn4NIkypGnp8URYsxSK
k8ZYpURDgXaV5QSDav0Lub+SC8wlXEw5m/fPHgzClmk4xgGjIc3fgJYKT2f+UprcAlf3cM
IZOdthyU9ISB5NAvqQAAAA50ZXN0QGxvY2FsaG9zdAECAw==
-----END OPENSSH PRIVATE KEY-----"#;

        let key = PrivateKey::parse_pem(pem_content).unwrap();
        assert_eq!(key.key_type(), crate::auth::key::KeyType::Rsa);
    }

    #[test]
    fn test_ed25519_signature_creation() {
        let pem_content = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDye0bbrSGsotdwr4icJwRADJ/afJrfoBav6YdoYkpU0AAAAJgYjh9oGI4f
aAAAAAtzc2gtZWQyNTUxOQAAACDye0bbrSGsotdwr4icJwRADJ/afJrfoBav6YdoYkpU0A
AAAECoR1gOXudrcRYwcKRRRdHAdcivlSivKk76HhJMCUt3OfJ7RtutIayi13CviJwnBEAM
n9p8mt+gFq/ph2hiSlTQAAAADnRlc3RAbG9jYWxob3N0AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----"#;

        let private_key = PrivateKey::parse_pem(pem_content).unwrap();
        
        if let PrivateKey::Ed25519(key) = private_key {
            let data = b"test signature data";
            let signature = Ed25519SignatureEncoder::encode(&key, data).unwrap();
            
            assert_eq!(signature.algorithm, SSH_SIG_ALGORITHM_ED25519);
            assert!(!signature.data.is_empty());
            
            // Verify signature
            let public_key = key.verifying_key();
            let sig_bytes = signature.data[33..].to_vec(); // Skip algorithm string
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            public_key.verify(data, &sig).unwrap();
        } else {
            panic!("Expected Ed25519 key");
        }
    }

    #[test]
    fn test_rsa_signature_creation() {
        let pem_content = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEApKskAVxvB/bN/SeqOmiMmqRHnoRF8TIk768Fp0QF0ky1mjrRcAbB
b4qhm/s5RIdDYOl/AszPy/Q6KoSyMIsjN1hcvxpOJnZdP5IEclQRRGzrfh9krDmU2n0oNp
SsYIzFjyQ2nQtL4yV4z9IVRurajLhWnAQuAhTnPrp2jAL/8mfFP6RFjxTCx8P0QwrkuX8p
WnCFKuU7lMpg+zEydtbnStJ9VJ17lnNkEgPWxwJmwFnhuAJWV+p8MuE5gf3Ovxl7sKff4R
C6BSCfppX1LbXcMTWEU00h5OpzXQ0N4FR2+g08z+mi3ev2MBdlcQIe8IFN75fsKCCCLfEh
bnVK/RPKVwAAA8jAFbyDwBW8gwAAAAdzc2gtcnNhAAABAQCkqyQBXG8H9s39J6o6aIyapE
eehEXxMiTvrwWnRAXSTLWaOtFwBsFviqGb+zlEh0Ng6X8CzM/L9DoqhLIwiyM3WFy/Gk4m
dl0/kgRyVBFEbOt+H2SsOZTafSg2lKxgjMWPJDadC0vjJXjP0hVG6tqMuFacBC4CFOc+un
aMAv/yZ8U/pEWPFMLHw/RDCuS5fylacIUq5TuUymD7MTJ21udK0n1UnXuWc2QSA9bHAmbA
WeG4AlZX6nwy4TmB/c6/GXuwp9/hELoFIJ+mlfUttdwxNYRTTSHk6nNdDQ3gVHb6DTzP6a
Ld6/YwF2VxAh7wgU3vl+woIIIt8SFudUr9E8pXAAAAAwEAAQAAAQEAjKkcUoVQ2u66Otud
D9Oq95YJD6FR1ZzN7GgHXkA+8MtR/XLs4NMEfXFgZ0uMObuJlMkgE5Y8kq4G2bcMN2dDJ8
21PBEOXNCTCvCCF98z+M1JxCyw5GUzgAeVSDprnPXi9Eks1a2Gn3us3WlJf5CyK65zXUY8
vs54Uh8ZkLQnSjp3WMKi1IDAAagsf1QribP0qSdfWD+OoZ3AWXLRGN529vjyPIyxYSG68V
HpwsSKxah4J5J7o86586ZjWM/AKvLcxGgE+iJR/HGzrQd9fwies8IbN5O72ulClRORNTX2
bl4AR+ueys7TR8lJ3CuUKJP3bPjKvqT2o4GHVn2Gic/3oQAAAIEAwId3DITlSZ1MHEnzvS
NFROo1VqrwYl1x3hLb2IYCmSOXzlt5UQSs4a/qReoAoulLjooW5Na8q2EL078V1ISuem3h
E4C1aL81F1Px2UzdRBiflkuQC1FSxez3UH8XmIsSPeDO5qvPNPCHPN9BbbTj3utBseitIt
nXp1XxEAlAUkgAAACBANOCdgVD7PFQ4P3JyPXLar2ARcuWX2FfmsRaDRtTNTsSL2SE6Ico
MWsyu0XGxBYXbmAT91ogH/LXLTcerFISFgjOXPcTOTbZYoQzWFFXf6lr4277Rcz9S0NhbV
KEo0vdZ+jRuMXtTmnEPaU72JLL4Ht36RZH8bNhZRXF38m16Gn/AAAAgQDHTlfECu+IXDUc
EK50EOHAfdJWcQPG3kDhFuNFiYk3tytrK+tvx+ZUt/iN1VkmpKSnn4NIkypGnp8URYsxSK
k8ZYpURDgXaV5QSDav0Lub+SC8wlXEw5m/fPHgzClmk4xgGjIc3fgJYKT2f+UprcAlf3cM
IZOdthyU9ISB5NAvqQAAAA50ZXN0QGxvY2FsaG9zdAECAw==
-----END OPENSSH PRIVATE KEY-----"#;

        let private_key = PrivateKey::parse_pem(pem_content).unwrap();
        
        if let PrivateKey::Rsa(key) = private_key {
            let data = b"test signature data";
            let signature = RsaSignatureEncoder::encode(&key, data).unwrap();
            
            assert_eq!(signature.algorithm, SSH_SIG_ALGORITHM_RSA);
            assert!(!signature.data.is_empty());
            
            // Note: Full verification would require extracting public key from RSA key
            // For now, we just verify encoding works
        } else {
            panic!("Expected RSA key");
        }
    }

    #[test]
    fn test_signature_data_creation() {
        let session_id = vec![0x01; 20];
        let username = "testuser";
        let service = "ssh-connection";
        let method = "publickey";
        let has_signature = true;
        let public_key_algorithm = "ssh-ed25519";
        let public_key_blob = vec![0x02; 32];

        let sig_data = create_signature_data(
            &session_id,
            username,
            service,
            method,
            has_signature,
            public_key_algorithm,
            &public_key_blob,
        );

        assert_eq!(sig_data.len(), 60); // SHA-256 hash
    }

    #[test]
    fn test_public_key_hash() {
        let pem_content = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDye0bbrSGsotdwr4icJwRADJ/afJrfoBav6YdoYkpU0AAAAJgYjh9oGI4f
aAAAAAtzc2gtZWQyNTUxOQAAACDye0bbrSGsotdwr4icJwRADJ/afJrfoBav6YdoYkpU0A
AAAECoR1gOXudrcRYwcKRRRdHAdcivlSivKk76HhJMCUt3OfJ7RtutIayi13CviJwnBEAM
n9p8mt+gFq/ph2hiSlTQAAAADnRlc3RAbG9jYWxob3N0AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----"#;

        let private_key = PrivateKey::parse_pem(pem_content).unwrap();
        let hash = private_key.public_key_hash().unwrap();
        
        assert_eq!(hash.len(), 32); // SHA-256 hash
    }

    #[test]
    fn test_public_key_extraction() {
        let pem_content = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDye0bbrSGsotdwr4icJwRADJ/afJrfoBav6YdoYkpU0AAAAJgYjh9oGI4f
aAAAAAtzc2gtZWQyNTUxOQAAACDye0bbrSGsotdwr4icJwRADJ/afJrfoBav6YdoYkpU0A
AAAECoR1gOXudrcRYwcKRRRdHAdcivlSivKk76HhJMCUt3OfJ7RtutIayi13CviJwnBEAM
n9p8mt+gFq/ph2hiSlTQAAAADnRlc3RAbG9jYWxob3N0AQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----"#;

        let private_key = PrivateKey::parse_pem(pem_content).unwrap();
        let public_key = private_key.to_public_key().unwrap();
        
        assert_eq!(public_key.algorithm, "ssh-ed25519");
        assert!(!public_key.blob.is_empty());
    }

    #[test]
    fn test_ed25519_auth_message_format() {
        let session_id = vec![0x01; 20];
        let username = "testuser";
        let private_key = PrivateKey::Ed25519(Ed25519SigningKey::from_bytes(
            &[0u8; 32]
        ));
        
        let public_key = private_key.to_public_key().unwrap();
        let sig_data = create_signature_data(
            &session_id,
            username,
            "ssh-connection",
            "publickey",
            true,
            &public_key.algorithm,
            &public_key.blob,
        );
        
        let signature = Ed25519SignatureEncoder::encode(
            match private_key {
                PrivateKey::Ed25519(ref key) => key,
                _ => panic!("Expected Ed25519 key"),
            },
            &sig_data,
        ).unwrap();
        
        // Build SSH_MSG_USERAUTH_REQUEST message
        let mut msg = Message::new();
        msg.write_byte(MessageType::UserauthRequest.value());
        msg.write_string(username.as_bytes());
        msg.write_string(b"ssh-connection");
        msg.write_string(b"publickey");
        msg.write_bool(true); // has signature
        msg.write_string(public_key.algorithm.as_bytes());
        msg.write_bytes(&public_key.blob);
        msg.write_bytes(&signature.encode());
        
        // Verify message can be parsed back
        let msg_bytes = msg.as_bytes();
        let parsed = Message::from(msg_bytes.to_vec());
        assert_eq!(parsed.msg_type(), Some(MessageType::UserauthRequest));
    }

    #[test]
    fn test_rsa_auth_message_format() {
        let session_id = vec![0x01; 20];
        let username = "testuser";
        
        let pem_content = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEApKskAVxvB/bN/SeqOmiMmqRHnoRF8TIk768Fp0QF0ky1mjrRcAbB
b4qhm/s5RIdDYOl/AszPy/Q6KoSyMIsjN1hcvxpOJnZdP5IEclQRRGzrfh9krDmU2n0oNp
SsYIzFjyQ2nQtL4yV4z9IVRurajLhWnAQuAhTnPrp2jAL/8mfFP6RFjxTCx8P0QwrkuX8p
WnCFKuU7lMpg+zEydtbnStJ9VJ17lnNkEgPWxwJmwFnhuAJWV+p8MuE5gf3Ovxl7sKff4R
C6BSCfppX1LbXcMTWEU00h5OpzXQ0N4FR2+g08z+mi3ev2MBdlcQIe8IFN75fsKCCCLfEh
bnVK/RPKVwAAA8jAFbyDwBW8gwAAAAdzc2gtcnNhAAABAQCkqyQBXG8H9s39J6o6aIyapE
eehEXxMiTvrwWnRAXSTLWaOtFwBsFviqGb+zlEh0Ng6X8CzM/L9DoqhLIwiyM3WFy/Gk4m
dl0/kgRyVBFEbOt+H2SsOZTafSg2lKxgjMWPJDadC0vjJXjP0hVG6tqMuFacBC4CFOc+un
aMAv/yZ8U/pEWPFMLHw/RDCuS5fylacIUq5TuUymD7MTJ21udK0n1UnXuWc2QSA9bHAmbA
WeG4AlZX6nwy4TmB/c6/GXuwp9/hELoFIJ+mlfUttdwxNYRTTSHk6nNdDQ3gVHb6DTzP6a
Ld6/YwF2VxAh7wgU3vl+woIIIt8SFudUr9E8pXAAAAAwEAAQAAAQEAjKkcUoVQ2u66Otud
D9Oq95YJD6FR1ZzN7GgHXkA+8MtR/XLs4NMEfXFgZ0uMObuJlMkgE5Y8kq4G2bcMN2dDJ8
21PBEOXNCTCvCCF98z+M1JxCyw5GUzgAeVSDprnPXi9Eks1a2Gn3us3WlJf5CyK65zXUY8
vs54Uh8ZkLQnSjp3WMKi1IDAAagsf1QribP0qSdfWD+OoZ3AWXLRGN529vjyPIyxYSG68V
HpwsSKxah4J5J7o86586ZjWM/AKvLcxGgE+iJR/HGzrQd9fwies8IbN5O72ulClRORNTX2
bl4AR+ueys7TR8lJ3CuUKJP3bPjKvqT2o4GHVn2Gic/3oQAAAIEAwId3DITlSZ1MHEnzvS
NFROo1VqrwYl1x3hLb2IYCmSOXzlt5UQSs4a/qReoAoulLjooW5Na8q2EL078V1ISuem3h
E4C1aL81F1Px2UzdRBiflkuQC1FSxez3UH8XmIsSPeDO5qvPNPCHPN9BbbTj3utBseitIt
nXp1XxEAlAUkgAAACBANOCdgVD7PFQ4P3JyPXLar2ARcuWX2FfmsRaDRtTNTsSL2SE6Ico
MWsyu0XGxBYXbmAT91ogH/LXLTcerFISFgjOXPcTOTbZYoQzWFFXf6lr4277Rcz9S0NhbV
KEo0vdZ+jRuMXtTmnEPaU72JLL4Ht36RZH8bNhZRXF38m16Gn/AAAAgQDHTlfECu+IXDUc
EK50EOHAfdJWcQPG3kDhFuNFiYk3tytrK+tvx+ZUt/iN1VkmpKSnn4NIkypGnp8URYsxSK
k8ZYpURDgXaV5QSDav0Lub+SC8wlXEw5m/fPHgzClmk4xgGjIc3fgJYKT2f+UprcAlf3cM
IZOdthyU9ISB5NAvqQAAAA50ZXN0QGxvY2FsaG9zdAECAw==
-----END OPENSSH PRIVATE KEY-----"#;

        let private_key = PrivateKey::parse_pem(pem_content).unwrap();
        
        if let PrivateKey::Rsa(key) = private_key {
            let public_key = key.to_public_key().unwrap();
            let sig_data = create_signature_data(
                &session_id,
                username,
                "ssh-connection",
                "publickey",
                true,
                &public_key.algorithm,
                &public_key.blob,
            );
            
            let signature = RsaSignatureEncoder::encode(&key, &sig_data).unwrap();
            
            // Build SSH_MSG_USERAUTH_REQUEST message
            let mut msg = Message::new();
            msg.write_byte(MessageType::UserauthRequest.value());
            msg.write_string(username.as_bytes());
            msg.write_string(b"ssh-connection");
            msg.write_string(b"publickey");
            msg.write_bool(true); // has signature
            msg.write_string(public_key.algorithm.as_bytes());
            msg.write_bytes(&public_key.blob);
            msg.write_bytes(&signature.encode());
            
            // Verify message can be parsed back
            let msg_bytes = msg.as_bytes();
            let parsed = Message::from(msg_bytes.to_vec());
            assert_eq!(parsed.msg_type(), Some(MessageType::UserauthRequest));
        } else {
            panic!("Expected RSA key");
        }
    }
}