//! SSH Agent Protocol Stub
//!
//! Implements basic SSH agent protocol message types for communicating
//! with an ssh-agent process via the `SSH_AUTH_SOCK` Unix domain socket.
//!
//! Currently implemented:
//! - `SSH_AGENTC_REQUEST_IDENTITIES` (11) — list keys held by the agent
//! - `SSH_AGENTC_SIGN_REQUEST` (13) — request the agent to sign data
//!
//! TODO:
//! - Wire this into `Authenticator` for agent-based public key auth
//! - Handle agent forwarding over SSH channels
//! - Support key constraints (lifetime, confirm)

use crate::error::SshError;
use bytes::{BufMut, BytesMut};
use std::path::PathBuf;

// Agent protocol message types (from draft-miller-ssh-agent)
/// Client request: list identities held by the agent
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// Agent response: list of identities
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// Client request: sign data with a specific key
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// Agent response: signature
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
/// Agent response: failure
pub const SSH_AGENT_FAILURE: u8 = 5;

/// An identity (public key + comment) reported by the agent.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    /// Public key blob in SSH wire format
    pub key_blob: Vec<u8>,
    /// Comment string (typically the key file path)
    pub comment: String,
}

/// A signature returned by the agent.
#[derive(Debug, Clone)]
pub struct AgentSignature {
    /// Signature blob in SSH wire format (string(algorithm) || string(sig))
    pub signature_blob: Vec<u8>,
}

/// SSH agent client stub.
///
/// Connects to the agent via the `SSH_AUTH_SOCK` environment variable.
/// All methods are currently synchronous stubs that construct/parse
/// protocol messages but do not yet perform I/O.
#[derive(Debug)]
pub struct AgentClient {
    /// Path to the agent socket
    socket_path: PathBuf,
}

impl AgentClient {
    /// Create a new agent client from the `SSH_AUTH_SOCK` environment variable.
    ///
    /// Returns `Err` if the variable is not set.
    pub fn from_env() -> Result<Self, SshError> {
        let path = std::env::var("SSH_AUTH_SOCK")
            .map_err(|_| SshError::AuthenticationFailed(
                "SSH_AUTH_SOCK environment variable not set".to_string(),
            ))?;
        Ok(Self {
            socket_path: PathBuf::from(path),
        })
    }

    /// Create a new agent client with an explicit socket path.
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Get the agent socket path.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Build an `SSH_AGENTC_REQUEST_IDENTITIES` message.
    ///
    /// Wire format: `uint32(1) || byte(11)`
    pub fn build_request_identities() -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(5);
        buf.put_u32(1); // message length
        buf.put_u8(SSH_AGENTC_REQUEST_IDENTITIES);
        buf.to_vec()
    }

    /// Parse an `SSH_AGENT_IDENTITIES_ANSWER` response.
    ///
    /// Wire format: `byte(12) || uint32(nkeys) || (string(key_blob) || string(comment))*`
    ///
    /// The input should be the message payload (after the 4-byte length prefix).
    pub fn parse_identities_answer(data: &[u8]) -> Result<Vec<AgentIdentity>, SshError> {
        if data.is_empty() {
            return Err(SshError::ProtocolError("Empty agent response".to_string()));
        }
        if data[0] == SSH_AGENT_FAILURE {
            return Err(SshError::AuthenticationFailed("Agent returned failure".to_string()));
        }
        if data[0] != SSH_AGENT_IDENTITIES_ANSWER {
            return Err(SshError::ProtocolError(format!(
                "Expected IDENTITIES_ANSWER (12), got {}", data[0]
            )));
        }
        if data.len() < 5 {
            return Err(SshError::ProtocolError("Truncated identities answer".to_string()));
        }

        let nkeys = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        let mut identities = Vec::with_capacity(nkeys);
        let mut offset = 5;

        for _ in 0..nkeys {
            // key blob
            if offset + 4 > data.len() {
                return Err(SshError::ProtocolError("Truncated key blob length".to_string()));
            }
            let blob_len = u32::from_be_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            ]) as usize;
            offset += 4;
            if offset + blob_len > data.len() {
                return Err(SshError::ProtocolError("Truncated key blob".to_string()));
            }
            let key_blob = data[offset..offset + blob_len].to_vec();
            offset += blob_len;

            // comment
            if offset + 4 > data.len() {
                return Err(SshError::ProtocolError("Truncated comment length".to_string()));
            }
            let comment_len = u32::from_be_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            ]) as usize;
            offset += 4;
            if offset + comment_len > data.len() {
                return Err(SshError::ProtocolError("Truncated comment".to_string()));
            }
            let comment = String::from_utf8_lossy(&data[offset..offset + comment_len]).to_string();
            offset += comment_len;

            identities.push(AgentIdentity { key_blob, comment });
        }

        Ok(identities)
    }

    /// Build an `SSH_AGENTC_SIGN_REQUEST` message.
    ///
    /// Wire format: `uint32(len) || byte(13) || string(key_blob) || string(data) || uint32(flags)`
    pub fn build_sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let msg_len = 1 + 4 + key_blob.len() + 4 + data.len() + 4;
        let mut buf = BytesMut::with_capacity(4 + msg_len);
        buf.put_u32(msg_len as u32);
        buf.put_u8(SSH_AGENTC_SIGN_REQUEST);
        buf.put_u32(key_blob.len() as u32);
        buf.put_slice(key_blob);
        buf.put_u32(data.len() as u32);
        buf.put_slice(data);
        buf.put_u32(flags);
        buf.to_vec()
    }

    /// Parse an `SSH_AGENT_SIGN_RESPONSE`.
    ///
    /// Wire format: `byte(14) || string(signature_blob)`
    ///
    /// The input should be the message payload (after the 4-byte length prefix).
    pub fn parse_sign_response(data: &[u8]) -> Result<AgentSignature, SshError> {
        if data.is_empty() {
            return Err(SshError::ProtocolError("Empty agent sign response".to_string()));
        }
        if data[0] == SSH_AGENT_FAILURE {
            return Err(SshError::AuthenticationFailed("Agent refused to sign".to_string()));
        }
        if data[0] != SSH_AGENT_SIGN_RESPONSE {
            return Err(SshError::ProtocolError(format!(
                "Expected SIGN_RESPONSE (14), got {}", data[0]
            )));
        }
        if data.len() < 5 {
            return Err(SshError::ProtocolError("Truncated sign response".to_string()));
        }

        let sig_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if data.len() < 5 + sig_len {
            return Err(SshError::ProtocolError("Truncated signature blob".to_string()));
        }

        Ok(AgentSignature {
            signature_blob: data[5..5 + sig_len].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_request_identities() {
        let msg = AgentClient::build_request_identities();
        assert_eq!(msg.len(), 5);
        assert_eq!(msg[0..4], [0, 0, 0, 1]); // length = 1
        assert_eq!(msg[4], SSH_AGENTC_REQUEST_IDENTITIES);
    }

    #[test]
    fn test_parse_identities_answer_empty_list() {
        // msg_type(12) || nkeys(0)
        let data = vec![12, 0, 0, 0, 0];
        let identities = AgentClient::parse_identities_answer(&data).unwrap();
        assert!(identities.is_empty());
    }

    #[test]
    fn test_parse_identities_answer_one_key() {
        let key_blob = b"fake-key-blob";
        let comment = b"test@host";
        let mut data = vec![12]; // msg type
        data.extend_from_slice(&1u32.to_be_bytes()); // nkeys = 1
        data.extend_from_slice(&(key_blob.len() as u32).to_be_bytes());
        data.extend_from_slice(key_blob);
        data.extend_from_slice(&(comment.len() as u32).to_be_bytes());
        data.extend_from_slice(comment);

        let identities = AgentClient::parse_identities_answer(&data).unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].key_blob, key_blob.to_vec());
        assert_eq!(identities[0].comment, "test@host");
    }

    #[test]
    fn test_parse_identities_answer_failure() {
        let data = vec![SSH_AGENT_FAILURE];
        let result = AgentClient::parse_identities_answer(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_sign_request() {
        let key_blob = b"key";
        let data = b"data-to-sign";
        let msg = AgentClient::build_sign_request(key_blob, data, 0);
        // length prefix + msg_type + string(key) + string(data) + flags
        let msg_len = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
        assert_eq!(msg.len(), 4 + msg_len);
        assert_eq!(msg[4], SSH_AGENTC_SIGN_REQUEST);
    }

    #[test]
    fn test_parse_sign_response() {
        let sig = b"fake-signature";
        let mut data = vec![SSH_AGENT_SIGN_RESPONSE];
        data.extend_from_slice(&(sig.len() as u32).to_be_bytes());
        data.extend_from_slice(sig);

        let result = AgentClient::parse_sign_response(&data).unwrap();
        assert_eq!(result.signature_blob, sig.to_vec());
    }

    #[test]
    fn test_parse_sign_response_failure() {
        let data = vec![SSH_AGENT_FAILURE];
        let result = AgentClient::parse_sign_response(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_agent_client_from_env_missing() {
        // Ensure SSH_AUTH_SOCK is not set for this test
        std::env::remove_var("SSH_AUTH_SOCK");
        let result = AgentClient::from_env();
        assert!(result.is_err());
    }

    #[test]
    fn test_agent_client_new() {
        let client = AgentClient::new(PathBuf::from("/tmp/test.sock"));
        assert_eq!(client.socket_path(), std::path::Path::new("/tmp/test.sock"));
    }
}
