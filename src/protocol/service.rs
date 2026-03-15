//! SSH Service Request Handler
//!
//! Implements the service request/accept handshake for establishing
//! the ssh-connection protocol after authentication.

use crate::protocol::{MessageType, SshString};
use bytes::{BufMut, BytesMut};

/// Service request message
#[derive(Debug, Clone)]
pub struct ServiceRequest {
    /// Service name (e.g., "ssh-connection")
    pub service: String,
}

/// Service accept message
#[derive(Debug, Clone)]
pub struct ServiceAccept {
    /// Accepted service name
    pub service: String,
}

impl ServiceRequest {
    /// Encode service request message
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(64);
        
        // Message type
        buf.put_u8(MessageType::ServiceRequest.value());
        
        // Service name
        buf.put_u32(self.service.len() as u32);
        buf.put_slice(self.service.as_bytes());
        
        buf.to_vec()
    }

    /// Decode service request message
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 5 {
            return Err("Data too short for service request".to_string());
        }

        let msg_type = data[0];
        if msg_type != MessageType::ServiceRequest.value() {
            return Err(format!("Invalid message type: expected {}, got {}", 
                MessageType::ServiceRequest.value(), msg_type));
        }

        let mut cursor = &data[1..];
        let service_len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        
        if cursor.len() < service_len {
            return Err("Data too short for service name".to_string());
        }

        let service = String::from_utf8(cursor[..service_len].to_vec())
            .map_err(|_| "Invalid UTF-8 in service name".to_string())?;

        Ok(ServiceRequest { service })
    }
}

impl ServiceAccept {
    /// Encode service accept message
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(64);
        
        // Message type
        buf.put_u8(MessageType::ServiceAccept.value());
        
        // Service name
        buf.put_u32(self.service.len() as u32);
        buf.put_slice(self.service.as_bytes());
        
        buf.to_vec()
    }

    /// Decode service accept message
    pub fn decode(data: &[u8]) -> Result<Self, String> {
        if data.len() < 5 {
            return Err("Data too short for service accept".to_string());
        }

        let msg_type = data[0];
        if msg_type != MessageType::ServiceAccept.value() {
            return Err(format!("Invalid message type: expected {}, got {}", 
                MessageType::ServiceAccept.value(), msg_type));
        }

        let mut cursor = &data[1..];
        let service_len = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]) as usize;
        cursor = &cursor[4..];
        
        if cursor.len() < service_len {
            return Err("Data too short for service name".to_string());
        }

        let service = String::from_utf8(cursor[..service_len].to_vec())
            .map_err(|_| "Invalid UTF-8 in service name".to_string())?;

        Ok(ServiceAccept { service })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_request_encode_decode() {
        let request = ServiceRequest {
            service: "ssh-connection".to_string(),
        };

        let encoded = request.encode();
        let decoded = ServiceRequest::decode(&encoded).unwrap();

        assert_eq!(decoded.service, "ssh-connection");
    }

    #[test]
    fn test_service_accept_encode_decode() {
        let accept = ServiceAccept {
            service: "ssh-connection".to_string(),
        };

        let encoded = accept.encode();
        let decoded = ServiceAccept::decode(&encoded).unwrap();

        assert_eq!(decoded.service, "ssh-connection");
    }

    #[test]
    fn test_service_request_invalid_message_type() {
        let data = vec![0xFF, 0x00, 0x00, 0x00, 0x0D, b's', b's', b'h', b'-', 
                       b'c', b'o', b'n', b'n', b'e', b'c', b't', b'i', b'o', b'n'];
        
        let result = ServiceRequest::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_service_accept_invalid_message_type() {
        let data = vec![0xFF, 0x00, 0x00, 0x00, 0x0D, b's', b's', b'h', b'-', 
                       b'c', b'o', b'n', b'n', b'e', b'c', b't', b'i', b'o', b'n'];
        
        let result = ServiceAccept::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_service_request_short_data() {
        let data = vec![0x05, 0x00, 0x00, 0x00]; // Missing service name
        
        let result = ServiceRequest::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_service_accept_short_data() {
        let data = vec![0x06, 0x00, 0x00, 0x00]; // Missing service name
        
        let result = ServiceAccept::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_service_request_empty_service() {
        let request = ServiceRequest {
            service: "".to_string(),
        };

        let encoded = request.encode();
        let decoded = ServiceRequest::decode(&encoded).unwrap();

        assert_eq!(decoded.service, "");
    }

    #[test]
    fn test_service_request_special_characters() {
        let request = ServiceRequest {
            service: "ssh-connection@openssh.com".to_string(),
        };

        let encoded = request.encode();
        let decoded = ServiceRequest::decode(&encoded).unwrap();

        assert_eq!(decoded.service, "ssh-connection@openssh.com");
    }
}