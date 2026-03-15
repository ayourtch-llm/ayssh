//! Basic integration test skeleton.

/// Example integration test using TestServer
#[cfg(test)]
mod tests {
    use super::super::helpers::TestServer;

    #[test]
    fn test_server_basic() {
        let server = TestServer::new().expect("Failed to create test server");
        assert!(server.port() > 0);
        assert!(server.private_key_path().exists());
    }
}