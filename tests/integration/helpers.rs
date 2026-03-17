//! Test server utilities for integration tests.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

/// Supported key types for test server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ed25519,
    Rsa { bits: u32 },
    Ecdsa { curve: EcdsaCurve },
}

/// ECDSA curves supported
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaCurve {
    P256,
    P384,
    P521,
}

impl KeyType {
    /// Get the default key type (Ed25519)
    #[allow(dead_code)]
    pub fn default() -> Self {
        KeyType::Ed25519
    }

    /// Get the ssh-keygen algorithm name
    pub fn algorithm(&self) -> &'static str {
        match self {
            KeyType::Ed25519 => "ed25519",
            KeyType::Rsa { .. } => "rsa",
            KeyType::Ecdsa { curve } => match curve {
                EcdsaCurve::P256 => "ecdsa-sha2-nistp256",
                EcdsaCurve::P384 => "ecdsa-sha2-nistp384",
                EcdsaCurve::P521 => "ecdsa-sha2-nistp521",
            },
        }
    }

    /// Get the key size/bits for display
    #[allow(dead_code)]
    pub fn size(&self) -> String {
        match self {
            KeyType::Ed25519 => "ed25519".to_string(),
            KeyType::Rsa { bits } => format!("rsa-{}-bits", bits),
            KeyType::Ecdsa { curve } => match curve {
                EcdsaCurve::P256 => "ecdsa-nistp256".to_string(),
                EcdsaCurve::P384 => "ecdsa-nistp384".to_string(),
                EcdsaCurve::P521 => "ecdsa-nistp521".to_string(),
            },
        }
    }
}

/// TestServer provides a real SSH server for integration testing.
///
/// This struct:
/// - Generates test SSH keys (ed25519, RSA, ECDSA)
/// - Sets up authorized_keys
/// - Starts sshd in debug mode on an available port
/// - Captures host key fingerprint
/// - Provides cleanup and debug output
///
/// # Example
/// ```rust
/// let server = TestServerBuilder::new()
///     .with_keys(vec![KeyType::Ed25519, KeyType::Rsa { bits: 2048 }])
///     .with_debug(true)
///     .build()
///     .unwrap();
///
/// // Use server.port(), server.private_key_paths(), etc.
/// ```
#[allow(dead_code)]
pub struct TestServer {
    /// Temporary directory for test files
    temp_dir: TempDir,
    /// Paths to generated private keys (one per key type)
    private_key_paths: Vec<PathBuf>,
    /// Path to the authorized_keys file
    authorized_keys_path: PathBuf,
    /// Path to the temporary known_hosts file
    known_hosts_path: PathBuf,
    /// The sshd process (if running)
    sshd: Option<Child>,
    /// Port the server is listening on
    pub port: u16,
    /// Server host key fingerprint (SHA256)
    pub host_key_fingerprint: String,
    /// Whether debug output is enabled
    debug_enabled: bool,
    /// Captured debug output
    debug_output: String,
}

/// Builder for TestServer
pub struct TestServerBuilder {
    key_types: Vec<KeyType>,
    enable_debug: bool,
}

impl Default for TestServerBuilder {
    fn default() -> Self {
        Self {
            key_types: vec![KeyType::Ed25519],
            enable_debug: false,
        }
    }
}

impl TestServerBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the key types to generate
    pub fn with_keys(mut self, key_types: Vec<KeyType>) -> Self {
        self.key_types = key_types;
        self
    }

    /// Enable debug output capture
    pub fn with_debug(mut self, enabled: bool) -> Self {
        self.enable_debug = enabled;
        self
    }

    /// Build the test server
    pub fn build(self) -> Result<TestServer, Box<dyn std::error::Error>> {
        TestServer::new_with_keys(&self.key_types, self.enable_debug)
    }
}

impl TestServer {
    /// Creates a new TestServer with default Ed25519 key.
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_keys(&[KeyType::Ed25519], false)
    }

    /// Creates a new TestServer with specified key types.
    pub fn new_with_keys(
        key_types: &[KeyType],
        debug_enabled: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let authorized_keys_path = temp_dir.path().join("authorized_keys");
        let known_hosts_path = temp_dir.path().join("known_hosts");

        // Generate keys
        let mut private_key_paths = Vec::new();
        let mut public_keys = Vec::new();

        for key_type in key_types {
            let key_path = temp_dir.path().join(format!("test_{}", key_type.algorithm()));
            Self::generate_key(key_path.as_path(), key_type)?;
            private_key_paths.push(key_path);

            // Read public key
            let pub_path = temp_dir.path().join(format!("test_{}.pub", key_type.algorithm()));
            let public_key = fs::read_to_string(&pub_path)?;
            public_keys.push(public_key);
        }

        // Set up authorized_keys with all public keys
        let auth_content = public_keys.join("\n");
        fs::write(&authorized_keys_path, &auth_content)?;

        // Make authorized_keys readable only by owner (ssh requirement)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&authorized_keys_path, std::fs::Permissions::from_mode(0o600))?;
        }

        // Find an available port
        let port = Self::find_available_port()?;

        // Start sshd in debug mode
        let (sshd, host_key_fingerprint) = Self::start_sshd(&temp_dir, port, debug_enabled)?;

        Ok(Self {
            temp_dir,
            private_key_paths,
            authorized_keys_path,
            known_hosts_path,
            sshd: Some(sshd),
            port,
            host_key_fingerprint,
            debug_enabled,
            debug_output: String::new(),
        })
    }

    /// Generates an SSH key pair.
    fn generate_key(path: &Path, key_type: &KeyType) -> Result<(), Box<dyn std::error::Error>> {
        let mut cmd = Command::new("ssh-keygen");
        cmd.args(["-t", key_type.algorithm(), "-N", "", "-f"])
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let KeyType::Rsa { bits } = key_type {
            cmd.arg("-b").arg(bits.to_string());
        }

        let output = cmd.output()?;

        if !output.status.success() {
            return Err(format!("Failed to generate SSH key: {}", String::from_utf8_lossy(&output.stderr)).into());
        }

        Ok(())
    }

    /// Finds an available port on localhost.
    fn find_available_port() -> Result<u16, Box<dyn std::error::Error>> {
        // Try a range of ports starting from a random high port
        let start_port = 20000 + rand::random::<u16>() % 10000;
        
        for port in start_port..start_port + 1000 {
            if let Ok(_listener) = std::net::TcpListener::bind(format!("127.0.0.1:{}", port)) {
                return Ok(port);
            }
        }

        Err("No available ports found".into())
    }

    /// Starts the sshd process and captures host key fingerprint.
    fn start_sshd(
        temp_dir: &TempDir,
        port: u16,
        debug_enabled: bool,
    ) -> Result<(Child, String), Box<dyn std::error::Error>> {
        let authorized_keys_path = temp_dir.path().join("authorized_keys");
        
        // Generate ephemeral host key
        let host_key_path = temp_dir.path().join("host_key");
        Self::generate_key(&host_key_path, &KeyType::Ed25519)?;

        // Create sshd config
        let sshd_config = temp_dir.path().join("sshd_config");
        let config_content = format!(
            r#"Port {}
PasswordAuthentication no
PermitRootLogin yes
AuthorizedKeysFile {}
HostKey {}
Subsystem sftp /usr/libexec/sftp-server
"#,
            port,
            authorized_keys_path.display(),
            host_key_path.display()
        );

        fs::write(&sshd_config, &config_content)?;

        // Start sshd
        let mut cmd = Command::new("sshd");
        cmd.args([
            "-f",
            &sshd_config.to_string_lossy(),
            "-d",
            "-e",
        ]);

        if debug_enabled {
            cmd.arg("-d"); // Extra debug level
        }

        let child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Poll until port is listening
        Self::wait_for_port(port)?;

        // Capture host key fingerprint
        let fingerprint = Self::get_host_key_fingerprint(&host_key_path)?;

        // Give sshd a moment to fully initialize
        std::thread::sleep(Duration::from_millis(200));

        Ok((child, fingerprint))
    }

    /// Waits for a port to be listening.
    fn wait_for_port(port: u16) -> Result<(), Box<dyn std::error::Error>> {
        const MAX_RETRIES: usize = 50;
        for i in 0..MAX_RETRIES {
            if std::net::TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok() {
                return Ok(());
            }
            if i < MAX_RETRIES - 1 {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        Err(format!("Port {} not listening after retries", port).into())
    }

    /// Gets the host key fingerprint.
    fn get_host_key_fingerprint(host_key_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new("ssh-keygen")
            .args(["-lf", &host_key_path.to_string_lossy()])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()?;

        if output.status.success() {
            let output = String::from_utf8_lossy(&output.stdout);
            // Format: "256 SHA256:xxx... ed25519 key comment (timestamp)"
            let parts: Vec<&str> = output.split_whitespace().collect();
            if parts.len() >= 2 {
                Ok(parts[1].to_string())
            } else {
                Err("Invalid fingerprint format".into())
            }
        } else {
            Err("Failed to get host key fingerprint".into())
        }
    }

    /// Creates a temporary known_hosts file with the server's host key.
    #[allow(dead_code)]
    pub fn create_known_hosts(&self) -> Result<(), Box<dyn std::error::Error>> {
        let host_key_path = self.temp_dir.path().join("host_key");
        let output = Command::new("ssh-keygen")
            .args(["-f", self.known_hosts_path.to_str().unwrap(), "-q", "-h", host_key_path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()?;

        if !output.status.success() {
            return Err("Failed to create known_hosts".into());
        }

        Ok(())
    }

    /// Returns the port the test server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the paths to the private keys.
    pub fn private_key_paths(&self) -> &[PathBuf] {
        &self.private_key_paths
    }

    /// Returns the path to the authorized_keys file.
    pub fn authorized_keys_path(&self) -> &PathBuf {
        &self.authorized_keys_path
    }

    /// Returns the path to the known_hosts file.
    #[allow(dead_code)]
    pub fn known_hosts_path(&self) -> &PathBuf {
        &self.known_hosts_path
    }

    /// Returns the server host key fingerprint.
    pub fn host_key_fingerprint(&self) -> &str {
        &self.host_key_fingerprint
    }

    /// Returns whether debug output is enabled.
    pub fn debug_enabled(&self) -> bool {
        self.debug_enabled
    }

    /// Returns the captured debug output.
    #[allow(dead_code)]
    pub fn debug_output(&self) -> &str {
        &self.debug_output
    }

    /// Stops the sshd process and captures debug output.
    pub fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref mut child) = self.sshd.take() {
            // Capture debug output before killing
            if let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) {
                let stdout_reader = BufReader::new(stdout);
                let stderr_reader = BufReader::new(stderr);
                
                self.debug_output = stdout_reader.lines()
                    .chain(stderr_reader.lines())
                    .filter_map(|line| line.ok())
                    .collect::<Vec<_>>()
                    .join("\n");
            }

            child.kill()?;
            child.wait()?;
        }
        Ok(())
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Stop the sshd process
        let _ = self.stop();
        
        // TempDir will clean up the rest automatically
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let server = TestServer::new().expect("Failed to create test server");
        assert!(server.port() > 0);
        assert!(!server.private_key_paths().is_empty());
        assert!(server.authorized_keys_path().exists());
        assert!(!server.host_key_fingerprint().is_empty());
    }

    #[test]
    fn test_server_multi_key() {
        let keys = vec![
            KeyType::Ed25519,
            KeyType::Rsa { bits: 2048 },
            KeyType::Ecdsa { curve: EcdsaCurve::P256 },
        ];
        
        let server = TestServer::new_with_keys(&keys, false)
            .expect("Failed to create multi-key test server");
        
        assert_eq!(server.private_key_paths().len(), 3);
    }

    #[test]
    fn test_server_builder() {
        let server = TestServerBuilder::new()
            .with_keys(vec![KeyType::Ed25519, KeyType::Rsa { bits: 2048 }])
            .with_debug(true)
            .build()
            .expect("Failed to build test server");
        
        assert_eq!(server.private_key_paths().len(), 2);
        assert!(server.debug_enabled());
    }

    #[test]
    fn test_server_cleanup() {
        let server = TestServer::new().expect("Failed to create test server");
        let port = server.port();

        drop(server);
        
        // After drop, the port should no longer be in use (sshd stopped)
        // Give it a moment to release
        std::thread::sleep(std::time::Duration::from_millis(200));
        
        // Port should be available again
        assert!(std::net::TcpListener::bind(format!("127.0.0.1:{}", port)).is_ok());
    }

    #[tokio::test]
    async fn test_server_async() {
        let server = TestServer::new().expect("Failed to create test server");
        assert!(server.port() > 0);
        
        // Simulate async work
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        assert!(server.port() > 0);
    }
}