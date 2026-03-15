//! Test server utilities for integration tests.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use tempfile::TempDir;

/// TestServer provides a mock SSH server for integration testing.
///
/// This struct:
/// - Generates a test SSH key (ed25519)
/// - Sets up authorized_keys
/// - Starts sshd in debug mode
/// - Provides port and auth key path
/// - Cleans up on drop
pub struct TestServer {
    /// Temporary directory for test files
    temp_dir: TempDir,
    /// Path to the generated private key
    private_key_path: PathBuf,
    /// Path to the authorized_keys file
    authorized_keys_path: PathBuf,
    /// The sshd process (if running)
    sshd: Option<Child>,
    /// Port the server is listening on
    port: u16,
}

impl TestServer {
    /// Creates a new TestServer instance.
    ///
    /// This will:
    /// 1. Create a temporary directory
    /// 2. Generate an ed25519 test key pair
    /// 3. Set up the authorized_keys file
    /// 4. Start sshd in debug mode on an available port
    ///
    /// # Returns
    /// * `Result<TestServer>` - The configured test server
    ///
    /// # Errors
    /// Returns an error if any step fails (key generation, file creation, or sshd startup)
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let private_key_path = temp_dir.path().join("test_key");
        let authorized_keys_path = temp_dir.path().join("authorized_keys");

        // Generate ed25519 test key
        Self::generate_ed25519_key(&private_key_path)?;

        // Set up authorized_keys
        let public_key_path = temp_dir.path().join("test_key.pub");
        let public_key = fs::read_to_string(&public_key_path)?;
        fs::write(&authorized_keys_path, public_key)?;

        // Make authorized_keys readable only by owner (ssh requirement)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::metadata(&authorized_keys_path)?.permissions();
            fs::set_permissions(&authorized_keys_path, std::fs::Permissions::from_mode(0o600))?;
        }

        // Find an available port
        let port = Self::find_available_port()?;

        // Start sshd in debug mode
        let sshd = Self::start_sshd(&temp_dir, port)?;

        Ok(Self {
            temp_dir,
            private_key_path,
            authorized_keys_path,
            sshd: Some(sshd),
            port,
        })
    }

    /// Generates an ed25519 SSH key pair.
    fn generate_ed25519_key(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        // Use ssh-keygen to generate the key
        let output = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-f"])
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()?;

        if !output.status.success() {
            return Err("Failed to generate SSH key".into());
        }

        Ok(())
    }

    /// Finds an available port on localhost.
    fn find_available_port() -> Result<u16, Box<dyn std::error::Error>> {
        // Try a range of ports starting from a random high port
        let start_port = 20000 + rand::random::<u16>() % 10000;
        
        for port in start_port..start_port + 1000 {
            if let Ok(listener) = std::net::TcpListener::bind(format!("127.0.0.1:{}", port)) {
                // Port is available, close the listener and return the port
                drop(listener);
                return Ok(port);
            }
        }

        Err("No available ports found".into())
    }

    /// Starts the sshd process.
    fn start_sshd(temp_dir: &TempDir, port: u16) -> Result<Child, Box<dyn std::error::Error>> {
        let authorized_keys_path = temp_dir.path().join("authorized_keys");
        let host_key_path = temp_dir.path().join("test_key");

        // Create a minimal sshd config
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

        fs::write(&sshd_config, config_content)?;

        // Start sshd in debug mode with single debug level
        let child = Command::new("sshd")
            .args([
                "-f",
                &sshd_config.to_string_lossy(),
                "-d",
                "-e",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Give sshd a moment to start
        std::thread::sleep(std::time::Duration::from_millis(500));

        Ok(child)
    }

    /// Returns the port the test server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the path to the private key.
    pub fn private_key_path(&self) -> &PathBuf {
        &self.private_key_path
    }

    /// Returns the path to the authorized_keys file.
    pub fn authorized_keys_path(&self) -> &PathBuf {
        &self.authorized_keys_path
    }

    /// Returns the path to the temporary directory.
    pub fn temp_dir(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Stops the sshd process.
    pub fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref mut child) = self.sshd.take() {
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
        assert!(server.private_key_path().exists());
        assert!(server.authorized_keys_path().exists());
    }

    #[test]
    fn test_server_cleanup() {
        let server = TestServer::new().expect("Failed to create test server");
        let port = server.port();
        
        drop(server);
        
        // After drop, the port should no longer be in use (sshd stopped)
        // We can't easily verify this, but the test passes if no panic occurs
    }
}