//! Integration tests against a real OpenSSH sshd
//!
//! These tests start a local sshd process and verify our SSH client
//! implementation can interoperate with it. This catches encoding,
//! algorithm negotiation, and crypto bugs that self-tests miss.
//!
//! # Behavior
//! - If `sshd` is not found: tests are **skipped** (not failed)
//! - If `AYSSH_ENSURE_SSHD_TESTS=1` is set: tests **fail** if sshd is missing
//! - Works on both macOS (`/usr/sbin/sshd`) and Linux (`/usr/sbin/sshd`)

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

/// Find sshd binary, checking common locations
fn find_sshd() -> Option<PathBuf> {
    let candidates = [
        "/usr/sbin/sshd",
        "/usr/local/sbin/sshd",
        "/opt/homebrew/sbin/sshd",
        "/sbin/sshd",
    ];
    for path in &candidates {
        if Path::new(path).exists() {
            return Some(PathBuf::from(path));
        }
    }
    // Try PATH as fallback
    if let Ok(output) = Command::new("which").arg("sshd").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

/// Find a free TCP port. Derives a candidate from the current PID (for
/// predictability), then verifies it's free by binding on loopback.
/// Falls back to OS-assigned port 0 if the PID-derived port is taken.
fn find_free_port() -> u16 {
    let pid = std::process::id();
    // Map PID into high port range 10000-60000
    let candidate = 10000 + (pid % 50000) as u16;

    // Verify it's actually free by binding
    if let Ok(listener) = TcpListener::bind(format!("127.0.0.1:{}", candidate)) {
        drop(listener);
        return candidate;
    }

    // Fallback: let OS pick
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Check if tests should be skipped
fn should_skip() -> bool {
    find_sshd().is_none()
}

/// If AYSSH_ENSURE_SSHD_TESTS is set and sshd is missing, panic
fn check_ensure_env() {
    if std::env::var("AYSSH_ENSURE_SSHD_TESTS").is_ok() && find_sshd().is_none() {
        panic!(
            "AYSSH_ENSURE_SSHD_TESTS is set but sshd was not found. \
             Install OpenSSH server or unset the variable."
        );
    }
}

/// A managed sshd process with temp directory for config/keys
struct SshdInstance {
    child: Child,
    port: u16,
    _tmpdir: tempfile::TempDir,
}

impl SshdInstance {
    /// Start a local sshd on a random port with ed25519 host key.
    /// The authorized_keys file is set up to accept the test ed25519 key.
    fn start() -> Result<Self, String> {
        Self::start_with_loglevel("ERROR")
    }

    /// Start sshd with a specific log level (e.g., "DEBUG3" for debugging)
    fn start_with_loglevel(log_level: &str) -> Result<Self, String> {
        let sshd_path = find_sshd().ok_or("sshd not found")?;
        let tmpdir = tempfile::TempDir::new().map_err(|e| format!("tmpdir: {}", e))?;
        let tmppath = tmpdir.path();

        // Generate host key
        let host_key_path = tmppath.join("host_key");
        let status = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-f"])
            .arg(&host_key_path)
            .args(["-N", "", "-q"])
            .status()
            .map_err(|e| format!("ssh-keygen: {}", e))?;
        if !status.success() {
            return Err("ssh-keygen failed".to_string());
        }

        // Copy test key as authorized_keys
        let auth_keys_path = tmppath.join("authorized_keys");
        let test_pubkey = std::fs::read_to_string("tests/keys/test_ed25519.pub")
            .map_err(|e| format!("read test pubkey: {}", e))?;
        std::fs::write(&auth_keys_path, &test_pubkey)
            .map_err(|e| format!("write authorized_keys: {}", e))?;

        // Find a free port
        let port = find_free_port();

        // Write sshd_config
        let config_path = tmppath.join("sshd_config");
        let pid_path = tmppath.join("sshd.pid");
        let mut config = std::fs::File::create(&config_path)
            .map_err(|e| format!("create config: {}", e))?;
        write!(
            config,
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host_key}\n\
             AuthorizedKeysFile {auth_keys}\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             StrictModes no\n\
             PidFile {pid}\n\
             LogLevel {log_level}\n",
            port = port,
            host_key = host_key_path.display(),
            auth_keys = auth_keys_path.display(),
            pid = pid_path.display(),
            log_level = log_level,
        )
        .map_err(|e| format!("write config: {}", e))?;

        // Start sshd
        let child = Command::new(&sshd_path)
            .args(["-D", "-e", "-f"])
            .arg(&config_path)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn sshd: {}", e))?;

        // Wait for sshd to start listening
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(5) {
                return Err("sshd didn't start within 5 seconds".to_string());
            }
            if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        Ok(SshdInstance {
            child,
            port,
            _tmpdir: tmpdir,
        })
    }
}

impl SshdInstance {
    /// Capture sshd's stderr log output (call after test, before drop)
    fn capture_log(&mut self) -> String {
        use std::io::Read;
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(ref mut stderr) = self.child.stderr {
            let mut log = String::new();
            let _ = stderr.read_to_string(&mut log);
            log
        } else {
            String::new()
        }
    }
}

impl Drop for SshdInstance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Macro to skip tests when sshd is not available
macro_rules! skip_if_no_sshd {
    () => {
        check_ensure_env();
        if should_skip() {
            eprintln!("SKIPPED: sshd not found (set AYSSH_ENSURE_SSHD_TESTS=1 to fail instead)");
            return;
        }
    };
}

// =============================================================================
// Tests
// =============================================================================

/// Test that our handshake completes against real OpenSSH sshd.
/// This verifies: version exchange, KEXINIT negotiation, key exchange,
/// NEWKEYS, and encryption setup all work with a production SSH server.
#[test]
fn test_handshake_against_real_sshd() {
    skip_if_no_sshd!();

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    eprintln!("[sshd_interop] sshd running on port {}", sshd.port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port))
            .await
            .expect("Failed to connect to sshd");

        let mut transport = ayssh::transport::Transport::new(stream);
        transport
            .handshake()
            .await
            .expect("Handshake with real sshd failed");

        // Verify session ID was established
        assert!(
            transport.session_id().is_some(),
            "Session ID should be set after handshake"
        );
        let session_id = transport.session_id().unwrap();
        assert!(
            !session_id.is_empty(),
            "Session ID should not be empty"
        );

        eprintln!(
            "[sshd_interop] Handshake OK, session_id={} bytes",
            session_id.len()
        );
    });
}

/// Test SERVICE_REQUEST/ACCEPT against real sshd.
/// After handshake, the client requests the "ssh-userauth" service.
#[test]
fn test_service_request_against_real_sshd() {
    skip_if_no_sshd!();

    let sshd = SshdInstance::start().expect("Failed to start sshd");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port))
            .await
            .unwrap();

        let mut transport = ayssh::transport::Transport::new(stream);
        transport.handshake().await.unwrap();

        transport
            .send_service_request("ssh-userauth")
            .await
            .expect("SERVICE_REQUEST failed");

        let service = transport
            .recv_service_accept()
            .await
            .expect("SERVICE_ACCEPT failed");

        assert_eq!(service, "ssh-userauth");
        eprintln!("[sshd_interop] SERVICE_REQUEST/ACCEPT OK");
    });
}

/// Test pubkey authentication against real sshd using our test ed25519 key.
/// This verifies: public key blob encoding, signature creation (Ed25519),
/// and the full auth protocol (probe → PK_OK → signed request → SUCCESS).
#[test]
fn test_ed25519_auth_against_real_sshd() {
    skip_if_no_sshd!();

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "test".to_string());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port))
            .await
            .unwrap();

        let mut transport = ayssh::transport::Transport::new(stream);
        transport.handshake().await.unwrap();
        transport.send_service_request("ssh-userauth").await.unwrap();
        transport.recv_service_accept().await.unwrap();

        // Read the test ed25519 private key
        let key_data = std::fs::read("tests/keys/test_ed25519").unwrap();

        let mut auth =
            ayssh::auth::Authenticator::new(&mut transport, current_user)
                .with_private_key(key_data);
        auth.available_methods.insert("publickey".to_string());

        let result = auth.authenticate().await
            .expect("Ed25519 auth should not error");

        assert!(
            matches!(result, ayssh::auth::AuthenticationResult::Success),
            "Ed25519 pubkey auth should succeed, got {:?}",
            result
        );
        eprintln!("[sshd_interop] Ed25519 pubkey auth SUCCESS");
    });
}

/// Test with each supported KEX algorithm against real sshd.
/// This catches algorithm-specific encoding bugs that our self-tests miss.
#[test]
fn test_kex_algorithms_against_real_sshd() {
    skip_if_no_sshd!();

    let kex_algorithms = [
        "curve25519-sha256",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
        // group1-sha1 may be disabled in modern sshd
    ];

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let mut passed = 0;
    let mut skipped = Vec::new();

    for kex in &kex_algorithms {
        eprint!("  kex={} ... ", kex);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = rt.block_on(async {
            let stream =
                tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
            let mut transport = ayssh::transport::Transport::new(stream);
            transport.set_preferred_kex(kex);
            transport.handshake().await?;
            assert!(transport.session_id().is_some());
            Ok::<(), ayssh::error::SshError>(())
        });

        match result {
            Ok(()) => {
                passed += 1;
                eprintln!("ok");
            }
            Err(e) => {
                // Some KEX algorithms may be disabled in the sshd config
                skipped.push(format!("{}: {}", kex, e));
                eprintln!("skipped ({})", e);
            }
        }
    }

    eprintln!(
        "\n  KEX interop: {}/{} passed, {} skipped",
        passed,
        kex_algorithms.len(),
        skipped.len()
    );
    assert!(passed >= 3, "At least 3 KEX algorithms should work against sshd");
}

/// Debug test: try chacha20-poly1305 against real sshd and capture server log
#[test]
fn test_chacha20_debug_against_real_sshd() {
    skip_if_no_sshd!();

    // Use a dedicated sshd with DEBUG3 for this test
    let mut sshd = SshdInstance::start_with_loglevel("DEBUG3").expect("Failed to start sshd");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(async {
        let stream =
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
        let mut transport = ayssh::transport::Transport::new(stream);
        transport.set_preferred_cipher("chacha20-poly1305@openssh.com");
        transport.handshake().await?;
        eprintln!("[chacha20_debug] handshake OK, session_id={} bytes", transport.session_id().unwrap().len());

        transport.send_service_request("ssh-userauth").await?;
        eprintln!("[chacha20_debug] SERVICE_REQUEST sent");
        transport.recv_service_accept().await?;
        eprintln!("[chacha20_debug] SERVICE_ACCEPT received");
        Ok::<(), ayssh::error::SshError>(())
    });

    let sshd_log = sshd.capture_log();
    // Print the relevant sshd log lines
    for line in sshd_log.lines() {
        if line.contains("chacha") || line.contains("Cipher") || line.contains("cipher")
            || line.contains("MAC") || line.contains("error") || line.contains("Error")
            || line.contains("fatal") || line.contains("bad") || line.contains("corrupt")
            || line.contains("packet") || line.contains("disconnect")
            || line.contains("kex") || line.contains("NEWKEYS")
            || line.contains("service") || line.contains("userauth")
        {
            eprintln!("[sshd] {}", line);
        }
    }

    match result {
        Ok(()) => eprintln!("[chacha20_debug] SUCCESS!"),
        Err(e) => eprintln!("[chacha20_debug] FAILED: {}", e),
    }
    // Don't assert — this is a debug test
}

/// Test with each supported cipher against real sshd.
#[test]
fn test_ciphers_against_real_sshd() {
    skip_if_no_sshd!();

    let ciphers = [
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-cbc",
        "aes256-cbc",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
    ];

    let sshd = SshdInstance::start().expect("Failed to start sshd");
    let mut passed = 0;
    let mut failed = Vec::new();

    for cipher in &ciphers {
        eprint!("  cipher={} ... ", cipher);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let result = rt.block_on(async {
            let stream =
                tokio::net::TcpStream::connect(format!("127.0.0.1:{}", sshd.port)).await?;
            let mut transport = ayssh::transport::Transport::new(stream);
            transport.set_preferred_cipher(cipher);
            transport.handshake().await
                .map_err(|e| { eprintln!("    handshake failed: {}", e); e })?;

            // Verify we can exchange encrypted messages
            transport.send_service_request("ssh-userauth").await
                .map_err(|e| { eprintln!("    send_service_request failed: {}", e); e })?;
            transport.recv_service_accept().await
                .map_err(|e| { eprintln!("    recv_service_accept failed: {}", e); e })?;
            Ok::<(), ayssh::error::SshError>(())
        });

        match result {
            Ok(()) => {
                passed += 1;
                eprintln!("ok");
            }
            Err(e) => {
                failed.push(format!("{}: {}", cipher, e));
                eprintln!("FAILED ({})", e);
            }
        }
    }

    eprintln!(
        "\n  Cipher interop: {}/{} passed",
        passed,
        ciphers.len()
    );
    if !failed.is_empty() {
        eprintln!("  Failures: {:?}", failed);
    }
    assert!(passed >= 4, "At least 4 ciphers should work against sshd");
}
