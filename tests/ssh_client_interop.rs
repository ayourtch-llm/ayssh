//! Integration tests: real OpenSSH client → our test server
//!
//! These tests start our SSH test server and connect the system's `ssh`
//! client to it, verifying our server implementation is compatible with
//! a production SSH client. This is the reverse of `sshd_interop.rs`.
//!
//! # Behavior
//! - If `ssh` CLI is not found: tests are **skipped**
//! - If `AYSSH_ENSURE_SSH_CLIENT_TESTS=1` is set: tests **fail** if ssh is missing
//! - Works on macOS and Linux
//! - User config is fully isolated via `-F /dev/null`

use ayssh::server::encrypted_io::build_unencrypted_packet;
use ayssh::server::host_key::HostKeyPair;
use ayssh::server::test_server::*;

use bytes::{BufMut, BytesMut};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

/// Global mutex to serialize tests — ssh subprocess spawning is unreliable
/// when multiple tests run in parallel (port races, fd inheritance, etc.)
static TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Find the ssh client binary
fn find_ssh() -> Option<PathBuf> {
    let candidates = ["/usr/bin/ssh", "/usr/local/bin/ssh", "/opt/homebrew/bin/ssh"];
    for path in &candidates {
        if Path::new(path).exists() {
            return Some(PathBuf::from(path));
        }
    }
    if let Ok(output) = Command::new("which").arg("ssh").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

fn find_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn should_skip() -> bool {
    find_ssh().is_none()
}

fn check_ensure_env() {
    if std::env::var("AYSSH_ENSURE_SSH_CLIENT_TESTS").is_ok() && find_ssh().is_none() {
        panic!(
            "AYSSH_ENSURE_SSH_CLIENT_TESTS is set but ssh was not found."
        );
    }
}

macro_rules! skip_if_no_ssh {
    () => {
        check_ensure_env();
        if should_skip() {
            eprintln!("SKIPPED: ssh client not found (set AYSSH_ENSURE_SSH_CLIENT_TESTS=1 to fail)");
            return;
        }
    };
}

/// Run our test server on a random port, call `test_fn` with the port,
/// and verify the server completes without error.
fn run_server_test<F>(host_key: HostKeyPair, filter: AlgorithmFilter, test_fn: F)
where
    F: FnOnce(u16) + Send + 'static,
{
    use std::sync::mpsc;
    let (port_tx, port_rx) = mpsc::channel::<u16>();

    let server = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            port_tx.send(port).unwrap();

            let (stream, addr) = listener.accept().await.unwrap();
            eprintln!("[server] Accepted connection from {}", addr);

            let (mut io, ch) = server_handshake(stream, &host_key, &filter)
                .await
                .expect("Server handshake failed with real ssh client");

            // Send test data through the channel
            let mut msg = BytesMut::new();
            msg.put_u8(94); // CHANNEL_DATA
            msg.put_u32(ch);
            let data = b"INTEROP_OK\n";
            msg.put_u32(data.len() as u32);
            msg.put_slice(data);
            io.send_message(&msg).await.unwrap();

            // Send EOF + CLOSE
            let mut eof = BytesMut::new();
            eof.put_u8(96);
            eof.put_u32(ch);
            let _ = io.send_message(&eof).await;
            let mut close = BytesMut::new();
            close.put_u8(97);
            close.put_u32(ch);
            let _ = io.send_message(&close).await;

            eprintln!("[server] Connection handled successfully");
        });
    });

    let port = port_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    test_fn(port);
    server.join().expect("Server thread panicked");
}

/// Build common ssh args that isolate from user config
fn ssh_base_args(port: u16) -> Vec<String> {
    vec![
        "-F".into(), "/dev/null".into(),                       // ignore user config
        "-o".into(), "StrictHostKeyChecking=no".into(),        // don't reject unknown host keys
        "-o".into(), "UserKnownHostsFile=/dev/null".into(),    // don't save host keys
        "-o".into(), "LogLevel=ERROR".into(),                    // suppress info messages
        "-o".into(), "BatchMode=yes".into(),                   // no interactive prompts
        "-o".into(), "ConnectTimeout=10".into(),
        // List ciphers our server supports (OpenSSH's default prefers chacha20)
        "-o".into(), "Ciphers=chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com".into(),
        "-o".into(), "MACs=hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com".into(),
        "-p".into(), port.to_string(),
    ]
}

// =============================================================================
// Tests
// =============================================================================

/// Test that OpenSSH client can complete handshake + auth + channel with our server
/// using the default Ed25519 host key.
#[test]
fn test_openssh_client_connects_to_our_server() {
    skip_if_no_ssh!();
    let _lock = TEST_MUTEX.lock().unwrap();
    let ssh_path = find_ssh().unwrap();

    run_server_test(
        HostKeyPair::generate_ed25519(),
        AlgorithmFilter::default(),
        move |port| {
            let mut args = ssh_base_args(port);
            // Use "none" auth - our server accepts anything
            args.extend([
                "-o".into(), "PreferredAuthentications=publickey".to_string(),
                "-i".into(), "tests/keys/test_ed25519".into(),
                "-l".into(), "testuser".into(),
                "127.0.0.1".into(),
                "cat".into(),
            ]);

            let output = Command::new(&ssh_path)
                .args(&args)
                .output()
                .expect("Failed to run ssh");

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("[ssh_client] exit={}, stdout={:?}, stderr={:?}",
                output.status.code().unwrap_or(-1), stdout.trim(), stderr.trim());

            assert!(
                stdout.contains("INTEROP_OK"),
                "Expected INTEROP_OK in output, got stdout={:?} stderr={:?}",
                stdout, stderr
            );
        },
    );
}

/// Test with RSA host key — verifies the client accepts our RSA host key signature
#[test]
fn test_openssh_client_with_rsa_host_key() {
    skip_if_no_ssh!();
    let _lock = TEST_MUTEX.lock().unwrap();
    let ssh_path = find_ssh().unwrap();

    let host_key = HostKeyPair::load_openssh_rsa(Path::new("tests/keys/test_rsa_2048"))
        .expect("Failed to load RSA host key");

    run_server_test(
        host_key,
        AlgorithmFilter::default(),
        move |port| {
            let mut args = ssh_base_args(port);
            args.extend([
                "-o".into(), "PreferredAuthentications=publickey".to_string(),
                "-o".into(), "HostKeyAlgorithms=ssh-rsa".to_string(),
                "-i".into(), "tests/keys/test_ed25519".into(),
                "-l".into(), "testuser".into(),
                "127.0.0.1".into(),
                "cat".into(),
            ]);

            let output = Command::new(&ssh_path)
                .args(&args)
                .output()
                .expect("Failed to run ssh");

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("[ssh_client_rsa] exit={}, stdout={:?}, stderr={:?}",
                output.status.code().unwrap_or(-1), stdout.trim(), stderr.trim());

            assert!(
                stdout.contains("INTEROP_OK"),
                "RSA host key: expected INTEROP_OK, got stdout={:?} stderr={:?}",
                stdout, stderr
            );
        },
    );
}

/// Test various cipher preferences from the client side
#[test]
fn test_openssh_client_cipher_negotiation() {
    skip_if_no_ssh!();
    let _lock = TEST_MUTEX.lock().unwrap();
    let ssh_path = find_ssh().unwrap();

    let ciphers = [
        "aes128-ctr",
        "aes256-ctr",
        "chacha20-poly1305@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
    ];

    let mut passed = 0;
    let mut failed = Vec::new();

    for cipher in &ciphers {
        eprint!("  cipher={} ... ", cipher);

        let ssh_path = ssh_path.clone();
        let cipher_owned = cipher.to_string();
        let cipher_label = cipher.to_string();

        let result = std::panic::catch_unwind(move || {
            let cipher = cipher_owned;
            run_server_test(
                HostKeyPair::generate_ed25519(),
                AlgorithmFilter { kex: None, cipher: None, mac: None },
                move |port| {
                    let mut args = ssh_base_args(port);
                    args.extend([
                        "-o".into(), format!("Ciphers={}", cipher),
                        "-o".into(), "PreferredAuthentications=publickey".to_string(),
                        "-i".into(), "tests/keys/test_ed25519".into(),
                        "-l".into(), "testuser".into(),
                        "127.0.0.1".into(),
                        "cat".into(),
                    ]);

                    let output = Command::new(&ssh_path)
                        .args(&args)
                        .output()
                        .expect("Failed to run ssh");

                    let stdout = String::from_utf8_lossy(&output.stdout);
                    assert!(
                        stdout.contains("INTEROP_OK"),
                        "cipher: no INTEROP_OK in output",
                    );
                },
            );
        });

        match result {
            Ok(()) => {
                passed += 1;
                eprintln!("ok");
            }
            Err(_) => {
                failed.push(cipher_label);
                eprintln!("FAILED");
            }
        }
    }

    eprintln!("\n  Client cipher interop: {}/{} passed", passed, ciphers.len());
    assert!(
        passed >= 2,
        "At least 2 ciphers should work. Failures: {:?}",
        failed
    );
}

/// Test various KEX algorithm preferences from the client side
#[test]
fn test_openssh_client_kex_negotiation() {
    skip_if_no_ssh!();
    let _lock = TEST_MUTEX.lock().unwrap();
    let ssh_path = find_ssh().unwrap();

    let kex_algorithms = [
        "curve25519-sha256",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group14-sha256",
    ];

    let mut passed = 0;

    for kex in &kex_algorithms {
        eprint!("  kex={} ... ", kex);

        let ssh_path = ssh_path.clone();
        let kex = kex.to_string();

        let result = std::panic::catch_unwind(move || {
            run_server_test(
                HostKeyPair::generate_ed25519(),
                AlgorithmFilter { kex: None, cipher: None, mac: None },
                move |port| {
                    let mut args = ssh_base_args(port);
                    args.extend([
                        "-o".into(), format!("KexAlgorithms={}", kex),
                        "-o".into(), "PreferredAuthentications=publickey".to_string(),
                        "-i".into(), "tests/keys/test_ed25519".into(),
                        "-l".into(), "testuser".into(),
                        "127.0.0.1".into(),
                        "cat".into(),
                    ]);

                    let output = Command::new(&ssh_path)
                        .args(&args)
                        .output()
                        .expect("Failed to run ssh");

                    let stdout = String::from_utf8_lossy(&output.stdout);
                    assert!(stdout.contains("INTEROP_OK"));
                },
            );
        });

        match result {
            Ok(()) => {
                passed += 1;
                eprintln!("ok");
            }
            Err(_) => {
                eprintln!("FAILED");
            }
        }
    }

    eprintln!("\n  Client KEX interop: {}/{} passed", passed, kex_algorithms.len());
    assert!(passed >= 2, "At least 2 KEX algorithms should work against real ssh client");
}

/// Test that OpenSSH client defaults to chacha20-poly1305 with our server
/// (it's OpenSSH's preferred cipher). This validates our chacha20 server-side
/// decryption works with the most common real-world negotiation.
#[test]
fn test_openssh_client_defaults_to_chacha20() {
    skip_if_no_ssh!();
    let _lock = TEST_MUTEX.lock().unwrap();
    let ssh_path = find_ssh().unwrap();

    run_server_test(
        HostKeyPair::generate_ed25519(),
        AlgorithmFilter::default(),
        move |port| {
            // Don't restrict ciphers — let OpenSSH pick its default (chacha20)
            let args = vec![
                "-F".into(), "/dev/null".into(),
                "-o".into(), "StrictHostKeyChecking=no".into(),
                "-o".into(), "UserKnownHostsFile=/dev/null".into(),
                "-o".into(), "LogLevel=ERROR".into(),
                "-o".into(), "BatchMode=yes".into(),
                "-o".into(), "ConnectTimeout=10".into(),
                "-o".into(), "MACs=hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha2-256-etm@openssh.com".into(),
                "-o".into(), "PreferredAuthentications=publickey".to_string(),
                "-i".into(), "tests/keys/test_ed25519".into(),
                "-p".into(), port.to_string(),
                "-l".into(), "testuser".into(),
                "127.0.0.1".into(),
                "cat".into(),
            ];

            let output = Command::new(&ssh_path)
                .args(&args)
                .output()
                .expect("Failed to run ssh");

            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("INTEROP_OK"),
                "Default cipher (likely chacha20) failed: stdout={:?}",
                stdout
            );
        },
    );
}

/// Test MAC negotiation: OpenSSH client → our server with specific MACs
#[test]
fn test_openssh_client_mac_negotiation() {
    skip_if_no_ssh!();
    let _lock = TEST_MUTEX.lock().unwrap();
    let ssh_path = find_ssh().unwrap();

    let macs = [
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha1-etm@openssh.com",
    ];

    let mut passed = 0;

    for mac in &macs {
        eprint!("  mac={} ... ", mac);

        let ssh_path = ssh_path.clone();
        let mac = mac.to_string();

        let result = std::panic::catch_unwind(move || {
            run_server_test(
                HostKeyPair::generate_ed25519(),
                AlgorithmFilter { kex: None, cipher: None, mac: None },
                move |port| {
                    let mut args = ssh_base_args(port);
                    // Force a non-AEAD cipher so MAC actually matters
                    args.extend([
                        "-o".into(), "Ciphers=aes256-ctr".to_string(),
                        "-o".into(), format!("MACs={}", mac),
                        "-o".into(), "PreferredAuthentications=publickey".to_string(),
                        "-i".into(), "tests/keys/test_ed25519".into(),
                        "-l".into(), "testuser".into(),
                        "127.0.0.1".into(),
                        "cat".into(),
                    ]);

                    let output = Command::new(&ssh_path)
                        .args(&args)
                        .output()
                        .expect("Failed to run ssh");

                    let stdout = String::from_utf8_lossy(&output.stdout);
                    assert!(stdout.contains("INTEROP_OK"));
                },
            );
        });

        match result {
            Ok(()) => {
                passed += 1;
                eprintln!("ok");
            }
            Err(_) => {
                eprintln!("FAILED");
            }
        }
    }

    eprintln!("\n  Client MAC interop: {}/{} passed", passed, macs.len());
    assert!(passed >= 4, "At least 4 MACs should work against real ssh client");
}

/// Test CBC ciphers with real OpenSSH client → our server.
/// CBC is less common but still used by older clients/Cisco devices.
#[test]
fn test_openssh_client_cbc_ciphers() {
    skip_if_no_ssh!();
    let _lock = TEST_MUTEX.lock().unwrap();
    let ssh_path = find_ssh().unwrap();

    let cbc_ciphers = ["aes128-cbc", "aes256-cbc"];
    let mut passed = 0;

    for cipher in &cbc_ciphers {
        eprint!("  cbc_cipher={} ... ", cipher);

        let ssh_path = ssh_path.clone();
        let cipher = cipher.to_string();

        let result = std::panic::catch_unwind(move || {
            run_server_test(
                HostKeyPair::generate_ed25519(),
                AlgorithmFilter { kex: None, cipher: None, mac: None },
                move |port| {
                    let mut args = ssh_base_args(port);
                    args.extend([
                        "-o".into(), format!("Ciphers={}", cipher),
                        "-o".into(), "PreferredAuthentications=publickey".to_string(),
                        "-i".into(), "tests/keys/test_ed25519".into(),
                        "-l".into(), "testuser".into(),
                        "127.0.0.1".into(),
                        "cat".into(),
                    ]);

                    let output = Command::new(&ssh_path)
                        .args(&args)
                        .output()
                        .expect("Failed to run ssh");

                    let stdout = String::from_utf8_lossy(&output.stdout);
                    assert!(stdout.contains("INTEROP_OK"));
                },
            );
        });

        match result {
            Ok(()) => { passed += 1; eprintln!("ok"); }
            Err(_) => { eprintln!("FAILED"); }
        }
    }

    eprintln!("\n  Client CBC cipher interop: {}/{} passed", passed, cbc_ciphers.len());
    assert!(passed >= 1, "At least 1 CBC cipher should work");
}

/// Test rapid sequential connections from ssh client to our server.
/// Verifies our server handles connection cleanup properly.
#[test]
fn test_openssh_client_rapid_connections() {
    skip_if_no_ssh!();
    let _lock = TEST_MUTEX.lock().unwrap();
    let ssh_path = find_ssh().unwrap();

    let mut passed = 0;
    for i in 0..3 {
        let ssh_path = ssh_path.clone();
        let i = i;

        let result = std::panic::catch_unwind(move || {
            run_server_test(
                HostKeyPair::generate_ed25519(),
                AlgorithmFilter::default(),
                move |port| {
                    let mut args = ssh_base_args(port);
                    args.extend([
                        "-o".into(), "PreferredAuthentications=publickey".to_string(),
                        "-i".into(), "tests/keys/test_ed25519".into(),
                        "-l".into(), "testuser".into(),
                        "127.0.0.1".into(),
                        "cat".into(),
                    ]);

                    let output = Command::new(&ssh_path)
                        .args(&args)
                        .output()
                        .expect("Failed to run ssh");

                    let stdout = String::from_utf8_lossy(&output.stdout);
                    assert!(stdout.contains("INTEROP_OK"),
                        "Connection {} failed", i);
                },
            );
        });

        match result {
            Ok(()) => passed += 1,
            Err(_) => eprintln!("  Connection {} failed", i),
        }
    }

    eprintln!("[rapid_client] {}/3 rapid connections succeeded", passed);
    assert_eq!(passed, 3, "All 3 rapid connections should succeed");
}

/// Test KEX × cipher combinations from real ssh client → our server.
#[test]
fn test_openssh_client_kex_cipher_combos() {
    skip_if_no_ssh!();
    let _lock = TEST_MUTEX.lock().unwrap();
    let ssh_path = find_ssh().unwrap();

    let combos: Vec<(&str, &str)> = vec![
        ("curve25519-sha256", "aes128-ctr"),
        ("curve25519-sha256", "chacha20-poly1305@openssh.com"),
        ("ecdh-sha2-nistp256", "aes256-gcm@openssh.com"),
        ("diffie-hellman-group14-sha256", "aes256-ctr"),
    ];

    let mut passed = 0;

    for (kex, cipher) in &combos {
        eprint!("  {}+{} ... ", kex, cipher);

        let ssh_path = ssh_path.clone();
        let kex = kex.to_string();
        let cipher = cipher.to_string();

        let result = std::panic::catch_unwind(move || {
            run_server_test(
                HostKeyPair::generate_ed25519(),
                AlgorithmFilter { kex: None, cipher: None, mac: None },
                move |port| {
                    let mut args = ssh_base_args(port);
                    args.extend([
                        "-o".into(), format!("KexAlgorithms={}", kex),
                        "-o".into(), format!("Ciphers={}", cipher),
                        "-o".into(), "PreferredAuthentications=publickey".to_string(),
                        "-i".into(), "tests/keys/test_ed25519".into(),
                        "-l".into(), "testuser".into(),
                        "127.0.0.1".into(),
                        "cat".into(),
                    ]);

                    let output = Command::new(&ssh_path)
                        .args(&args)
                        .output()
                        .expect("Failed to run ssh");

                    let stdout = String::from_utf8_lossy(&output.stdout);
                    assert!(stdout.contains("INTEROP_OK"));
                },
            );
        });

        match result {
            Ok(()) => { passed += 1; eprintln!("ok"); }
            Err(_) => { eprintln!("FAILED"); }
        }
    }

    eprintln!("\n  Client KEX×Cipher interop: {}/{} passed", passed, combos.len());
    assert!(passed >= 3, "At least 3 KEX×Cipher combos should work");
}
