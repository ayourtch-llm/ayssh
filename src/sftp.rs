//! SCP / SFTP Subsystem Stub
//!
//! Provides basic types and a stub API for file transfer over SSH.
//!
//! Currently implemented:
//! - `ScpCommand` — builds `scp -t` / `scp -f` exec requests for upload/download
//! - `SftpOp` — enumerates SFTP operations (type definitions only)
//! - `RawSshSession::exec()` — opens an exec channel (implemented below)
//!
//! TODO:
//! - Implement actual SCP data framing (D/C/E protocol lines)
//! - Implement SFTP subsystem with binary packet framing
//! - Add streaming upload/download with progress callbacks
//! - Add recursive directory transfer

use crate::error::SshError;

/// SCP transfer direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScpDirection {
    /// Upload: `scp -t <path>` on the remote side
    Upload,
    /// Download: `scp -f <path>` on the remote side
    Download,
}

/// An SCP command to be executed via an exec channel.
#[derive(Debug, Clone)]
pub struct ScpCommand {
    /// Transfer direction
    pub direction: ScpDirection,
    /// Remote file path
    pub remote_path: String,
    /// Whether to transfer recursively (directories)
    pub recursive: bool,
}

impl ScpCommand {
    /// Create an upload command for a single file.
    pub fn upload(remote_path: &str) -> Self {
        Self {
            direction: ScpDirection::Upload,
            remote_path: remote_path.to_string(),
            recursive: false,
        }
    }

    /// Create a download command for a single file.
    pub fn download(remote_path: &str) -> Self {
        Self {
            direction: ScpDirection::Download,
            remote_path: remote_path.to_string(),
            recursive: false,
        }
    }

    /// Set recursive mode (for directory transfers).
    pub fn with_recursive(mut self) -> Self {
        self.recursive = true;
        self
    }

    /// Build the remote command string to be passed to `exec`.
    ///
    /// For upload: `scp -t [-r] <path>`
    /// For download: `scp -f [-r] <path>`
    pub fn to_command_string(&self) -> String {
        let flag = match self.direction {
            ScpDirection::Upload => "-t",
            ScpDirection::Download => "-f",
        };
        if self.recursive {
            format!("scp {} -r {}", flag, self.remote_path)
        } else {
            format!("scp {} {}", flag, self.remote_path)
        }
    }
}

/// SFTP operation types (stub — type definitions only).
///
/// These correspond to SSH_FXP_* packet types from the SFTP protocol.
/// Full implementation is a TODO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SftpOp {
    /// Open a file (SSH_FXP_OPEN)
    Open {
        path: String,
        flags: u32,
    },
    /// Close a handle (SSH_FXP_CLOSE)
    Close {
        handle: Vec<u8>,
    },
    /// Read from a file (SSH_FXP_READ)
    Read {
        handle: Vec<u8>,
        offset: u64,
        length: u32,
    },
    /// Write to a file (SSH_FXP_WRITE)
    Write {
        handle: Vec<u8>,
        offset: u64,
        data: Vec<u8>,
    },
    /// Get file attributes (SSH_FXP_STAT)
    Stat {
        path: String,
    },
    /// List directory contents (SSH_FXP_READDIR)
    ReadDir {
        handle: Vec<u8>,
    },
    /// Open a directory (SSH_FXP_OPENDIR)
    OpenDir {
        path: String,
    },
    /// Remove a file (SSH_FXP_REMOVE)
    Remove {
        path: String,
    },
    /// Create a directory (SSH_FXP_MKDIR)
    Mkdir {
        path: String,
    },
    /// Rename a file (SSH_FXP_RENAME)
    Rename {
        old_path: String,
        new_path: String,
    },
}

/// SFTP open flags (from SSH_FXF_*)
pub mod sftp_flags {
    pub const SSH_FXF_READ: u32 = 0x00000001;
    pub const SSH_FXF_WRITE: u32 = 0x00000002;
    pub const SSH_FXF_APPEND: u32 = 0x00000004;
    pub const SSH_FXF_CREAT: u32 = 0x00000008;
    pub const SSH_FXF_TRUNC: u32 = 0x00000010;
    pub const SSH_FXF_EXCL: u32 = 0x00000020;
}

// Note: The `RawSshSession::exec_on_new_connection()` method is defined in
// `raw_session.rs` where it has access to private helper methods.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scp_upload_command() {
        let cmd = ScpCommand::upload("/tmp/test.txt");
        assert_eq!(cmd.to_command_string(), "scp -t /tmp/test.txt");
        assert_eq!(cmd.direction, ScpDirection::Upload);
        assert!(!cmd.recursive);
    }

    #[test]
    fn test_scp_download_command() {
        let cmd = ScpCommand::download("/home/user/file.tar");
        assert_eq!(cmd.to_command_string(), "scp -f /home/user/file.tar");
        assert_eq!(cmd.direction, ScpDirection::Download);
    }

    #[test]
    fn test_scp_recursive() {
        let cmd = ScpCommand::upload("/tmp/mydir").with_recursive();
        assert_eq!(cmd.to_command_string(), "scp -t -r /tmp/mydir");
        assert!(cmd.recursive);
    }

    #[test]
    fn test_scp_download_recursive() {
        let cmd = ScpCommand::download("/tmp/mydir").with_recursive();
        assert_eq!(cmd.to_command_string(), "scp -f -r /tmp/mydir");
    }

    #[test]
    fn test_sftp_op_variants() {
        // Just verify the enum variants compile and can be created
        let _open = SftpOp::Open { path: "/tmp/f".into(), flags: sftp_flags::SSH_FXF_READ };
        let _close = SftpOp::Close { handle: vec![1, 2, 3] };
        let _read = SftpOp::Read { handle: vec![1], offset: 0, length: 1024 };
        let _write = SftpOp::Write { handle: vec![1], offset: 0, data: vec![0; 100] };
        let _stat = SftpOp::Stat { path: "/tmp/f".into() };
        let _readdir = SftpOp::ReadDir { handle: vec![1] };
        let _opendir = SftpOp::OpenDir { path: "/tmp".into() };
        let _remove = SftpOp::Remove { path: "/tmp/f".into() };
        let _mkdir = SftpOp::Mkdir { path: "/tmp/d".into() };
        let _rename = SftpOp::Rename { old_path: "/tmp/a".into(), new_path: "/tmp/b".into() };
    }

    #[test]
    fn test_sftp_flags() {
        assert_eq!(sftp_flags::SSH_FXF_READ, 1);
        assert_eq!(sftp_flags::SSH_FXF_WRITE, 2);
        assert_eq!(sftp_flags::SSH_FXF_CREAT, 8);
        assert_eq!(sftp_flags::SSH_FXF_READ | sftp_flags::SSH_FXF_WRITE, 3);
    }
}
