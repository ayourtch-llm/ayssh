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

/// SCP file transfer over a RawSshSession exec channel.
///
/// Implements the SCP protocol for single-file upload and download.
pub struct ScpSession {
    session: crate::raw_session::RawSshSession,
}

impl ScpSession {
    /// Upload a file via SCP to the remote host.
    ///
    /// Opens an exec channel with `scp -t <remote_path>`, sends the file data,
    /// and waits for confirmation.
    pub async fn upload(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        remote_path: &str,
        data: &[u8],
        mode: u32,
    ) -> Result<(), SshError> {
        let cmd = ScpCommand::upload(remote_path);
        let mut session = crate::raw_session::RawSshSession::exec_with_password(
            host, port, username, password, &cmd.to_command_string(),
        ).await?;

        // Wait for initial OK from scp -t
        let resp = session.receive(std::time::Duration::from_secs(10)).await?;
        if !resp.is_empty() && resp[0] != 0 {
            return Err(SshError::ProtocolError(format!(
                "SCP error: {}", String::from_utf8_lossy(&resp)
            )));
        }

        // Extract filename from path
        let filename = remote_path.rsplit('/').next().unwrap_or(remote_path);

        // Send file header: C<mode> <size> <filename>\n
        let header = format!("C{:04o} {} {}\n", mode, data.len(), filename);
        session.send(header.as_bytes()).await?;

        // Wait for OK
        let resp = session.receive(std::time::Duration::from_secs(10)).await?;
        if !resp.is_empty() && resp[0] != 0 {
            return Err(SshError::ProtocolError(format!(
                "SCP header rejected: {}", String::from_utf8_lossy(&resp)
            )));
        }

        // Send file data
        session.send(data).await?;

        // Send completion marker (single \0)
        session.send(&[0]).await?;

        // Wait for final OK
        let resp = session.receive(std::time::Duration::from_secs(10)).await?;
        if !resp.is_empty() && resp[0] != 0 {
            return Err(SshError::ProtocolError(format!(
                "SCP transfer failed: {}", String::from_utf8_lossy(&resp)
            )));
        }

        let _ = session.disconnect().await;
        Ok(())
    }

    /// Download a file via SCP from the remote host.
    ///
    /// Opens an exec channel with `scp -f <remote_path>`, reads the file data,
    /// and returns it.
    pub async fn download(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        remote_path: &str,
    ) -> Result<Vec<u8>, SshError> {
        let cmd = ScpCommand::download(remote_path);
        let mut session = crate::raw_session::RawSshSession::exec_with_password(
            host, port, username, password, &cmd.to_command_string(),
        ).await?;

        // Send ready signal
        session.send(&[0]).await?;

        // Read file header: C<mode> <size> <filename>\n
        let header_data = session.receive(std::time::Duration::from_secs(10)).await?;
        let header = String::from_utf8_lossy(&header_data);

        if !header.starts_with('C') {
            return Err(SshError::ProtocolError(format!(
                "SCP: expected file header (C...), got: {}", header.trim()
            )));
        }

        // Parse size from "C0644 <size> <filename>\n"
        let parts: Vec<&str> = header.trim().splitn(3, ' ').collect();
        if parts.len() < 3 {
            return Err(SshError::ProtocolError(format!(
                "SCP: malformed header: {}", header.trim()
            )));
        }
        let file_size: usize = parts[1].parse().map_err(|_| {
            SshError::ProtocolError(format!("SCP: invalid file size: {}", parts[1]))
        })?;

        // Send OK
        session.send(&[0]).await?;

        // Read file data
        let mut data = Vec::with_capacity(file_size);
        while data.len() < file_size {
            let chunk = session.receive(std::time::Duration::from_secs(30)).await?;
            if chunk.is_empty() {
                return Err(SshError::ProtocolError("SCP: timeout reading file data".into()));
            }
            data.extend_from_slice(&chunk);
        }
        // Trim to exact size (may have read trailing \0)
        data.truncate(file_size);

        // Send final OK
        session.send(&[0]).await?;

        let _ = session.disconnect().await;
        Ok(data)
    }

    /// Upload a file via SCP using public key authentication.
    pub async fn upload_with_publickey(
        host: &str,
        port: u16,
        username: &str,
        private_key: &[u8],
        remote_path: &str,
        data: &[u8],
        mode: u32,
    ) -> Result<(), SshError> {
        let cmd = ScpCommand::upload(remote_path);
        let mut session = crate::raw_session::RawSshSession::exec_with_publickey(
            host, port, username, private_key, &cmd.to_command_string(),
        ).await?;

        // Wait for initial OK from scp -t
        let resp = session.receive(std::time::Duration::from_secs(10)).await?;
        if !resp.is_empty() && resp[0] != 0 {
            return Err(SshError::ProtocolError(format!(
                "SCP error: {}", String::from_utf8_lossy(&resp)
            )));
        }

        let filename = remote_path.rsplit('/').next().unwrap_or(remote_path);
        let header = format!("C{:04o} {} {}\n", mode, data.len(), filename);
        session.send(header.as_bytes()).await?;

        let resp = session.receive(std::time::Duration::from_secs(10)).await?;
        if !resp.is_empty() && resp[0] != 0 {
            return Err(SshError::ProtocolError(format!(
                "SCP header rejected: {}", String::from_utf8_lossy(&resp)
            )));
        }

        session.send(data).await?;
        session.send(&[0]).await?;

        let resp = session.receive(std::time::Duration::from_secs(10)).await?;
        if !resp.is_empty() && resp[0] != 0 {
            return Err(SshError::ProtocolError(format!(
                "SCP transfer failed: {}", String::from_utf8_lossy(&resp)
            )));
        }

        let _ = session.disconnect().await;
        Ok(())
    }

    /// Download a file via SCP using public key authentication.
    pub async fn download_with_publickey(
        host: &str,
        port: u16,
        username: &str,
        private_key: &[u8],
        remote_path: &str,
    ) -> Result<Vec<u8>, SshError> {
        let cmd = ScpCommand::download(remote_path);
        let mut session = crate::raw_session::RawSshSession::exec_with_publickey(
            host, port, username, private_key, &cmd.to_command_string(),
        ).await?;

        session.send(&[0]).await?;

        let header_data = session.receive(std::time::Duration::from_secs(10)).await?;
        let header = String::from_utf8_lossy(&header_data);

        if !header.starts_with('C') {
            return Err(SshError::ProtocolError(format!(
                "SCP: expected file header (C...), got: {}", header.trim()
            )));
        }

        let parts: Vec<&str> = header.trim().splitn(3, ' ').collect();
        if parts.len() < 3 {
            return Err(SshError::ProtocolError(format!(
                "SCP: malformed header: {}", header.trim()
            )));
        }
        let file_size: usize = parts[1].parse().map_err(|_| {
            SshError::ProtocolError(format!("SCP: invalid file size: {}", parts[1]))
        })?;

        session.send(&[0]).await?;

        let mut data = Vec::with_capacity(file_size);
        while data.len() < file_size {
            let chunk = session.receive(std::time::Duration::from_secs(30)).await?;
            if chunk.is_empty() {
                return Err(SshError::ProtocolError("SCP: timeout reading file data".into()));
            }
            data.extend_from_slice(&chunk);
        }
        data.truncate(file_size);

        session.send(&[0]).await?;

        let _ = session.disconnect().await;
        Ok(data)
    }
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

// SFTP protocol constants
const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_STAT: u8 = 7;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;

const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;

use bytes::{BufMut, BytesMut};

/// SFTP file attributes
#[derive(Debug, Clone, Default)]
pub struct SftpAttrs {
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
}

/// SFTP directory entry
#[derive(Debug, Clone)]
pub struct SftpDirEntry {
    pub filename: String,
    pub longname: String,
    pub attrs: SftpAttrs,
}

/// SFTP client over an SSH session channel.
///
/// Opens the "sftp" subsystem and communicates using the SFTP binary protocol.
pub struct SftpClient {
    session: crate::raw_session::RawSshSession,
    request_id: u32,
}

impl SftpClient {
    /// Connect with public key auth and open an SFTP session.
    pub async fn connect_with_publickey(
        host: &str,
        port: u16,
        username: &str,
        private_key: &[u8],
    ) -> Result<Self, SshError> {
        let mut transport = crate::raw_session::RawSshSession::connect_and_handshake(host, port).await?;
        crate::raw_session::RawSshSession::authenticate_publickey(&mut transport, username, private_key).await?;

        // Open channel
        let session_obj = crate::session::Session::open(&mut transport).await?;
        let channel_id = session_obj.remote_channel_id();

        // Request "sftp" subsystem (not exec, not shell)
        let mut subsys_msg = BytesMut::new();
        subsys_msg.put_u8(crate::protocol::MessageType::ChannelRequest as u8);
        subsys_msg.put_u32(channel_id);
        let req_type = b"subsystem";
        subsys_msg.put_u32(req_type.len() as u32);
        subsys_msg.put_slice(req_type);
        subsys_msg.put_u8(1); // want reply
        let subsys_name = b"sftp";
        subsys_msg.put_u32(subsys_name.len() as u32);
        subsys_msg.put_slice(subsys_name);
        transport.send_message(&subsys_msg).await?;

        // Wait for channel success
        let resp = transport.recv_message().await?;
        if !resp.is_empty() && resp[0] == 100 {
            return Err(SshError::ChannelError("SFTP subsystem request rejected".into()));
        }

        let mut client = Self {
            session: crate::raw_session::RawSshSession::from_parts(transport, channel_id),
            request_id: 0,
        };

        // Send SSH_FXP_INIT (version 3)
        client.send_init().await?;

        Ok(client)
    }

    fn next_id(&mut self) -> u32 {
        let id = self.request_id;
        self.request_id += 1;
        id
    }

    /// Send SSH_FXP_INIT and receive SSH_FXP_VERSION.
    async fn send_init(&mut self) -> Result<u32, SshError> {
        let mut pkt = BytesMut::new();
        pkt.put_u8(SSH_FXP_INIT);
        pkt.put_u32(3); // SFTP version 3
        self.send_sftp_packet(&pkt).await?;

        let resp = self.recv_sftp_packet().await?;
        if resp.is_empty() || resp[0] != SSH_FXP_VERSION {
            return Err(SshError::ProtocolError("Expected SSH_FXP_VERSION".into()));
        }
        let version = u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]]);
        Ok(version)
    }

    /// Send an SFTP packet (4-byte length prefix + payload).
    async fn send_sftp_packet(&mut self, payload: &[u8]) -> Result<(), SshError> {
        let mut framed = BytesMut::with_capacity(4 + payload.len());
        framed.put_u32(payload.len() as u32);
        framed.put_slice(payload);
        self.session.send(&framed).await
    }

    /// Receive an SFTP packet (read 4-byte length, then payload).
    async fn recv_sftp_packet(&mut self) -> Result<Vec<u8>, SshError> {
        // SFTP packets arrive as CHANNEL_DATA — the session handles SSH framing,
        // we need to handle SFTP framing (4-byte length + payload).
        let mut buf = Vec::new();

        // Accumulate until we have a complete SFTP packet
        loop {
            if buf.len() >= 4 {
                let pkt_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if buf.len() >= 4 + pkt_len {
                    return Ok(buf[4..4 + pkt_len].to_vec());
                }
            }

            let chunk = self.session.receive(std::time::Duration::from_secs(30)).await?;
            if chunk.is_empty() {
                return Err(SshError::ProtocolError("SFTP: timeout waiting for packet".into()));
            }
            buf.extend_from_slice(&chunk);
        }
    }

    /// Open a remote file. Returns a handle.
    pub async fn open(
        &mut self,
        path: &str,
        flags: u32,
        attrs: &SftpAttrs,
    ) -> Result<Vec<u8>, SshError> {
        let id = self.next_id();
        let mut pkt = BytesMut::new();
        pkt.put_u8(SSH_FXP_OPEN);
        pkt.put_u32(id);
        pkt.put_u32(path.len() as u32);
        pkt.put_slice(path.as_bytes());
        pkt.put_u32(flags);
        Self::encode_attrs(&mut pkt, attrs);
        self.send_sftp_packet(&pkt).await?;

        let resp = self.recv_sftp_packet().await?;
        if resp[0] == SSH_FXP_HANDLE {
            let handle_len = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]) as usize;
            Ok(resp[9..9 + handle_len].to_vec())
        } else if resp[0] == SSH_FXP_STATUS {
            let code = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]);
            Err(SshError::ProtocolError(format!("SFTP open failed: status {}", code)))
        } else {
            Err(SshError::ProtocolError(format!("SFTP: unexpected response type {}", resp[0])))
        }
    }

    /// Read from an open file handle.
    pub async fn read(&mut self, handle: &[u8], offset: u64, length: u32) -> Result<Vec<u8>, SshError> {
        let id = self.next_id();
        let mut pkt = BytesMut::new();
        pkt.put_u8(SSH_FXP_READ);
        pkt.put_u32(id);
        pkt.put_u32(handle.len() as u32);
        pkt.put_slice(handle);
        pkt.put_u64(offset);
        pkt.put_u32(length);
        self.send_sftp_packet(&pkt).await?;

        let resp = self.recv_sftp_packet().await?;
        if resp[0] == SSH_FXP_DATA {
            let data_len = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]) as usize;
            Ok(resp[9..9 + data_len].to_vec())
        } else if resp[0] == SSH_FXP_STATUS {
            let code = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]);
            if code == SSH_FX_EOF {
                Ok(vec![]) // EOF
            } else {
                Err(SshError::ProtocolError(format!("SFTP read failed: status {}", code)))
            }
        } else {
            Err(SshError::ProtocolError(format!("SFTP: unexpected response type {}", resp[0])))
        }
    }

    /// Write to an open file handle.
    pub async fn write(&mut self, handle: &[u8], offset: u64, data: &[u8]) -> Result<(), SshError> {
        let id = self.next_id();
        let mut pkt = BytesMut::new();
        pkt.put_u8(SSH_FXP_WRITE);
        pkt.put_u32(id);
        pkt.put_u32(handle.len() as u32);
        pkt.put_slice(handle);
        pkt.put_u64(offset);
        pkt.put_u32(data.len() as u32);
        pkt.put_slice(data);
        self.send_sftp_packet(&pkt).await?;

        let resp = self.recv_sftp_packet().await?;
        if resp[0] == SSH_FXP_STATUS {
            let code = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]);
            if code == SSH_FX_OK {
                Ok(())
            } else {
                Err(SshError::ProtocolError(format!("SFTP write failed: status {}", code)))
            }
        } else {
            Err(SshError::ProtocolError(format!("SFTP: unexpected response type {}", resp[0])))
        }
    }

    /// Close a file handle.
    pub async fn close(&mut self, handle: &[u8]) -> Result<(), SshError> {
        let id = self.next_id();
        let mut pkt = BytesMut::new();
        pkt.put_u8(SSH_FXP_CLOSE);
        pkt.put_u32(id);
        pkt.put_u32(handle.len() as u32);
        pkt.put_slice(handle);
        self.send_sftp_packet(&pkt).await?;

        let resp = self.recv_sftp_packet().await?;
        if resp[0] == SSH_FXP_STATUS {
            Ok(()) // ignore status code on close
        } else {
            Err(SshError::ProtocolError(format!("SFTP: unexpected close response type {}", resp[0])))
        }
    }

    /// Stat a remote file (get attributes).
    pub async fn stat(&mut self, path: &str) -> Result<SftpAttrs, SshError> {
        let id = self.next_id();
        let mut pkt = BytesMut::new();
        pkt.put_u8(SSH_FXP_STAT);
        pkt.put_u32(id);
        pkt.put_u32(path.len() as u32);
        pkt.put_slice(path.as_bytes());
        self.send_sftp_packet(&pkt).await?;

        let resp = self.recv_sftp_packet().await?;
        if resp[0] == SSH_FXP_ATTRS {
            Ok(Self::decode_attrs(&resp[5..]))
        } else if resp[0] == SSH_FXP_STATUS {
            let code = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]);
            Err(SshError::ProtocolError(format!("SFTP stat failed: status {}", code)))
        } else {
            Err(SshError::ProtocolError(format!("SFTP: unexpected response type {}", resp[0])))
        }
    }

    /// Remove a remote file.
    pub async fn remove(&mut self, path: &str) -> Result<(), SshError> {
        let id = self.next_id();
        let mut pkt = BytesMut::new();
        pkt.put_u8(SSH_FXP_REMOVE);
        pkt.put_u32(id);
        pkt.put_u32(path.len() as u32);
        pkt.put_slice(path.as_bytes());
        self.send_sftp_packet(&pkt).await?;

        let resp = self.recv_sftp_packet().await?;
        if resp[0] == SSH_FXP_STATUS {
            let code = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]);
            if code == SSH_FX_OK {
                Ok(())
            } else {
                Err(SshError::ProtocolError(format!("SFTP remove failed: status {}", code)))
            }
        } else {
            Err(SshError::ProtocolError(format!("SFTP: unexpected response type {}", resp[0])))
        }
    }

    /// Encode SFTP attrs (simplified: just flags=0 for empty attrs).
    fn encode_attrs(buf: &mut BytesMut, attrs: &SftpAttrs) {
        let mut flags = 0u32;
        if attrs.size.is_some() { flags |= 0x01; }
        if attrs.uid.is_some() && attrs.gid.is_some() { flags |= 0x02; }
        if attrs.permissions.is_some() { flags |= 0x04; }

        buf.put_u32(flags);
        if let Some(size) = attrs.size { buf.put_u64(size); }
        if let (Some(uid), Some(gid)) = (attrs.uid, attrs.gid) {
            buf.put_u32(uid);
            buf.put_u32(gid);
        }
        if let Some(perm) = attrs.permissions { buf.put_u32(perm); }
    }

    /// Decode SFTP attrs from response data.
    fn decode_attrs(data: &[u8]) -> SftpAttrs {
        if data.len() < 4 { return SftpAttrs::default(); }
        let flags = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let mut offset = 4;
        let mut attrs = SftpAttrs::default();

        if flags & 0x01 != 0 && offset + 8 <= data.len() {
            attrs.size = Some(u64::from_be_bytes(data[offset..offset+8].try_into().unwrap()));
            offset += 8;
        }
        if flags & 0x02 != 0 && offset + 8 <= data.len() {
            attrs.uid = Some(u32::from_be_bytes(data[offset..offset+4].try_into().unwrap()));
            attrs.gid = Some(u32::from_be_bytes(data[offset+4..offset+8].try_into().unwrap()));
            offset += 8;
        }
        if flags & 0x04 != 0 && offset + 4 <= data.len() {
            attrs.permissions = Some(u32::from_be_bytes(data[offset..offset+4].try_into().unwrap()));
        }

        attrs
    }

    /// Disconnect the SFTP session.
    pub async fn disconnect(&mut self) -> Result<(), SshError> {
        self.session.disconnect().await
    }
}

impl std::fmt::Debug for SftpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpClient")
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

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
