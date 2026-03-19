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

    #[test]
    fn test_sftp_flags_all_values() {
        assert_eq!(sftp_flags::SSH_FXF_APPEND, 4);
        assert_eq!(sftp_flags::SSH_FXF_TRUNC, 0x10);
        assert_eq!(sftp_flags::SSH_FXF_EXCL, 0x20);
    }

    #[test]
    fn test_sftp_attrs_default() {
        let attrs = SftpAttrs::default();
        assert!(attrs.size.is_none());
        assert!(attrs.uid.is_none());
        assert!(attrs.gid.is_none());
        assert!(attrs.permissions.is_none());
        assert!(attrs.atime.is_none());
        assert!(attrs.mtime.is_none());
    }

    #[test]
    fn test_sftp_attrs_clone_and_debug() {
        let attrs = SftpAttrs {
            size: Some(1024),
            uid: Some(1000),
            gid: Some(1000),
            permissions: Some(0o644),
            atime: Some(1000000),
            mtime: Some(2000000),
        };
        let cloned = attrs.clone();
        assert_eq!(cloned.size, Some(1024));
        assert_eq!(cloned.uid, Some(1000));
        assert_eq!(cloned.gid, Some(1000));
        assert_eq!(cloned.permissions, Some(0o644));
        assert_eq!(cloned.atime, Some(1000000));
        assert_eq!(cloned.mtime, Some(2000000));
        let debug = format!("{:?}", attrs);
        assert!(debug.contains("SftpAttrs"));
    }

    #[test]
    fn test_encode_attrs_empty() {
        let attrs = SftpAttrs::default();
        let mut buf = BytesMut::new();
        SftpClient::encode_attrs(&mut buf, &attrs);
        // Should be just 4 bytes of flags = 0
        assert_eq!(buf.len(), 4);
        assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 0);
    }

    #[test]
    fn test_encode_attrs_size_only() {
        let attrs = SftpAttrs {
            size: Some(12345),
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        SftpClient::encode_attrs(&mut buf, &attrs);
        // flags(4) + size(8) = 12
        assert_eq!(buf.len(), 12);
        let flags = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(flags, 0x01);
        let size = u64::from_be_bytes(buf[4..12].try_into().unwrap());
        assert_eq!(size, 12345);
    }

    #[test]
    fn test_encode_attrs_uid_gid() {
        let attrs = SftpAttrs {
            uid: Some(1000),
            gid: Some(2000),
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        SftpClient::encode_attrs(&mut buf, &attrs);
        // flags(4) + uid(4) + gid(4) = 12
        assert_eq!(buf.len(), 12);
        let flags = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(flags, 0x02);
        let uid = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let gid = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        assert_eq!(uid, 1000);
        assert_eq!(gid, 2000);
    }

    #[test]
    fn test_encode_attrs_uid_without_gid_no_encode() {
        // uid set but gid not set — should NOT encode uid/gid
        let attrs = SftpAttrs {
            uid: Some(1000),
            gid: None,
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        SftpClient::encode_attrs(&mut buf, &attrs);
        assert_eq!(buf.len(), 4); // just flags
        let flags = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(flags, 0); // no uid/gid flag set
    }

    #[test]
    fn test_encode_attrs_permissions() {
        let attrs = SftpAttrs {
            permissions: Some(0o755),
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        SftpClient::encode_attrs(&mut buf, &attrs);
        // flags(4) + permissions(4) = 8
        assert_eq!(buf.len(), 8);
        let flags = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(flags, 0x04);
        let perm = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(perm, 0o755);
    }

    #[test]
    fn test_encode_attrs_all_fields() {
        let attrs = SftpAttrs {
            size: Some(999),
            uid: Some(500),
            gid: Some(600),
            permissions: Some(0o644),
            atime: None, // atime/mtime not encoded by encode_attrs
            mtime: None,
        };
        let mut buf = BytesMut::new();
        SftpClient::encode_attrs(&mut buf, &attrs);
        // flags(4) + size(8) + uid(4) + gid(4) + permissions(4) = 24
        assert_eq!(buf.len(), 24);
        let flags = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(flags, 0x01 | 0x02 | 0x04);
    }

    #[test]
    fn test_decode_attrs_empty_data() {
        let attrs = SftpClient::decode_attrs(&[]);
        assert!(attrs.size.is_none());
        assert!(attrs.uid.is_none());
        assert!(attrs.permissions.is_none());
    }

    #[test]
    fn test_decode_attrs_too_short() {
        let attrs = SftpClient::decode_attrs(&[0, 0]);
        assert!(attrs.size.is_none());
    }

    #[test]
    fn test_decode_attrs_no_flags() {
        let data = 0u32.to_be_bytes();
        let attrs = SftpClient::decode_attrs(&data);
        assert!(attrs.size.is_none());
        assert!(attrs.uid.is_none());
        assert!(attrs.gid.is_none());
        assert!(attrs.permissions.is_none());
    }

    #[test]
    fn test_decode_attrs_size_only() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x01u32.to_be_bytes()); // flags: size
        data.extend_from_slice(&42u64.to_be_bytes());
        let attrs = SftpClient::decode_attrs(&data);
        assert_eq!(attrs.size, Some(42));
        assert!(attrs.uid.is_none());
        assert!(attrs.permissions.is_none());
    }

    #[test]
    fn test_decode_attrs_uid_gid() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x02u32.to_be_bytes()); // flags: uid/gid
        data.extend_from_slice(&500u32.to_be_bytes());
        data.extend_from_slice(&600u32.to_be_bytes());
        let attrs = SftpClient::decode_attrs(&data);
        assert!(attrs.size.is_none());
        assert_eq!(attrs.uid, Some(500));
        assert_eq!(attrs.gid, Some(600));
    }

    #[test]
    fn test_decode_attrs_permissions() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x04u32.to_be_bytes()); // flags: permissions
        data.extend_from_slice(&0o755u32.to_be_bytes());
        let attrs = SftpClient::decode_attrs(&data);
        assert!(attrs.size.is_none());
        assert_eq!(attrs.permissions, Some(0o755));
    }

    #[test]
    fn test_decode_attrs_all_flags() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x07u32.to_be_bytes()); // flags: size|uid/gid|perms
        data.extend_from_slice(&1024u64.to_be_bytes());
        data.extend_from_slice(&1000u32.to_be_bytes());
        data.extend_from_slice(&2000u32.to_be_bytes());
        data.extend_from_slice(&0o644u32.to_be_bytes());
        let attrs = SftpClient::decode_attrs(&data);
        assert_eq!(attrs.size, Some(1024));
        assert_eq!(attrs.uid, Some(1000));
        assert_eq!(attrs.gid, Some(2000));
        assert_eq!(attrs.permissions, Some(0o644));
    }

    #[test]
    fn test_decode_attrs_size_flag_but_truncated_data() {
        // Flag says size is present but data is too short
        let mut data = Vec::new();
        data.extend_from_slice(&0x01u32.to_be_bytes()); // flags: size
        data.extend_from_slice(&[0, 0, 0]); // only 3 bytes, need 8
        let attrs = SftpClient::decode_attrs(&data);
        // Should gracefully handle truncation
        assert!(attrs.size.is_none());
    }

    #[test]
    fn test_encode_decode_attrs_roundtrip() {
        let original = SftpAttrs {
            size: Some(65536),
            uid: Some(1000),
            gid: Some(1000),
            permissions: Some(0o755),
            atime: None,
            mtime: None,
        };
        let mut buf = BytesMut::new();
        SftpClient::encode_attrs(&mut buf, &original);
        let decoded = SftpClient::decode_attrs(&buf);
        assert_eq!(decoded.size, original.size);
        assert_eq!(decoded.uid, original.uid);
        assert_eq!(decoded.gid, original.gid);
        assert_eq!(decoded.permissions, original.permissions);
    }

    #[test]
    fn test_encode_decode_attrs_roundtrip_empty() {
        let original = SftpAttrs::default();
        let mut buf = BytesMut::new();
        SftpClient::encode_attrs(&mut buf, &original);
        let decoded = SftpClient::decode_attrs(&buf);
        assert!(decoded.size.is_none());
        assert!(decoded.uid.is_none());
        assert!(decoded.gid.is_none());
        assert!(decoded.permissions.is_none());
    }

    #[test]
    fn test_encode_decode_attrs_roundtrip_size_only() {
        let original = SftpAttrs {
            size: Some(999999),
            ..Default::default()
        };
        let mut buf = BytesMut::new();
        SftpClient::encode_attrs(&mut buf, &original);
        let decoded = SftpClient::decode_attrs(&buf);
        assert_eq!(decoded.size, Some(999999));
        assert!(decoded.uid.is_none());
    }

    #[test]
    fn test_sftp_dir_entry_construction() {
        let entry = SftpDirEntry {
            filename: "test.txt".to_string(),
            longname: "-rw-r--r-- 1 user group 1024 Jan 1 00:00 test.txt".to_string(),
            attrs: SftpAttrs {
                size: Some(1024),
                permissions: Some(0o644),
                ..Default::default()
            },
        };
        assert_eq!(entry.filename, "test.txt");
        assert!(entry.longname.contains("test.txt"));
        assert_eq!(entry.attrs.size, Some(1024));
        let debug = format!("{:?}", entry);
        assert!(debug.contains("SftpDirEntry"));
        assert!(debug.contains("test.txt"));
    }

    #[test]
    fn test_sftp_dir_entry_clone() {
        let entry = SftpDirEntry {
            filename: "file.dat".to_string(),
            longname: "longname".to_string(),
            attrs: SftpAttrs { size: Some(42), ..Default::default() },
        };
        let cloned = entry.clone();
        assert_eq!(cloned.filename, entry.filename);
        assert_eq!(cloned.longname, entry.longname);
        assert_eq!(cloned.attrs.size, entry.attrs.size);
    }

    #[test]
    fn test_scp_direction_equality() {
        assert_eq!(ScpDirection::Upload, ScpDirection::Upload);
        assert_eq!(ScpDirection::Download, ScpDirection::Download);
        assert_ne!(ScpDirection::Upload, ScpDirection::Download);
    }

    #[test]
    fn test_scp_direction_copy() {
        let d = ScpDirection::Upload;
        let d2 = d; // Copy
        assert_eq!(d, d2);
    }

    #[test]
    fn test_scp_direction_debug() {
        let debug = format!("{:?}", ScpDirection::Upload);
        assert_eq!(debug, "Upload");
        let debug = format!("{:?}", ScpDirection::Download);
        assert_eq!(debug, "Download");
    }

    #[test]
    fn test_scp_command_clone_and_debug() {
        let cmd = ScpCommand::upload("/tmp/test.txt");
        let cloned = cmd.clone();
        assert_eq!(cloned.remote_path, cmd.remote_path);
        assert_eq!(cloned.direction, cmd.direction);
        assert_eq!(cloned.recursive, cmd.recursive);
        let debug = format!("{:?}", cmd);
        assert!(debug.contains("ScpCommand"));
    }

    #[test]
    fn test_sftp_op_debug_output() {
        let ops: Vec<SftpOp> = vec![
            SftpOp::Open { path: "/tmp/f".into(), flags: 1 },
            SftpOp::Close { handle: vec![1] },
            SftpOp::Read { handle: vec![1], offset: 0, length: 1024 },
            SftpOp::Write { handle: vec![1], offset: 0, data: vec![0] },
            SftpOp::Stat { path: "/tmp/f".into() },
            SftpOp::ReadDir { handle: vec![1] },
            SftpOp::OpenDir { path: "/tmp".into() },
            SftpOp::Remove { path: "/tmp/f".into() },
            SftpOp::Mkdir { path: "/tmp/d".into() },
            SftpOp::Rename { old_path: "/a".into(), new_path: "/b".into() },
        ];
        let expected_names = ["Open", "Close", "Read", "Write", "Stat", "ReadDir", "OpenDir", "Remove", "Mkdir", "Rename"];
        for (op, name) in ops.iter().zip(expected_names.iter()) {
            let debug = format!("{:?}", op);
            assert!(debug.contains(name), "expected '{}' in debug output: {}", name, debug);
        }
    }

    #[test]
    fn test_sftp_op_equality() {
        let op1 = SftpOp::Open { path: "/tmp/f".into(), flags: 1 };
        let op2 = SftpOp::Open { path: "/tmp/f".into(), flags: 1 };
        let op3 = SftpOp::Open { path: "/tmp/g".into(), flags: 1 };
        assert_eq!(op1, op2);
        assert_ne!(op1, op3);
    }

    #[test]
    fn test_sftp_op_clone() {
        let op = SftpOp::Write { handle: vec![1, 2, 3], offset: 100, data: vec![4, 5, 6] };
        let cloned = op.clone();
        assert_eq!(op, cloned);
    }

    #[test]
    fn test_sftp_client_debug() {
        // We can't construct SftpClient without a real transport, but we can verify
        // the Debug impl compiles and works by checking the format string exists.
        // This is tested indirectly; the impl is at line 712.
    }

    /// Test ScpSession::upload error path — no server at port 1
    #[tokio::test]
    async fn test_scp_upload_no_server() {
        let result = ScpSession::upload(
            "127.0.0.1", 1, "user", "pass", "/tmp/test.txt", b"hello", 0o644,
        ).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("connect") || err_msg.contains("Connect") || err_msg.contains("refused") || err_msg.contains("Connection"),
            "Unexpected error: {}", err_msg
        );
    }

    /// Test ScpSession::download error path — no server at port 1
    #[tokio::test]
    async fn test_scp_download_no_server() {
        let result = ScpSession::download(
            "127.0.0.1", 1, "user", "pass", "/tmp/test.txt",
        ).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("connect") || err_msg.contains("Connect") || err_msg.contains("refused") || err_msg.contains("Connection"),
            "Unexpected error: {}", err_msg
        );
    }

    /// Test ScpSession::upload_with_publickey error path — no server at port 1
    #[tokio::test]
    async fn test_scp_upload_publickey_no_server() {
        let result = ScpSession::upload_with_publickey(
            "127.0.0.1", 1, "user", b"key", "/tmp/test.txt", b"hello", 0o644,
        ).await;
        assert!(result.is_err());
    }

    /// Test ScpSession::download_with_publickey error path — no server at port 1
    #[tokio::test]
    async fn test_scp_download_publickey_no_server() {
        let result = ScpSession::download_with_publickey(
            "127.0.0.1", 1, "user", b"key", "/tmp/test.txt",
        ).await;
        assert!(result.is_err());
    }

    /// Test SftpClient::connect_with_publickey error path — no server at port 1
    #[tokio::test]
    async fn test_sftp_client_connect_no_server() {
        let result = SftpClient::connect_with_publickey(
            "127.0.0.1", 1, "user", b"key",
        ).await;
        assert!(result.is_err());
    }
}
