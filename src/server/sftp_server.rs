//! SFTP Server Implementation
//!
//! Provides a trait-based SFTP server that can be plugged into the test SSH
//! server or used standalone. The `SftpHandler` trait defines the backend
//! operations; `MemoryFs` provides an in-memory implementation for testing.
//!
//! # Architecture
//!
//! ```text
//! SSH Channel ←→ SftpServerSession ←→ SftpHandler (trait)
//!                    (protocol)            ↓
//!                                    MemoryFs / FilesystemFs / ...
//! ```

use crate::error::SshError;
use crate::server::encrypted_io::ServerEncryptedIO;
use crate::sftp::{SftpAttrs, sftp_flags};
use bytes::{BufMut, BytesMut};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// SFTP packet types
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
const SSH_FXP_FSTAT: u8 = 8;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;

const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;
const SSH_FX_NO_SUCH_FILE: u32 = 2;
const SSH_FX_PERMISSION_DENIED: u32 = 3;
const SSH_FX_FAILURE: u32 = 4;

// ==========================================================================
// Handler trait
// ==========================================================================

/// Trait for SFTP backend implementations.
///
/// Implement this to provide custom file storage. All methods are synchronous
/// for simplicity (the SFTP server runs them in the async context but they
/// don't need to be async themselves for typical backends).
pub trait SftpHandler: Send + Sync {
    /// Open a file. Returns a handle ID.
    fn open(&self, path: &str, flags: u32, attrs: &SftpAttrs) -> Result<Vec<u8>, u32>;

    /// Read from an open file handle.
    fn read(&self, handle: &[u8], offset: u64, length: u32) -> Result<Vec<u8>, u32>;

    /// Write to an open file handle.
    fn write(&self, handle: &[u8], offset: u64, data: &[u8]) -> Result<(), u32>;

    /// Close a file handle.
    fn close(&self, handle: &[u8]) -> Result<(), u32>;

    /// Stat a file (get attributes).
    fn stat(&self, path: &str) -> Result<SftpAttrs, u32>;

    /// Remove a file.
    fn remove(&self, path: &str) -> Result<(), u32>;

    /// Create a directory.
    fn mkdir(&self, path: &str, _attrs: &SftpAttrs) -> Result<(), u32> {
        Err(SSH_FX_FAILURE) // default: not implemented
    }

    /// Rename a file.
    fn rename(&self, old_path: &str, new_path: &str) -> Result<(), u32> {
        Err(SSH_FX_FAILURE)
    }

    /// Stat an open file handle (FSTAT).
    fn fstat(&self, handle: &[u8]) -> Result<SftpAttrs, u32> {
        Err(SSH_FX_FAILURE)
    }

    /// Resolve a path to its canonical form (REALPATH).
    /// Default: returns the path unchanged.
    fn realpath(&self, path: &str) -> Result<String, u32> {
        Ok(path.to_string())
    }

    /// Open a directory for reading. Returns a handle.
    fn opendir(&self, path: &str) -> Result<Vec<u8>, u32> {
        Err(SSH_FX_FAILURE)
    }

    /// Read directory entries from an open directory handle.
    /// Returns a list of (filename, longname, attrs) entries.
    /// Return Err(SSH_FX_EOF) when all entries have been returned.
    fn readdir(&self, handle: &[u8]) -> Result<Vec<(String, String, SftpAttrs)>, u32> {
        Err(SSH_FX_EOF)
    }
}

// ==========================================================================
// In-memory filesystem
// ==========================================================================

/// An in-memory file stored in MemoryFs.
#[derive(Debug, Clone)]
struct MemoryFile {
    data: Vec<u8>,
    permissions: u32,
}

/// In-memory filesystem for testing.
///
/// Thread-safe via internal `Mutex`. Files are stored as `HashMap<String, Vec<u8>>`.
#[derive(Debug, Clone)]
pub struct MemoryFs {
    files: Arc<Mutex<HashMap<String, MemoryFile>>>,
    handles: Arc<Mutex<HashMap<u32, String>>>,       // file handle_id → path
    dir_handles: Arc<Mutex<HashMap<u32, DirHandle>>>, // dir handle_id → state
    next_handle: Arc<Mutex<u32>>,
}

/// State for an open directory listing.
#[derive(Debug, Clone)]
struct DirHandle {
    path: String,
    returned: bool, // true after entries have been returned (next call → EOF)
}

impl MemoryFs {
    /// Create an empty in-memory filesystem.
    pub fn new() -> Self {
        Self {
            files: Arc::new(Mutex::new(HashMap::new())),
            handles: Arc::new(Mutex::new(HashMap::new())),
            dir_handles: Arc::new(Mutex::new(HashMap::new())),
            next_handle: Arc::new(Mutex::new(1)),
        }
    }

    /// Pre-populate a file.
    pub fn add_file(&self, path: &str, data: &[u8], permissions: u32) {
        self.files.lock().unwrap().insert(path.to_string(), MemoryFile {
            data: data.to_vec(),
            permissions,
        });
    }

    /// Get a file's contents (for test verification).
    pub fn get_file(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().unwrap().get(path).map(|f| f.data.clone())
    }

    /// List all file paths.
    pub fn list_files(&self) -> Vec<String> {
        self.files.lock().unwrap().keys().cloned().collect()
    }

    fn alloc_handle(&self) -> u32 {
        let mut next = self.next_handle.lock().unwrap();
        let id = *next;
        *next += 1;
        id
    }
}

impl Default for MemoryFs {
    fn default() -> Self {
        Self::new()
    }
}

impl SftpHandler for MemoryFs {
    fn open(&self, path: &str, flags: u32, attrs: &SftpAttrs) -> Result<Vec<u8>, u32> {
        let mut files = self.files.lock().unwrap();

        if flags & sftp_flags::SSH_FXF_CREAT != 0 {
            if !files.contains_key(path) || flags & sftp_flags::SSH_FXF_TRUNC != 0 {
                files.insert(path.to_string(), MemoryFile {
                    data: Vec::new(),
                    permissions: attrs.permissions.unwrap_or(0o644),
                });
            }
        }

        if !files.contains_key(path) {
            return Err(SSH_FX_NO_SUCH_FILE);
        }

        let handle_id = self.alloc_handle();
        self.handles.lock().unwrap().insert(handle_id, path.to_string());

        Ok(handle_id.to_be_bytes().to_vec())
    }

    fn read(&self, handle: &[u8], offset: u64, length: u32) -> Result<Vec<u8>, u32> {
        if handle.len() != 4 { return Err(SSH_FX_FAILURE); }
        let handle_id = u32::from_be_bytes([handle[0], handle[1], handle[2], handle[3]]);

        let handles = self.handles.lock().unwrap();
        let path = handles.get(&handle_id).ok_or(SSH_FX_FAILURE)?;

        let files = self.files.lock().unwrap();
        let file = files.get(path).ok_or(SSH_FX_NO_SUCH_FILE)?;

        let start = offset as usize;
        if start >= file.data.len() {
            return Err(SSH_FX_EOF);
        }

        let end = (start + length as usize).min(file.data.len());
        Ok(file.data[start..end].to_vec())
    }

    fn write(&self, handle: &[u8], offset: u64, data: &[u8]) -> Result<(), u32> {
        if handle.len() != 4 { return Err(SSH_FX_FAILURE); }
        let handle_id = u32::from_be_bytes([handle[0], handle[1], handle[2], handle[3]]);

        let handles = self.handles.lock().unwrap();
        let path = handles.get(&handle_id).ok_or(SSH_FX_FAILURE)?;

        let mut files = self.files.lock().unwrap();
        let file = files.get_mut(path).ok_or(SSH_FX_NO_SUCH_FILE)?;

        let start = offset as usize;
        let end = start + data.len();
        if end > file.data.len() {
            file.data.resize(end, 0);
        }
        file.data[start..end].copy_from_slice(data);
        Ok(())
    }

    fn close(&self, handle: &[u8]) -> Result<(), u32> {
        if handle.len() != 4 { return Err(SSH_FX_FAILURE); }
        let handle_id = u32::from_be_bytes([handle[0], handle[1], handle[2], handle[3]]);
        self.handles.lock().unwrap().remove(&handle_id);
        self.dir_handles.lock().unwrap().remove(&handle_id);
        Ok(())
    }

    fn stat(&self, path: &str) -> Result<SftpAttrs, u32> {
        let files = self.files.lock().unwrap();
        let file = files.get(path).ok_or(SSH_FX_NO_SUCH_FILE)?;
        Ok(SftpAttrs {
            size: Some(file.data.len() as u64),
            permissions: Some(file.permissions),
            ..Default::default()
        })
    }

    fn remove(&self, path: &str) -> Result<(), u32> {
        let mut files = self.files.lock().unwrap();
        if files.remove(path).is_some() {
            Ok(())
        } else {
            Err(SSH_FX_NO_SUCH_FILE)
        }
    }

    fn mkdir(&self, _path: &str, _attrs: &SftpAttrs) -> Result<(), u32> {
        Ok(()) // no-op for flat file store
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<(), u32> {
        let mut files = self.files.lock().unwrap();
        if let Some(file) = files.remove(old_path) {
            files.insert(new_path.to_string(), file);
            Ok(())
        } else {
            Err(SSH_FX_NO_SUCH_FILE)
        }
    }

    fn fstat(&self, handle: &[u8]) -> Result<SftpAttrs, u32> {
        if handle.len() != 4 { return Err(SSH_FX_FAILURE); }
        let handle_id = u32::from_be_bytes([handle[0], handle[1], handle[2], handle[3]]);

        let handles = self.handles.lock().unwrap();
        let path = handles.get(&handle_id).ok_or(SSH_FX_FAILURE)?;

        let files = self.files.lock().unwrap();
        let file = files.get(path).ok_or(SSH_FX_NO_SUCH_FILE)?;
        Ok(SftpAttrs {
            size: Some(file.data.len() as u64),
            permissions: Some(file.permissions),
            ..Default::default()
        })
    }

    fn realpath(&self, path: &str) -> Result<String, u32> {
        // Normalize: collapse "." and resolve relative to "/"
        if path == "." || path.is_empty() {
            Ok("/".to_string())
        } else if path.starts_with('/') {
            Ok(path.to_string())
        } else {
            Ok(format!("/{}", path))
        }
    }

    fn opendir(&self, path: &str) -> Result<Vec<u8>, u32> {
        let handle_id = self.alloc_handle();
        self.dir_handles.lock().unwrap().insert(handle_id, DirHandle {
            path: path.to_string(),
            returned: false,
        });
        Ok(handle_id.to_be_bytes().to_vec())
    }

    fn readdir(&self, handle: &[u8]) -> Result<Vec<(String, String, SftpAttrs)>, u32> {
        if handle.len() != 4 { return Err(SSH_FX_FAILURE); }
        let handle_id = u32::from_be_bytes([handle[0], handle[1], handle[2], handle[3]]);

        let mut dir_handles = self.dir_handles.lock().unwrap();
        let dir_handle = dir_handles.get_mut(&handle_id).ok_or(SSH_FX_FAILURE)?;

        if dir_handle.returned {
            return Err(SSH_FX_EOF); // Already returned entries
        }
        dir_handle.returned = true;

        let files = self.files.lock().unwrap();
        let prefix = if dir_handle.path == "/" { String::new() } else { dir_handle.path.clone() };

        let mut entries = Vec::new();

        // Add "." and ".." entries
        entries.push((".".to_string(), "drwxr-xr-x 1 0 0 0 Jan 1 00:00 .".to_string(),
            SftpAttrs { permissions: Some(0o40755), ..Default::default() }));
        entries.push(("..".to_string(), "drwxr-xr-x 1 0 0 0 Jan 1 00:00 ..".to_string(),
            SftpAttrs { permissions: Some(0o40755), ..Default::default() }));

        for (path, file) in files.iter() {
            // Check if this file is in the requested directory
            let name = if prefix.is_empty() {
                // Root listing: show files at top level
                if path.starts_with('/') && !path[1..].contains('/') {
                    &path[1..]
                } else {
                    continue;
                }
            } else if let Some(rest) = path.strip_prefix(&format!("{}/", prefix)) {
                if rest.contains('/') { continue; } // skip nested
                rest
            } else {
                continue;
            };

            let longname = format!("-rw-r--r-- 1 0 0 {} Jan 1 00:00 {}",
                file.data.len(), name);
            entries.push((name.to_string(), longname, SftpAttrs {
                size: Some(file.data.len() as u64),
                permissions: Some(file.permissions),
                ..Default::default()
            }));
        }

        Ok(entries)
    }
}

// ==========================================================================
// SFTP Server Session (protocol handler)
// ==========================================================================

/// Runs an SFTP server session over an SSH channel.
///
/// Reads SFTP packets from the channel, dispatches to the `SftpHandler`,
/// and sends responses back. Call `run()` after the SFTP subsystem has
/// been established.
pub struct SftpServerSession<H: SftpHandler> {
    handler: Arc<H>,
}

impl<H: SftpHandler + 'static> SftpServerSession<H> {
    pub fn new(handler: Arc<H>) -> Self {
        Self { handler }
    }

    /// Run the SFTP server loop on an SSH channel.
    ///
    /// `io` is the encrypted SSH I/O, `client_channel` is the channel ID
    /// for sending data back to the client.
    pub async fn run(
        &self,
        io: &mut ServerEncryptedIO,
        client_channel: u32,
    ) -> Result<(), SshError> {
        loop {
            // Read SFTP packet from channel
            let msg = match io.recv_message().await {
                Ok(m) => m,
                Err(_) => break, // connection closed
            };

            if msg.is_empty() { continue; }

            // Extract SFTP data from CHANNEL_DATA
            if msg[0] != 94 { continue; } // not CHANNEL_DATA
            if msg.len() < 9 { continue; }
            let data_len = u32::from_be_bytes([msg[5], msg[6], msg[7], msg[8]]) as usize;
            if msg.len() < 9 + data_len { continue; }
            let sftp_data = &msg[9..9 + data_len];

            // Parse SFTP packet: 4-byte length + payload
            if sftp_data.len() < 4 { continue; }
            let pkt_len = u32::from_be_bytes([sftp_data[0], sftp_data[1], sftp_data[2], sftp_data[3]]) as usize;
            if sftp_data.len() < 4 + pkt_len { continue; }
            let pkt = &sftp_data[4..4 + pkt_len];

            if pkt.is_empty() { continue; }

            let response = self.handle_packet(pkt);

            // Send response as CHANNEL_DATA with SFTP framing
            let mut resp_msg = BytesMut::new();
            resp_msg.put_u8(94); // CHANNEL_DATA
            resp_msg.put_u32(client_channel);
            // SFTP framing: 4-byte length + response
            let framed_len = 4 + response.len();
            resp_msg.put_u32(framed_len as u32);
            resp_msg.put_u32(response.len() as u32);
            resp_msg.put_slice(&response);

            io.send_message(&resp_msg).await?;
        }

        Ok(())
    }

    /// Handle a single SFTP packet and return the response.
    fn handle_packet(&self, pkt: &[u8]) -> Vec<u8> {
        let pkt_type = pkt[0];

        match pkt_type {
            SSH_FXP_INIT => self.handle_init(pkt),
            SSH_FXP_OPEN => self.handle_open(pkt),
            SSH_FXP_CLOSE => self.handle_close(pkt),
            SSH_FXP_READ => self.handle_read(pkt),
            SSH_FXP_WRITE => self.handle_write(pkt),
            SSH_FXP_STAT => self.handle_stat(pkt),
            SSH_FXP_FSTAT => self.handle_fstat(pkt),
            SSH_FXP_REMOVE => self.handle_remove(pkt),
            SSH_FXP_MKDIR => self.handle_mkdir(pkt),
            SSH_FXP_RENAME => self.handle_rename(pkt),
            SSH_FXP_REALPATH => self.handle_realpath(pkt),
            SSH_FXP_OPENDIR => self.handle_opendir(pkt),
            SSH_FXP_READDIR => self.handle_readdir(pkt),
            _ => self.make_status(0, SSH_FX_FAILURE, "Unsupported operation"),
        }
    }

    fn handle_init(&self, _pkt: &[u8]) -> Vec<u8> {
        let mut resp = BytesMut::new();
        resp.put_u8(SSH_FXP_VERSION);
        resp.put_u32(3); // SFTP version 3
        resp.to_vec()
    }

    fn handle_open(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
        let mut offset = 5;

        let (path, new_offset) = match self.read_string(pkt, offset) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad path"),
        };
        offset = new_offset;

        if offset + 4 > pkt.len() { return self.make_status(id, SSH_FX_FAILURE, "Truncated flags"); }
        let flags = u32::from_be_bytes([pkt[offset], pkt[offset+1], pkt[offset+2], pkt[offset+3]]);
        offset += 4;

        let attrs = self.parse_attrs(pkt, offset);

        match self.handler.open(&path, flags, &attrs) {
            Ok(handle) => {
                let mut resp = BytesMut::new();
                resp.put_u8(SSH_FXP_HANDLE);
                resp.put_u32(id);
                resp.put_u32(handle.len() as u32);
                resp.put_slice(&handle);
                resp.to_vec()
            }
            Err(code) => self.make_status(id, code, "Open failed"),
        }
    }

    fn handle_close(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);

        let (handle, _) = match self.read_string_bytes(pkt, 5) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad handle"),
        };

        match self.handler.close(&handle) {
            Ok(()) => self.make_status(id, SSH_FX_OK, ""),
            Err(code) => self.make_status(id, code, "Close failed"),
        }
    }

    fn handle_read(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);

        let (handle, offset_pos) = match self.read_string_bytes(pkt, 5) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad handle"),
        };

        if offset_pos + 12 > pkt.len() { return self.make_status(id, SSH_FX_FAILURE, "Truncated"); }
        let file_offset = u64::from_be_bytes([
            pkt[offset_pos], pkt[offset_pos+1], pkt[offset_pos+2], pkt[offset_pos+3],
            pkt[offset_pos+4], pkt[offset_pos+5], pkt[offset_pos+6], pkt[offset_pos+7],
        ]);
        let length = u32::from_be_bytes([
            pkt[offset_pos+8], pkt[offset_pos+9], pkt[offset_pos+10], pkt[offset_pos+11],
        ]);

        match self.handler.read(&handle, file_offset, length) {
            Ok(data) => {
                let mut resp = BytesMut::new();
                resp.put_u8(SSH_FXP_DATA);
                resp.put_u32(id);
                resp.put_u32(data.len() as u32);
                resp.put_slice(&data);
                resp.to_vec()
            }
            Err(code) => self.make_status(id, code, if code == SSH_FX_EOF { "EOF" } else { "Read failed" }),
        }
    }

    fn handle_write(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);

        let (handle, offset_pos) = match self.read_string_bytes(pkt, 5) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad handle"),
        };

        if offset_pos + 8 > pkt.len() { return self.make_status(id, SSH_FX_FAILURE, "Truncated"); }
        let file_offset = u64::from_be_bytes([
            pkt[offset_pos], pkt[offset_pos+1], pkt[offset_pos+2], pkt[offset_pos+3],
            pkt[offset_pos+4], pkt[offset_pos+5], pkt[offset_pos+6], pkt[offset_pos+7],
        ]);

        let (data, _) = match self.read_string_bytes(pkt, offset_pos + 8) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad data"),
        };

        match self.handler.write(&handle, file_offset, &data) {
            Ok(()) => self.make_status(id, SSH_FX_OK, ""),
            Err(code) => self.make_status(id, code, "Write failed"),
        }
    }

    fn handle_stat(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);

        let (path, _) = match self.read_string(pkt, 5) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad path"),
        };

        match self.handler.stat(&path) {
            Ok(attrs) => {
                let mut resp = BytesMut::new();
                resp.put_u8(SSH_FXP_ATTRS);
                resp.put_u32(id);
                Self::encode_attrs(&mut resp, &attrs);
                resp.to_vec()
            }
            Err(code) => self.make_status(id, code, "Stat failed"),
        }
    }

    fn handle_remove(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);

        let (path, _) = match self.read_string(pkt, 5) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad path"),
        };

        match self.handler.remove(&path) {
            Ok(()) => self.make_status(id, SSH_FX_OK, ""),
            Err(code) => self.make_status(id, code, "Remove failed"),
        }
    }

    fn handle_mkdir(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);

        let (path, offset) = match self.read_string(pkt, 5) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad path"),
        };
        let attrs = self.parse_attrs(pkt, offset);

        match self.handler.mkdir(&path, &attrs) {
            Ok(()) => self.make_status(id, SSH_FX_OK, ""),
            Err(code) => self.make_status(id, code, "Mkdir failed"),
        }
    }

    fn handle_rename(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);

        let (old_path, offset) = match self.read_string(pkt, 5) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad old path"),
        };
        let (new_path, _) = match self.read_string(pkt, offset) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad new path"),
        };

        match self.handler.rename(&old_path, &new_path) {
            Ok(()) => self.make_status(id, SSH_FX_OK, ""),
            Err(code) => self.make_status(id, code, "Rename failed"),
        }
    }

    fn handle_fstat(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);

        let (handle, _) = match self.read_string_bytes(pkt, 5) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad handle"),
        };

        match self.handler.fstat(&handle) {
            Ok(attrs) => {
                let mut resp = BytesMut::new();
                resp.put_u8(SSH_FXP_ATTRS);
                resp.put_u32(id);
                Self::encode_attrs(&mut resp, &attrs);
                resp.to_vec()
            }
            Err(code) => self.make_status(id, code, "Fstat failed"),
        }
    }

    fn handle_realpath(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);

        let (path, _) = match self.read_string(pkt, 5) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad path"),
        };

        match self.handler.realpath(&path) {
            Ok(resolved) => {
                // SSH_FXP_NAME response with single entry
                let mut resp = BytesMut::new();
                resp.put_u8(SSH_FXP_NAME);
                resp.put_u32(id);
                resp.put_u32(1); // count = 1
                // filename
                resp.put_u32(resolved.len() as u32);
                resp.put_slice(resolved.as_bytes());
                // longname (same as filename for realpath)
                resp.put_u32(resolved.len() as u32);
                resp.put_slice(resolved.as_bytes());
                // attrs (empty)
                resp.put_u32(0); // flags = 0
                resp.to_vec()
            }
            Err(code) => self.make_status(id, code, "Realpath failed"),
        }
    }

    fn handle_opendir(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);

        let (path, _) = match self.read_string(pkt, 5) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad path"),
        };

        match self.handler.opendir(&path) {
            Ok(handle) => {
                let mut resp = BytesMut::new();
                resp.put_u8(SSH_FXP_HANDLE);
                resp.put_u32(id);
                resp.put_u32(handle.len() as u32);
                resp.put_slice(&handle);
                resp.to_vec()
            }
            Err(code) => self.make_status(id, code, "Opendir failed"),
        }
    }

    fn handle_readdir(&self, pkt: &[u8]) -> Vec<u8> {
        if pkt.len() < 5 { return self.make_status(0, SSH_FX_FAILURE, "Truncated"); }
        let id = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);

        let (handle, _) = match self.read_string_bytes(pkt, 5) {
            Some(v) => v,
            None => return self.make_status(id, SSH_FX_FAILURE, "Bad handle"),
        };

        match self.handler.readdir(&handle) {
            Ok(entries) => {
                let mut resp = BytesMut::new();
                resp.put_u8(SSH_FXP_NAME);
                resp.put_u32(id);
                resp.put_u32(entries.len() as u32);

                for (filename, longname, attrs) in &entries {
                    resp.put_u32(filename.len() as u32);
                    resp.put_slice(filename.as_bytes());
                    resp.put_u32(longname.len() as u32);
                    resp.put_slice(longname.as_bytes());
                    Self::encode_attrs(&mut resp, attrs);
                }

                resp.to_vec()
            }
            Err(code) => self.make_status(id, code, if code == SSH_FX_EOF { "EOF" } else { "Readdir failed" }),
        }
    }

    // --- Helpers ---

    fn make_status(&self, id: u32, code: u32, message: &str) -> Vec<u8> {
        let mut resp = BytesMut::new();
        resp.put_u8(SSH_FXP_STATUS);
        resp.put_u32(id);
        resp.put_u32(code);
        resp.put_u32(message.len() as u32);
        resp.put_slice(message.as_bytes());
        resp.put_u32(0); // language tag (empty)
        resp.to_vec()
    }

    fn read_string(&self, data: &[u8], offset: usize) -> Option<(String, usize)> {
        if offset + 4 > data.len() { return None; }
        let len = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
        if offset + 4 + len > data.len() { return None; }
        let s = String::from_utf8_lossy(&data[offset+4..offset+4+len]).to_string();
        Some((s, offset + 4 + len))
    }

    fn read_string_bytes(&self, data: &[u8], offset: usize) -> Option<(Vec<u8>, usize)> {
        if offset + 4 > data.len() { return None; }
        let len = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]) as usize;
        if offset + 4 + len > data.len() { return None; }
        Some((data[offset+4..offset+4+len].to_vec(), offset + 4 + len))
    }

    fn parse_attrs(&self, data: &[u8], offset: usize) -> SftpAttrs {
        if offset + 4 > data.len() { return SftpAttrs::default(); }
        let flags = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        let mut pos = offset + 4;
        let mut attrs = SftpAttrs::default();

        if flags & 0x01 != 0 && pos + 8 <= data.len() {
            attrs.size = Some(u64::from_be_bytes(data[pos..pos+8].try_into().unwrap()));
            pos += 8;
        }
        if flags & 0x02 != 0 && pos + 8 <= data.len() {
            attrs.uid = Some(u32::from_be_bytes(data[pos..pos+4].try_into().unwrap()));
            attrs.gid = Some(u32::from_be_bytes(data[pos+4..pos+8].try_into().unwrap()));
            pos += 8;
        }
        if flags & 0x04 != 0 && pos + 4 <= data.len() {
            attrs.permissions = Some(u32::from_be_bytes(data[pos..pos+4].try_into().unwrap()));
        }

        attrs
    }

    fn encode_attrs(buf: &mut BytesMut, attrs: &SftpAttrs) {
        let mut flags = 0u32;
        if attrs.size.is_some() { flags |= 0x01; }
        if attrs.uid.is_some() && attrs.gid.is_some() { flags |= 0x02; }
        if attrs.permissions.is_some() { flags |= 0x04; }

        buf.put_u32(flags);
        if let Some(size) = attrs.size { buf.put_u64(size); }
        if let (Some(uid), Some(gid)) = (attrs.uid, attrs.gid) {
            buf.put_u32(uid); buf.put_u32(gid);
        }
        if let Some(perm) = attrs.permissions { buf.put_u32(perm); }
    }
}

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_fs_basic() {
        let fs = MemoryFs::new();
        fs.add_file("/tmp/test.txt", b"hello world", 0o644);

        assert_eq!(fs.get_file("/tmp/test.txt"), Some(b"hello world".to_vec()));
        assert_eq!(fs.get_file("/nonexistent"), None);
        assert_eq!(fs.list_files().len(), 1);
    }

    #[test]
    fn test_memory_fs_open_read_write_close() {
        let fs = MemoryFs::new();

        // Open + create
        let handle = fs.open("/tmp/new.txt", sftp_flags::SSH_FXF_WRITE | sftp_flags::SSH_FXF_CREAT, &SftpAttrs::default()).unwrap();

        // Write
        fs.write(&handle, 0, b"hello").unwrap();
        fs.write(&handle, 5, b" world").unwrap();

        // Close
        fs.close(&handle).unwrap();

        // Open for read
        let handle = fs.open("/tmp/new.txt", sftp_flags::SSH_FXF_READ, &SftpAttrs::default()).unwrap();

        // Read
        let data = fs.read(&handle, 0, 100).unwrap();
        assert_eq!(data, b"hello world");

        // Read past EOF
        let eof = fs.read(&handle, 100, 10);
        assert_eq!(eof, Err(SSH_FX_EOF));

        fs.close(&handle).unwrap();
    }

    #[test]
    fn test_memory_fs_stat() {
        let fs = MemoryFs::new();
        fs.add_file("/f.txt", b"data", 0o755);

        let attrs = fs.stat("/f.txt").unwrap();
        assert_eq!(attrs.size, Some(4));
        assert_eq!(attrs.permissions, Some(0o755));

        assert_eq!(fs.stat("/nope"), Err(SSH_FX_NO_SUCH_FILE));
    }

    #[test]
    fn test_memory_fs_remove() {
        let fs = MemoryFs::new();
        fs.add_file("/f.txt", b"data", 0o644);

        fs.remove("/f.txt").unwrap();
        assert_eq!(fs.get_file("/f.txt"), None);
        assert_eq!(fs.remove("/f.txt"), Err(SSH_FX_NO_SUCH_FILE));
    }

    #[test]
    fn test_memory_fs_rename() {
        let fs = MemoryFs::new();
        fs.add_file("/old.txt", b"content", 0o644);

        fs.rename("/old.txt", "/new.txt").unwrap();
        assert_eq!(fs.get_file("/old.txt"), None);
        assert_eq!(fs.get_file("/new.txt"), Some(b"content".to_vec()));
    }

    #[test]
    fn test_memory_fs_open_nonexistent() {
        let fs = MemoryFs::new();
        let result = fs.open("/nope", sftp_flags::SSH_FXF_READ, &SftpAttrs::default());
        assert_eq!(result, Err(SSH_FX_NO_SUCH_FILE));
    }

    #[test]
    fn test_memory_fs_overwrite() {
        let fs = MemoryFs::new();
        fs.add_file("/f.txt", b"old", 0o644);

        let handle = fs.open("/f.txt",
            sftp_flags::SSH_FXF_WRITE | sftp_flags::SSH_FXF_CREAT | sftp_flags::SSH_FXF_TRUNC,
            &SftpAttrs::default(),
        ).unwrap();

        fs.write(&handle, 0, b"new content").unwrap();
        fs.close(&handle).unwrap();

        assert_eq!(fs.get_file("/f.txt"), Some(b"new content".to_vec()));
    }

    #[test]
    fn test_sftp_server_handle_init() {
        let handler = Arc::new(MemoryFs::new());
        let server = SftpServerSession::new(handler);

        let mut pkt = vec![SSH_FXP_INIT];
        pkt.extend_from_slice(&3u32.to_be_bytes());

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_VERSION);
        assert_eq!(u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]]), 3);
    }

    #[test]
    fn test_sftp_server_open_write_read_close() {
        let fs = Arc::new(MemoryFs::new());
        let server = SftpServerSession::new(fs.clone());

        // OPEN (create)
        let path = "/test.txt";
        let flags = sftp_flags::SSH_FXF_WRITE | sftp_flags::SSH_FXF_CREAT;
        let mut pkt = vec![SSH_FXP_OPEN];
        pkt.extend_from_slice(&1u32.to_be_bytes()); // id
        pkt.extend_from_slice(&(path.len() as u32).to_be_bytes());
        pkt.extend_from_slice(path.as_bytes());
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // attrs flags = 0

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_HANDLE);
        let handle_len = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]) as usize;
        let handle = resp[9..9+handle_len].to_vec();

        // WRITE
        let data = b"hello sftp server!";
        let mut pkt = vec![SSH_FXP_WRITE];
        pkt.extend_from_slice(&2u32.to_be_bytes()); // id
        pkt.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        pkt.extend_from_slice(&handle);
        pkt.extend_from_slice(&0u64.to_be_bytes()); // offset
        pkt.extend_from_slice(&(data.len() as u32).to_be_bytes());
        pkt.extend_from_slice(data);

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_STATUS);
        assert_eq!(u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]), SSH_FX_OK);

        // CLOSE
        let mut pkt = vec![SSH_FXP_CLOSE];
        pkt.extend_from_slice(&3u32.to_be_bytes());
        pkt.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        pkt.extend_from_slice(&handle);
        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_STATUS);

        // Verify via MemoryFs
        assert_eq!(fs.get_file("/test.txt"), Some(data.to_vec()));

        // OPEN for read
        let flags = sftp_flags::SSH_FXF_READ;
        let mut pkt = vec![SSH_FXP_OPEN];
        pkt.extend_from_slice(&4u32.to_be_bytes());
        pkt.extend_from_slice(&(path.len() as u32).to_be_bytes());
        pkt.extend_from_slice(path.as_bytes());
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_HANDLE);
        let handle_len = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]) as usize;
        let handle2 = resp[9..9+handle_len].to_vec();

        // READ
        let mut pkt = vec![SSH_FXP_READ];
        pkt.extend_from_slice(&5u32.to_be_bytes());
        pkt.extend_from_slice(&(handle2.len() as u32).to_be_bytes());
        pkt.extend_from_slice(&handle2);
        pkt.extend_from_slice(&0u64.to_be_bytes()); // offset
        pkt.extend_from_slice(&1024u32.to_be_bytes()); // length

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_DATA);
        let data_len = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]) as usize;
        assert_eq!(&resp[9..9+data_len], data);
    }

    #[test]
    fn test_sftp_server_stat_remove() {
        let fs = Arc::new(MemoryFs::new());
        fs.add_file("/f.txt", b"data", 0o755);
        let server = SftpServerSession::new(fs.clone());

        // STAT
        let path = "/f.txt";
        let mut pkt = vec![SSH_FXP_STAT];
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&(path.len() as u32).to_be_bytes());
        pkt.extend_from_slice(path.as_bytes());

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_ATTRS);

        // REMOVE
        let mut pkt = vec![SSH_FXP_REMOVE];
        pkt.extend_from_slice(&2u32.to_be_bytes());
        pkt.extend_from_slice(&(path.len() as u32).to_be_bytes());
        pkt.extend_from_slice(path.as_bytes());

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_STATUS);
        assert_eq!(u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]), SSH_FX_OK);

        // STAT after remove should fail
        let mut pkt = vec![SSH_FXP_STAT];
        pkt.extend_from_slice(&3u32.to_be_bytes());
        pkt.extend_from_slice(&(path.len() as u32).to_be_bytes());
        pkt.extend_from_slice(path.as_bytes());

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_STATUS);
        assert_eq!(u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]), SSH_FX_NO_SUCH_FILE);
    }

    #[test]
    fn test_memory_fs_fstat() {
        let fs = MemoryFs::new();
        let handle = fs.open("/f.txt", sftp_flags::SSH_FXF_WRITE | sftp_flags::SSH_FXF_CREAT, &SftpAttrs::default()).unwrap();
        fs.write(&handle, 0, b"test data").unwrap();
        let attrs = fs.fstat(&handle).unwrap();
        assert_eq!(attrs.size, Some(9));
    }

    #[test]
    fn test_memory_fs_realpath() {
        let fs = MemoryFs::new();
        assert_eq!(fs.realpath(".").unwrap(), "/");
        assert_eq!(fs.realpath("").unwrap(), "/");
        assert_eq!(fs.realpath("/home/user").unwrap(), "/home/user");
        assert_eq!(fs.realpath("relative").unwrap(), "/relative");
    }

    #[test]
    fn test_memory_fs_opendir_readdir() {
        let fs = MemoryFs::new();
        fs.add_file("/file1.txt", b"data1", 0o644);
        fs.add_file("/file2.txt", b"data2", 0o755);
        fs.add_file("/subdir/file3.txt", b"nested", 0o644);

        let handle = fs.opendir("/").unwrap();

        // First readdir returns entries
        let entries = fs.readdir(&handle).unwrap();
        let filenames: Vec<&str> = entries.iter().map(|(n, _, _)| n.as_str()).collect();
        assert!(filenames.contains(&"."));
        assert!(filenames.contains(&".."));
        assert!(filenames.contains(&"file1.txt"));
        assert!(filenames.contains(&"file2.txt"));
        // subdir/file3.txt should not appear in root listing
        assert!(!filenames.contains(&"file3.txt"));

        // Second readdir returns EOF
        assert_eq!(fs.readdir(&handle), Err(SSH_FX_EOF));

        fs.close(&handle).unwrap();
    }

    #[test]
    fn test_sftp_server_realpath() {
        let handler = Arc::new(MemoryFs::new());
        let server = SftpServerSession::new(handler);

        let mut pkt = vec![SSH_FXP_REALPATH];
        pkt.extend_from_slice(&1u32.to_be_bytes()); // id
        let path = b".";
        pkt.extend_from_slice(&(path.len() as u32).to_be_bytes());
        pkt.extend_from_slice(path);

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_NAME);
        // count = 1
        assert_eq!(u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]), 1);
        // filename should be "/"
        let name_len = u32::from_be_bytes([resp[9], resp[10], resp[11], resp[12]]) as usize;
        assert_eq!(&resp[13..13+name_len], b"/");
    }

    #[test]
    fn test_sftp_server_fstat() {
        let fs = Arc::new(MemoryFs::new());
        let server = SftpServerSession::new(fs.clone());

        // Create and write a file
        let path = "/fstat_test.txt";
        let flags = sftp_flags::SSH_FXF_WRITE | sftp_flags::SSH_FXF_CREAT;
        let mut pkt = vec![SSH_FXP_OPEN];
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&(path.len() as u32).to_be_bytes());
        pkt.extend_from_slice(path.as_bytes());
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_HANDLE);
        let handle_len = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]) as usize;
        let handle = resp[9..9+handle_len].to_vec();

        // Write data
        let data = b"fstat test data!";
        let mut pkt = vec![SSH_FXP_WRITE];
        pkt.extend_from_slice(&2u32.to_be_bytes());
        pkt.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        pkt.extend_from_slice(&handle);
        pkt.extend_from_slice(&0u64.to_be_bytes());
        pkt.extend_from_slice(&(data.len() as u32).to_be_bytes());
        pkt.extend_from_slice(data);
        server.handle_packet(&pkt);

        // FSTAT
        let mut pkt = vec![SSH_FXP_FSTAT];
        pkt.extend_from_slice(&3u32.to_be_bytes());
        pkt.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        pkt.extend_from_slice(&handle);

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_ATTRS);
        // Parse size from attrs
        let flags = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]);
        assert!(flags & 0x01 != 0); // size flag set
        let size = u64::from_be_bytes(resp[9..17].try_into().unwrap());
        assert_eq!(size, data.len() as u64);
    }

    #[test]
    fn test_sftp_server_opendir_readdir() {
        let fs = Arc::new(MemoryFs::new());
        fs.add_file("/dir_test.txt", b"hello", 0o644);
        let server = SftpServerSession::new(fs);

        // OPENDIR
        let path = "/";
        let mut pkt = vec![SSH_FXP_OPENDIR];
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&(path.len() as u32).to_be_bytes());
        pkt.extend_from_slice(path.as_bytes());

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_HANDLE);
        let handle_len = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]) as usize;
        let handle = resp[9..9+handle_len].to_vec();

        // READDIR — should return entries
        let mut pkt = vec![SSH_FXP_READDIR];
        pkt.extend_from_slice(&2u32.to_be_bytes());
        pkt.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        pkt.extend_from_slice(&handle);

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_NAME);
        let count = u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]);
        assert!(count >= 3); // at least ".", "..", and "dir_test.txt"

        // READDIR again — should return EOF
        let mut pkt = vec![SSH_FXP_READDIR];
        pkt.extend_from_slice(&3u32.to_be_bytes());
        pkt.extend_from_slice(&(handle.len() as u32).to_be_bytes());
        pkt.extend_from_slice(&handle);

        let resp = server.handle_packet(&pkt);
        assert_eq!(resp[0], SSH_FXP_STATUS);
        assert_eq!(u32::from_be_bytes([resp[5], resp[6], resp[7], resp[8]]), SSH_FX_EOF);
    }
}
