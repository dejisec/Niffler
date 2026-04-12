//! NFSv4 operations on a mounted libnfs context.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};
use std::sync::Arc;

use crate::nfs::errors::NfsError;
use crate::nfs::ops::NfsOps;
use crate::nfs::types::{DirEntry, NfsAttrs, NfsFh, NfsFileType, ReadResult};

use super::ffi::{
    LibnfsContext, get_libnfs_error, map_libnfs_error, nfs_close, nfs_closedir, nfs_context,
    nfs_open, nfs_opendir, nfs_pread, nfs_readdir, nfs_readlink2, nfs_stat_64, nfs_stat64, nfsdir,
    nfsfh,
};

// Platform-portable mode constants (libc types: u16 on macOS, u32 on Linux).
#[allow(clippy::unnecessary_cast)]
mod mode_bits {
    pub const IFMT: u32 = libc::S_IFMT as u32;
    pub const IFREG: u32 = libc::S_IFREG as u32;
    pub const IFDIR: u32 = libc::S_IFDIR as u32;
    pub const IFLNK: u32 = libc::S_IFLNK as u32;
}
use mode_bits::{IFDIR, IFLNK, IFMT, IFREG};

/// Store a path string as bytes in an NfsFh.
///
/// Unlike NFSv3 where file handles are opaque server-assigned byte arrays,
/// NFSv4 via libnfs uses path-based operations. We store the path as bytes
/// in NfsFh so the trait interface works uniformly.
pub(crate) fn path_to_nfsfh(path: &str) -> NfsFh {
    NfsFh::new(path.as_bytes().to_vec())
}

/// Extract a path string from an NfsFh's bytes.
pub(crate) fn nfsfh_to_path(fh: &NfsFh) -> String {
    String::from_utf8_lossy(fh.as_bytes()).into_owned()
}

/// Convert an `nfs_stat_64` struct to `NfsAttrs`.
pub(crate) fn stat_to_nfsattrs(st: &nfs_stat_64) -> NfsAttrs {
    let mode32 = st.nfs_mode as u32;
    let file_type = match mode32 & IFMT {
        m if m == IFREG => NfsFileType::Regular,
        m if m == IFDIR => NfsFileType::Directory,
        m if m == IFLNK => NfsFileType::Symlink,
        _ => NfsFileType::Other,
    };
    NfsAttrs {
        file_type,
        size: st.nfs_size,
        mode: (st.nfs_mode as u32) & 0o7777,
        uid: st.nfs_uid as u32,
        gid: st.nfs_gid as u32,
        mtime: st.nfs_mtime,
    }
}

/// Returns true for "." and ".." entries that should be filtered from directory listings.
pub(crate) fn is_dot_entry(name: &str) -> bool {
    name == "." || name == ".."
}

/// NFSv4 operations on a mounted libnfs context.
///
/// Holds the libnfs context (connection + mount) and the root file handle.
/// All methods take `&mut self` — libnfs is not thread-safe (invariant #3).
///
/// The context is stored behind `Arc<Mutex<>>` so it can be shared with
/// `spawn_blocking` closures. If `tokio::time::timeout` cancels the outer
/// `.await`, the blocking task still completes, releases the lock, and the
/// `Arc` keeps the `LibnfsContext` alive. The next method call simply waits
/// for the lock — no context is ever lost.
pub(crate) struct Nfs4Ops {
    ctx: Arc<std::sync::Mutex<LibnfsContext>>,
    root_fh: NfsFh,
}

// SAFETY: Nfs4Ops wraps LibnfsContext which is Send. All access is through
// &mut self, ensuring exclusive use by one task. NOT Sync.
unsafe impl Send for Nfs4Ops {}

impl Nfs4Ops {
    /// Create a new `Nfs4Ops` from a mounted context and root handle.
    pub(super) fn new(ctx: LibnfsContext, root_fh: NfsFh) -> Self {
        Self {
            ctx: Arc::new(std::sync::Mutex::new(ctx)),
            root_fh,
        }
    }
}

/// RAII guard — calls nfs_closedir on drop (panic safety).
struct DirHandleGuard {
    ctx: *mut nfs_context,
    dirp: *mut nfsdir,
}

impl Drop for DirHandleGuard {
    fn drop(&mut self) {
        if !self.dirp.is_null() && !self.ctx.is_null() {
            unsafe {
                nfs_closedir(self.ctx, self.dirp);
            }
        }
    }
}

// Bug 6.6: RAII guards contain raw pointers which are !Send by default.
// SAFETY: Pointers are derived from LibnfsContext which is exclusively owned via &mut self.
// Guards are created and dropped within a single spawn_blocking closure without crossing
// thread boundaries — the raw pointers never escape the blocking thread.
unsafe impl Send for DirHandleGuard {}

/// RAII guard — calls nfs_close on drop (panic safety).
struct FileHandleGuard {
    ctx: *mut nfs_context,
    fh: *mut nfsfh,
}

impl Drop for FileHandleGuard {
    fn drop(&mut self) {
        if !self.fh.is_null() && !self.ctx.is_null() {
            unsafe {
                nfs_close(self.ctx, self.fh);
            }
        }
    }
}

// Bug 6.6: RAII guards contain raw pointers which are !Send by default.
// SAFETY: Pointers are derived from LibnfsContext which is exclusively owned via &mut self.
// Guards are created and dropped within a single spawn_blocking closure without crossing
// thread boundaries — the raw pointers never escape the blocking thread.
unsafe impl Send for FileHandleGuard {}

/// Helper to box an NfsError as a trait-object error.
fn box_err(e: NfsError) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(e)
}

/// Helper to convert a JoinError from spawn_blocking into our error type.
fn join_err(e: tokio::task::JoinError) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::other(e.to_string()))
}

#[async_trait::async_trait]
impl NfsOps for Nfs4Ops {
    // All NfsOps methods use spawn_blocking to avoid blocking the tokio async
    // runtime. The LibnfsContext lives in an Arc<Mutex<>> — each method clones
    // the Arc, locks the mutex inside the blocking closure, does FFI work, then
    // unlocks. If the outer future is cancelled (e.g. by tokio::time::timeout),
    // the blocking task still completes and releases the lock; the Arc keeps the
    // context alive, and the next call simply waits for the lock.
    async fn readdirplus(&mut self, dir: &NfsFh) -> crate::nfs::ops::Result<Vec<DirEntry>> {
        let dir_path = nfsfh_to_path(dir);
        let ctx = Arc::clone(&self.ctx);

        tokio::task::spawn_blocking(move || {
            let mut guard = ctx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ptr = guard.as_ptr();

            let c_path = CString::new(dir_path.as_str())
                .map_err(|_| box_err(NfsError::ExportFatal("invalid path".into())))?;

            let mut dirp: *mut nfsdir = std::ptr::null_mut();
            // SAFETY: ptr is a valid mounted libnfs context. c_path is a valid C string.
            // dirp is written by nfs_opendir on success.
            let ret = unsafe { nfs_opendir(ptr, c_path.as_ptr(), &mut dirp) };
            if ret != 0 {
                let err_msg = get_libnfs_error(ptr);
                return Err(Box::new(map_libnfs_error(ret, &err_msg))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            let mut entries = Vec::new();

            // RAII guard ensures nfs_closedir is called even on panic.
            let _dir_guard = DirHandleGuard { ctx: ptr, dirp };

            // Iterate directory entries. nfs_readdir returns NULL at end of listing.
            loop {
                // SAFETY: ptr and dirp are valid — dirp was successfully opened above.
                // nfs_readdir returns a borrowed pointer to an internal dirent (owned by dirp).
                let dirent_ptr = unsafe { nfs_readdir(ptr, dirp) };
                if dirent_ptr.is_null() {
                    break;
                }

                // SAFETY: dirent_ptr is non-null, returned by nfs_readdir. The name field
                // is a valid NUL-terminated C string owned by the directory handle.
                let dirent = unsafe { &*dirent_ptr };
                let name = unsafe { CStr::from_ptr(dirent.name) }
                    .to_string_lossy()
                    .into_owned();

                if is_dot_entry(&name) {
                    continue;
                }

                let child_path = format!("{}/{}", dir_path.trim_end_matches('/'), name);

                // Convert dirent mode bits to file type
                let mode32 = dirent.mode;
                let file_type = match mode32 & IFMT {
                    m if m == IFREG => NfsFileType::Regular,
                    m if m == IFDIR => NfsFileType::Directory,
                    m if m == IFLNK => NfsFileType::Symlink,
                    _ => NfsFileType::Other,
                };

                let attrs = NfsAttrs {
                    file_type,
                    size: dirent.size,
                    mode: mode32 & 0o7777,
                    uid: dirent.uid,
                    gid: dirent.gid,
                    mtime: dirent.mtime.tv_sec.max(0) as u64,
                };

                entries.push(DirEntry {
                    name,
                    fh: path_to_nfsfh(&child_path),
                    attrs,
                });
            }

            // Guard drops here, calling nfs_closedir.
            drop(_dir_guard);

            Ok(entries)
        })
        .await
        .map_err(join_err)?
    }

    async fn getattr(&mut self, fh: &NfsFh) -> crate::nfs::ops::Result<NfsAttrs> {
        let path = nfsfh_to_path(fh);
        let ctx = Arc::clone(&self.ctx);

        tokio::task::spawn_blocking(move || {
            let mut guard = ctx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ptr = guard.as_ptr();

            let c_path = CString::new(path.as_str())
                .map_err(|_| box_err(NfsError::ExportFatal("invalid path".into())))?;

            let mut st = nfs_stat_64::default();
            // SAFETY: ptr is a valid mounted libnfs context. c_path is a valid C string.
            // st is a valid mutable reference to a stack-allocated nfs_stat_64.
            let ret = unsafe { nfs_stat64(ptr, c_path.as_ptr(), &mut st) };
            if ret != 0 {
                let err_msg = get_libnfs_error(ptr);
                return Err(Box::new(map_libnfs_error(ret, &err_msg))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            Ok(stat_to_nfsattrs(&st))
        })
        .await
        .map_err(join_err)?
    }

    async fn read(
        &mut self,
        fh: &NfsFh,
        offset: u64,
        count: u32,
    ) -> crate::nfs::ops::Result<ReadResult> {
        let path = nfsfh_to_path(fh);
        let ctx = Arc::clone(&self.ctx);

        tokio::task::spawn_blocking(move || {
            let mut guard = ctx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ptr = guard.as_ptr();

            let c_path = CString::new(path.as_str())
                .map_err(|_| box_err(NfsError::ExportFatal("invalid path".into())))?;

            let mut file_handle: *mut nfsfh = std::ptr::null_mut();
            // SAFETY: ptr is valid. c_path is a valid C string. O_RDONLY=0 is safe.
            // file_handle is written on success.
            let ret = unsafe { nfs_open(ptr, c_path.as_ptr(), libc::O_RDONLY, &mut file_handle) };
            if ret != 0 {
                let err_msg = get_libnfs_error(ptr);
                return Err(Box::new(map_libnfs_error(ret, &err_msg))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            // RAII guard ensures nfs_close is called even on panic.
            let file_guard = FileHandleGuard {
                ctx: ptr,
                fh: file_handle,
            };

            let mut buf = vec![0u8; count as usize];
            // SAFETY: ptr and file_handle are valid. buf has count bytes of capacity.
            let bytes_read = unsafe {
                nfs_pread(
                    ptr,
                    file_handle,
                    buf.as_mut_ptr() as *mut c_void,
                    count as usize,
                    offset,
                )
            };

            // Bug 6.5: Capture the error message BEFORE dropping the guard.
            // nfs_close (called by the guard's drop) may overwrite the libnfs
            // internal error buffer, losing the actual error from nfs_pread.
            let err_msg = if bytes_read < 0 {
                Some(get_libnfs_error(ptr))
            } else {
                None
            };

            // Guard drops here, calling nfs_close. Error buffer may be overwritten.
            drop(file_guard);

            if let Some(msg) = err_msg {
                return Err(Box::new(map_libnfs_error(bytes_read, &msg))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            let n = bytes_read as usize;
            buf.truncate(n);
            let eof = n < count as usize;

            Ok(ReadResult { data: buf, eof })
        })
        .await
        .map_err(join_err)?
    }

    async fn lookup(
        &mut self,
        dir: &NfsFh,
        name: &str,
    ) -> crate::nfs::ops::Result<(NfsFh, NfsAttrs)> {
        let full_path = format!("{}/{}", nfsfh_to_path(dir).trim_end_matches('/'), name);
        let ctx = Arc::clone(&self.ctx);

        tokio::task::spawn_blocking(move || {
            let mut guard = ctx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ptr = guard.as_ptr();

            let c_path = CString::new(full_path.as_str())
                .map_err(|_| box_err(NfsError::ExportFatal("invalid path".into())))?;

            let mut st = nfs_stat_64::default();
            // SAFETY: ptr is a valid mounted context. c_path is a valid C string.
            let ret = unsafe { nfs_stat64(ptr, c_path.as_ptr(), &mut st) };
            if ret != 0 {
                let err_msg = get_libnfs_error(ptr);
                return Err(Box::new(map_libnfs_error(ret, &err_msg))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            Ok((path_to_nfsfh(&full_path), stat_to_nfsattrs(&st)))
        })
        .await
        .map_err(join_err)?
    }

    async fn readlink(&mut self, link: &NfsFh) -> crate::nfs::ops::Result<String> {
        let path = nfsfh_to_path(link);
        let ctx = Arc::clone(&self.ctx);

        tokio::task::spawn_blocking(move || {
            let mut guard = ctx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ptr = guard.as_ptr();

            let c_path = CString::new(path.as_str())
                .map_err(|_| box_err(NfsError::ExportFatal("invalid path".into())))?;

            let mut bufptr: *mut c_char = std::ptr::null_mut();
            // SAFETY: ptr is valid. c_path is a valid C string. bufptr is written on success.
            let ret = unsafe { nfs_readlink2(ptr, c_path.as_ptr(), &mut bufptr) };
            if ret != 0 {
                let err_msg = get_libnfs_error(ptr);
                return Err(Box::new(map_libnfs_error(ret, &err_msg))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            // Bug 6.3: nfs_readlink2 returns a pointer to an internal libnfs buffer.
            // The buffer is managed by libnfs and will be freed/reused on the next
            // operation. We copy it immediately to a Rust String. Do NOT call
            // libc::free() — the pointer is not heap-allocated by malloc; it points
            // into libnfs-internal storage.
            //
            // SAFETY: bufptr is non-null on success, pointing to a NUL-terminated
            // C string managed internally by libnfs.
            let target = unsafe { CStr::from_ptr(bufptr) }
                .to_string_lossy()
                .into_owned();

            Ok(target)
        })
        .await
        .map_err(join_err)?
    }

    fn root_handle(&self) -> &NfsFh {
        &self.root_fh
    }
}

#[cfg(test)]
mod tests {
    use super::super::connector::Nfs4Connector;
    use super::*;
    use crate::nfs::auth::AuthCreds;
    use crate::nfs::connector::NfsConnector;

    #[test]
    fn path_to_nfsfh_stores_bytes() {
        let fh = path_to_nfsfh("/export/dir/file");
        assert_eq!(fh.as_bytes(), b"/export/dir/file");
    }

    #[test]
    fn nfsfh_path_round_trip() {
        let path = "/export/dir/file";
        let fh = path_to_nfsfh(path);
        assert_eq!(nfsfh_to_path(&fh), path);
    }

    #[test]
    fn nfsfh_root_path_round_trip() {
        let fh = path_to_nfsfh("/");
        assert_eq!(nfsfh_to_path(&fh), "/");
    }

    #[test]
    fn nfsfh_empty_path() {
        let fh = path_to_nfsfh("");
        assert_eq!(nfsfh_to_path(&fh), "");
        assert!(fh.as_bytes().is_empty());
    }

    #[test]
    fn stat_regular_file() {
        let st = nfs_stat_64 {
            nfs_mode: libc::S_IFREG as u64 | 0o644,
            ..Default::default()
        };
        let attrs = stat_to_nfsattrs(&st);
        assert!(attrs.is_file());
        assert!(!attrs.is_directory());
        assert!(!attrs.is_symlink());
    }

    #[test]
    fn stat_directory() {
        let st = nfs_stat_64 {
            nfs_mode: libc::S_IFDIR as u64 | 0o755,
            ..Default::default()
        };
        let attrs = stat_to_nfsattrs(&st);
        assert!(attrs.is_directory());
    }

    #[test]
    fn stat_symlink() {
        let st = nfs_stat_64 {
            nfs_mode: libc::S_IFLNK as u64 | 0o777,
            ..Default::default()
        };
        let attrs = stat_to_nfsattrs(&st);
        assert!(attrs.is_symlink());
    }

    #[test]
    fn stat_block_device_maps_to_other() {
        let st = nfs_stat_64 {
            nfs_mode: libc::S_IFBLK as u64,
            ..Default::default()
        };
        let attrs = stat_to_nfsattrs(&st);
        assert_eq!(attrs.file_type, NfsFileType::Other);
    }

    #[test]
    fn stat_numeric_fields_preserved() {
        let st = nfs_stat_64 {
            nfs_mode: libc::S_IFREG as u64 | 0o644,
            nfs_size: 4096,
            nfs_uid: 1000,
            nfs_gid: 1000,
            nfs_mtime: 1700000000,
            ..Default::default()
        };
        let attrs = stat_to_nfsattrs(&st);
        assert_eq!(attrs.size, 4096);
        assert_eq!(attrs.mode, 0o644);
        assert_eq!(attrs.uid, 1000);
        assert_eq!(attrs.gid, 1000);
        assert_eq!(attrs.mtime, 1700000000);
    }

    #[test]
    fn dot_entry_filtered() {
        assert!(is_dot_entry("."));
    }

    #[test]
    fn dotdot_entry_filtered() {
        assert!(is_dot_entry(".."));
    }

    #[test]
    fn dotfile_kept() {
        assert!(!is_dot_entry(".bashrc"));
    }

    #[test]
    fn negative_mtime_wraps_incorrectly_without_clamp() {
        let neg: i64 = -100;
        assert_ne!(neg as u64, 0, "raw cast wraps");
        assert_eq!(neg.max(0) as u64, 0, "clamped cast is safe");
    }

    #[tokio::test]
    #[ignore = "requires NFSv4 server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn nfs4_connect_and_list_root() {
        let host = std::env::var("NFS_TEST_HOST").expect("NFS_TEST_HOST not set");
        let export = std::env::var("NFS_TEST_EXPORT").expect("NFS_TEST_EXPORT not set");
        let connector = Nfs4Connector::new();
        let mut ops = connector
            .connect(&host, &export, &AuthCreds::root())
            .await
            .expect("connect failed");
        let root_fh = ops.root_handle().clone();
        let entries = ops.readdirplus(&root_fh).await.expect("readdirplus failed");
        assert!(!entries.is_empty(), "expected at least one directory entry");
    }

    #[tokio::test]
    #[ignore = "requires NFSv4 server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn nfs4_getattr_on_root() {
        let host = std::env::var("NFS_TEST_HOST").expect("NFS_TEST_HOST not set");
        let export = std::env::var("NFS_TEST_EXPORT").expect("NFS_TEST_EXPORT not set");
        let connector = Nfs4Connector::new();
        let mut ops = connector
            .connect(&host, &export, &AuthCreds::root())
            .await
            .expect("connect failed");
        let root_fh = ops.root_handle().clone();
        let attrs = ops.getattr(&root_fh).await.expect("getattr failed");
        assert!(attrs.is_directory(), "root should be a directory");
    }

    #[tokio::test]
    #[ignore = "requires NFSv4 server — set NFS_TEST_HOST, NFS_TEST_EXPORT, NFS_TEST_FILE"]
    async fn nfs4_read_file() {
        let host = std::env::var("NFS_TEST_HOST").expect("NFS_TEST_HOST not set");
        let export = std::env::var("NFS_TEST_EXPORT").expect("NFS_TEST_EXPORT not set");
        let file = std::env::var("NFS_TEST_FILE").expect("NFS_TEST_FILE not set");
        let connector = Nfs4Connector::new();
        let mut ops = connector
            .connect(&host, &export, &AuthCreds::root())
            .await
            .expect("connect failed");
        let root_fh = ops.root_handle().clone();
        let (file_fh, _attrs) = ops.lookup(&root_fh, &file).await.expect("lookup failed");
        let result = ops.read(&file_fh, 0, 4096).await.expect("read failed");
        assert!(!result.data.is_empty(), "expected non-empty file data");
    }
}
