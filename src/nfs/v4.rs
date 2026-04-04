//! NFSv4 client implementation via libnfs.
//!
//! Always compiled in — requires system libnfs (linked via pkg-config in build.rs).
//! Uses manual FFI declarations against the libnfs C library
//! (linked via pkg-config in build.rs).

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

use crate::nfs::auth::AuthCreds;
use crate::nfs::connector;
use crate::nfs::connector::NfsConnector;
use crate::nfs::errors::NfsError;
use crate::nfs::ops::NfsOps;
use crate::nfs::types::{DirEntry, NfsAttrs, NfsFh, NfsFileType, NfsVersion};

// Platform-portable mode constants (libc types: u16 on macOS, u32 on Linux).
#[allow(clippy::unnecessary_cast)]
mod mode_bits {
    pub const IFMT: u32 = libc::S_IFMT as u32;
    pub const IFREG: u32 = libc::S_IFREG as u32;
    pub const IFDIR: u32 = libc::S_IFDIR as u32;
    pub const IFLNK: u32 = libc::S_IFLNK as u32;
}
use mode_bits::{IFDIR, IFLNK, IFMT, IFREG};

/// Opaque libnfs NFS context handle.
#[repr(C)]
pub(crate) struct nfs_context {
    _private: [u8; 0],
}

/// Opaque libnfs file handle (from nfs_open).
#[repr(C)]
pub(crate) struct nfsfh {
    _private: [u8; 0],
}

/// Opaque libnfs directory handle (from nfs_opendir).
#[repr(C)]
pub(crate) struct nfsdir {
    _private: [u8; 0],
}

/// File attributes returned by nfs_stat64.
#[repr(C)]
#[derive(Debug, Default)]
pub(crate) struct nfs_stat_64 {
    pub nfs_dev: u64,
    pub nfs_ino: u64,
    pub nfs_mode: u64,
    pub nfs_nlink: u64,
    pub nfs_uid: u64,
    pub nfs_gid: u64,
    pub nfs_rdev: u64,
    pub nfs_size: u64,
    pub nfs_blksize: u64,
    pub nfs_blocks: u64,
    pub nfs_atime: u64,
    pub nfs_mtime: u64,
    pub nfs_ctime: u64,
    pub nfs_atime_nsec: u64,
    pub nfs_mtime_nsec: u64,
    pub nfs_ctime_nsec: u64,
    pub nfs_used: u64,
}

/// C timeval struct used in nfsdirent.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// Directory entry returned by nfs_readdir (linked list).
#[repr(C)]
pub(crate) struct nfsdirent {
    pub next: *mut nfsdirent,
    pub name: *mut c_char,
    pub inode: u64,
    pub type_: u32,
    pub mode: u32,
    pub size: u64,
    pub atime: timeval,
    pub mtime: timeval,
    pub ctime: timeval,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub dev: u64,
    pub rdev: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub used: u64,
    pub atime_nsec: u32,
    pub mtime_nsec: u32,
    pub ctime_nsec: u32,
}

unsafe extern "C" {
    fn nfs_init_context() -> *mut nfs_context;
    fn nfs_destroy_context(nfs: *mut nfs_context);

    fn nfs_mount(nfs: *mut nfs_context, server: *const c_char, exportname: *const c_char) -> c_int;

    fn nfs_get_error(nfs: *mut nfs_context) -> *mut c_char;

    // Credential setting (must be called before nfs_mount)
    fn nfs_set_uid(nfs: *mut nfs_context, uid: c_int);
    fn nfs_set_gid(nfs: *mut nfs_context, gid: c_int);
    fn nfs_set_auxiliary_gids(nfs: *mut nfs_context, len: u32, gids: *mut u32);

    fn nfs_set_version(nfs: *mut nfs_context, version: c_int) -> c_int;

    fn nfs_stat64(nfs: *mut nfs_context, path: *const c_char, st: *mut nfs_stat_64) -> c_int;

    fn nfs_opendir(nfs: *mut nfs_context, path: *const c_char, nfsdir: *mut *mut nfsdir) -> c_int;
    fn nfs_readdir(nfs: *mut nfs_context, nfsdir: *mut nfsdir) -> *mut nfsdirent;
    fn nfs_closedir(nfs: *mut nfs_context, nfsdir: *mut nfsdir);

    fn nfs_open(
        nfs: *mut nfs_context,
        path: *const c_char,
        flags: c_int,
        nfsfh: *mut *mut nfsfh,
    ) -> c_int;
    fn nfs_pread(
        nfs: *mut nfs_context,
        nfsfh: *mut nfsfh,
        buf: *mut c_void,
        count: usize,
        offset: u64,
    ) -> c_int;
    fn nfs_close(nfs: *mut nfs_context, nfsfh: *mut nfsfh) -> c_int;

    fn nfs_readlink2(nfs: *mut nfs_context, path: *const c_char, bufptr: *mut *mut c_char)
    -> c_int;
}

/// Safe wrapper around a raw libnfs `nfs_context` pointer.
///
/// Implements `Drop` to call `nfs_destroy_context` automatically.
/// Implements `Send` (can be moved between threads) but NOT `Sync`
/// (libnfs contexts are not thread-safe, matching our `&mut self` requirement).
pub(crate) struct LibnfsContext {
    ctx: *mut nfs_context,
}

// SAFETY: libnfs contexts are single-threaded but can be moved between threads.
// All access is gated through `&mut self`, ensuring exclusive use by one task.
unsafe impl Send for LibnfsContext {}

impl Drop for LibnfsContext {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            // SAFETY: ctx was obtained from nfs_init_context(), we have exclusive
            // ownership via &mut self, and the context is being dropped — no further
            // use is possible.
            unsafe {
                nfs_destroy_context(self.ctx);
            }
        }
    }
}

impl LibnfsContext {
    /// Create a new libnfs context.
    pub fn new() -> Result<Self, NfsError> {
        // SAFETY: nfs_init_context is a pure C function that allocates and returns
        // a new context, or NULL on failure. No preconditions.
        let ctx = unsafe { nfs_init_context() };
        if ctx.is_null() {
            return Err(NfsError::ExportFatal(
                "failed to initialize libnfs context".into(),
            ));
        }
        Ok(Self { ctx })
    }

    /// Get the raw context pointer for FFI calls.
    ///
    /// Takes `&mut self` to enforce exclusive access — libnfs contexts
    /// are not thread-safe.
    pub fn as_ptr(&mut self) -> *mut nfs_context {
        self.ctx
    }
}

/// Safely extract the error message string from a libnfs context.
///
/// Returns `"unknown error"` if the pointer is null or the string is invalid.
pub(crate) fn get_libnfs_error(ctx: *mut nfs_context) -> String {
    if ctx.is_null() {
        return "unknown error".into();
    }
    // SAFETY: ctx is a valid, non-null libnfs context pointer. nfs_get_error
    // returns a pointer to an internal string buffer owned by the context —
    // valid for the lifetime of the context and until the next operation.
    let ptr = unsafe { nfs_get_error(ctx) };
    if ptr.is_null() {
        return "unknown error".into();
    }
    // SAFETY: ptr is a non-null, NUL-terminated C string from libnfs.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

/// Map a libnfs return code (negative errno) and error string to an `NfsError`.
///
/// libnfs operations return 0 on success or -errno on failure. This function
/// converts the absolute value of the return code to the appropriate NfsError
/// variant, using the error string for context in ambiguous cases.
pub(crate) fn map_libnfs_error(retcode: i32, ctx_error: &str) -> NfsError {
    let errno = retcode.unsigned_abs();
    match errno {
        e if e == libc::EACCES as u32 || e == libc::EPERM as u32 => NfsError::PermissionDenied,
        e if e == libc::ESTALE as u32 => NfsError::StaleHandle,
        e if e == libc::ENOENT as u32 => NfsError::NotFound,
        e if e == libc::EIO as u32 || e == libc::ETIMEDOUT as u32 || e == libc::EAGAIN as u32 => {
            NfsError::Transient(ctx_error.into())
        }
        e if e == libc::ECONNREFUSED as u32
            || e == libc::ECONNRESET as u32
            || e == libc::ECONNABORTED as u32
            || e == libc::ENETUNREACH as u32
            || e == libc::EHOSTUNREACH as u32 =>
        {
            NfsError::ConnectionLost
        }
        _ => NfsError::Transient(ctx_error.into()),
    }
}

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

/// NFSv4 connection factory using libnfs.
///
/// Implements `NfsConnector` (Send + Sync). Each call to `connect()` creates
/// an independent libnfs context with the specified credentials.
#[derive(Default)]
pub struct Nfs4Connector;

impl Nfs4Connector {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl NfsConnector for Nfs4Connector {
    async fn connect(
        &self,
        host: &str,
        export: &str,
        creds: &AuthCreds,
    ) -> connector::Result<Box<dyn NfsOps>> {
        let mut ctx = LibnfsContext::new()?;
        let ptr = ctx.as_ptr();

        // Force NFSv4 protocol
        // SAFETY: ptr is a valid, non-null libnfs context from LibnfsContext::new().
        unsafe {
            nfs_set_version(ptr, 4);
        }

        // Set credentials BEFORE mount (invariant #4)
        // SAFETY: ptr is valid. UID/GID are simple integer values.
        unsafe {
            nfs_set_uid(ptr, creds.uid as c_int);
            nfs_set_gid(ptr, creds.gid as c_int);
        }

        if !creds.aux_gids.is_empty() {
            let mut gids: Vec<u32> = creds.aux_gids.clone();
            // SAFETY: ptr is valid. gids slice is valid for len elements.
            unsafe {
                nfs_set_auxiliary_gids(ptr, gids.len() as u32, gids.as_mut_ptr());
            }
        }

        let c_host =
            CString::new(host).map_err(|_| NfsError::ExportFatal("invalid host string".into()))?;
        let c_export = CString::new(export)
            .map_err(|_| NfsError::ExportFatal("invalid export string".into()))?;

        // SAFETY: ptr is valid. c_host and c_export are valid NUL-terminated C strings.
        let ret = unsafe { nfs_mount(ptr, c_host.as_ptr(), c_export.as_ptr()) };
        if ret != 0 {
            let err_msg = get_libnfs_error(ptr);
            return Err(Box::new(map_libnfs_error(ret, &err_msg)));
        }

        // Root file handle is "/" (root of the mounted export)
        let root_fh = path_to_nfsfh("/");

        Ok(Box::new(Nfs4Ops { ctx, root_fh }))
    }

    async fn detect_version(&self, host: &str) -> connector::Result<NfsVersion> {
        let host = host.to_string();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::task::spawn_blocking(move || {
                let mut ctx = LibnfsContext::new()?;
                let ptr = ctx.as_ptr();

                // SAFETY: ptr is valid. Force NFSv4.
                unsafe {
                    nfs_set_version(ptr, 4);
                }

                let c_host = CString::new(host)
                    .map_err(|_| NfsError::ExportFatal("invalid host string".into()))?;
                let c_root = CString::new("/").unwrap();

                // Try mounting pseudo-root — if it works, server supports NFSv4
                // SAFETY: ptr is valid. c_host and c_root are valid NUL-terminated C strings.
                let ret = unsafe { nfs_mount(ptr, c_host.as_ptr(), c_root.as_ptr()) };
                if ret != 0 {
                    let err_msg = get_libnfs_error(ptr);
                    return Err(Box::new(map_libnfs_error(ret, &err_msg))
                        as Box<dyn std::error::Error + Send + Sync>);
                }

                // Drop cleans up the context (unmount + destroy)
                drop(ctx);
                Ok(NfsVersion::V4)
            }),
        )
        .await;

        match result {
            Ok(Ok(inner)) => inner,
            Ok(Err(join_err)) => Err(Box::new(NfsError::Transient(format!(
                "detect_version task failed: {join_err}"
            )))),
            Err(_) => Err(Box::new(NfsError::Transient(
                "NFSv4 version detection timed out".into(),
            ))),
        }
    }
}

/// NFSv4 operations on a mounted libnfs context.
///
/// Holds the libnfs context (connection + mount) and the root file handle.
/// All methods take `&mut self` — libnfs is not thread-safe (invariant #3).
pub(crate) struct Nfs4Ops {
    ctx: LibnfsContext,
    root_fh: NfsFh,
}

// SAFETY: Nfs4Ops wraps LibnfsContext which is Send. All access is through
// &mut self, ensuring exclusive use by one task. NOT Sync.
unsafe impl Send for Nfs4Ops {}

use crate::nfs::types::ReadResult;

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

#[async_trait::async_trait]
impl NfsOps for Nfs4Ops {
    async fn readdirplus(&mut self, dir: &NfsFh) -> crate::nfs::ops::Result<Vec<DirEntry>> {
        let dir_path = nfsfh_to_path(dir);
        let c_path = CString::new(dir_path.as_str())
            .map_err(|_| NfsError::ExportFatal("invalid path".into()))?;
        let ptr = self.ctx.as_ptr();

        let mut dirp: *mut nfsdir = std::ptr::null_mut();
        // SAFETY: ptr is a valid mounted libnfs context. c_path is a valid C string.
        // dirp is written by nfs_opendir on success.
        let ret = unsafe { nfs_opendir(ptr, c_path.as_ptr(), &mut dirp) };
        if ret != 0 {
            let err_msg = get_libnfs_error(ptr);
            return Err(Box::new(map_libnfs_error(ret, &err_msg)));
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
    }

    async fn getattr(&mut self, fh: &NfsFh) -> crate::nfs::ops::Result<NfsAttrs> {
        let path = nfsfh_to_path(fh);
        let c_path =
            CString::new(path).map_err(|_| NfsError::ExportFatal("invalid path".into()))?;
        let ptr = self.ctx.as_ptr();

        let mut st = nfs_stat_64::default();
        // SAFETY: ptr is a valid mounted libnfs context. c_path is a valid C string.
        // st is a valid mutable reference to a stack-allocated nfs_stat_64.
        let ret = unsafe { nfs_stat64(ptr, c_path.as_ptr(), &mut st) };
        if ret != 0 {
            let err_msg = get_libnfs_error(ptr);
            return Err(Box::new(map_libnfs_error(ret, &err_msg)));
        }

        Ok(stat_to_nfsattrs(&st))
    }

    async fn read(
        &mut self,
        fh: &NfsFh,
        offset: u64,
        count: u32,
    ) -> crate::nfs::ops::Result<ReadResult> {
        let path = nfsfh_to_path(fh);
        let c_path =
            CString::new(path).map_err(|_| NfsError::ExportFatal("invalid path".into()))?;
        let ptr = self.ctx.as_ptr();

        let mut file_handle: *mut nfsfh = std::ptr::null_mut();
        // SAFETY: ptr is valid. c_path is a valid C string. O_RDONLY=0 is safe.
        // file_handle is written on success.
        let ret = unsafe { nfs_open(ptr, c_path.as_ptr(), libc::O_RDONLY, &mut file_handle) };
        if ret != 0 {
            let err_msg = get_libnfs_error(ptr);
            return Err(Box::new(map_libnfs_error(ret, &err_msg)));
        }

        // RAII guard ensures nfs_close is called even on panic.
        let _file_guard = FileHandleGuard {
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

        // Guard drops here, calling nfs_close.
        drop(_file_guard);

        if bytes_read < 0 {
            let err_msg = get_libnfs_error(ptr);
            return Err(Box::new(map_libnfs_error(bytes_read, &err_msg)));
        }

        let n = bytes_read as usize;
        buf.truncate(n);
        let eof = n < count as usize;

        Ok(ReadResult { data: buf, eof })
    }

    async fn lookup(
        &mut self,
        dir: &NfsFh,
        name: &str,
    ) -> crate::nfs::ops::Result<(NfsFh, NfsAttrs)> {
        let full_path = format!("{}/{}", nfsfh_to_path(dir).trim_end_matches('/'), name);
        let c_path = CString::new(full_path.as_str())
            .map_err(|_| NfsError::ExportFatal("invalid path".into()))?;
        let ptr = self.ctx.as_ptr();

        let mut st = nfs_stat_64::default();
        // SAFETY: ptr is a valid mounted context. c_path is a valid C string.
        let ret = unsafe { nfs_stat64(ptr, c_path.as_ptr(), &mut st) };
        if ret != 0 {
            let err_msg = get_libnfs_error(ptr);
            return Err(Box::new(map_libnfs_error(ret, &err_msg)));
        }

        Ok((path_to_nfsfh(&full_path), stat_to_nfsattrs(&st)))
    }

    async fn readlink(&mut self, link: &NfsFh) -> crate::nfs::ops::Result<String> {
        let path = nfsfh_to_path(link);
        let c_path =
            CString::new(path).map_err(|_| NfsError::ExportFatal("invalid path".into()))?;
        let ptr = self.ctx.as_ptr();

        let mut bufptr: *mut c_char = std::ptr::null_mut();
        // SAFETY: ptr is valid. c_path is a valid C string. bufptr is written on success.
        // The returned buffer is heap-allocated by libnfs and must be freed by the caller.
        let ret = unsafe { nfs_readlink2(ptr, c_path.as_ptr(), &mut bufptr) };
        if ret != 0 {
            let err_msg = get_libnfs_error(ptr);
            return Err(Box::new(map_libnfs_error(ret, &err_msg)));
        }

        // SAFETY: bufptr is non-null on success, pointing to a heap-allocated
        // NUL-terminated C string. We copy it to a Rust String then free.
        let target = unsafe { CStr::from_ptr(bufptr) }
            .to_string_lossy()
            .into_owned();

        // SAFETY: bufptr was heap-allocated by libnfs. The caller must free it.
        unsafe {
            libc::free(bufptr as *mut c_void);
        }

        Ok(target)
    }

    fn root_handle(&self) -> &NfsFh {
        &self.root_fh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn map_eacces() {
        let err = map_libnfs_error(-libc::EACCES, "Permission denied");
        assert!(matches!(err, NfsError::PermissionDenied));
    }

    #[test]
    fn map_eperm() {
        let err = map_libnfs_error(-libc::EPERM, "Operation not permitted");
        assert!(matches!(err, NfsError::PermissionDenied));
    }

    #[test]
    fn map_estale() {
        let err = map_libnfs_error(-libc::ESTALE, "Stale file handle");
        assert!(matches!(err, NfsError::StaleHandle));
    }

    #[test]
    fn map_enoent() {
        let err = map_libnfs_error(-libc::ENOENT, "No such file");
        assert!(matches!(err, NfsError::NotFound));
    }

    #[test]
    fn map_eio() {
        let err = map_libnfs_error(-libc::EIO, "I/O error");
        assert!(matches!(err, NfsError::Transient(_)));
    }

    #[test]
    fn map_etimedout() {
        let err = map_libnfs_error(-libc::ETIMEDOUT, "Connection timed out");
        assert!(matches!(err, NfsError::Transient(_)));
    }

    #[test]
    fn map_econnrefused() {
        let err = map_libnfs_error(-libc::ECONNREFUSED, "Connection refused");
        assert!(matches!(err, NfsError::ConnectionLost));
    }

    #[test]
    fn map_econnreset() {
        let err = map_libnfs_error(-libc::ECONNRESET, "Connection reset");
        assert!(matches!(err, NfsError::ConnectionLost));
    }

    #[test]
    fn map_unknown_defaults_to_transient() {
        let err = map_libnfs_error(-999, "some unknown error");
        match err {
            NfsError::Transient(msg) => assert_eq!(msg, "some unknown error"),
            other => panic!("expected Transient, got {:?}", other),
        }
    }

    #[tokio::test]
    #[ignore = "requires NFSv4 server — set NFS_TEST_HOST and NFS_TEST_EXPORT"]
    async fn nfs4_connector_connects_and_mounts() {
        let host = std::env::var("NFS_TEST_HOST").expect("NFS_TEST_HOST not set");
        let export = std::env::var("NFS_TEST_EXPORT").expect("NFS_TEST_EXPORT not set");
        let connector = Nfs4Connector::new();
        let ops = connector
            .connect(&host, &export, &AuthCreds::root())
            .await
            .expect("connect failed");
        assert!(!ops.root_handle().as_bytes().is_empty());
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

    #[tokio::test]
    #[ignore = "requires NFSv4 server — set NFS_TEST_HOST"]
    async fn nfs4_detect_version() {
        let host = std::env::var("NFS_TEST_HOST").expect("NFS_TEST_HOST not set");
        let connector = Nfs4Connector::new();
        let version = connector
            .detect_version(&host)
            .await
            .expect("detect_version failed");
        assert_eq!(version, NfsVersion::V4);
    }

    #[tokio::test]
    #[ignore = "network-dependent: verifies detect_version times out on unreachable host"]
    async fn nfs4_detect_version_times_out_on_unreachable() {
        let connector = Nfs4Connector::new();
        let start = std::time::Instant::now();
        // RFC 5737 TEST-NET-1: should be unreachable/black-holed
        let result = connector.detect_version("192.0.2.1").await;
        assert!(result.is_err(), "should fail on unreachable host");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(35),
            "detect_version took too long ({:?}), likely missing timeout",
            start.elapsed()
        );
    }
}
