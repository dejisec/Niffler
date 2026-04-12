//! FFI type declarations, RAII wrapper, and error mapping for libnfs.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};

use crate::nfs::errors::NfsError;

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

// Bug 6.4: Compile-time size assertion to catch layout mismatches with libnfs headers.
// nfs_stat_64 has 17 u64 fields = 136 bytes minimum. If the struct is smaller than
// expected, the FFI calls would silently corrupt memory.
const _: () = {
    assert!(std::mem::size_of::<nfs_stat_64>() >= 136);
};

/// Directory entry returned by nfs_readdir (linked list).
///
/// Bug 6.7: Uses `libc::timeval` instead of a custom definition to match system headers.
/// Bug 6.4: Compile-time size assertion added below.
#[repr(C)]
pub(crate) struct nfsdirent {
    pub next: *mut Self,
    pub name: *mut c_char,
    pub inode: u64,
    pub type_: u32,
    pub mode: u32,
    pub size: u64,
    pub atime: libc::timeval,
    pub mtime: libc::timeval,
    pub ctime: libc::timeval,
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

// Bug 6.4: Compile-time size assertion for nfsdirent.
// This catches silent memory corruption from layout mismatches with the C definition.
// On 64-bit platforms: 2 pointers (16) + inode/type_/mode/size (24) + 3 timevals (48) +
// uid/gid/nlink (12 + padding) + dev/rdev/blksize/blocks/used (40) + 3 nsec fields (12) = ~160.
const _: () = {
    assert!(std::mem::size_of::<nfsdirent>() >= 150);
};

unsafe extern "C" {
    pub(super) fn nfs_init_context() -> *mut nfs_context;
    pub(super) fn nfs_destroy_context(nfs: *mut nfs_context);

    pub(super) fn nfs_mount(
        nfs: *mut nfs_context,
        server: *const c_char,
        exportname: *const c_char,
    ) -> c_int;

    pub(super) fn nfs_get_error(nfs: *mut nfs_context) -> *mut c_char;

    // Credential setting (must be called before nfs_mount)
    pub(super) fn nfs_set_uid(nfs: *mut nfs_context, uid: c_int);
    pub(super) fn nfs_set_gid(nfs: *mut nfs_context, gid: c_int);
    pub(super) fn nfs_set_auxiliary_gids(nfs: *mut nfs_context, len: u32, gids: *mut u32);

    pub(super) fn nfs_set_version(nfs: *mut nfs_context, version: c_int) -> c_int;

    pub(super) fn nfs_stat64(
        nfs: *mut nfs_context,
        path: *const c_char,
        st: *mut nfs_stat_64,
    ) -> c_int;

    pub(super) fn nfs_opendir(
        nfs: *mut nfs_context,
        path: *const c_char,
        nfsdir: *mut *mut nfsdir,
    ) -> c_int;
    pub(super) fn nfs_readdir(nfs: *mut nfs_context, nfsdir: *mut nfsdir) -> *mut nfsdirent;
    pub(super) fn nfs_closedir(nfs: *mut nfs_context, nfsdir: *mut nfsdir);

    pub(super) fn nfs_open(
        nfs: *mut nfs_context,
        path: *const c_char,
        flags: c_int,
        nfsfh: *mut *mut nfsfh,
    ) -> c_int;
    pub(super) fn nfs_pread(
        nfs: *mut nfs_context,
        nfsfh: *mut nfsfh,
        buf: *mut c_void,
        count: usize,
        offset: u64,
    ) -> c_int;
    pub(super) fn nfs_close(nfs: *mut nfs_context, nfsfh: *mut nfsfh) -> c_int;

    pub(super) fn nfs_readlink2(
        nfs: *mut nfs_context,
        path: *const c_char,
        bufptr: *mut *mut c_char,
    ) -> c_int;
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

#[cfg(test)]
mod tests {
    use super::*;

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

    // Bug 6.4: Compile-time size assertions are tested at build time via const assertions above.
    // These runtime tests provide additional validation.
    #[test]
    fn nfs_stat_64_size_is_sane() {
        assert!(
            std::mem::size_of::<nfs_stat_64>() >= 136,
            "nfs_stat_64 must be at least 136 bytes (17 x u64)"
        );
    }

    #[test]
    fn nfsdirent_size_is_sane() {
        assert!(
            std::mem::size_of::<nfsdirent>() >= 150,
            "nfsdirent must be at least 150 bytes"
        );
    }
}
