//! NFSv4 connection factory using libnfs.

use std::ffi::CString;
use std::os::raw::c_int;

use crate::nfs::auth::AuthCreds;
use crate::nfs::connector;
use crate::nfs::connector::NfsConnector;
use crate::nfs::errors::NfsError;
use crate::nfs::ops::NfsOps;
use crate::nfs::types::NfsVersion;

use super::ffi::{
    LibnfsContext, get_libnfs_error, map_libnfs_error, nfs_mount, nfs_set_auxiliary_gids,
    nfs_set_gid, nfs_set_uid, nfs_set_version,
};
use super::ops::{Nfs4Ops, path_to_nfsfh};

/// NFSv4 connection factory using libnfs.
///
/// Implements `NfsConnector` (Send + Sync). Each call to `connect()` creates
/// an independent libnfs context with the specified credentials.
#[derive(Default)]
pub struct Nfs4Connector;

impl Nfs4Connector {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl NfsConnector for Nfs4Connector {
    // Bug 6.2: Wrap all FFI calls in connect() inside spawn_blocking to avoid
    // blocking the tokio async runtime with synchronous libnfs network I/O.
    async fn connect(
        &self,
        host: &str,
        export: &str,
        creds: &AuthCreds,
    ) -> connector::Result<Box<dyn NfsOps>> {
        let host = host.to_string();
        let export = export.to_string();
        let creds = creds.clone();

        tokio::task::spawn_blocking(move || {
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

            let c_host = CString::new(host)
                .map_err(|_| NfsError::ExportFatal("invalid host string".into()))?;
            let c_export = CString::new(export)
                .map_err(|_| NfsError::ExportFatal("invalid export string".into()))?;

            // SAFETY: ptr is valid. c_host and c_export are valid NUL-terminated C strings.
            let ret = unsafe { nfs_mount(ptr, c_host.as_ptr(), c_export.as_ptr()) };
            if ret != 0 {
                let err_msg = get_libnfs_error(ptr);
                return Err(Box::new(map_libnfs_error(ret, &err_msg))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            // Root file handle is "/" (root of the mounted export)
            let root_fh = path_to_nfsfh("/");

            Ok(Box::new(Nfs4Ops::new(ctx, root_fh)) as Box<dyn NfsOps>)
        })
        .await
        .map_err(|e| {
            Box::new(NfsError::Transient(format!("connect task failed: {e}")))
                as Box<dyn std::error::Error + Send + Sync>
        })?
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

#[cfg(test)]
mod tests {
    use super::*;

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
