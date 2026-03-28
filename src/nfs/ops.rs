use crate::nfs::types::{DirEntry, NfsAttrs, NfsFh, ReadResult};

/// Result alias for NFS operations.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Operations on an established NFS connection.
/// The connection holds a mounted export and fixed AUTH_SYS credentials.
/// All async methods take &mut self because nfs3_client requires exclusive access.
#[cfg_attr(any(test, feature = "testing"), mockall::automock)]
#[async_trait::async_trait]
pub trait NfsOps: Send {
    /// List directory entries with attributes (READDIRPLUS).
    /// Falls back to READDIR + GETATTR if READDIRPLUS is unsupported.
    async fn readdirplus(&mut self, dir: &NfsFh) -> Result<Vec<DirEntry>>;

    /// Get file attributes (GETATTR).
    async fn getattr(&mut self, fh: &NfsFh) -> Result<NfsAttrs>;

    /// Read file contents. Returns up to count bytes starting at offset.
    async fn read(&mut self, fh: &NfsFh, offset: u64, count: u32) -> Result<ReadResult>;

    /// Lookup a name within a directory. Returns handle + attributes.
    async fn lookup(&mut self, dir: &NfsFh, name: &str) -> Result<(NfsFh, NfsAttrs)>;

    /// Read symlink target.
    async fn readlink(&mut self, link: &NfsFh) -> Result<String>;

    /// Get the root file handle for the mounted export.
    fn root_handle(&self) -> &NfsFh;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_nfs_ops_compiles() {
        let mut mock = MockNfsOps::new();
        mock.expect_root_handle().return_const(NfsFh::default());

        let result = mock.root_handle();
        assert!(result.as_bytes().is_empty());

        let _: Box<dyn NfsOps> = Box::new(mock);
    }
}
