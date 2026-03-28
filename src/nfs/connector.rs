use crate::nfs::auth::AuthCreds;
use crate::nfs::ops::NfsOps;
use crate::nfs::types::NfsVersion;

/// Result alias for NFS connector operations
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Factory for creating NFS connections with specific credentials.
/// Each call to connect() returns an independent connection.
/// UID cycling is achieved by calling connect() with different AuthCreds.
#[cfg_attr(any(test, feature = "testing"), mockall::automock)]
#[async_trait::async_trait]
pub trait NfsConnector: Send + Sync {
    /// Create a new NFS connection to host:export with the given credentials.
    async fn connect(&self, host: &str, export: &str, creds: &AuthCreds)
    -> Result<Box<dyn NfsOps>>;

    /// Detect which NFS version the server supports.
    async fn detect_version(&self, host: &str) -> Result<NfsVersion>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::ops::MockNfsOps;
    use std::sync::Arc;

    #[tokio::test]
    async fn mock_nfs_connector_returns_ops() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect().returning(|_, _, _| {
            let ops = MockNfsOps::new();
            Ok(Box::new(ops))
        });

        let result = mock
            .connect("192.168.1.1", "/exports/share", &AuthCreds::root())
            .await;
        assert!(result.is_ok());

        let _: Arc<dyn NfsConnector> = Arc::new(mock);
    }
}
