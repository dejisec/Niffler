use std::net::SocketAddr;

use crate::nfs::auth::AuthCreds;
use crate::nfs::connector::NfsConnector;
use crate::nfs::types::Misconfiguration;
use crate::nfs::v3::Nfs3Connector;

/// Heuristic check for `no_root_squash` on an export.
///
/// Connects as UID 0 and attempts `getattr` on the root handle. If successful,
/// flags `PossibleNoRootSquash`. Note: this is NOT conclusive — with `root_squash`
/// enabled, UID 0 is squashed to `nobody`, which can still `getattr` on
/// world-readable (0o755) directories. A definitive check would require `setattr`
/// or a write operation, which `NfsOps` does not currently expose.
pub async fn check_no_root_squash(
    connector: &dyn NfsConnector,
    host: &str,
    export: &str,
) -> Option<Misconfiguration> {
    let mut ops = match connector.connect(host, export, &AuthCreds::root()).await {
        Ok(ops) => ops,
        Err(e) => {
            tracing::debug!(host, export, error = %e, "no_root_squash check: connect failed (inconclusive)");
            return None;
        }
    };
    let root = ops.root_handle().clone();
    match ops.getattr(&root).await {
        Ok(_) => Some(Misconfiguration::PossibleNoRootSquash),
        Err(e) => {
            tracing::debug!(host, export, error = %e, "no_root_squash check: getattr denied");
            None
        }
    }
}

/// Detect if the export accepts connections from non-privileged ports.
///
/// Creates its own connector with `privileged_port=false` to test whether the
/// server accepts unprivileged connections. If the unprivileged connection
/// succeeds and `getattr` works, the export has `insecure` set. If the
/// connection is refused, the server requires privileged ports (secure).
pub async fn check_insecure_export(
    host: &str,
    export: &str,
    proxy: Option<SocketAddr>,
) -> Option<Misconfiguration> {
    // Create a connector that does NOT use a privileged port
    let connector = match proxy {
        Some(addr) => Nfs3Connector::with_proxy(addr),
        None => Nfs3Connector::new(false), // privileged_port = false
    };
    let mut ops = match connector.connect(host, export, &AuthCreds::nobody()).await {
        Ok(ops) => ops,
        Err(e) => {
            tracing::debug!(host, export, error = %e, "insecure_export check: unprivileged connect failed (server is secure)");
            return None; // Can't connect without privileged port = server is secure
        }
    };
    let root = ops.root_handle().clone();
    match ops.getattr(&root).await {
        Ok(_) => Some(Misconfiguration::InsecureExport),
        Err(e) => {
            tracing::debug!(host, export, error = %e, "insecure_export check: getattr denied");
            None
        }
    }
}

/// Detect if the export is vulnerable to `subtree_check` bypass.
/// Attempts to `LOOKUP ".."` from the export root. If the server returns a
/// different handle (i.e. the actual parent directory), `subtree_check` is
/// likely disabled — the client has escaped the export boundary.
pub async fn check_subtree_bypass(
    connector: &dyn NfsConnector,
    host: &str,
    export: &str,
) -> Option<Misconfiguration> {
    let mut ops = match connector.connect(host, export, &AuthCreds::nobody()).await {
        Ok(ops) => ops,
        Err(e) => {
            tracing::debug!(host, export, error = %e, "subtree_check check: connect failed (inconclusive)");
            return None;
        }
    };
    let root = ops.root_handle().clone();
    let (parent_fh, _) = match ops.lookup(&root, "..").await {
        Ok(result) => result,
        Err(e) => {
            tracing::debug!(host, export, error = %e, "subtree_check check: lookup .. failed (likely enforced)");
            return None;
        }
    };
    // If ".." resolved back to the export root, subtree_check is enforced.
    if parent_fh == root {
        return None;
    }
    // The handle points outside the export — confirm access.
    match ops.getattr(&parent_fh).await {
        Ok(_) => Some(Misconfiguration::SubtreeBypass),
        Err(e) => {
            tracing::debug!(host, export, error = %e, "subtree_check check: getattr on parent denied");
            None
        }
    }
}

/// Run all misconfiguration checks on an export.
pub async fn detect_misconfigurations(
    connector: &dyn NfsConnector,
    host: &str,
    export: &str,
    check_subtree: bool,
    proxy: Option<SocketAddr>,
) -> Vec<Misconfiguration> {
    let mut misconfigs = Vec::new();

    if let Some(m) = check_no_root_squash(connector, host, export).await {
        misconfigs.push(m);
    }

    if let Some(m) = check_insecure_export(host, export, proxy).await {
        misconfigs.push(m);
    }

    if check_subtree && let Some(m) = check_subtree_bypass(connector, host, export).await {
        misconfigs.push(m);
    }

    misconfigs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::errors::NfsError;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::types::{NfsAttrs, NfsFh, NfsFileType};

    fn mock_attrs() -> NfsAttrs {
        NfsAttrs {
            file_type: NfsFileType::Directory,
            size: 4096,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn mock_ops_success() -> MockNfsOps {
        let mut ops = MockNfsOps::new();
        ops.expect_root_handle()
            .return_const(NfsFh::new(vec![1, 2, 3]));
        ops.expect_getattr().returning(|_| Ok(mock_attrs()));
        ops
    }

    fn mock_ops_permission_denied() -> MockNfsOps {
        let mut ops = MockNfsOps::new();
        ops.expect_root_handle()
            .return_const(NfsFh::new(vec![1, 2, 3]));
        ops.expect_getattr()
            .returning(|_| Err(Box::new(NfsError::PermissionDenied)));
        ops
    }

    #[tokio::test]
    async fn no_root_squash_detected_when_root_reads_succeed() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect()
            .returning(|_, _, _| Ok(Box::new(mock_ops_success())));

        let result = check_no_root_squash(&mock, "host", "/export").await;
        assert_eq!(result, Some(Misconfiguration::PossibleNoRootSquash));
    }

    #[tokio::test]
    async fn no_root_squash_absent_when_permission_denied() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect()
            .returning(|_, _, _| Ok(Box::new(mock_ops_permission_denied())));

        let result = check_no_root_squash(&mock, "host", "/export").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn no_root_squash_absent_on_connection_failure() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect()
            .returning(|_, _, _| Err(Box::new(NfsError::ConnectionLost)));

        let result = check_no_root_squash(&mock, "host", "/export").await;
        assert_eq!(result, None);
    }

    // Note: check_insecure_export now creates its own Nfs3Connector internally
    // and cannot be tested with mocks. Integration tests cover it via
    // detect_misconfigurations against a real NFS server.
    #[tokio::test]
    #[ignore = "requires NFS server — check_insecure_export makes real TCP connection"]
    async fn insecure_export_detected_when_unprivileged_connects() {
        // This test requires a real NFS server with `insecure` option.
        let result = check_insecure_export("localhost", "/export", None).await;
        assert_eq!(result, Some(Misconfiguration::InsecureExport));
    }

    #[tokio::test]
    #[ignore = "requires NFS server — check_insecure_export makes real TCP connection"]
    async fn insecure_export_absent_when_unprivileged_rejected() {
        // This test requires a real NFS server that rejects unprivileged ports.
        let result = check_insecure_export("localhost", "/secure_export", None).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn subtree_bypass_detected_when_parent_lookup_succeeds() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            let root_fh = NfsFh::new(vec![1, 2, 3]);
            ops.expect_root_handle().return_const(root_fh);
            // ".." returns a different handle — escaped export boundary
            ops.expect_lookup()
                .returning(|_, _| Ok((NfsFh::new(vec![9, 8, 7]), mock_attrs())));
            ops.expect_getattr().returning(|_| Ok(mock_attrs()));
            Ok(Box::new(ops))
        });

        let result = check_subtree_bypass(&mock, "host", "/export").await;
        assert_eq!(result, Some(Misconfiguration::SubtreeBypass));
    }

    #[tokio::test]
    async fn subtree_bypass_absent_when_lookup_returns_same_handle() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            let root_fh = NfsFh::new(vec![1, 2, 3]);
            ops.expect_root_handle().return_const(root_fh.clone());
            // ".." resolves back to root — subtree_check is enforced
            ops.expect_lookup()
                .returning(|_, _| Ok((NfsFh::new(vec![1, 2, 3]), mock_attrs())));
            Ok(Box::new(ops))
        });

        let result = check_subtree_bypass(&mock, "host", "/export").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn subtree_bypass_absent_when_lookup_fails() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle()
                .return_const(NfsFh::new(vec![1, 2, 3]));
            ops.expect_lookup()
                .returning(|_, _| Err(Box::new(NfsError::PermissionDenied)));
            Ok(Box::new(ops))
        });

        let result = check_subtree_bypass(&mock, "host", "/export").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn subtree_bypass_absent_on_connection_failure() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect()
            .returning(|_, _, _| Err(Box::new(NfsError::ConnectionLost)));

        let result = check_subtree_bypass(&mock, "host", "/export").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn detect_misconfigs_includes_possible_no_root_squash() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect()
            .returning(|_, _, _| Ok(Box::new(mock_ops_success())));

        // Note: check_insecure_export makes a real TCP connection to "host"
        // which will fail (no server), so only PossibleNoRootSquash is detected.
        let result = detect_misconfigurations(&mock, "host", "/export", false, None).await;
        assert!(result.contains(&Misconfiguration::PossibleNoRootSquash));
    }

    #[tokio::test]
    async fn detect_misconfigs_empty_when_all_secure() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect()
            .returning(|_, _, _| Err(Box::new(NfsError::ConnectionLost)));

        let result = detect_misconfigurations(&mock, "host", "/export", false, None).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn detect_misconfigs_with_subtree_enabled() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            let root_fh = NfsFh::new(vec![1, 2, 3]);
            ops.expect_root_handle().return_const(root_fh);
            ops.expect_getattr().returning(|_| Ok(mock_attrs()));
            ops.expect_lookup()
                .returning(|_, _| Ok((NfsFh::new(vec![9, 8, 7]), mock_attrs())));
            Ok(Box::new(ops))
        });

        let result = detect_misconfigurations(&mock, "host", "/export", true, None).await;
        assert!(result.contains(&Misconfiguration::PossibleNoRootSquash));
        assert!(result.contains(&Misconfiguration::SubtreeBypass));
    }

    #[tokio::test]
    async fn detect_misconfigs_with_subtree_disabled() {
        let mut mock = MockNfsConnector::new();
        mock.expect_connect()
            .returning(|_, _, _| Ok(Box::new(mock_ops_success())));

        let result = detect_misconfigurations(&mock, "host", "/export", false, None).await;
        assert!(!result.contains(&Misconfiguration::SubtreeBypass));
    }
}
