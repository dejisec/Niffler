use std::collections::HashSet;

use crate::nfs::auth::AuthCreds;
use crate::nfs::connector::NfsConnector;
use crate::nfs::types::DirEntry;

#[must_use]
pub fn extract_unique_creds(entries: &[DirEntry]) -> Vec<AuthCreds> {
    let unique: HashSet<(u32, u32)> = entries.iter().map(|e| (e.attrs.uid, e.attrs.gid)).collect();
    unique
        .into_iter()
        .map(|(uid, gid)| AuthCreds::new(uid, gid))
        .collect()
}

pub async fn harvest_uids(
    connector: &dyn NfsConnector,
    host: &str,
    export_path: &str,
    creds: &AuthCreds,
) -> Vec<AuthCreds> {
    let mut ops = match connector.connect(host, export_path, creds).await {
        Ok(ops) => ops,
        Err(e) => {
            tracing::debug!(host, export_path, error = %e, "UID harvest: connect failed");
            return vec![];
        }
    };

    let root = ops.root_handle().clone();
    let entries = match ops.readdirplus(&root).await {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!(host, export_path, error = %e, "UID harvest: readdirplus failed");
            return vec![];
        }
    };

    extract_unique_creds(&entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::connector::MockNfsConnector;
    use crate::nfs::errors::NfsError;
    use crate::nfs::ops::MockNfsOps;
    use crate::nfs::types::{NfsAttrs, NfsFh, NfsFileType};

    fn make_entry(name: &str, uid: u32, gid: u32) -> DirEntry {
        DirEntry {
            name: name.into(),
            fh: NfsFh::default(),
            attrs: NfsAttrs {
                file_type: NfsFileType::Regular,
                size: 100,
                mode: 0o644,
                uid,
                gid,
                mtime: 0,
            },
        }
    }

    #[test]
    fn extract_empty_entries_returns_empty() {
        let result = extract_unique_creds(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_single_entry() {
        let entries = vec![make_entry("file1", 1000, 1000)];
        let result = extract_unique_creds(&entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], AuthCreds::new(1000, 1000));
    }

    #[test]
    fn extract_removes_duplicates() {
        let entries = vec![
            make_entry("a", 1000, 1000),
            make_entry("b", 1000, 1000),
            make_entry("c", 1000, 1000),
        ];
        let result = extract_unique_creds(&entries);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn extract_preserves_unique_pairs() {
        let entries = vec![
            make_entry("a", 1000, 1000),
            make_entry("b", 1001, 1001),
            make_entry("c", 0, 0),
        ];
        let result = extract_unique_creds(&entries);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn extract_distinguishes_same_uid_different_gid() {
        let entries = vec![make_entry("a", 1000, 100), make_entry("b", 1000, 200)];
        let result = extract_unique_creds(&entries);
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn harvest_uids_from_mock_export() {
        let mut mock_connector = MockNfsConnector::new();
        mock_connector.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle()
                .return_const(NfsFh::new(vec![1, 2, 3]));
            ops.expect_readdirplus().returning(|_| {
                Ok(vec![
                    make_entry("f1", 1000, 1000),
                    make_entry("f2", 1001, 1001),
                    make_entry("f3", 1000, 1000), // duplicate
                    make_entry("f4", 0, 0),
                    make_entry("f5", 1001, 1001), // duplicate
                ])
            });
            Ok(Box::new(ops))
        });

        let creds = AuthCreds::nobody();
        let result = harvest_uids(&mock_connector, "host", "/export", &creds).await;
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn harvest_uids_permission_denied_returns_empty() {
        let mut mock_connector = MockNfsConnector::new();
        mock_connector.expect_connect().returning(|_, _, _| {
            let mut ops = MockNfsOps::new();
            ops.expect_root_handle()
                .return_const(NfsFh::new(vec![1, 2, 3]));
            ops.expect_readdirplus()
                .returning(|_| Err(Box::new(NfsError::PermissionDenied)));
            Ok(Box::new(ops))
        });

        let creds = AuthCreds::nobody();
        let result = harvest_uids(&mock_connector, "host", "/export", &creds).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn harvest_uids_connection_error_returns_empty() {
        let mut mock_connector = MockNfsConnector::new();
        mock_connector
            .expect_connect()
            .returning(|_, _, _| Err(Box::new(NfsError::ConnectionLost)));

        let creds = AuthCreds::nobody();
        let result = harvest_uids(&mock_connector, "host", "/export", &creds).await;
        assert!(result.is_empty());
    }
}
