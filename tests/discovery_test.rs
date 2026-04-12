#[path = "integration/helpers.rs"]
mod helpers;

use niffler::discovery::{check_no_root_squash, extract_unique_creds, harvest_uids};
use niffler::nfs::connector::MockNfsConnector;
use niffler::nfs::ops::MockNfsOps;
use niffler::nfs::{AuthCreds, DirEntry, Misconfiguration, NfsAttrs, NfsFh, NfsFileType};

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
fn discovery_uid_harvest_collects_unique_pairs() {
    let entries = vec![
        make_entry("file1", 1000, 1000),
        make_entry("file2", 1001, 1001),
        make_entry("file3", 1000, 1000),
        make_entry("file4", 0, 0),
        make_entry("file5", 1001, 1001),
    ];
    let result = extract_unique_creds(&entries);
    assert_eq!(
        result.len(),
        3,
        "5 entries with 3 unique (uid,gid) pairs should yield 3 AuthCreds"
    );
}

#[tokio::test]
async fn discovery_harvest_uids_with_mock() {
    let mut mock_connector = MockNfsConnector::new();
    mock_connector.expect_connect().returning(|_, _, _| {
        let mut ops = MockNfsOps::new();
        ops.expect_root_handle()
            .return_const(NfsFh::new(vec![1, 2, 3]));
        ops.expect_readdirplus().returning(|_| {
            Ok(vec![
                make_entry("a", 1000, 1000),
                make_entry("b", 1001, 1001),
                make_entry("c", 1000, 1000),
                make_entry("d", 0, 0),
            ])
        });
        Ok(Box::new(ops))
    });

    let creds = AuthCreds::nobody();
    let result = harvest_uids(&mock_connector, "10.0.0.1", "/export", &creds).await;
    assert_eq!(result.len(), 3, "should harvest 3 unique (uid,gid) pairs");
}

#[tokio::test]
async fn discovery_misconfig_no_root_squash() {
    let mut mock = MockNfsConnector::new();
    mock.expect_connect().returning(|_, _, _| {
        let mut ops = MockNfsOps::new();
        ops.expect_root_handle()
            .return_const(NfsFh::new(vec![1, 2, 3]));
        ops.expect_getattr().returning(|_| {
            Ok(NfsAttrs {
                file_type: NfsFileType::Directory,
                size: 4096,
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 0,
            })
        });
        Ok(Box::new(ops))
    });

    let result = check_no_root_squash(&mock, "10.0.0.1", "/export").await;
    assert_eq!(
        result,
        Some(Misconfiguration::PossibleNoRootSquash),
        "root connect + getattr success should detect possible_no_root_squash (heuristic)"
    );
}

#[tokio::test]
async fn discovery_detect_misconfigurations_none_when_denied() {
    let mut mock = MockNfsConnector::new();
    mock.expect_connect().returning(|_, _, _| {
        let mut ops = MockNfsOps::new();
        ops.expect_root_handle()
            .return_const(NfsFh::new(vec![1, 2, 3]));
        ops.expect_getattr()
            .returning(|_| Err(Box::new(niffler::nfs::NfsError::PermissionDenied)));
        Ok(Box::new(ops))
    });

    let result = check_no_root_squash(&mock, "10.0.0.1", "/export").await;
    assert_eq!(
        result, None,
        "permission denied on getattr should mean no_root_squash is NOT present"
    );
}
