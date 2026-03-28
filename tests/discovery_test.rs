#[path = "integration/helpers.rs"]
mod helpers;

use std::io::Write;
use std::net::IpAddr;

use niffler::discovery::{
    TargetHost, check_no_root_squash, detect_misconfigurations, extract_unique_creds, harvest_uids,
    resolve_single_target, resolve_targets_from_file, resolve_targets_from_list,
};
use niffler::nfs::connector::MockNfsConnector;
use niffler::nfs::ops::MockNfsOps;
use niffler::nfs::{AuthCreds, DirEntry, Misconfiguration, NfsAttrs, NfsFh, NfsFileType};

#[test]
fn target_parse_single_ip() {
    let result = resolve_single_target("192.168.1.1").unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0],
        TargetHost::Ip("192.168.1.1".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn target_parse_cidr_24() {
    let result = resolve_single_target("10.0.0.0/24").unwrap();
    assert_eq!(result.len(), 254, "a /24 should expand to 254 host IPs");
    assert_eq!(
        result[0],
        TargetHost::Ip("10.0.0.1".parse::<IpAddr>().unwrap()),
        "first host should be 10.0.0.1"
    );
    assert_eq!(
        result[253],
        TargetHost::Ip("10.0.0.254".parse::<IpAddr>().unwrap()),
        "last host should be 10.0.0.254"
    );
}

#[test]
fn target_parse_cidr_32() {
    let result = resolve_single_target("10.0.0.1/32").unwrap();
    assert_eq!(result.len(), 1, "/32 should produce exactly 1 host");
    assert_eq!(
        result[0],
        TargetHost::Ip("10.0.0.1".parse::<IpAddr>().unwrap())
    );
}

#[test]
fn target_parse_hostname() {
    let result = resolve_single_target("nfs-server.internal").unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0],
        TargetHost::Hostname("nfs-server.internal".into())
    );
}

#[test]
fn target_parse_file_input() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "192.168.1.1").unwrap();
    writeln!(tmp, "# comment line").unwrap();
    writeln!(tmp).unwrap(); // blank line
    writeln!(tmp, "10.0.0.0/30").unwrap();
    writeln!(tmp, "nfs-host").unwrap();
    tmp.flush().unwrap();

    let result = resolve_targets_from_file(tmp.path().to_str().unwrap()).unwrap();
    // 1 IP + 2 from /30 + 1 hostname = 4
    assert_eq!(
        result.len(),
        4,
        "expected 4 targets (comment and blank skipped)"
    );

    assert!(matches!(result[0], TargetHost::Ip(_)), "first should be IP");
    assert_eq!(
        result[3],
        TargetHost::Hostname("nfs-host".into()),
        "last should be hostname"
    );
}

#[test]
fn target_parse_mixed_cli() {
    let specs: Vec<String> = vec![
        "192.168.1.1".into(),
        "10.0.0.0/30".into(),
        "nfs-host".into(),
    ];
    let result = resolve_targets_from_list(&specs).unwrap();
    // 1 IP + 2 from /30 + 1 hostname = 4
    assert_eq!(result.len(), 4, "expected 4 targets from mixed CLI input");
    assert_eq!(
        result[0],
        TargetHost::Ip("192.168.1.1".parse::<IpAddr>().unwrap())
    );
    assert_eq!(result[3], TargetHost::Hostname("nfs-host".into()));
}

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
        make_entry("file3", 1000, 1000), // duplicate
        make_entry("file4", 0, 0),
        make_entry("file5", 1001, 1001), // duplicate
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
                make_entry("c", 1000, 1000), // duplicate
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
        Some(Misconfiguration::NoRootSquash),
        "root connect + getattr success should detect no_root_squash"
    );
}

#[tokio::test]
async fn discovery_error_resilience_continues_after_host_failure() {
    let mut mock_connector = MockNfsConnector::new();
    mock_connector
        .expect_connect()
        .returning(|_, _, _| Err(Box::new(niffler::nfs::NfsError::ConnectionLost)));

    // harvest_uids gracefully returns empty vec on connection failure
    let creds = AuthCreds::nobody();
    let result = harvest_uids(&mock_connector, "10.0.0.2", "/export", &creds).await;
    assert!(
        result.is_empty(),
        "connection failure should return empty vec, not panic"
    );

    // detect_misconfigurations also returns empty on failure
    let misconfigs = detect_misconfigurations(&mock_connector, "10.0.0.2", "/export", false).await;
    assert!(
        misconfigs.is_empty(),
        "connection failure should produce no misconfigs, not error"
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
