#![allow(unused_imports)]

use std::collections::HashMap;
use std::path::PathBuf;

use niffler::classifier::Triage;
use niffler::config::{
    DiscoveryConfig, NifflerConfig, OperatingMode, OutputConfig, ScannerConfig, WalkerConfig,
};
use niffler::nfs::connector::MockNfsConnector;
use niffler::nfs::ops::MockNfsOps;
use niffler::nfs::{
    AuthCreds, DirEntry, NfsAttrs, NfsFh, NfsFileType, NfsOps, NfsVersion, ReadResult,
};
use niffler::pipeline::{FileMsg, FileReader};

/// Create a temp directory under `CARGO_MANIFEST_DIR` instead of `/tmp`,
/// avoiding `DiscardLinuxSystemPaths` pruning scan input.
#[allow(dead_code)]
pub fn scan_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("niffler-test-")
        .tempdir_in(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")))
        .unwrap()
}

/// Resolve a path relative to `tests/fixtures/`.
pub fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative)
}

/// Read a sample file from `tests/fixtures/sample_files/{name}`.
/// Panics if the file is missing — fixture absence is a test setup bug.
#[allow(dead_code)]
pub fn sample_file_content(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(&format!("sample_files/{name}")))
        .unwrap_or_else(|e| panic!("fixture file 'sample_files/{name}' missing: {e}"))
}

/// Create a minimal `NifflerConfig` for integration tests.
///
/// Low concurrency values to keep tests fast. JSON output to a temp file
/// (disables progress bars). Embedded default rules only.
#[allow(dead_code)]
pub fn test_config(mode: OperatingMode) -> NifflerConfig {
    NifflerConfig {
        mode,
        discovery: DiscoveryConfig {
            targets: None,
            target_file: None,
            nfs_version: None,
            privileged_port: false,
            discovery_tasks: 2,
            timeout_secs: 5,
            proxy: None,
            connect_timeout_secs: 10,
        },
        walker: WalkerConfig {
            walker_tasks: 2,
            max_depth: 50,
            local_paths: None,
            max_connections_per_host: 4,
            walk_retries: 2,
            walk_retry_delay_ms: 500,
            uid_cycle: true,
            max_uid_attempts: 5,
            nfs_timeout_secs: 30,
            connect_timeout_secs: 10,
            parallel_dirs: 1,
        },
        scanner: ScannerConfig {
            scanner_tasks: 5,
            max_scan_size: 1_048_576,
            read_chunk_size: 1_048_576,
            uid: 0,
            gid: 0,
            uid_cycle: false,
            max_uid_attempts: 3,
            max_connections_per_host: 4,
            check_subtree_bypass: false,
            nfs_timeout_secs: 30,
            connect_timeout_secs: 10,
            task_timeout_secs: 300,
            scan_retries: 0,
            scan_retry_delay_ms: 0,
        },
        output: OutputConfig {
            db_path: std::env::temp_dir().join("niffler_integration_test.db"),
            live: false,
            min_severity: Triage::Green,
        },
        health: niffler::config::HealthConfig {
            error_threshold: 10,
            cooldown_secs: 60,
        },
        rules_dir: None,
        extra_rules: None,
        generate_config: false,
    }
}

/// Build a `MockNfsOps` that returns the given directory entries from
/// `readdirplus()` and file contents from `read()` keyed by file handle bytes.
#[allow(dead_code)]
pub fn mock_nfs_ops_with_entries(
    entries: Vec<DirEntry>,
    file_contents: HashMap<Vec<u8>, Vec<u8>>,
) -> MockNfsOps {
    let mut ops = MockNfsOps::new();

    ops.expect_root_handle()
        .return_const(NfsFh::new(vec![0, 0, 1]));

    ops.expect_readdirplus()
        .returning(move |_| Ok(entries.clone()));

    ops.expect_getattr().returning(|_| Ok(dir_attrs()));

    ops.expect_read()
        .returning(move |fh: &NfsFh, offset: u64, count: u32| {
            let key = fh.as_bytes().to_vec();
            match file_contents.get(&key) {
                Some(data) => {
                    let start = offset as usize;
                    let end = (start + count as usize).min(data.len());
                    if start >= data.len() {
                        Ok(ReadResult {
                            data: vec![],
                            eof: true,
                        })
                    } else {
                        Ok(ReadResult {
                            data: data[start..end].to_vec(),
                            eof: end >= data.len(),
                        })
                    }
                }
                None => Ok(ReadResult {
                    data: vec![],
                    eof: true,
                }),
            }
        });

    ops.expect_lookup().returning(|_, _| {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        )))
    });

    ops.expect_readlink().returning(|_| {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a symlink",
        )))
    });

    ops
}

/// Build a `MockNfsConnector` whose `connect()` calls the factory each time.
#[allow(dead_code)]
pub fn mock_connector_returning(
    ops_factory: impl Fn() -> MockNfsOps + Send + Sync + 'static,
) -> MockNfsConnector {
    let mut mock = MockNfsConnector::new();

    mock.expect_connect()
        .returning(move |_, _, _| Ok(Box::new(ops_factory()) as Box<dyn niffler::nfs::NfsOps>));

    mock.expect_detect_version()
        .returning(|_| Ok(NfsVersion::V3));

    mock
}

/// Construct a `FileMsg` with default file handle and `FileReader::Nfs`.
#[allow(dead_code)]
pub fn make_file_msg(host: &str, export: &str, path: &str, attrs: NfsAttrs) -> FileMsg {
    FileMsg {
        host: host.into(),
        export_path: export.into(),
        file_path: path.into(),
        file_handle: NfsFh::default(),
        attrs,
        reader: FileReader::Nfs {
            host: host.into(),
            export: export.into(),
        },
        harvested_uids: vec![],
    }
}

/// Create `NfsAttrs` for a regular file.
#[allow(dead_code)]
pub fn file_attrs(size: u64, uid: u32, gid: u32, mode: u32) -> NfsAttrs {
    NfsAttrs {
        file_type: NfsFileType::Regular,
        size,
        mode,
        uid,
        gid,
        mtime: 0,
    }
}

/// Create `NfsAttrs` for a directory.
#[allow(dead_code)]
pub fn dir_attrs() -> NfsAttrs {
    NfsAttrs {
        file_type: NfsFileType::Directory,
        size: 4096,
        mode: 0o755,
        uid: 0,
        gid: 0,
        mtime: 0,
    }
}
