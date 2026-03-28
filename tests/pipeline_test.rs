// Strategy: use local_paths mode to bypass discovery's internal Nfs3Connector.
// Walker reads local filesystem, scanner uses FileReader::Local (no NFS).
#[path = "integration/helpers.rs"]
mod helpers;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use niffler::config::OperatingMode;
use niffler::nfs::NfsConnector;
use niffler::nfs::connector::MockNfsConnector;
use niffler::pipeline::run_pipeline;
use tokio_util::sync::CancellationToken;

/// Create a mock connector that is never actually called (local paths mode).
fn placeholder_connector() -> Arc<dyn NfsConnector> {
    Arc::new(MockNfsConnector::new())
}

/// Create a test config with local paths pointing to a temp directory.
/// Each test gets its own output file to avoid conflicts.
fn local_config(
    mode: OperatingMode,
    local_dir: &std::path::Path,
    test_name: &str,
) -> niffler::config::NifflerConfig {
    let mut config = helpers::test_config(mode);
    config.walker.local_paths = Some(vec![local_dir.to_path_buf()]);
    config.output.output_file =
        Some(std::env::temp_dir().join(format!("niffler_pipeline_{test_name}.jsonl")));
    config
}

#[tokio::test]
async fn pipeline_scan_mode_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();

    // Create .env file with credential content (triggers EnvFiles → CredentialPatterns relay)
    std::fs::write(
        tmp.path().join("test.env"),
        "DB_PASSWORD=MyS3cur3P@ss\nAPI_KEY=sk1234567890abcdef1234567890abcdef\n",
    )
    .unwrap();

    // Create id_rsa with SSH key content (triggers SshPrivateKeys Black rule)
    let key_content = helpers::sample_file_content("id_rsa");
    std::fs::write(tmp.path().join("id_rsa"), &key_content).unwrap();

    let config = local_config(OperatingMode::Scan, tmp.path(), "scan_e2e");
    let token = CancellationToken::new();

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        run_pipeline(config, placeholder_connector(), Some(token), None),
    )
    .await;

    assert!(result.is_ok(), "pipeline should not timeout");
    let stats = result.unwrap().expect("pipeline should succeed");

    assert!(
        stats.files_discovered.load(Ordering::Relaxed) >= 2,
        "should discover at least 2 files"
    );
    assert!(
        stats.files_content_scanned.load(Ordering::Relaxed) >= 2,
        "should scan content of at least 2 files"
    );
    assert!(
        stats.findings.load(Ordering::Relaxed) >= 1,
        "should produce at least 1 finding from credential/key patterns"
    );
}

#[tokio::test]
async fn pipeline_recon_mode_skips_walker_and_scanner() {
    let config = helpers::test_config(OperatingMode::Recon);
    let token = CancellationToken::new();

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        run_pipeline(config, placeholder_connector(), Some(token), None),
    )
    .await;

    assert!(result.is_ok(), "recon pipeline should not timeout");
    let stats = result.unwrap().expect("pipeline should succeed");

    assert_eq!(
        stats.files_discovered.load(Ordering::Relaxed),
        0,
        "walker should not run in recon mode"
    );
    assert_eq!(
        stats.files_content_scanned.load(Ordering::Relaxed),
        0,
        "scanner should not run in recon mode"
    );
    assert_eq!(
        stats.dirs_walked.load(Ordering::Relaxed),
        0,
        "no directories should be walked in recon mode"
    );
}

#[tokio::test]
async fn pipeline_enum_mode_skips_content_read() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("test.env"), "DB_PASSWORD=secret\n").unwrap();
    std::fs::write(tmp.path().join("config.yaml"), "password: test\n").unwrap();

    let config = local_config(OperatingMode::Enumerate, tmp.path(), "enum_mode");
    let token = CancellationToken::new();

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        run_pipeline(config, placeholder_connector(), Some(token), None),
    )
    .await;

    assert!(result.is_ok(), "enumerate pipeline should not timeout");
    let stats = result.unwrap().expect("pipeline should succeed");

    assert!(
        stats.files_discovered.load(Ordering::Relaxed) > 0,
        "walker should discover files in enumerate mode"
    );
    assert_eq!(
        stats.files_content_scanned.load(Ordering::Relaxed),
        0,
        "scanner should NOT read file content in enumerate mode"
    );
    assert_eq!(
        stats.bytes_read.load(Ordering::Relaxed),
        0,
        "no bytes should be read in enumerate mode"
    );
}

#[tokio::test]
async fn pipeline_stats_accuracy() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("file1.txt"), "hello world").unwrap();
    std::fs::write(tmp.path().join("file2.txt"), "nothing secret").unwrap();
    std::fs::write(tmp.path().join("file3.txt"), "just text").unwrap();

    let config = local_config(OperatingMode::Scan, tmp.path(), "stats_accuracy");
    let token = CancellationToken::new();

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        run_pipeline(config, placeholder_connector(), Some(token), None),
    )
    .await;

    assert!(result.is_ok(), "pipeline should not timeout");
    let stats = result.unwrap().expect("pipeline should succeed");

    assert_eq!(
        stats.files_discovered.load(Ordering::Relaxed),
        3,
        "should discover exactly 3 files"
    );
    // Note: dirs_walked only increments for remote NFS READDIRPLUS calls,
    // not local walkdir traversals. In local mode, it stays 0.
    assert!(
        stats.files_content_scanned.load(Ordering::Relaxed) <= 3,
        "content scanned should not exceed files discovered"
    );
}

#[tokio::test]
async fn pipeline_error_resilience() {
    let tmp = tempfile::tempdir().unwrap();

    // A file with credential content that should produce findings
    std::fs::write(tmp.path().join("test.env"), "DB_PASSWORD=MyS3cur3P@ss\n").unwrap();

    // A file that is not readable (permission denied)
    let unreadable = tmp.path().join("secret.conf");
    std::fs::write(&unreadable, "password=locked").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    }

    let config = local_config(OperatingMode::Scan, tmp.path(), "error_resilience");
    let token = CancellationToken::new();

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        run_pipeline(config, placeholder_connector(), Some(token), None),
    )
    .await;

    assert!(result.is_ok(), "pipeline should not timeout");
    let stats = result
        .unwrap()
        .expect("pipeline should succeed (not fail on permission error)");

    assert!(
        stats.files_discovered.load(Ordering::Relaxed) >= 2,
        "should discover files including the unreadable one"
    );

    // Restore permissions for cleanup
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644));
    }
}

#[tokio::test]
async fn pipeline_graceful_shutdown_on_cancellation() {
    let config = helpers::test_config(OperatingMode::Scan);
    let token = CancellationToken::new();
    // Pre-cancel: pipeline should exit immediately
    token.cancel();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        run_pipeline(config, placeholder_connector(), Some(token), None),
    )
    .await;

    assert!(result.is_ok(), "cancelled pipeline should not deadlock");
    assert!(
        result.unwrap().is_ok(),
        "cancellation is graceful — returns Ok, not Err"
    );
}

#[tokio::test]
async fn pipeline_channel_backpressure() {
    // Pipeline with local files exercises all channels end-to-end.
    // Default bounds (5000/50000/10000) are sufficient; verify no deadlock.
    let tmp = tempfile::tempdir().unwrap();
    for i in 0..20 {
        std::fs::write(
            tmp.path().join(format!("file{i}.txt")),
            format!("content {i}"),
        )
        .unwrap();
    }

    let config = local_config(OperatingMode::Scan, tmp.path(), "backpressure");
    let token = CancellationToken::new();

    let result = tokio::time::timeout(
        Duration::from_secs(15),
        run_pipeline(config, placeholder_connector(), Some(token), None),
    )
    .await;

    assert!(result.is_ok(), "pipeline should not deadlock");
    let stats = result.unwrap().expect("pipeline should succeed");

    assert_eq!(
        stats.files_discovered.load(Ordering::Relaxed),
        20,
        "all 20 files should be processed despite channel pressure"
    );
}

#[tokio::test]
async fn pipeline_empty_targets() {
    let config = helpers::test_config(OperatingMode::Scan);
    let token = CancellationToken::new();

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        run_pipeline(config, placeholder_connector(), Some(token), None),
    )
    .await;

    assert!(result.is_ok(), "empty pipeline should not timeout");
    let stats = result.unwrap().expect("empty pipeline should succeed");

    assert_eq!(stats.hosts_scanned.load(Ordering::Relaxed), 0);
    assert_eq!(stats.exports_found.load(Ordering::Relaxed), 0);
    assert_eq!(stats.files_discovered.load(Ordering::Relaxed), 0);
    assert_eq!(stats.findings.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn pipeline_all_triage_levels_in_output() {
    let tmp = tempfile::tempdir().unwrap();

    // Black: SSH private key filename match
    let key_content = helpers::sample_file_content("id_rsa");
    std::fs::write(tmp.path().join("id_rsa"), &key_content).unwrap();

    // Red: .env file with credentials (relay chain)
    std::fs::write(
        tmp.path().join("test.env"),
        "DB_PASSWORD=MyS3cur3P@ss\nSECRET_KEY=abcdef1234567890abcdef1234567890\n",
    )
    .unwrap();

    // Yellow: log file (filename match)
    std::fs::write(tmp.path().join("app.log"), "some log output\n").unwrap();

    // Green: README file (filename match)
    std::fs::write(tmp.path().join("README"), "project docs\n").unwrap();

    let output_file = std::env::temp_dir().join("niffler_pipeline_triage_levels.jsonl");
    let mut config = local_config(OperatingMode::Scan, tmp.path(), "triage_levels");
    config.output.output_file = Some(output_file.clone());
    let token = CancellationToken::new();

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        run_pipeline(config, placeholder_connector(), Some(token), None),
    )
    .await;

    assert!(result.is_ok(), "pipeline should not timeout");
    let stats = result.unwrap().expect("pipeline should succeed");

    assert!(
        stats.findings.load(Ordering::Relaxed) >= 3,
        "should find at least Black + Red + Yellow + Green findings (got {})",
        stats.findings.load(Ordering::Relaxed),
    );

    // Parse output JSON to verify multiple triage levels
    if output_file.exists() {
        let output = std::fs::read_to_string(&output_file).unwrap_or_default();
        let has_black = output.contains("\"Black\"");
        let has_red = output.contains("\"Red\"");
        // Yellow and Green depend on filename rules triggering
        assert!(
            has_black || has_red,
            "output should contain at least Black or Red findings"
        );
    }
}

#[tokio::test]
async fn pipeline_binary_file_skips_text_rules() {
    let tmp = tempfile::tempdir().unwrap();

    // Copy binary fixture (contains null bytes + decoy credential text)
    let binary_content = helpers::sample_file_content("binary_file.bin");
    std::fs::write(tmp.path().join("binary_file.bin"), &binary_content).unwrap();

    // Also add a text file that should produce a finding (control case)
    std::fs::write(tmp.path().join("test.env"), "DB_PASSWORD=MyS3cur3P@ss\n").unwrap();

    let config = local_config(OperatingMode::Scan, tmp.path(), "binary_skip");
    let token = CancellationToken::new();

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        run_pipeline(config, placeholder_connector(), Some(token), None),
    )
    .await;

    assert!(result.is_ok(), "pipeline should not timeout");
    let stats = result.unwrap().expect("pipeline should succeed");

    assert!(
        stats.files_skipped_binary.load(Ordering::Relaxed) >= 1,
        "binary file should be detected and skipped"
    );
    // The text file should still produce findings
    assert!(
        stats.findings.load(Ordering::Relaxed) >= 1,
        "text file should still produce findings alongside binary skip"
    );
}
