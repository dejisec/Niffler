use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn cli_help_succeeds() {
    Command::cargo_bin("niffler")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("NFS"))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("serve"))
        .stdout(predicate::str::contains("export"));
}

#[test]
fn scan_help_contains_all_flag_groups() {
    let assert = Command::cargo_bin("niffler")
        .unwrap()
        .args(["scan", "--help"])
        .assert()
        .success();

    let flags = [
        "--targets",
        "--mode",
        "--uid",
        "--gid",
        "--live",
        "--output",
        "--rules-dir",
        "--max-scan-size",
        "--scanner-tasks",
        "--walker-tasks",
        "--discovery-tasks",
        "--max-depth",
        "--no-privileged-port",
        "--generate-config",
        "--config",
        "--min-severity",
    ];

    let mut a = assert;
    for flag in flags {
        a = a.stdout(predicate::str::contains(flag));
    }
}

#[test]
fn cli_generate_config_outputs_valid_toml() {
    let output = Command::cargo_bin("niffler")
        .unwrap()
        .args(["scan", "-z"])
        .output()
        .expect("failed to run niffler scan -z");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("stdout is valid UTF-8");
    let value: toml::Value = toml::from_str(&stdout).expect("stdout should be valid TOML");
    assert!(value.is_table(), "TOML output should be a table");
}

#[test]
fn cli_generate_config_contains_key_fields() {
    Command::cargo_bin("niffler")
        .unwrap()
        .args(["scan", "-z"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mode"))
        .stdout(predicate::str::contains("max_depth"))
        .stdout(predicate::str::contains("max_scan_size"))
        .stdout(predicate::str::contains("uid"))
        .stdout(predicate::str::contains("db_path"));
}

#[test]
fn cli_no_subcommand_fails() {
    Command::cargo_bin("niffler").unwrap().assert().failure();
}

#[test]
fn scan_no_targets_fails() {
    Command::cargo_bin("niffler")
        .unwrap()
        .arg("scan")
        .assert()
        .failure()
        .stderr(predicate::str::contains("no targets"));
}

#[test]
fn serve_help_shows_options() {
    Command::cargo_bin("niffler")
        .unwrap()
        .args(["serve", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--db"))
        .stdout(predicate::str::contains("--port"))
        .stdout(predicate::str::contains("--bind"));
}

#[test]
fn export_help_shows_options() {
    Command::cargo_bin("niffler")
        .unwrap()
        .args(["export", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--db"))
        .stdout(predicate::str::contains("--format"))
        .stdout(predicate::str::contains("--min-severity"))
        .stdout(predicate::str::contains("--host"))
        .stdout(predicate::str::contains("--rule"))
        .stdout(predicate::str::contains("--scan-id"));
}

#[test]
fn scan_subcommand_with_generate_config() {
    Command::cargo_bin("niffler")
        .unwrap()
        .args(["scan", "-t", "10.0.0.1", "-z"])
        .assert()
        .success()
        .stdout(predicate::str::contains("10.0.0.1"));
}

#[test]
fn scan_creates_default_db() {
    let work_dir = tempfile::tempdir().unwrap();
    let data_dir = tempfile::Builder::new()
        .prefix("niffler-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();

    std::fs::write(
        data_dir.path().join("test.env"),
        "DB_PASSWORD=MyS3cur3P@ss\n",
    )
    .unwrap();

    Command::cargo_bin("niffler")
        .unwrap()
        .current_dir(work_dir.path())
        .args(["scan", "-i", data_dir.path().to_str().unwrap()])
        .timeout(Duration::from_secs(30))
        .assert()
        .success();

    assert!(
        work_dir.path().join("niffler.db").exists(),
        "scan should create niffler.db in the working directory"
    );
}

#[test]
fn scan_live_flag() {
    let data_dir = tempfile::Builder::new()
        .prefix("niffler-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap();
    let db_file = tempfile::NamedTempFile::new().unwrap();

    std::fs::write(
        data_dir.path().join("test.env"),
        "DB_PASSWORD=MyS3cur3P@ss\nAPI_KEY=sk1234567890abcdef1234567890abcdef\n",
    )
    .unwrap();

    Command::cargo_bin("niffler")
        .unwrap()
        .args([
            "scan",
            "-i",
            data_dir.path().to_str().unwrap(),
            "--live",
            "-o",
            db_file.path().to_str().unwrap(),
        ])
        .timeout(Duration::from_secs(30))
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not());
}

#[test]
fn global_verbosity_before_subcommand() {
    Command::cargo_bin("niffler")
        .unwrap()
        .args(["-v", "debug", "scan", "-z"])
        .assert()
        .success();
}
