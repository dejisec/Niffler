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
        .stdout(predicate::str::contains("--targets"));
}

#[test]
fn cli_help_contains_all_flag_groups() {
    let assert = Command::cargo_bin("niffler")
        .unwrap()
        .arg("--help")
        .assert()
        .success();

    let flags = [
        "--mode",
        "--uid",
        "--gid",
        "--format",
        "--output",
        "--rules-dir",
        "--max-scan-size",
        "--scanner-tasks",
        "--walker-tasks",
        "--discovery-tasks",
        "--max-depth",
        "--privileged-port",
        "--generate-config",
        "--config",
        "--verbosity",
        "--min-severity",
    ];

    let mut a = assert;
    for flag in flags {
        a = a.stdout(predicate::str::contains(flag));
    }
}

#[test]
fn cli_help_shows_default_values() {
    Command::cargo_bin("niffler")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("console"))
        .stdout(predicate::str::contains("50"))
        .stdout(predicate::str::contains("1048576"));
}

#[test]
fn cli_generate_config_outputs_valid_toml() {
    let output = Command::cargo_bin("niffler")
        .unwrap()
        .arg("-z")
        .output()
        .expect("failed to run niffler -z");

    assert!(output.status.success(), "niffler -z should exit 0");

    let stdout = String::from_utf8(output.stdout).expect("stdout is valid UTF-8");
    let value: toml::Value = toml::from_str(&stdout).expect("stdout should be valid TOML");
    assert!(value.is_table(), "TOML output should be a table");
}

#[test]
fn cli_generate_config_contains_sections() {
    Command::cargo_bin("niffler")
        .unwrap()
        .arg("-z")
        .assert()
        .success()
        .stdout(predicate::str::contains("[discovery]"))
        .stdout(predicate::str::contains("[walker]"))
        .stdout(predicate::str::contains("[scanner]"))
        .stdout(predicate::str::contains("[output]"));
}

#[test]
fn cli_generate_config_contains_key_fields() {
    Command::cargo_bin("niffler")
        .unwrap()
        .arg("-z")
        .assert()
        .success()
        .stdout(predicate::str::contains("mode"))
        .stdout(predicate::str::contains("max_depth"))
        .stdout(predicate::str::contains("max_scan_size"))
        .stdout(predicate::str::contains("uid"))
        .stdout(predicate::str::contains("format"));
}

#[test]
fn cli_no_targets_fails() {
    Command::cargo_bin("niffler")
        .unwrap()
        .assert()
        .failure()
        .stderr(predicate::str::contains("no targets"));
}

#[test]
fn cli_version_or_about() {
    Command::cargo_bin("niffler")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("niffler"));
}
