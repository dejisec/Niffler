use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_flag_exits_zero() {
    Command::cargo_bin("niffler")
        .unwrap()
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn help_output_contains_description() {
    Command::cargo_bin("niffler")
        .unwrap()
        .arg("--help")
        .assert()
        .stdout(predicate::str::contains("NFS"));
}

#[test]
fn help_output_contains_key_flags() {
    let assert = Command::cargo_bin("niffler")
        .unwrap()
        .arg("--help")
        .assert()
        .success();

    assert
        .stdout(predicate::str::contains("--targets"))
        .stdout(predicate::str::contains("--mode"))
        .stdout(predicate::str::contains("--uid"));
}
