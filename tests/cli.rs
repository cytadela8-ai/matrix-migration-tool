//! CLI contract tests exercise error exit codes and report persistence without live accounts.

use std::{path::Path, process::Command};

use matrix_migration_tool::report::Report;
use tempfile::TempDir;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_matrix-migration-tool"))
}

#[test]
fn help_and_invalid_arguments_have_expected_exit_codes() {
    assert!(cli().arg("--help").output().unwrap().status.success());
    let output = cli().arg("unknown-command").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
}

#[test]
fn invalid_config_fails_before_creating_state() {
    let directory = TempDir::new().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(&config, "invalid TOML [").unwrap();
    let output = cli()
        .arg("--config")
        .arg(config)
        .arg("--state-dir")
        .arg(directory.path().join("state"))
        .arg("migrate")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!directory.path().join("state").exists());
}

#[test]
fn missing_secret_produces_fatal_report_without_disclosing_values() {
    let directory = TempDir::new().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(&config, include_str!("../config.toml.example")).unwrap();
    let report = directory.path().join("report.json");
    let output = cli()
        .arg("--config")
        .arg(config)
        .arg("--state-dir")
        .arg(directory.path().join("state"))
        .args(["migrate", "--report"])
        .arg(&report)
        .env_remove("MATRIX_STORE_PASSPHRASE")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let result = read_report(&report);
    assert!(result.fatal.unwrap().contains("MATRIX_STORE_PASSPHRASE"));
    assert_eq!(result.from, "@alice:old.example");
}

#[test]
fn saved_account_mismatch_is_rejected_before_network_login() {
    let directory = TempDir::new().unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(&config, include_str!("../config.toml.example")).unwrap();
    let account = directory.path().join("state/from");
    std::fs::create_dir_all(&account).unwrap();
    let session = serde_json::json!({"homeserver": "https://other.example", "session": {
        "user_id": "@someone:other.example", "device_id": "OTHER_DEVICE",
        "access_token": "test-only-never-use-this-token"
    }});
    std::fs::write(account.join("session.json"), serde_json::to_vec(&session).unwrap()).unwrap();
    let report = directory.path().join("report.json");
    let output = cli()
        .arg("--config")
        .arg(config)
        .arg("--state-dir")
        .arg(directory.path().join("state"))
        .args(["migrate", "--report"])
        .arg(&report)
        .env("MATRIX_STORE_PASSPHRASE", "test-store-passphrase")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(read_report(&report).fatal.unwrap().contains("another account"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("test-only-never-use-this-token"));
}

fn read_report(path: &Path) -> Report {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
