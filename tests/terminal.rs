//! Linux pseudo-terminal tests cover Ctrl-C during normal/hidden input and echo restoration.
//! util-linux `script` supplies a real controlling terminal without unsafe code or credentials.

#![cfg(target_os = "linux")]

use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

use matrix_migration_tool::config::Config;

#[test]
fn ctrl_c_at_account_prompt_exits_without_creating_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    let output = interrupt(&config, "Source Matrix ID", "");
    assert!(output.to_lowercase().contains("interrupted"), "Unexpected terminal output: {output}");
    assert!(!config.exists());
}

#[test]
fn hidden_input_is_not_echoed_and_ctrl_c_restores_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let mut config: Config = toml::from_str(include_str!("../config.toml.example")).unwrap();
    config.from.password_env = None;
    config.to.password_env = None;
    config.store_passphrase_env = None;
    let original = toml::to_string_pretty(&config).unwrap();
    std::fs::write(&path, &original).unwrap();
    let output = interrupt(&path, "Local store passphrase:", "never-echo-test-secret");
    assert!(!output.contains("never-echo-test-secret"));
    assert!(output.to_lowercase().contains("interrupted"), "Unexpected terminal output: {output}");
    assert!(output.contains(" echo "), "Terminal echo must be restored: {output}");
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
}

fn interrupt(config: &std::path::Path, stop: &str, secret: &str) -> String {
    let state = config.parent().unwrap().join("state");
    let mut child = Command::new("script")
        .args([
            "-qefc",
            concat!(
                "\"$MATRIX_TEST_BINARY\" --config \"$MATRIX_TEST_CONFIG\" ",
                "--state-dir \"$MATRIX_TEST_STATE\" init; status=$?; stty -a; exit $status"
            ),
            "/dev/null",
        ])
        .env("MATRIX_TEST_BINARY", env!("CARGO_BIN_EXE_matrix-migration-tool"))
        .env("MATRIX_TEST_CONFIG", config)
        .env("MATRIX_TEST_STATE", state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Linux terminal tests require util-linux script");
    let mut input = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut bytes = [0; 4096];
        loop {
            let count = stdout.read(&mut bytes).unwrap();
            if count == 0 {
                break;
            }
            sender.send(String::from_utf8_lossy(&bytes[..count]).into_owned()).unwrap();
        }
    });
    let mut output = String::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut confirmed = false;
    while !output.contains(stop) {
        let timeout = deadline.saturating_duration_since(Instant::now());
        output.push_str(&receiver.recv_timeout(timeout).expect("Wizard prompt timed out"));
        if !confirmed && output.contains("Set up this migration?") {
            input.write_all(b"yes\n").unwrap();
            input.flush().unwrap();
            confirmed = true;
        }
    }
    // Let the hidden reader disable echo before sending an unfinished password.
    std::thread::sleep(Duration::from_millis(100));
    input.write_all(secret.as_bytes()).unwrap();
    input.flush().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    input.write_all(&[3]).unwrap();
    input.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("Ctrl-C did not stop setup promptly");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(1));
    drop(input);
    reader.join().unwrap();
    for chunk in receiver {
        output.push_str(&chunk);
    }
    output
}
