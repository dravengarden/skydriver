//! Process-level contract tests for Carrack CLI failures.

use std::process::{Command, Output};

use serde_json::Value;

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_carrack"))
        .args(arguments)
        .env_remove("CARRACK_CONTROL_URL")
        .env_remove("CARRACK_VFS_TOKEN")
        .output()
        .expect("run carrack CLI")
}

fn assert_failure(output: &Output, status: i32, code: &str) {
    assert_eq!(output.status.code(), Some(status));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).expect("decode CLI error JSON");
    assert_eq!(error["schema"], "carrack.cli-error.v1");
    assert_eq!(error["code"], code);
    assert_eq!(error["exit_status"], status);
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
}

#[test]
fn process_status_matches_the_machine_readable_error() {
    assert_failure(&run(&[]), 2, "invalid_arguments");
    assert_failure(
        &run(&["compatibility", "--control-url", "http://example.com"]),
        4,
        "invalid_control_plane",
    );
    assert_failure(
        &run(&["list", "/", "--control-url", "https://example.com"]),
        14,
        "missing_environment",
    );
}
