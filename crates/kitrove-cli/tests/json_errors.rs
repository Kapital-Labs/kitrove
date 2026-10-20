#![forbid(unsafe_code)]

use std::fs;
use std::process::{Command, Output, Stdio};

fn invoke(root: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .env_clear()
        .env("HOME", root)
        .env("USERPROFILE", root)
        .env("KITROVE_STATE_HOME", root.join("state"))
        .env("KITROVE_ENV", root.join("collection"))
        .current_dir(root)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn usage_and_operational_errors_have_only_version_code_and_exit_status() {
    let root = kitrove_testkit::trusted_tempdir(".kitrove-json-errors-");
    for (args, status) in [
        (vec!["--json-errors", "UNKNOWN-SECRET-CANARY"], 2),
        (vec!["--json-errors", "status", "--json"], 1),
        (vec!["--json-errors", "configure", "--json"], 2),
    ] {
        let output = invoke(root.path(), &args);
        assert_eq!(output.status.code(), Some(status));
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["schema_version"], 1);
        assert_eq!(error["exit_code"], status);
        assert_eq!(error.as_object().unwrap().len(), 3);
        assert_eq!(error["error"].as_object().unwrap().len(), 1);
        assert!(error["error"]["code"].as_str().unwrap().contains('.'));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("CANARY"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(root.path().to_str().unwrap()));
        assert!(!root.path().join("state").exists());
        assert!(!root.path().join("collection").exists());
    }
}

#[test]
fn opt_in_preserves_success_json_and_default_error_behavior() {
    let root = kitrove_testkit::trusted_tempdir(".kitrove-json-errors-");
    let default = invoke(root.path(), &["status", "--json"]);
    assert_eq!(default.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&default.stderr).starts_with("error["));
    let opted = invoke(root.path(), &["--json-errors", "status", "--json"]);
    let error: serde_json::Value = serde_json::from_slice(&opted.stderr).unwrap();
    assert!(
        String::from_utf8_lossy(&default.stderr).starts_with(&format!(
            "error[{}]:",
            error["error"]["code"].as_str().unwrap()
        ))
    );

    fs::create_dir(root.path().join("collection")).unwrap();
    kitrove_testkit::owned_fixture::create(
        &root.path().join("collection/kitrove.toml"),
        b"schema_version = 1\n",
    );
    let default = invoke(root.path(), &["status", "--json"]);
    let opted = invoke(root.path(), &["--json-errors", "status", "--json"]);
    assert_eq!(default.status.code(), opted.status.code());
    assert!(opted.stderr.is_empty());
    assert_eq!(default.stdout, opted.stdout);
    serde_json::from_slice::<serde_json::Value>(&opted.stdout).unwrap();
}

#[test]
fn selector_is_only_recognized_in_the_leading_position() {
    let root = kitrove_testkit::trusted_tempdir(".kitrove-json-errors-");
    let output = invoke(root.path(), &["status", "--json-errors"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("error["));
    let output = invoke(root.path(), &["--json-errors", "--json-errors", "status"]);
    assert_eq!(output.status.code(), Some(2));
    serde_json::from_slice::<serde_json::Value>(&output.stderr).unwrap();
}
