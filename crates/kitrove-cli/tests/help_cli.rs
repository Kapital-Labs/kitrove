use std::process::{Command, Output};

fn invoke(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kitrove"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn index_and_topics_are_separate_from_the_full_reference() {
    let index = invoke(&["--help"]);
    assert!(index.status.success());
    let index = String::from_utf8(index.stdout).unwrap();
    assert!(index.lines().count() <= 24);
    assert!(!index.contains("--expected-prior"));

    for path in [
        &["scan"][..],
        &["apply"],
        &["sync", "plan"],
        &["pack", "rollback"],
        &["trust", "apply"],
        &["doctor"],
        &["recover", "preserve"],
        &["versions", "probe"],
    ] {
        let mut suffix = path.to_vec();
        suffix.push("--help");
        let mut prefix = vec!["help"];
        prefix.extend(path);
        let first = invoke(&suffix);
        let second = invoke(&prefix);
        assert!(first.status.success(), "{suffix:?}");
        assert!(second.status.success(), "{prefix:?}");
        assert_eq!(first.stdout, second.stdout, "{path:?}");
        assert!(first.stderr.is_empty());
        let text = String::from_utf8(first.stdout).unwrap();
        assert!(text.contains(&format!("kitrove {}", path.join(" "))));
        assert!(text.lines().count() < 18);
    }

    let all = invoke(&["help", "--all"]);
    assert!(all.status.success());
    assert!(
        String::from_utf8(all.stdout)
            .unwrap()
            .contains("--expected-prior")
    );
}

#[test]
fn malformed_input_uses_compact_redacted_hints_and_preserves_json_errors() {
    let bad = invoke(&["sync", "plan", "--private-value"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
    let error = String::from_utf8(bad.stderr).unwrap();
    assert_eq!(error.lines().count(), 2);
    assert!(error.ends_with("Run kitrove sync plan --help.\n"));
    assert!(!error.contains("private-value"));

    let unknown = invoke(&["unknown-command"]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(
        String::from_utf8(unknown.stderr)
            .unwrap()
            .ends_with("Run kitrove --help.\n")
    );

    let malformed = invoke(&["--json-errors", "scan", "--help", "--unknown"]);
    assert_eq!(malformed.status.code(), Some(2));
    assert!(malformed.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&malformed.stderr).unwrap();
    assert_eq!(error["schema_version"], 1);
    assert_eq!(error["exit_code"], 2);
    assert_eq!(error.as_object().unwrap().len(), 3);
}
