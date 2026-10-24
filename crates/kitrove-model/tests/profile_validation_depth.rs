use std::fmt::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kitrove_model::EnvironmentManifest;

const CHILD_CASE: &str = "KITROVE_TEST_PROFILE_GRAPH_CASE";

#[test]
fn deep_profile_graphs_validate_without_aborting() {
    for case in ["acyclic", "cycle", "shared", "late-cycle"] {
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "profile_graph_child", "--nocapture"])
            .env(CHILD_CASE, case)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start isolated profile validator");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if child.try_wait().expect("poll validator").is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().expect("stop timed-out validator");
                child.wait().expect("reap validator");
                panic!("profile validator exceeded fixture deadline for {case}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().expect("collect validator result");
        assert!(
            output.status.success(),
            "profile validator aborted for {case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn profile_graph_child() {
    let Ok(case) = std::env::var(CHILD_CASE) else {
        return;
    };
    let count = 20_000;
    let mut input = String::from("schema_version = 1\n");
    for index in 0..count {
        writeln!(input, "[profiles.p{index:05}]\nid = 'p{index:05}'").unwrap();
        if index + 1 < count {
            writeln!(input, "extends = 'p{:05}'", index + 1).unwrap();
        } else if case == "cycle" {
            input.push_str("extends = 'p00000'\n");
        }
    }
    if case == "shared" {
        input.push_str("[profiles.shared]\nid = 'shared'\nextends = 'p10000'\n");
    } else if case == "late-cycle" {
        input.push_str("[profiles.z0]\nid = 'z0'\nextends = 'z1'\n");
        input.push_str("[profiles.z1]\nid = 'z1'\nextends = 'z0'\n");
    }
    let result = EnvironmentManifest::from_toml(&input);
    match case.as_str() {
        "acyclic" | "shared" => {
            let manifest = result.expect("deep acyclic profile graph is valid");
            assert_eq!(
                manifest.profiles.len(),
                count + usize::from(case == "shared")
            );
        }
        "cycle" | "late-cycle" => {
            assert_eq!(result.unwrap_err().code(), "manifest.profile_cycle");
        }
        _ => panic!("unknown owned fixture case"),
    }
}

#[test]
fn profile_identity_parent_and_self_cycle_checks_are_preserved() {
    for (profile, expected) in [
        ("id = 'a'\nextends = 'a'", "manifest.profile_cycle"),
        (
            "id = 'a'\nextends = 'missing'",
            "manifest.unknown_profile_parent",
        ),
        ("id = 'other'", "manifest.profile_key_mismatch"),
    ] {
        let input = format!("schema_version = 1\n[profiles.a]\n{profile}\n");
        assert_eq!(
            EnvironmentManifest::from_toml(&input).unwrap_err().code(),
            expected
        );
    }
}
