use super::*;

#[cfg(all(unix, debug_assertions))]
#[cfg(test)]
#[path = "command_workflow_tests.rs"]
mod workflow;

#[cfg(all(windows, debug_assertions))]
#[cfg(test)]
#[path = "windows_command_workflow_tests.rs"]
mod windows_workflow;

pub(super) fn arguments(command: &str) -> Vec<OsString> {
    [
        command,
        "--archive",
        "archive",
        "--bundle",
        "bundle",
        "--tag",
        "v1.2.3",
        "--commit",
        "0123456789012345678901234567890123456789",
        "--sha256",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "--destination",
        "destination",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

#[test]
fn bundle_selection_accepts_only_exact_release_inputs() {
    for (command, expected_kind) in [
        ("select-application-bundle", BundleArtifactKind::Application),
        ("select-installer-bundle", BundleArtifactKind::Installer),
    ] {
        let mut args = arguments(command);
        args.truncate(args.len() - 2); // No destination for read-only selection.
        let Parsed::BundleSelection(kind, _) =
            parse(args.clone()).unwrap_or_else(|error| panic!("{error}"))
        else {
            panic!("selection parsed as a mutation");
        };
        assert_eq!(kind, expected_kind);
        for extra in [
            vec!["--destination", "somewhere"],
            vec!["--state-root", "state"],
            vec!["--no-state-roots"],
            vec!["--operation", "0123456789abcdef0123456789abcdef"],
            vec!["--prior-tag", "v1.2.2"],
            vec!["--bundle", "duplicate"],
        ] {
            let mut bad = args.clone();
            bad.extend(extra.into_iter().map(OsString::from));
            assert!(parse(bad).is_err());
        }
        for option in ["--archive", "--bundle", "--tag", "--commit", "--sha256"] {
            let mut bad = args.clone();
            let index = bad.iter().position(|value| value == option).unwrap();
            bad.drain(index..=index + 1);
            assert!(parse(bad).is_err());
        }
    }
}

#[test]
fn directional_replacement_commands_require_independent_exact_prior_inputs() {
    for direction in ["upgrade", "rollback"] {
        for (command, fresh, history, status) in [
            (format!("preflight-{direction}"), true, false, false),
            (direction.into(), true, false, false),
            (format!("recover-{direction}"), false, false, false),
            (format!("retire-{direction}"), false, false, false),
            (format!("{direction}-history-status"), false, true, true),
            (format!("{direction}-history-sync"), false, true, false),
        ] {
            let mut args = arguments(&command);
            if !status {
                args.push("--no-state-roots".into());
            }
            if history {
                args.extend(
                    ["--operation", "0123456789abcdef0123456789abcdef"].map(OsString::from),
                );
            }
            assert!(parse(args.clone()).is_err());
            args.extend(
                [
                    "--prior-tag",
                    "v1.2.2",
                    "--prior-commit",
                    "0123456789012345678901234567890123456789",
                    "--prior-sha256",
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                ]
                .map(OsString::from),
            );
            if fresh {
                assert!(parse(args.clone()).is_err());
                args.extend(
                    [
                        "--prior-archive",
                        "prior-archive",
                        "--prior-bundle",
                        "prior-bundle",
                    ]
                    .map(OsString::from),
                );
            }
            if let Err(error) = parse(args.clone()) {
                panic!("rejected {command}: {error}");
            }
            for option in ["--prior-tag", "--prior-commit", "--prior-sha256"] {
                let index = args.iter().position(|value| value == option).unwrap();
                let mut bad = args.clone();
                bad.drain(index..=index + 1);
                assert!(
                    parse(bad).is_err(),
                    "accepted missing {option} for {command}"
                );
                let mut bad = args.clone();
                bad[index + 1] = "invalid-release-pin".into();
                assert!(parse(bad).is_err());
                let mut bad = args.clone();
                bad.extend([args[index].clone(), args[index + 1].clone()]);
                assert!(parse(bad).is_err());
            }
            if !fresh {
                for option in ["--prior-archive", "--prior-bundle"] {
                    let mut bad = args.clone();
                    bad.extend([option, "unexpected-file"].map(OsString::from));
                    assert!(parse(bad).is_err());
                }
            }
            if status {
                args.push("--no-state-roots".into());
                assert!(parse(args).is_err());
            }
        }
    }
    let mut first_install = arguments("install");
    first_install.extend(["--no-state-roots", "--prior-tag", "v1.2.2"].map(OsString::from));
    assert!(parse(first_install).is_err());
}

#[test]
fn commands_require_explicit_roots_and_history_selection() {
    for command in [
        "preflight-install",
        "install",
        "recover-install",
        "retire-install",
        "history-sync",
    ] {
        let mut args = arguments(command);
        if command == "history-sync" {
            args.extend(["--operation", "0123456789abcdef0123456789abcdef"].map(OsString::from));
        }
        assert!(parse(args.clone()).is_err());
        args.push("--no-state-roots".into());
        assert!(matches!(parse(args.clone()), Ok(Parsed::Request(_))));
        args.extend(["--state-root", "state"].map(OsString::from));
        assert!(parse(args).is_err());
    }
    let mut args = arguments("history-status");
    assert!(parse(args.clone()).is_err());
    args.extend(["--operation", "0123456789abcdef0123456789abcdef"].map(OsString::from));
    assert!(matches!(parse(args.clone()), Ok(Parsed::Request(_))));
    args.push("--no-state-roots".into());
    assert!(parse(args).is_err());
}

#[test]
fn malformed_or_ambiguous_arguments_never_reach_intake() {
    let mut valid = arguments("install");
    valid.push("--no-state-roots".into());
    for extra in [
        vec!["--archive", "other"],
        vec!["--unknown", "value"],
        vec!["--no-state-roots"],
        vec!["--operation", "0123456789abcdef0123456789abcdef"],
    ] {
        let mut args = valid.clone();
        args.extend(extra.into_iter().map(OsString::from));
        assert!(parse(args).is_err());
    }
    for option in [
        "--archive",
        "--bundle",
        "--tag",
        "--commit",
        "--sha256",
        "--destination",
    ] {
        let index = valid.iter().position(|arg| arg == option).unwrap();
        let mut args = valid.clone();
        args.drain(index..=index + 1);
        assert!(parse(args).is_err(), "accepted missing {option}");
        let mut args = valid.clone();
        args[index + 1] = "".into();
        assert!(parse(args).is_err(), "accepted empty {option}");
    }
    for command in ["upgrade", "rollback", "latest"] {
        assert!(parse([command.into()]).is_err());
    }
}

#[test]
fn help_and_version_do_not_require_files_or_accept_extra_actions() {
    assert!(
        run(["--help".into()])
            .unwrap()
            .contains("Offline Kitrove installer")
    );
    assert!(
        run(["--version".into()])
            .unwrap()
            .starts_with("kitrove-installer ")
    );
    assert!(run(["--help".into(), "install".into()]).is_err());
    assert!(run(["--version".into(), "install".into()]).is_err());
}

#[test]
fn state_root_limit_is_enforced_during_parsing() {
    let mut args = arguments("install");
    for index in 0..crate::state_preflight::MAX_STATE_ROOTS {
        args.extend([
            OsString::from("--state-root"),
            format!("state-{index}").into(),
        ]);
    }
    assert!(parse(args.clone()).is_ok());
    args.extend(["--state-root", "one-too-many"].map(OsString::from));
    assert!(parse(args).is_err());
}

#[cfg(unix)]
#[test]
fn native_paths_are_preserved_without_lossy_decoding() {
    use std::os::unix::ffi::OsStringExt;
    let mut args = arguments("install");
    let native = OsString::from_vec(b"state-\xff".to_vec());
    args.extend(["--state-root".into(), native.clone()]);
    let Parsed::Request(request) = parse(args).unwrap() else {
        panic!("not a request")
    };
    assert_eq!(request.roots, [PathBuf::from(native)]);
}
