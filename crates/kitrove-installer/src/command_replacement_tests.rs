use super::*;
use crate::command::{Parsed, parse};
use std::fs;
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

fn request(
    command: &str,
    destination: &Path,
    state: &Path,
    prior: &AuthenticatedRecoveryMaterial,
    operation: Option<&str>,
) -> Box<super::super::Request> {
    let mut args = crate::command::tests::arguments(command);
    let index = args.iter().position(|arg| arg == "--destination").unwrap();
    args[index + 1] = destination.as_os_str().to_owned();
    let subject = prior.executable().subject();
    args.extend([
        OsString::from("--prior-tag"),
        subject.release_tag().into(),
        "--prior-commit".into(),
        subject.source_commit().into(),
        "--prior-sha256".into(),
        crate::record::encode_hex(&subject.archive_sha256()).into(),
    ]);
    let (action, _) = super::command(command).unwrap();
    if matches!(action, Action::Preflight | Action::Install) {
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
    if action != Action::Status {
        args.extend([OsString::from("--state-root"), state.as_os_str().to_owned()]);
    }
    if let Some(operation) = operation {
        args.extend(["--operation", operation].map(OsString::from));
    }
    let Parsed::Request(request) = parse(args).unwrap() else {
        panic!("not a request")
    };
    request
}

fn create_prior(destination: &Path, prior: &AuthenticatedRecoveryMaterial) {
    let executable = prior.executable();
    let name = executable.subject().spec().executable_name();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let path = destination.join(name);
        fs::write(&path, executable.bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    {
        use std::io::Write as _;
        let parent = kitrove_windows_security::validate_install_directory(destination).unwrap();
        let mut file = kitrove_windows_security::create_private_file(
            parent.directory().unwrap(),
            std::ffi::OsStr::new(name),
        )
        .unwrap();
        file.write_all(executable.bytes()).unwrap();
        file.sync_all().unwrap();
    }
}

#[cfg(unix)]
fn snapshot(destination: &Path) -> kitrove_testkit::FilesystemSnapshot {
    kitrove_testkit::FilesystemSnapshot::capture(destination).unwrap()
}

#[cfg(windows)]
fn snapshot(destination: &Path) -> std::collections::BTreeMap<PathBuf, Option<Vec<u8>>> {
    crate::windows_test_support::snapshot_tree(destination)
}

fn exercise(old: &[u8], new: &[u8], upgrade_succeeds: bool) {
    for (name, direction) in [
        ("upgrade", ReplacementDirection::Upgrade),
        ("rollback", ReplacementDirection::Rollback),
    ] {
        #[cfg(unix)]
        let destination = crate::test_support::private_tempdir();
        #[cfg(windows)]
        let destination =
            crate::windows_test_support::destination_in(&std::env::current_dir().unwrap());
        let (candidate, prior) =
            crate::test_support::replacement_releases_with_bytes(old, new, direction);
        create_prior(destination.path(), &prior);
        let state = destination.path().join("app-state");
        {
            let (authority, guard) =
                kitrove_state_lifecycle::StateAuthority::initialize_absent(&state).unwrap();
            authority
                .exclusive_access(&guard)
                .unwrap()
                .create_initial_state(crate::test_support::EMPTY_STATE)
                .unwrap();
        }
        let preflight = request(
            &format!("preflight-{name}"),
            destination.path(),
            &state,
            &prior,
            None,
        );
        let before = snapshot(destination.path());
        let selected = preflight.replacement.as_ref().unwrap();
        assert_eq!(selected.direction, direction);
        // Missing independently authenticated prior inputs cannot fall back to the
        // installed executable or remembered candidate authority.
        assert!(selected.execute(&preflight, &candidate).is_err());
        assert_eq!(snapshot(destination.path()), before);
        selected
            .execute_fresh(&preflight, &candidate, &prior)
            .unwrap();
        assert_eq!(snapshot(destination.path()), before);
        {
            let authority = kitrove_state_lifecycle::StateAuthority::open_existing(&state).unwrap();
            let _busy = authority.try_lock_shared().unwrap();
            assert!(
                selected
                    .execute_fresh(&preflight, &candidate, &prior)
                    .is_err()
            );
        }
        assert_eq!(snapshot(destination.path()), before);
        // An incompatible direction cannot gain authority through the command wrapper.
        let opposite = if name == "upgrade" {
            "rollback"
        } else {
            "upgrade"
        };
        let bad = request(
            &format!("preflight-{opposite}"),
            destination.path(),
            &state,
            &prior,
            None,
        );
        assert!(
            bad.replacement
                .as_ref()
                .unwrap()
                .execute_fresh(&bad, &candidate, &prior)
                .is_err()
        );
        assert_eq!(snapshot(destination.path()), before);
        let install = request(name, destination.path(), &state, &prior, None);
        // Opaque fixture material enters after production intake, with no CLI verifier bypass.
        let result = install
            .replacement
            .as_ref()
            .unwrap()
            .execute_fresh(&install, &candidate, &prior);
        let succeeds = direction == ReplacementDirection::Rollback || upgrade_succeeds;
        assert_eq!(result.is_ok(), succeeds, "{name}: {result:?}");
        let expected = if succeeds {
            candidate.bytes()
        } else {
            prior.executable().bytes()
        };
        assert_eq!(
            fs::read(
                destination
                    .path()
                    .join(candidate.subject().spec().executable_name())
            )
            .unwrap(),
            expected
        );
        let operation = fs::read_dir(destination.path().join(crate::INSTALLER_STATE_DIRECTORY))
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| entry.file_type().unwrap().is_dir())
            .unwrap()
            .file_name()
            .into_string()
            .unwrap();
        let before = snapshot(destination.path());
        assert!(
            selected
                .execute_fresh(&preflight, &candidate, &prior)
                .is_err()
        );
        assert_eq!(snapshot(destination.path()), before);
        // Recovery/retirement must not accept synthetic bundles through the production
        // verifier. Missing history also fails without mutation. Successful retained
        // workflows are tested separately at their authenticated owner boundary.
        for command in [
            format!("recover-{name}"),
            format!("retire-{name}"),
            format!("{name}-history-status"),
            format!("{name}-history-sync"),
        ] {
            let history = command.contains("-history-");
            let retained = request(
                &command,
                destination.path(),
                &state,
                &prior,
                history.then_some(operation.as_str()),
            );
            assert!(
                retained
                    .replacement
                    .as_ref()
                    .unwrap()
                    .execute(&retained, &candidate)
                    .is_err()
            );
            assert_eq!(snapshot(destination.path()), before);
        }
    }
}

#[cfg(unix)]
#[test]
fn directional_commands_share_authenticated_preflight_replacement_and_refusal() {
    exercise(
        b"#!/bin/sh\nprintf 'kitrove 1.2.3\\n'\n",
        b"#!/bin/sh\nprintf 'kitrove 1.2.4\\n'\n",
        true,
    );
    exercise(
        b"#!/bin/sh\nprintf 'kitrove 1.2.3\\n'\n",
        b"#!/bin/sh\nexit 1\n",
        false,
    );
}

#[cfg(windows)]
pub(super) fn exercise_windows() {
    kitrove_windows_security::require_unelevated_process().unwrap();
    let bytes = fs::read(
        std::env::current_dir()
            .unwrap()
            .join("application-probe-fixture.exe"),
    )
    .unwrap();
    exercise(&bytes, &bytes, false);
}
