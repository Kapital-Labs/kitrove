use super::tests::{machine, script, skill};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn initialized(root: &Path) -> PathBuf {
    let machine = machine(root, "existing");
    skill(&machine, "alpha", "Preserve the original instructions.");
    script(
        &machine,
        &format!(
            "1\n{}\noriginal-machine\nyes\n1\nyes\n5\n",
            machine.join("collection").display()
        ),
        false,
        "",
    );
    machine
}

// Snapshot only this synthetic fixture, including empty directories and links.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        let key = path.strip_prefix(root).unwrap().to_owned();
        if metadata.is_symlink() {
            entries.insert(
                key,
                std::fs::read_link(path)
                    .unwrap()
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
            );
        } else if metadata.is_dir() {
            entries.insert(key, Vec::new());
            for child in std::fs::read_dir(path).unwrap() {
                visit(root, &child.unwrap().path(), entries);
            }
        } else {
            entries.insert(key, std::fs::read(path).unwrap());
        }
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries);
    entries
}

#[test]
fn existing_setup_resumes_only_after_consent_without_reinitializing_or_running_start_action() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-resume-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = initialized(&root);
    let before = snapshot(&a);
    for start in ["1", "2", "3", "4"] {
        let output = script(
            &a,
            &format!("{start}\n{}\nyes\n5\n", a.join("collection").display()),
            false,
            "",
        );
        assert!(output.contains("Continue setup with this existing collection?"));
        assert!(output.contains("What would you like to do?"));
        assert!(!output.contains("Name this computer"));
        assert!(!output.contains("Create an empty collection"));
        assert!(!output.contains("Collection scan"));
        assert!(!output.contains("Backend 1-3"));
        assert_eq!(snapshot(&a), before);
    }
}

#[test]
fn existing_setup_skip_cancel_and_eof_preserve_every_fixture_byte() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-resume-cancel-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = initialized(&root);
    let before = snapshot(&a);
    for (answer, error) in [
        ("n\n", ""),
        ("\n", ""),
        ("q\n", "setup.cancelled"),
        ("", "setup.cancelled"),
    ] {
        let output = script(
            &a,
            &format!("1\n{}\n{answer}", a.join("collection").display()),
            false,
            error,
        );
        assert!(output.contains("Continue setup with this existing collection?"));
        assert!(!output.contains("Name this computer"));
        assert!(!output.contains("What would you like to do?"));
        assert_eq!(snapshot(&a), before);
    }
}

#[test]
fn partial_or_corrupt_existing_setup_stops_before_creation_prompts() {
    for defect in [
        "missing-manifest",
        "missing-state",
        "bad-state",
        "bad-lock",
        "pending-journal",
    ] {
        let tmp = kitrove_testkit::trusted_tempdir(".setup-resume-invalid-");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let a = initialized(&root);
        match defect {
            "missing-manifest" => std::fs::remove_file(a.join("collection/kitrove.toml")).unwrap(),
            "missing-state" => std::fs::remove_file(a.join("state/state.json")).unwrap(),
            "bad-state" => std::fs::write(a.join("state/state.json"), b"not state").unwrap(),
            "bad-lock" => {
                std::fs::write(a.join("collection/kitrove.lock.json"), b"not lock").unwrap()
            }
            "pending-journal" => {
                std::fs::write(
                    a.join("collection/.kitrove/adoption-journal.json"),
                    b"not journal",
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let before = snapshot(&a);
        let output = script(
            &a,
            &format!("1\n{}\n", a.join("collection").display()),
            false,
            "setup.existing_attention",
        );
        assert!(output.contains("kitrove status --environment"));
        assert!(!output.contains("Name this computer"));
        assert!(!output.contains("Create an empty collection"));
        assert!(!output.contains("Continue setup with this existing collection?"));
        assert_eq!(snapshot(&a), before, "{defect}");
    }
}

#[test]
fn default_existing_collection_resumes_without_new_machine_identity() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-resume-default-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = machine(&root, "default");
    script(&a, "1\n\noriginal-machine\nyes\n5\n", false, "");
    let before = snapshot(&a);
    let output = script(&a, "1\n\nyes\n5\n", false, "");
    assert!(output.contains("Continue setup with this existing collection?"));
    assert!(!output.contains("Name this computer"));
    assert_eq!(snapshot(&a), before);
}

#[test]
fn existing_local_state_cannot_be_bypassed_by_selecting_a_new_collection() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-resume-local-only-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = initialized(&root);
    let before = snapshot(&a);
    let output = script(
        &a,
        &format!("1\n{}\n", a.join("another-collection").display()),
        false,
        "setup.existing_attention",
    );
    assert!(!output.contains("Name this computer"));
    assert!(!output.contains("Continue setup with this existing collection?"));
    assert_eq!(snapshot(&a), before);
}

#[test]
fn an_in_use_state_refuses_resume_without_repair_or_new_identity() {
    let tmp = kitrove_testkit::trusted_tempdir(".setup-resume-in-use-");
    let root = std::fs::canonicalize(tmp.path()).unwrap();
    let a = initialized(&root);
    let before = snapshot(&a);
    let authority =
        kitrove_state_lifecycle::StateAuthority::open_existing(&a.join("state")).unwrap();
    let _guard = authority.try_lock_exclusive().unwrap();
    let output = script(
        &a,
        &format!("1\n{}\n", a.join("collection").display()),
        false,
        "setup.existing_attention",
    );
    assert!(!output.contains("Continue setup with this existing collection?"));
    assert_eq!(snapshot(&a), before);
}

#[cfg(unix)]
#[test]
fn redirected_control_files_are_never_offered_as_resumable_setup() {
    for relative in ["collection/kitrove.toml", "state/state.json"] {
        let tmp = kitrove_testkit::trusted_tempdir(".setup-resume-redirected-");
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let a = initialized(&root);
        let original = a.join(relative);
        let retained = a.join("retained-control");
        std::fs::rename(&original, &retained).unwrap();
        std::os::unix::fs::symlink(&retained, &original).unwrap();
        let before = snapshot(&a);
        let output = script(
            &a,
            &format!("1\n{}\n", a.join("collection").display()),
            false,
            "setup.existing_attention",
        );
        assert!(!output.contains("Continue setup with this existing collection?"));
        assert_eq!(snapshot(&a), before);
    }
}
