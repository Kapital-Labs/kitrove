#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::os::unix::fs::symlink;

use kitrove_testkit::{FilesystemSnapshot, FixtureBuilder, SnapshotEntry};

#[test]
fn checked_in_harness_fixtures_are_provenance_labeled_and_snapshot_stable() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/harnesses");
    let fixtures = [
        "claude/user",
        "claude/project",
        "claude/commands",
        "codex/user",
        "codex/project",
        "codex/admin",
        "codex/system",
        "pi/directory",
        "pi/standalone",
        "pi/compatibility",
        "pi/trust",
        "opencode/current",
        "opencode/v2",
    ];

    for fixture in fixtures {
        let path = root.join(fixture);
        let provenance = std::fs::read_to_string(path.join("PROVENANCE.md"))
            .expect("each checked-in fixture has provenance");
        assert!(
            provenance.contains("Policy line:"),
            "missing policy line for {fixture}"
        );
        assert!(
            provenance.contains("docs/research/"),
            "missing research document for {fixture}"
        );
        assert_eq!(
            FilesystemSnapshot::capture(&path).expect("first fixture snapshot"),
            FilesystemSnapshot::capture(&path).expect("second fixture snapshot"),
            "fixture snapshot changed for {fixture}"
        );
    }
}

#[test]
fn fixture_builder_covers_harness_layout_and_failure_inputs() {
    let fixture = FixtureBuilder::new()
        .repository()
        .user_root(".claude/skills")
        .directory_skill(
            "review",
            "---\nname: review\ndescription: inert\n---\nInert prose.\n",
        )
        .standalone_skill(
            "quick.md",
            "---\nname: quick\ndescription: inert\n---\nInert prose.\n",
        )
        .malformed_yaml("broken.md")
        .credential_canary("credential-canary")
        .duplicate_native_ids("review")
        .build()
        .expect("fixture creation succeeds");

    let repository_root = fixture.repository_root().expect("repository root");
    assert!(fixture.working_directory().starts_with(repository_root));
    assert!(
        fixture
            .home()
            .join(".claude/skills/review/SKILL.md")
            .is_file()
    );
    assert!(
        fixture
            .standalone_sources()
            .iter()
            .any(|path| path.ends_with("quick.md"))
    );
    assert!(
        fixture
            .malformed_sources()
            .iter()
            .any(|path| path.ends_with("broken.md"))
    );
    assert!(
        fixture
            .credential_canary_paths()
            .iter()
            .all(|path| path.is_file())
    );
    assert_eq!(fixture.duplicate_native_ids().get("review"), Some(&2));
}

#[test]
fn repository_and_no_repository_fixtures_use_distinct_working_boundaries() {
    let repository = FixtureBuilder::new()
        .repository()
        .build()
        .expect("repository fixture");
    let no_repository = FixtureBuilder::new()
        .no_repository()
        .build()
        .expect("no-repository fixture");

    assert!(
        repository
            .working_directory()
            .starts_with(repository.repository_root().expect("repository root"))
    );
    assert!(no_repository.repository_root().is_none());
    assert!(
        !no_repository
            .working_directory()
            .starts_with(repository.root())
    );
}

#[test]
fn fixture_builder_rejects_empty_or_traversing_user_roots() {
    for root in ["", "../outside", "/outside"] {
        let result = FixtureBuilder::new().user_root(root).build();
        assert!(result.is_err(), "accepted unsafe user root {root:?}");
    }
}

#[test]
fn filesystem_snapshot_preserves_bytes_modes_and_symlink_targets_without_following() {
    let fixture = FixtureBuilder::new()
        .no_repository()
        .build()
        .expect("fixture creation");
    let directory = fixture.root().join("snapshot");
    std::fs::create_dir_all(&directory).expect("snapshot directory");
    let executable = directory.join("run.sh");
    std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("inert script");
    #[cfg(unix)]
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("executable mode");
    std::fs::write(directory.join("target.txt"), b"exact target bytes").expect("target file");
    #[cfg(unix)]
    symlink("target.txt", directory.join("link.txt")).expect("fixture symlink");

    let snapshot = FilesystemSnapshot::capture(&directory).expect("snapshot capture");

    assert_eq!(
        snapshot.entries.get("run.sh"),
        Some(&SnapshotEntry::File {
            bytes: b"#!/bin/sh\nexit 0\n".to_vec(),
            executable: cfg!(unix),
        })
    );
    #[cfg(unix)]
    assert_eq!(
        snapshot.entries.get("link.txt"),
        Some(&SnapshotEntry::Symlink {
            target: "target.txt".into(),
        })
    );
}
