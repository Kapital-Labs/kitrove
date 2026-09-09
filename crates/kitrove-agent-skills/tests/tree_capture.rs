use std::collections::BTreeMap;
use std::io::Write as _;

use kitrove_agent_skills::{
    CaptureLimits, CapturedFile, FileMode, SkillError, capture_tree as capture_tree_raw, hash_tree,
};
use kitrove_model::PortablePath;

fn portable(path: &str) -> PortablePath {
    PortablePath::parse(path).expect("portable test path")
}

fn file(mode: FileMode, bytes: &[u8]) -> CapturedFile {
    CapturedFile {
        mode,
        bytes: bytes.to_vec(),
    }
}

fn one_file(path: &str, mode: FileMode, bytes: &[u8]) -> BTreeMap<PortablePath, CapturedFile> {
    BTreeMap::from([(portable(path), file(mode, bytes))])
}

// macOS exposes its temporary directory through `/var`, which is itself a symlink. Ordinary
// fixture tests use the direct filesystem path so only tests intentionally exercising root-path
// links pass a symlink-bearing root to the public API.
fn capture_tree(
    root: &std::path::Path,
    limits: CaptureLimits,
) -> Result<kitrove_agent_skills::CapturedTree, SkillError> {
    let direct_root = root.canonicalize().unwrap();
    capture_tree_raw(&direct_root, limits)
}

fn capture_error(root: &std::path::Path) -> SkillError {
    match capture_tree(root, CaptureLimits::default()) {
        Err(error) => error,
        Ok(_) => panic!("unsafe capture tree was accepted"),
    }
}

#[cfg(unix)]
fn capture_error_raw(root: &std::path::Path) -> SkillError {
    match capture_tree_raw(root, CaptureLimits::default()) {
        Err(error) => error,
        Ok(_) => panic!("unsafe capture tree was accepted"),
    }
}

fn assert_redacted(error: &SkillError, canary: &str) {
    assert!(!error.message().contains(canary));
    assert!(!error.to_string().contains(canary));
}

fn create_distinct_files_if_supported(
    root: &std::path::Path,
    first: &str,
    second: &str,
    canary: &str,
) -> bool {
    std::fs::write(root.join(first), canary.as_bytes()).unwrap();
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(second))
    {
        Ok(mut file) => {
            file.write_all(b"different bytes").unwrap();
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => panic!("failed to probe whether the host can represent both names: {error}"),
    }
}

fn create_distinct_directories_if_supported(
    root: &std::path::Path,
    first: &str,
    second: &str,
    canary: &str,
) -> bool {
    std::fs::create_dir(root.join(first)).unwrap();
    std::fs::write(root.join(first).join("first.md"), canary.as_bytes()).unwrap();
    match std::fs::create_dir(root.join(second)) {
        Ok(()) => {
            std::fs::write(root.join(second).join("second.md"), b"different bytes").unwrap();
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => panic!("failed to probe whether the host can represent both names: {error}"),
    }
}

#[test]
fn captures_files_in_portable_path_order_without_ordering_dependence() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("references")).unwrap();
    std::fs::write(root.path().join("references/z.md"), b"z").unwrap();
    std::fs::write(root.path().join("SKILL.md"), b"skill").unwrap();
    std::fs::write(root.path().join("a.txt"), b"a").unwrap();

    let tree = capture_tree(root.path(), CaptureLimits::default()).unwrap();

    let paths: Vec<_> = tree.files.keys().map(PortablePath::as_str).collect();
    assert_eq!(paths, ["SKILL.md", "a.txt", "references/z.md"]);
    assert_eq!(tree.hash, hash_tree(&tree.files));
}

#[test]
fn canonical_hash_catches_omitted_path_mode_or_length_framing() {
    let files = one_file("a", FileMode::Regular, b"x");

    assert_eq!(
        hash_tree(&files).as_str(),
        "blake3:01f7eadcb6ff5f6d704c54ea7a7203c0ede1d8ddcb72ea6abcdd4c66bc1763b1"
    );
}

#[test]
fn hash_changes_when_path_changes_so_path_omission_fails() {
    let left = one_file("a.txt", FileMode::Regular, b"same");
    let right = one_file("b.txt", FileMode::Regular, b"same");

    assert_ne!(hash_tree(&left), hash_tree(&right));
}

#[test]
fn hash_changes_when_mode_changes_so_mode_omission_fails() {
    let regular = one_file("script.sh", FileMode::Regular, b"exit 0\n");
    let executable = one_file("script.sh", FileMode::Executable, b"exit 0\n");

    assert_ne!(hash_tree(&regular), hash_tree(&executable));
}

#[test]
fn hash_changes_when_content_length_changes_so_length_omission_fails() {
    let shorter = one_file("data", FileMode::Regular, b"a");
    let longer = one_file("data", FileMode::Regular, b"a\0");

    assert_ne!(hash_tree(&shorter), hash_tree(&longer));
}

#[test]
fn hash_changes_when_equal_length_bytes_change_so_byte_omission_fails() {
    let left = one_file("data", FileMode::Regular, b"a");
    let right = one_file("data", FileMode::Regular, b"b");

    assert_ne!(hash_tree(&left), hash_tree(&right));
}

#[test]
fn hash_ignores_map_insertion_order_to_prevent_ordering_dependence() {
    let mut left = BTreeMap::new();
    left.insert(portable("b"), file(FileMode::Regular, b"second"));
    left.insert(portable("a"), file(FileMode::Regular, b"first"));

    let mut right = BTreeMap::new();
    right.insert(portable("a"), file(FileMode::Regular, b"first"));
    right.insert(portable("b"), file(FileMode::Regular, b"second"));

    assert_eq!(hash_tree(&left), hash_tree(&right));
}

#[test]
fn hash_preserves_lf_versus_crlf_to_prevent_byte_normalization() {
    let lf = one_file("SKILL.md", FileMode::Regular, b"one\ntwo\n");
    let crlf = one_file("SKILL.md", FileMode::Regular, b"one\r\ntwo\r\n");

    assert_ne!(hash_tree(&lf), hash_tree(&crlf));
}

#[test]
fn hash_includes_empty_files_to_prevent_file_omission() {
    let empty_tree = BTreeMap::new();
    let empty_file = one_file("empty", FileMode::Regular, b"");

    assert_ne!(hash_tree(&empty_tree), hash_tree(&empty_file));
}

#[test]
fn captures_empty_regular_files_without_file_omission() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("empty"), b"").unwrap();

    let tree = capture_tree(root.path(), CaptureLimits::default()).unwrap();

    assert_eq!(tree.files[&portable("empty")], file(FileMode::Regular, b""));
}

#[cfg(unix)]
#[test]
fn captures_unix_executable_mode_to_prevent_mode_omission() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let script = root.path().join("run.sh");
    std::fs::write(&script, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let tree = capture_tree(root.path(), CaptureLimits::default()).unwrap();

    assert_eq!(tree.files[&portable("run.sh")].mode, FileMode::Executable);
}

#[test]
fn rejects_nested_files_that_would_bypass_the_file_count_limit() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("nested")).unwrap();
    std::fs::write(root.path().join("one"), b"").unwrap();
    std::fs::write(root.path().join("nested/two"), b"").unwrap();
    let limits = CaptureLimits {
        max_files: 1,
        ..CaptureLimits::default()
    };

    let error = capture_tree(root.path(), limits).unwrap_err();

    assert_eq!(error.code(), "capture.file_count_limit");
}

#[test]
fn rejects_oversized_files_before_they_bypass_the_per_file_limit() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("large"), b"1234").unwrap();
    let limits = CaptureLimits {
        max_file_bytes: 3,
        ..CaptureLimits::default()
    };

    let error = capture_tree(root.path(), limits).unwrap_err();

    assert_eq!(error.code(), "capture.file_size_limit");
}

#[test]
fn rejects_nested_totals_that_would_bypass_the_total_byte_limit() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("nested")).unwrap();
    std::fs::write(root.path().join("one"), b"12").unwrap();
    std::fs::write(root.path().join("nested/two"), b"34").unwrap();
    let limits = CaptureLimits {
        max_total_bytes: 3,
        ..CaptureLimits::default()
    };

    let error = capture_tree(root.path(), limits).unwrap_err();

    assert_eq!(error.code(), "capture.total_size_limit");
}

#[test]
fn rejects_excess_empty_directories_before_traversal_limit_bypass() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..513 {
        std::fs::create_dir(root.path().join(format!("directory-{index:03}"))).unwrap();
    }

    let error = capture_tree(root.path(), CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "capture.traversal_limit");
}

#[test]
fn attributes_wide_directory_overflow_to_its_ordered_parent() {
    let cases = [
        (false, "KITROVE_C1_WIDE_DIRECTORY_CANARY_66074fa0"),
        (true, "KITROVE_C1_WIDE_DIRECTORY_REVERSED_CANARY_266209c5"),
    ];

    for (reverse, canary) in cases {
        let root = tempfile::tempdir().unwrap();
        let direct_root = root.path().canonicalize().unwrap();
        let wide = direct_root.join("a-wide");
        let competitor = direct_root.join("a-wide-competitor");
        if reverse {
            std::fs::write(&competitor, b"ordered competing frontier failure").unwrap();
        }
        std::fs::create_dir(&wide).unwrap();
        let indices: Box<dyn Iterator<Item = usize>> = if reverse {
            Box::new((0..1_024).rev())
        } else {
            Box::new(0..1_024)
        };
        for index in indices {
            let bytes = if index == 0 { canary.as_bytes() } else { b"x" };
            std::fs::write(wide.join(format!("entry-{index:04}")), bytes).unwrap();
        }
        if !reverse {
            std::fs::write(&competitor, b"ordered competing frontier failure").unwrap();
        }
        let limits = CaptureLimits {
            max_files: 0,
            ..CaptureLimits::default()
        };

        let error = match capture_tree_raw(&direct_root, limits) {
            Err(error) => error,
            Ok(_) => panic!("the wide directory did not exhaust the bounded entry allowance"),
        };

        assert_eq!(error.code(), "capture.traversal_limit");
        assert_eq!(error.path(), wide);
        assert!(!error.message().contains(canary));
        assert!(!error.to_string().contains(canary));
    }
}

#[test]
fn rejects_excess_nesting_before_recursive_stack_exhaustion() {
    let root = tempfile::tempdir().unwrap();
    let mut directory = root.path().to_path_buf();
    for _ in 0..65 {
        directory.push("d");
        std::fs::create_dir(&directory).unwrap();
    }

    let error = capture_tree(root.path(), CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "capture.depth_limit");
}

#[test]
fn rejects_raw_parent_directory_components_before_platform_absolutization() {
    let canary = "KITROVE_C1_RAW_PARENT_COMPONENT_CANARY_a1b5c2fd";
    let root = tempfile::tempdir().unwrap();
    let direct_root = root.path().canonicalize().unwrap();
    let skill = direct_root.join("skill");
    std::fs::create_dir(&skill).unwrap();
    std::fs::create_dir(direct_root.join("unverified")).unwrap();
    std::fs::write(skill.join("payload"), canary.as_bytes()).unwrap();
    let mut raw_root = direct_root.as_os_str().to_owned();
    raw_root.push(std::path::MAIN_SEPARATOR_STR);
    raw_root.push("unverified");
    raw_root.push(std::path::MAIN_SEPARATOR_STR);
    raw_root.push("..");
    raw_root.push(std::path::MAIN_SEPARATOR_STR);
    raw_root.push("skill");
    let raw_root = std::path::PathBuf::from(raw_root);

    let error = match capture_tree_raw(&raw_root, CaptureLimits::default()) {
        Err(error) => error,
        Ok(_) => panic!("raw parent-directory components were accepted"),
    };

    assert_eq!(error.code(), "capture.invalid_root_path");
    assert_eq!(error.path(), raw_root);
    assert!(!error.message().contains(canary));
    assert!(!error.to_string().contains(canary));
}

#[cfg(unix)]
#[test]
fn rejects_a_symlink_root_without_following_its_target() {
    use std::os::unix::fs::symlink;

    let parent = tempfile::tempdir().unwrap();
    let target = parent.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("secret"), b"must not be read").unwrap();
    let link = parent.path().join("skill");
    symlink(&target, &link).unwrap();

    let error = capture_tree_raw(&link, CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "capture.symlink");
}

#[cfg(unix)]
#[test]
fn rejects_a_symlink_in_a_capture_root_ancestor_without_following_it() {
    use std::os::unix::fs::symlink;

    let canary = "KITROVE_C1_ROOT_ANCESTOR_SYMLINK_CANARY_12c46d9a";
    let parent = tempfile::tempdir().unwrap();
    let direct_parent = parent.path().canonicalize().unwrap();
    let real_parent = direct_parent.join("real-parent");
    let skill = real_parent.join("skill");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(skill.join("secret"), canary.as_bytes()).unwrap();
    let linked_parent = direct_parent.join("linked-parent");
    symlink(&real_parent, &linked_parent).unwrap();

    let error = capture_error_raw(&linked_parent.join("skill"));

    assert_eq!(error.code(), "capture.symlink");
    assert!(error.path().ends_with("linked-parent"));
    assert_redacted(&error, canary);
}

#[cfg(unix)]
#[test]
fn rejects_a_file_symlink_without_following_its_target() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("secret");
    std::fs::write(&target, b"must not be read").unwrap();
    symlink(&target, root.path().join("linked")).unwrap();

    let error = capture_tree(root.path(), CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "capture.symlink");
}

#[cfg(unix)]
#[test]
fn rejects_a_directory_symlink_without_following_its_target() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("credentials"), b"must not be read").unwrap();
    symlink(outside.path(), root.path().join("references")).unwrap();

    let error = capture_tree(root.path(), CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "capture.symlink");
}

#[cfg(windows)]
#[test]
fn rejects_a_windows_directory_name_surrogate_without_returning_external_sentinel_bytes() {
    use std::os::windows::fs::symlink_dir;

    let canary = "KITROVE_C1_WINDOWS_NAME_SURROGATE_SENTINEL_CANARY_445cfcd1";
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join("external-sentinel.txt"),
        canary.as_bytes(),
    )
    .unwrap();
    let surrogate = root.path().join("references");
    symlink_dir(outside.path(), &surrogate).unwrap_or_else(|error| {
        panic!(
            "Windows name-surrogate fixture setup failed; enable Developer Mode or grant the Create symbolic links privilege: {error}"
        )
    });

    let result = capture_tree(root.path(), CaptureLimits::default());
    let error = match result {
        Err(error) => error,
        Ok(tree) => {
            assert!(
                tree.files
                    .values()
                    .all(|file| file.bytes.as_slice() != canary.as_bytes()),
                "capture returned bytes from the external name-surrogate target"
            );
            panic!("a Windows directory name surrogate was accepted");
        }
    };

    assert!(matches!(
        error.code(),
        "capture.symlink" | "capture.reparse_point"
    ));
    assert!(error.path().ends_with("references"));
    assert_redacted(&error, canary);
}

#[cfg(unix)]
#[test]
fn rejects_unix_sockets_to_prevent_special_file_acceptance() {
    use std::os::unix::net::UnixListener;

    let root = tempfile::tempdir().unwrap();
    let _listener = UnixListener::bind(root.path().join("agent.sock")).unwrap();

    let error = capture_tree(root.path(), CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "capture.special_file");
}

#[cfg(target_os = "linux")]
#[test]
fn rejects_non_utf8_names_to_prevent_cross_platform_invalid_path_acceptance() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join(OsString::from_vec(vec![b'a', 0xff])), b"x").unwrap();

    let error = capture_tree(root.path(), CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "capture.non_utf8_path");
}

#[cfg(unix)]
#[test]
fn rejects_dos_devices_with_suffixes_to_prevent_cross_platform_invalid_path_acceptance() {
    for name in [
        "CON",
        "con.txt",
        "Lpt1.md",
        "COM9.data",
        "COM¹.data",
        "com²",
        "Com³.txt",
        "aux.yaml",
        "LPT¹.md",
        "lpt²",
        "Lpt³.data",
        "NUL.bin",
    ] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(name), b"x").unwrap();

        let error = capture_tree(root.path(), CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "capture.invalid_portable_path", "{name}");
    }
}

#[cfg(unix)]
#[test]
fn rejects_separators_and_controls_to_prevent_cross_platform_invalid_path_acceptance() {
    for name in ["skill\\name", "skill\tname", "skill\nname"] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(name), b"x").unwrap();

        let error = capture_tree(root.path(), CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "capture.invalid_portable_path", "{name:?}");
    }
}

#[cfg(unix)]
#[test]
fn rejects_trailing_dots_and_spaces_to_prevent_cross_platform_invalid_path_acceptance() {
    for name in ["skill.", "skill "] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(name), b"x").unwrap();

        let error = capture_tree(root.path(), CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "capture.invalid_portable_path", "{name:?}");
    }
}

#[cfg(unix)]
#[test]
fn rejects_windows_punctuation_to_prevent_cross_platform_invalid_path_acceptance() {
    for character in ['<', '>', ':', '"', '|', '?', '*'] {
        let name = format!("skill{character}name");
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(&name), b"x").unwrap();

        let error = capture_tree(root.path(), CaptureLimits::default()).unwrap_err();

        assert_eq!(error.code(), "capture.invalid_portable_path", "{name:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn rejects_ascii_case_folded_sibling_collisions_before_file_insertion() {
    let canary = "KITROVE_C1_CASE_COLLISION_SIBLING_CANARY_b70e4029";
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("README.md"), canary.as_bytes()).unwrap();
    std::fs::write(root.path().join("Readme.md"), b"different bytes").unwrap();

    let error = capture_error(root.path());

    assert_eq!(error.code(), "capture.path_collision");
    assert!(error.path().ends_with("Readme.md"));
    assert_redacted(&error, canary);
}

#[cfg(target_os = "linux")]
#[test]
fn rejects_case_folded_directory_ancestor_collisions() {
    let canary = "KITROVE_C1_CASE_COLLISION_ANCESTOR_CANARY_cff40a92";
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("References")).unwrap();
    std::fs::create_dir(root.path().join("references")).unwrap();
    std::fs::write(root.path().join("References/first.md"), canary.as_bytes()).unwrap();
    std::fs::write(root.path().join("references/second.md"), b"different bytes").unwrap();

    let error = capture_error(root.path());

    assert_eq!(error.code(), "capture.path_collision");
    assert!(error.path().ends_with("references"));
    assert_redacted(&error, canary);
}

#[test]
fn rejects_canonically_equivalent_nfc_and_nfd_sibling_paths_when_host_represents_both() {
    let canary = "KITROVE_C1_NFC_NFD_SIBLING_CANARY_6e7b5b9c";
    let root = tempfile::tempdir().unwrap();
    if !create_distinct_files_if_supported(
        root.path(),
        "Résumé.md",
        "Re\u{301}sume\u{301}.md",
        canary,
    ) {
        return;
    }

    let error = capture_error(root.path());

    assert_eq!(error.code(), "capture.path_collision");
    assert_redacted(&error, canary);
}

#[test]
fn rejects_canonically_equivalent_nfc_and_nfd_ancestor_paths_when_host_represents_both() {
    let canary = "KITROVE_C1_NFC_NFD_ANCESTOR_CANARY_9c1de8ae";
    let root = tempfile::tempdir().unwrap();
    if !create_distinct_directories_if_supported(root.path(), "Café", "Cafe\u{301}", canary) {
        return;
    }

    let error = capture_error(root.path());

    assert_eq!(error.code(), "capture.path_collision");
    assert_redacted(&error, canary);
}

#[test]
fn rejects_full_case_fold_sharp_s_and_ss_sibling_paths_when_host_represents_both() {
    let canary = "KITROVE_C1_FULL_FOLD_SIBLING_CANARY_e5c4710b";
    let root = tempfile::tempdir().unwrap();
    if !create_distinct_files_if_supported(root.path(), "Straße.md", "STRASSE.md", canary) {
        return;
    }

    let error = capture_error(root.path());

    assert_eq!(error.code(), "capture.path_collision");
    assert_redacted(&error, canary);
}

#[test]
fn rejects_full_case_fold_sharp_s_and_ss_ancestor_paths_when_host_represents_both() {
    let canary = "KITROVE_C1_FULL_FOLD_ANCESTOR_CANARY_3eea7c85";
    let root = tempfile::tempdir().unwrap();
    if !create_distinct_directories_if_supported(root.path(), "Straße", "STRASSE", canary) {
        return;
    }

    let error = capture_error(root.path());

    assert_eq!(error.code(), "capture.path_collision");
    assert_redacted(&error, canary);
}

#[cfg(unix)]
fn create_ordered_invalid_tree(
    sibling_first: bool,
    canary: &str,
) -> (tempfile::TempDir, std::os::unix::net::UnixListener) {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    if sibling_first {
        symlink("missing-target", root.path().join("b-link")).unwrap();
    }
    std::fs::create_dir(root.path().join("a")).unwrap();
    std::fs::write(root.path().join("a/canary.txt"), canary.as_bytes()).unwrap();
    let listener =
        std::os::unix::net::UnixListener::bind(root.path().join("a/nested.sock")).unwrap();
    if !sibling_first {
        symlink("missing-target", root.path().join("b-link")).unwrap();
    }
    (root, listener)
}

#[cfg(unix)]
#[test]
fn reports_the_same_global_first_nested_error_for_opposite_creation_orders() {
    let canaries = [
        "KITROVE_C1_GLOBAL_ORDER_NESTED_CANARY_ef43d06c",
        "KITROVE_C1_GLOBAL_ORDER_REVERSED_CANARY_ed165f52",
    ];

    for (sibling_first, canary) in [(false, canaries[0]), (true, canaries[1])] {
        let (root, _listener) = create_ordered_invalid_tree(sibling_first, canary);

        let error = capture_error(root.path());

        assert_eq!(error.code(), "capture.special_file");
        assert!(error.path().ends_with("a/nested.sock"));
        assert_redacted(&error, canary);
    }
}

#[cfg(unix)]
fn create_ordered_symlink_siblings(reverse: bool, canary: &str) -> tempfile::TempDir {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("notes"), canary.as_bytes()).unwrap();
    let names = if reverse {
        ["b-link", "a-link"]
    } else {
        ["a-link", "b-link"]
    };
    for name in names {
        symlink("missing-target", root.path().join(name)).unwrap();
    }
    root
}

#[cfg(unix)]
#[test]
fn reports_the_same_lexicographically_first_sibling_error_for_opposite_creation_orders() {
    let canaries = [
        "KITROVE_C1_GLOBAL_ORDER_SIBLING_CANARY_f68e7b0f",
        "KITROVE_C1_GLOBAL_ORDER_SIBLING_REVERSED_CANARY_6268a5eb",
    ];

    for (reverse, canary) in [(false, canaries[0]), (true, canaries[1])] {
        let root = create_ordered_symlink_siblings(reverse, canary);

        let error = capture_error(root.path());

        assert_eq!(error.code(), "capture.symlink");
        assert!(error.path().ends_with("a-link"));
        assert_redacted(&error, canary);
    }
}

#[cfg(unix)]
#[test]
fn refuses_a_fifo_without_opening_or_reading_it() {
    let canary = "KITROVE_C1_FIFO_REFUSAL_CANARY_3f7969de";
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("notes"), canary.as_bytes()).unwrap();
    let fifo = root.path().join("payload.pipe");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo must be available on supported Unix test hosts");
    assert!(status.success());

    let error = capture_error(root.path());

    assert_eq!(error.code(), "capture.special_file");
    assert!(error.path().ends_with("payload.pipe"));
    assert_redacted(&error, canary);
}
