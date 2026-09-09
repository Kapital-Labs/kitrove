#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use kitrove_agent_skills::{CaptureLimits, SkillError, capture_skill};
use kitrove_model::ContentClass;

const CANARY: &str = "KITROVE_TASK4_UNIQUE_CREDENTIAL_CANARY_7d9c84e1";

fn skill_directory(skill_document: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let parent = tempfile::tempdir().unwrap();
    let directory = parent.path().join("code-review");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("SKILL.md"), skill_document).unwrap();
    let directory = directory.canonicalize().unwrap();
    (parent, directory)
}

fn basic_skill() -> &'static [u8] {
    b"---\nname: code-review\ndescription: Review a change.\n---\n# Review\n"
}

fn error_without_printing_captured_content(directory: &Path) -> SkillError {
    match capture_skill(directory, CaptureLimits::default()) {
        Err(error) => error,
        Ok(_) => panic!("credential artifact was accepted"),
    }
}

fn assert_canary_is_redacted(error: &SkillError) {
    assert!(!error.message().contains(CANARY));
    assert!(!error.to_string().contains(CANARY));
}

fn assert_specific_canary_is_redacted(error: &SkillError, canary: &str) {
    assert!(!error.message().contains(canary));
    assert!(!error.to_string().contains(canary));
}

#[test]
fn refuses_every_reserved_credential_basename_without_leaking_file_content() {
    for filename in [
        ".env",
        ".env.local",
        "auth.json",
        ".credentials.json",
        "credentials.json",
        "id_rsa",
        "id_ed25519",
    ] {
        let (_parent, directory) = skill_directory(basic_skill());
        std::fs::create_dir(directory.join("references")).unwrap();
        std::fs::write(
            directory.join("references").join(filename),
            CANARY.as_bytes(),
        )
        .unwrap();

        let error = error_without_printing_captured_content(&directory);

        assert_eq!(error.code(), "skill.credential_artifact", "{filename}");
        assert_canary_is_redacted(&error);
    }
}

#[test]
fn credential_basename_matching_is_case_insensitive_and_not_a_substring_search() {
    for filename in [".EnV.Production", "AUTH.JSON", "ID_Ed25519"] {
        let (_parent, directory) = skill_directory(basic_skill());
        std::fs::create_dir(directory.join("nested")).unwrap();
        std::fs::write(directory.join("nested").join(filename), CANARY.as_bytes()).unwrap();

        let error = error_without_printing_captured_content(&directory);

        assert_eq!(error.code(), "skill.credential_artifact", "{filename}");
        assert_canary_is_redacted(&error);
    }

    let (_parent, directory) = skill_directory(basic_skill());
    std::fs::write(
        directory.join("my-auth.json.backup"),
        b"ordinary reference content\n",
    )
    .unwrap();
    std::fs::write(directory.join("id_rsa.pub"), b"public key material\n").unwrap();

    let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

    assert_eq!(snapshot.content_class, ContentClass::AgentActive);
}

#[test]
fn refuses_private_key_markers_without_leaking_the_matching_bytes() {
    for marker in [
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
    ] {
        let (_parent, directory) = skill_directory(basic_skill());
        std::fs::create_dir(directory.join("references")).unwrap();
        let bytes = format!("ordinary notes\n-----{marker}-----\n{CANARY}\n");
        std::fs::write(directory.join("references/notes.md"), bytes.as_bytes()).unwrap();

        let error = error_without_printing_captured_content(&directory);

        assert_eq!(error.code(), "skill.credential_artifact", "{marker}");
        assert_canary_is_redacted(&error);
    }
}

#[test]
fn refuses_encrypted_pkcs8_private_keys_without_leaking_authored_content() {
    let canary = "KITROVE_C1_ENCRYPTED_PRIVATE_KEY_CANARY_45f8a291";
    let (_parent, directory) = skill_directory(basic_skill());
    let bytes = format!("ordinary notes\n-----BEGIN ENCRYPTED PRIVATE KEY-----\n{canary}\n");
    std::fs::write(directory.join("notes.md"), bytes.as_bytes()).unwrap();

    let error = error_without_printing_captured_content(&directory);

    assert_eq!(error.code(), "skill.credential_artifact");
    assert_specific_canary_is_redacted(&error, canary);
}

#[test]
fn refuses_path_specific_credential_files_without_substring_matching() {
    let cases = [
        (
            ".aws/credentials",
            "KITROVE_C1_AWS_CREDENTIALS_CANARY_39fd5c0a",
        ),
        (".netrc", "KITROVE_C1_NETRC_CANARY_57af30cc"),
        (
            "nested/.git-credentials",
            "KITROVE_C1_GIT_CREDENTIALS_CANARY_48239f8b",
        ),
        ("config/.npmrc", "KITROVE_C1_NPMRC_CANARY_b49c43a8"),
        ("config/.pypirc", "KITROVE_C1_PYPIRC_CANARY_631cfec7"),
    ];

    for (path, canary) in cases {
        let (_parent, directory) = skill_directory(basic_skill());
        let artifact = directory.join(path);
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        std::fs::write(&artifact, canary.as_bytes()).unwrap();

        let error = error_without_printing_captured_content(&directory);

        assert_eq!(error.code(), "skill.credential_artifact", "{path}");
        assert_specific_canary_is_redacted(&error, canary);
    }
}

#[test]
fn path_specific_credential_matching_does_not_reject_benign_substrings() {
    let (_parent, directory) = skill_directory(basic_skill());
    for path in [
        ".aws/credentials.backup",
        "notes.netrc",
        ".git-credentials.example",
        ".npmrc-guide",
        ".pypirc-notes",
        "aws/credentials",
    ] {
        let artifact = directory.join(path);
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        std::fs::write(artifact, b"ordinary reference content\n").unwrap();
    }

    let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

    assert_eq!(snapshot.content_class, ContentClass::AgentActive);
}

#[test]
fn refuses_credential_shaped_values_in_principal_and_supporting_files() {
    let token = ["sk-ant-api03-", "KITROVE_PORTABLE_SECRET_CANARY_42"].concat();
    for path in ["SKILL.md", "references/notes.md"] {
        let (_parent, directory) = skill_directory(basic_skill());
        let artifact = directory.join(path);
        std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        let content = if path == "SKILL.md" {
            format!("---\nname: code-review\ndescription: Review.\n---\nToken: {token}\n")
        } else {
            format!("ordinary notes\ncredential={token}\n")
        };
        std::fs::write(artifact, content).unwrap();

        let error = error_without_printing_captured_content(&directory);

        assert_eq!(error.code(), "skill.credential_artifact", "{path}");
        assert_specific_canary_is_redacted(&error, &token);
    }
}

#[test]
fn credential_content_detection_keeps_bounded_near_misses_portable() {
    let (_parent, directory) = skill_directory(basic_skill());
    std::fs::write(
        directory.join("notes.md"),
        b"sk-analysis github_pat_short contains-sk-ant-api03-but-is-benign\n",
    )
    .unwrap();

    let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

    assert_eq!(snapshot.content_class, ContentClass::AgentActive);
}

#[test]
fn classifies_every_script_extension_as_executable() {
    for extension in [
        "sh", "bash", "zsh", "fish", "ps1", "bat", "cmd", "exe", "dll", "dylib", "so", "wasm",
        "bin",
    ] {
        let (_parent, directory) = skill_directory(basic_skill());
        std::fs::write(
            directory.join(format!("payload.{extension}")),
            b"captured but never executed\n",
        )
        .unwrap();

        let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

        assert_eq!(
            snapshot.content_class,
            ContentClass::Executable,
            "{extension}"
        );
    }
}

#[test]
fn classifies_common_interpretable_payload_extensions_as_executable() {
    for extension in ["py", "js", "mjs", "cjs", "ts", "jar"] {
        let (_parent, directory) = skill_directory(basic_skill());
        std::fs::write(
            directory.join(format!("payload.{extension}")),
            b"captured but never executed\n",
        )
        .unwrap();

        let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

        assert_eq!(
            snapshot.content_class,
            ContentClass::Executable,
            "{extension}"
        );
    }
}

#[test]
fn classifies_an_extensionless_shebang_file_as_executable() {
    let (_parent, directory) = skill_directory(basic_skill());
    std::fs::write(
        directory.join("payload"),
        b"#!/usr/bin/env python3\nprint('captured, never executed')\n",
    )
    .unwrap();

    let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

    assert_eq!(snapshot.content_class, ContentClass::Executable);
}

#[test]
fn classifies_common_executable_binary_magic_as_executable() {
    let cases: [(&str, &[u8]); 4] = [
        ("elf", b"\x7fELF\x02\x01captured"),
        ("pe", b"MZ\x90\0captured"),
        ("mach-o", b"\xcf\xfa\xed\xfecaptured"),
        ("wasm", b"\0asm\x01\0\0\0captured"),
    ];

    for (label, bytes) in cases {
        let (_parent, directory) = skill_directory(basic_skill());
        std::fs::write(directory.join("payload.data"), bytes).unwrap();

        let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

        assert_eq!(snapshot.content_class, ContentClass::Executable, "{label}");
    }
}

#[test]
fn classifies_files_below_scripts_as_executable_without_using_an_extension() {
    let (_parent, directory) = skill_directory(basic_skill());
    std::fs::create_dir(directory.join("scripts")).unwrap();
    std::fs::write(
        directory.join("scripts/run"),
        b"captured but never executed\n",
    )
    .unwrap();

    let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

    assert_eq!(snapshot.content_class, ContentClass::Executable);
}

#[cfg(unix)]
#[test]
fn classifies_an_executable_file_mode_as_executable() {
    use std::os::unix::fs::PermissionsExt;

    let (_parent, directory) = skill_directory(basic_skill());
    let payload = directory.join("payload");
    std::fs::write(&payload, b"captured but never executed\n").unwrap();
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).unwrap();

    let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

    assert_eq!(snapshot.content_class, ContentClass::Executable);
}

#[test]
fn classifies_hook_and_lifecycle_native_fields_case_insensitively_as_executable() {
    for native_field in ["hook", "Hooks", "LIFECYCLE"] {
        let skill_document = format!(
            "---\nname: code-review\ndescription: Review a change.\n{native_field}: true\n---\n# Review\n"
        );
        let (_parent, directory) = skill_directory(skill_document.as_bytes());

        let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

        assert_eq!(
            snapshot.content_class,
            ContentClass::Executable,
            "{native_field}"
        );
    }
}

#[test]
fn classifies_known_native_execution_fields_as_executable() {
    for native_field in [
        "plugin",
        "plugins",
        "extension",
        "extensions",
        "setup",
        "install",
        "installer",
        "command",
        "commands",
        "hook",
        "hooks",
        "lifecycle",
    ] {
        let skill_document = format!(
            "---\nname: code-review\ndescription: Review a change.\n{native_field}: true\n---\n# Review\n"
        );
        let (_parent, directory) = skill_directory(skill_document.as_bytes());

        let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

        assert_eq!(
            snapshot.content_class,
            ContentClass::Executable,
            "{native_field}"
        );
    }
}

#[test]
fn preserves_unknown_native_field_names_without_inferring_execution_from_substrings() {
    for native_field in [
        "webhook-url",
        "plugin-notes",
        "installation-guide",
        "commandments",
    ] {
        let skill_document = format!(
            "---\nname: code-review\ndescription: Review a change.\n{native_field}: true\n---\n# Review\n"
        );
        let (_parent, directory) = skill_directory(skill_document.as_bytes());

        let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

        assert_eq!(
            snapshot.content_class,
            ContentClass::AgentActive,
            "{native_field}"
        );
        assert!(snapshot.native_fields.contains(native_field));
    }
}

#[test]
fn classifies_a_prose_only_skill_with_references_as_agent_active() {
    let (_parent, directory) = skill_directory(basic_skill());
    std::fs::create_dir(directory.join("references")).unwrap();
    std::fs::write(
        directory.join("references/checklist.md"),
        b"check every changed boundary\n",
    )
    .unwrap();

    let snapshot = capture_skill(&directory, CaptureLimits::default()).unwrap();

    assert_eq!(snapshot.content_class, ContentClass::AgentActive);
}
