#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::path::Path;

use kitrove_model::ContentClass;
use kitrove_risk::contains_credential_shaped_bytes;

use crate::frontmatter::reject_secret_metadata_keys;
use crate::{CapturedTree, FileMode, SkillError};
use crate::{NativeSkillObject, parse_observed_skill_document};

const PRIVATE_KEY_MARKERS: [&[u8]; 5] = [
    b"BEGIN PRIVATE KEY",
    b"BEGIN ENCRYPTED PRIVATE KEY",
    b"BEGIN RSA PRIVATE KEY",
    b"BEGIN EC PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
];

const EXECUTABLE_EXTENSIONS: [&str; 22] = [
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".exe", ".dll", ".dylib", ".so",
    ".wasm", ".bin", ".py", ".js", ".mjs", ".cjs", ".ts", ".jar", ".pyc", ".pyo", ".class",
];

const EXECUTABLE_MAGICS: [&[u8]; 9] = [
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\0asm",
];

pub(crate) fn reject_credential_artifacts(
    directory: &Path,
    exact: &CapturedTree,
) -> Result<(), SkillError> {
    for (path, file) in &exact.files {
        let display_path = directory.join(path.as_str());
        if credential_like_path(path.as_str()) {
            return Err(SkillError::new(
                "skill.credential_artifact",
                display_path,
                "credential-like filename is not eligible for portable capture",
            ));
        }
        if contains_private_key_marker(&file.bytes) {
            return Err(SkillError::new(
                "skill.credential_artifact",
                display_path,
                "private-key material is not eligible for portable capture",
            ));
        }
        if contains_credential_shaped_bytes(&file.bytes) {
            return Err(SkillError::new(
                "skill.credential_artifact",
                display_path,
                "credential-shaped content is not eligible for portable capture",
            ));
        }
    }
    Ok(())
}

pub(crate) fn classify(exact: &CapturedTree, native_fields: &BTreeSet<String>) -> ContentClass {
    let executable_file = exact.files.iter().any(|(path, file)| {
        let path = path.as_str();
        file.mode == FileMode::Executable
            || path.starts_with("scripts/")
            || executable_extension(path)
            || executable_signature(&file.bytes)
    });
    let executable_field = native_fields.iter().any(|field| {
        let normalized = field.to_ascii_lowercase();
        matches!(
            normalized.as_str(),
            "plugin"
                | "plugins"
                | "extension"
                | "extensions"
                | "setup"
                | "install"
                | "installer"
                | "command"
                | "commands"
                | "hook"
                | "hooks"
                | "lifecycle"
        )
    });

    if executable_file || executable_field {
        ContentClass::Executable
    } else {
        ContentClass::AgentActive
    }
}

/// Recomputes credential and executable risk from an already verified portable tree.
pub fn assess_portable_tree_risk(exact: &CapturedTree) -> Result<ContentClass, SkillError> {
    reject_credential_artifacts(Path::new("portable-object"), exact)?;
    Ok(classify(exact, &BTreeSet::new()))
}

/// Refuses credential artifacts in an executable native tree.
///
/// The caller has already classified this tree as executable by selecting a native executable
/// object format. This function deliberately does not parse or execute any payload bytes.
pub fn assess_native_executable_tree_risk(
    exact: &CapturedTree,
) -> Result<ContentClass, SkillError> {
    reject_credential_artifacts(Path::new("native-executable-object"), exact)?;
    Ok(ContentClass::Executable)
}

/// Recomputes credential and executable risk from a verified origin-native object.
pub fn assess_native_skill_object_risk(
    object: &NativeSkillObject,
) -> Result<ContentClass, SkillError> {
    let tree = object.tree();
    reject_credential_artifacts(Path::new("native-object"), tree)?;
    let document_path = kitrove_model::PortablePath::parse(object.original_document_name())
        .map_err(|_| {
            SkillError::new(
                "native_object.document_invalid",
                Path::new("native-object"),
                "native object principal document path is invalid",
            )
        })?;
    let document = tree.files.get(&document_path).ok_or_else(|| {
        SkillError::new(
            "native_object.document_missing",
            Path::new("native-object"),
            "native object principal document is missing",
        )
    })?;
    let observed =
        parse_observed_skill_document(Path::new(object.original_document_name()), &document.bytes)?;
    if observed.frontmatter.contains_key("metadata") && observed.metadata.is_none() {
        return Err(SkillError::new(
            "skill.metadata_invalid",
            Path::new(object.original_document_name()),
            "metadata must be a mapping of string keys to string values",
        ));
    }
    if let Some(metadata) = &observed.metadata {
        reject_secret_metadata_keys(Path::new(object.original_document_name()), metadata)?;
    }
    Ok(classify(tree, &observed.native_fields))
}

pub(crate) fn credential_like_path(path: &str) -> bool {
    let components: Vec<_> = path.split('/').map(str::to_ascii_lowercase).collect();
    let basename = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let reserved_basename = basename == ".env"
        || basename.starts_with(".env.")
        || matches!(
            basename.as_str(),
            "auth.json"
                | ".credentials.json"
                | "credentials.json"
                | "id_rsa"
                | "id_ed25519"
                | ".netrc"
                | ".git-credentials"
                | ".npmrc"
                | ".pypirc"
        );
    let aws_credentials = components
        .windows(2)
        .any(|pair| pair == [".aws", "credentials"]);
    reserved_basename || aws_credentials
}

fn contains_private_key_marker(bytes: &[u8]) -> bool {
    PRIVATE_KEY_MARKERS
        .iter()
        .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

fn executable_extension(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    EXECUTABLE_EXTENSIONS
        .iter()
        .any(|extension| basename.ends_with(extension))
}

fn executable_signature(bytes: &[u8]) -> bool {
    bytes.starts_with(b"#!")
        || EXECUTABLE_MAGICS
            .iter()
            .any(|magic| bytes.starts_with(magic))
}

/// Verifies the closed text-helper subset without interpreting or executing it.
/// Executable classification is retained; this grants no placement authority.
pub fn validate_scripted_skill_tree(
    tree: &CapturedTree,
    document_name: &str,
) -> Result<(), SkillError> {
    reject_credential_artifacts(Path::new("scripted-skill"), tree)?;
    let principal = tree
        .files
        .iter()
        .find(|(path, _)| path.as_str() == document_name)
        .map(|(_, file)| file)
        .ok_or_else(unsupported_script)?;
    if principal.mode != FileMode::Regular {
        return Err(unsupported_script());
    }
    let observed = parse_observed_skill_document(Path::new(document_name), &principal.bytes)?;
    let empty = CapturedTree {
        files: Default::default(),
        hash: crate::hash_tree(&Default::default()),
    };
    if classify(&empty, &observed.native_fields) == ContentClass::Executable {
        return Err(unsupported_script());
    }
    for (path, file) in &tree.files {
        let lower = path.as_str().to_ascii_lowercase();
        if [
            ".exe", ".dll", ".dylib", ".so", ".wasm", ".bin", ".jar", ".pyc", ".pyo", ".class",
        ]
        .iter()
        .any(|ext| lower.ends_with(ext))
            || EXECUTABLE_MAGICS
                .iter()
                .any(|magic| file.bytes.starts_with(magic))
        {
            return Err(unsupported_script());
        }
        if (file.mode == FileMode::Executable
            || path.as_str().starts_with("scripts/")
            || executable_extension(path.as_str())
            || file.bytes.starts_with(b"#!"))
            && (file.bytes.contains(&0) || std::str::from_utf8(&file.bytes).is_err())
        {
            return Err(unsupported_script());
        }
    }
    Ok(())
}

fn unsupported_script() -> SkillError {
    SkillError::new(
        "skill.script_bundle_unsupported",
        Path::new("scripted-skill"),
        "only text helper scripts with a regular principal document and no native lifecycle directives are eligible",
    )
}

#[cfg(test)]
mod scripted_tests {
    use super::*;
    use crate::{CapturedFile, hash_tree};
    use kitrove_model::PortablePath;
    fn tree(name: &str, mode: FileMode, bytes: &[u8]) -> CapturedTree {
        let files = std::collections::BTreeMap::from([
            (PortablePath::parse("SKILL.md").unwrap(), CapturedFile { mode: FileMode::Regular,
             bytes: b"---\nname: review\ndescription: Review changes.\n---\nUse the adjacent helper.\n".to_vec() }),
            (PortablePath::parse(name).unwrap(), CapturedFile { mode, bytes: bytes.to_vec() })]);
        CapturedTree {
            hash: hash_tree(&files),
            files,
        }
    }
    #[test]
    fn text_scripts_keep_modes_and_executable_classification_without_execution() {
        for mode in [FileMode::Regular, FileMode::Executable] {
            let tree = tree("helper.py", mode, b"raise SystemExit('must not execute')\n");
            validate_scripted_skill_tree(&tree, "SKILL.md").unwrap();
            assert_eq!(
                assess_portable_tree_risk(&tree).unwrap(),
                ContentClass::Executable
            );
            assert_eq!(
                tree.files[&PortablePath::parse("helper.py").unwrap()].mode,
                mode
            );
        }
    }
    #[test]
    fn binary_payloads_disguises_nontext_and_lifecycle_directives_are_refused() {
        for (name, bytes) in [
            ("helper.exe", b"text".as_slice()),
            ("helper.py", b"\x7fELFfake"),
            ("data/picture.png", b"MZfake"),
            ("helper.py", b"a\0b"),
            ("scripts/helper", b"\xff"),
            ("helper.pyc", b"cached"),
        ] {
            assert!(
                validate_scripted_skill_tree(&tree(name, FileMode::Regular, bytes), "SKILL.md")
                    .is_err()
            );
        }
        let mut tree = tree("helper.py", FileMode::Regular, b"pass\n");
        tree.files
            .get_mut(&PortablePath::parse("SKILL.md").unwrap())
            .unwrap()
            .bytes =
            b"---\nname: review\ndescription: Review changes.\nhooks: dangerous\n---\nReview.\n"
                .to_vec();
        assert!(validate_scripted_skill_tree(&tree, "SKILL.md").is_err());
    }
}
