#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

#[cfg(unix)]
use kitrove_agent_skills::FileMode;
use kitrove_agent_skills::{
    CaptureLimits, CaptureMeter, CaptureUsage, SkillSource, SkillSourceLayout,
    capture_skill_source, capture_skill_source_metered, capture_skill_source_with_meter,
    hash_skill_source,
};

#[derive(Default)]
struct RefusingMeter {
    max_file_attempts: usize,
    max_bytes: u64,
    usage: CaptureUsage,
}

impl CaptureMeter for RefusingMeter {
    fn try_file_attempt(&mut self) -> bool {
        if self.usage.file_attempts >= self.max_file_attempts {
            return false;
        }
        self.usage.file_attempts += 1;
        true
    }

    fn remaining_bytes(&self) -> u64 {
        self.max_bytes.saturating_sub(self.usage.bytes_read)
    }

    fn try_charge_bytes(&mut self, bytes: u64) -> bool {
        if bytes > self.remaining_bytes() {
            return false;
        }
        self.usage.bytes_read += bytes;
        true
    }
}

fn standalone(path: impl Into<PathBuf>) -> SkillSource {
    let path = path.into();
    let parent = path.parent().unwrap().canonicalize().unwrap();
    SkillSource::Standalone {
        path: parent.join(path.file_name().unwrap()),
    }
}

fn directory(path: impl Into<PathBuf>) -> SkillSource {
    SkillSource::Directory {
        path: path.into().canonicalize().unwrap(),
    }
}

fn write_source(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
}

fn valid_document() -> &'static [u8] {
    b"---\nname: review\ndescription: Review a change.\n---\n# Review\n"
}

#[test]
fn captures_a_standalone_markdown_file_without_its_siblings() {
    let root = tempfile::tempdir().unwrap();
    let document = root.path().join("review.md");
    write_source(&document, valid_document());
    write_source(&root.path().join("private-notes.md"), b"not captured\n");

    let captured = capture_skill_source(&standalone(&document), CaptureLimits::default()).unwrap();

    assert_eq!(captured.layout, SkillSourceLayout::Standalone);
    assert_eq!(captured.original_document_name, "review.md");
    assert_eq!(captured.exact.files.len(), 1);
    assert_eq!(
        captured.exact.files[&kitrove_model::PortablePath::parse("review.md").unwrap()].bytes,
        valid_document()
    );
}

#[test]
fn failed_parse_still_reports_attempted_io() {
    let root = tempfile::tempdir().unwrap();
    let document = root.path().join("malformed.md");
    write_source(&document, b"---\nname: [\n---\n");
    let mut usage = CaptureUsage::default();

    let result =
        capture_skill_source_metered(&standalone(&document), CaptureLimits::default(), &mut usage);

    assert!(result.is_err());
    assert_eq!(usage.file_attempts, 2);
    assert!(usage.bytes_read > 0);
}

#[test]
fn refusing_meter_never_exceeds_zero_or_one_operation_limits_on_failure() {
    let root = tempfile::tempdir().unwrap();
    let document = root.path().join("review.md");
    write_source(&document, valid_document());
    let source = standalone(&document);

    for max_file_attempts in [0, 1] {
        let mut meter = RefusingMeter {
            max_file_attempts,
            max_bytes: u64::MAX,
            ..RefusingMeter::default()
        };
        let error = capture_skill_source_with_meter(&source, CaptureLimits::default(), &mut meter)
            .unwrap_err();
        assert_eq!(error.code(), "capture.request_budget_exhausted");
        assert_eq!(meter.usage.file_attempts, max_file_attempts);
    }

    let mut meter = RefusingMeter {
        max_file_attempts: 8,
        max_bytes: 1,
        ..RefusingMeter::default()
    };
    let error =
        capture_skill_source_with_meter(&source, CaptureLimits::default(), &mut meter).unwrap_err();
    assert_eq!(error.code(), "capture.request_budget_exhausted");
    assert_eq!(meter.usage.bytes_read, 0);
    assert!(meter.usage.file_attempts <= meter.max_file_attempts);
}

#[test]
fn refusing_meter_accepts_a_source_that_exactly_fills_the_byte_budget() {
    let root = tempfile::tempdir().unwrap();
    let document = root.path().join("review.md");
    write_source(&document, valid_document());
    let source = standalone(&document);
    let source_len = u64::try_from(valid_document().len()).unwrap();
    let mut meter = RefusingMeter {
        max_file_attempts: 8,
        max_bytes: source_len,
        ..RefusingMeter::default()
    };

    let captured =
        capture_skill_source_with_meter(&source, CaptureLimits::default(), &mut meter).unwrap();

    assert_eq!(
        captured.exact.files[&kitrove_model::PortablePath::parse("review.md").unwrap()].bytes,
        valid_document()
    );
    assert_eq!(meter.usage.bytes_read, source_len);
}

#[test]
fn refusing_meter_rejects_a_source_one_byte_over_budget_without_overcharging() {
    let root = tempfile::tempdir().unwrap();
    let document = root.path().join("review.md");
    write_source(&document, valid_document());
    let source = standalone(&document);
    let max_bytes = u64::try_from(valid_document().len() - 1).unwrap();
    let mut meter = RefusingMeter {
        max_file_attempts: 8,
        max_bytes,
        ..RefusingMeter::default()
    };

    let error =
        capture_skill_source_with_meter(&source, CaptureLimits::default(), &mut meter).unwrap_err();

    assert_eq!(error.code(), "capture.request_budget_exhausted");
    assert_eq!(meter.usage.bytes_read, 0);
}

#[test]
fn exact_hash_uses_the_fixed_source_frame() {
    let root = tempfile::tempdir().unwrap();
    let document = root.path().join("review.md");
    write_source(&document, valid_document());

    let captured = capture_skill_source(&standalone(&document), CaptureLimits::default()).unwrap();

    assert_eq!(
        hash_skill_source(SkillSourceLayout::Standalone, "review.md", &captured.exact,).as_str(),
        "blake3:1daba578f2e10ceed03309dbe862d36a1eec43ee37ab5661a28780f656e9b86a"
    );
}

#[test]
fn exact_hash_preserves_crlf_bytes() {
    let root = tempfile::tempdir().unwrap();
    let lf = root.path().join("review.md");
    let crlf = root.path().join("review-crlf.md");
    write_source(&lf, valid_document());
    write_source(
        &crlf,
        b"---\r\nname: review\r\ndescription: Review a change.\r\n---\r\n# Review\r\n",
    );

    let lf = capture_skill_source(&standalone(lf), CaptureLimits::default()).unwrap();
    let crlf = capture_skill_source(&standalone(crlf), CaptureLimits::default()).unwrap();

    assert_ne!(lf.exact_source_hash, crlf.exact_source_hash);
}

#[test]
fn exact_hash_changes_when_the_original_filename_changes() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("review.md");
    let second = root.path().join("audit.md");
    write_source(&first, valid_document());
    write_source(&second, valid_document());

    let first = capture_skill_source(&standalone(first), CaptureLimits::default()).unwrap();
    let second = capture_skill_source(&standalone(second), CaptureLimits::default()).unwrap();

    assert_ne!(first.exact_source_hash, second.exact_source_hash);
}

#[test]
fn exact_hash_distinguishes_directory_and_standalone_layouts() {
    let root = tempfile::tempdir().unwrap();
    let directory_root = root.path().join("review");
    std::fs::create_dir(&directory_root).unwrap();
    write_source(&directory_root.join("SKILL.md"), valid_document());
    let standalone_file = root.path().join("SKILL.md");
    write_source(&standalone_file, valid_document());

    let directory =
        capture_skill_source(&directory(directory_root), CaptureLimits::default()).unwrap();
    let standalone =
        capture_skill_source(&standalone(standalone_file), CaptureLimits::default()).unwrap();

    assert_ne!(directory.exact_source_hash, standalone.exact_source_hash);
}

#[cfg(unix)]
#[test]
fn standalone_capture_preserves_executable_mode() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().unwrap();
    let document = root.path().join("review.md");
    write_source(&document, valid_document());
    std::fs::set_permissions(&document, std::fs::Permissions::from_mode(0o755)).unwrap();

    let captured = capture_skill_source(&standalone(document), CaptureLimits::default()).unwrap();

    assert_eq!(
        captured.exact.files[&kitrove_model::PortablePath::parse("review.md").unwrap()].mode,
        FileMode::Executable
    );
}

#[test]
fn standalone_capture_rejects_credential_shaped_names() {
    let root = tempfile::tempdir().unwrap();
    let document = root.path().join(".env");
    write_source(&document, valid_document());

    let error = capture_skill_source(&standalone(document), CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "skill.credential_artifact");
}

#[test]
fn standalone_preflight_rejects_credential_shaped_names_before_io() {
    let root = tempfile::tempdir().unwrap();
    let document = root.path().join(".env");
    write_source(&document, valid_document());
    let mut usage = CaptureUsage::default();

    let error =
        capture_skill_source_metered(&standalone(document), CaptureLimits::default(), &mut usage)
            .unwrap_err();

    assert_eq!(error.code(), "skill.credential_artifact");
    assert_eq!(usage, CaptureUsage::default());
}

#[test]
fn standalone_preflight_rejects_non_markdown_names_before_io() {
    let root = tempfile::tempdir().unwrap();
    let document = root.path().join("review.txt");
    write_source(&document, valid_document());
    let mut usage = CaptureUsage::default();

    let error =
        capture_skill_source_metered(&standalone(document), CaptureLimits::default(), &mut usage)
            .unwrap_err();

    assert_eq!(error.code(), "capture.standalone_not_markdown");
    assert_eq!(usage, CaptureUsage::default());
}

#[test]
fn standalone_capture_charges_the_identity_reopen() {
    let root = tempfile::tempdir().unwrap();
    let document = root.path().join("review.md");
    write_source(&document, valid_document());
    let mut usage = CaptureUsage::default();

    capture_skill_source_metered(&standalone(document), CaptureLimits::default(), &mut usage)
        .unwrap();

    assert_eq!(usage.file_attempts, 2);
}

#[test]
fn directory_capture_charges_the_identity_reopen() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("review");
    std::fs::create_dir(&source).unwrap();
    write_source(&source.join("SKILL.md"), valid_document());
    let mut usage = CaptureUsage::default();

    capture_skill_source_metered(&directory(source), CaptureLimits::default(), &mut usage).unwrap();

    assert_eq!(usage.file_attempts, 2);
}

#[test]
fn standalone_capture_enforces_the_four_mebibyte_document_boundary() {
    let root = tempfile::tempdir().unwrap();
    let accepted = root.path().join("accepted.md");
    let rejected = root.path().join("rejected.md");
    let bytes = vec![b'x'; 4 * 1024 * 1024];
    write_source(&accepted, &bytes);
    write_source(&rejected, &[bytes.as_slice(), b"x"].concat());

    let accepted_result = capture_skill_source(&standalone(accepted), CaptureLimits::default());
    let rejected_result = capture_skill_source(&standalone(rejected), CaptureLimits::default());

    assert!(accepted_result.is_ok());
    assert_eq!(
        rejected_result.unwrap_err().code(),
        "capture.file_size_limit"
    );
}

#[cfg(unix)]
#[test]
fn standalone_capture_refuses_a_symlink() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target.md");
    let link = root.path().join("review.md");
    write_source(&target, valid_document());
    symlink(&target, &link).unwrap();

    let error = capture_skill_source(&standalone(link), CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "capture.symlink");
}

#[cfg(unix)]
#[test]
fn standalone_capture_refuses_a_fifo() {
    let root = tempfile::tempdir().unwrap();
    let fifo = root.path().join("review.md");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());

    let error = capture_skill_source(&standalone(fifo), CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "capture.special_file");
}

#[cfg(target_os = "linux")]
#[test]
fn standalone_capture_rejects_non_utf8_filenames() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let root = tempfile::tempdir().unwrap();
    let document = root.path().join(OsString::from_vec(vec![b'r', 0xff]));
    write_source(&document, valid_document());

    let error = capture_skill_source(&standalone(document), CaptureLimits::default()).unwrap_err();

    assert_eq!(error.code(), "capture.non_utf8_path");
}
