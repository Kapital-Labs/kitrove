#![cfg(unix)]

use super::*;
use crate::NativeFileIdentity;
use crate::staging_policy::create_private_data_leaf;
use crate::test_support::private_tempdir;

fn fresh_binding(seed: u8) -> Binding {
    let identity = |byte| {
        let file_id = [byte; 16];
        serde_json::from_value::<NativeFileIdentity>(serde_json::json!({
            "platform": "windows", "filesystem_id": 7, "file_id": file_id
        }))
        .unwrap()
    };
    Binding::new([seed; 32], identity(1), identity(2)).unwrap()
}

fn directory(path: &std::path::Path) -> InstallerDirectory {
    InstallerDirectory::open_ambient_dir(path, cap_std::ambient_authority()).unwrap()
}

#[test]
fn every_interrupted_prefix_is_retained_without_repair() {
    let binding = fresh_binding(3);
    let phase = JournalStage::PriorRetained;
    let canonical = binding.bytes(phase).unwrap();
    let name = policy::name(phase, true).unwrap();
    for length in 0..=canonical.len() {
        let temp = private_tempdir();
        let parent = directory(temp.path());
        let bytes = canonical[..length].to_vec();
        let leaf = create_private_data_leaf(&parent, &name, bytes.clone()).unwrap();
        let journal = RetainedJournal::open(&parent, binding).unwrap();
        assert_eq!(journal.stage(&parent).unwrap(), JournalStage::Prepared);
        assert_eq!(journal.names(), vec![std::ffi::OsStr::new(&name)]);
        leaf.require_contents(&parent, &name, &bytes).unwrap();
        assert_eq!(parent.entries().unwrap().count(), 1);
    }
}

#[test]
fn malformed_or_foreign_complete_and_pending_records_are_preserved() {
    let binding = fresh_binding(3);
    let phase = JournalStage::PriorRetained;
    let canonical = binding.bytes(phase).unwrap();
    let mut extra = canonical.clone();
    extra.push(b' ');
    for pending in [false, true] {
        let mut invalid = vec![
            extra.clone(),
            vec![b'x'],
            vec![b'x'; MAX_RECORD_BYTES + 1],
            fresh_binding(4).bytes(phase).unwrap(),
        ];
        if !pending {
            invalid.extend([Vec::new(), canonical[..canonical.len() - 1].to_vec()]);
        }
        for bytes in invalid {
            let temp = private_tempdir();
            let parent = directory(temp.path());
            let name = policy::name(phase, pending).unwrap();
            let leaf = create_private_data_leaf(&parent, &name, bytes.clone()).unwrap();
            assert!(RetainedJournal::open(&parent, binding).is_err());
            leaf.require_contents(&parent, &name, &bytes).unwrap();
            assert_eq!(parent.entries().unwrap().count(), 1);
        }
    }
}

#[test]
fn retention_detects_new_missing_or_substituted_names() {
    let temp = private_tempdir();
    let parent = directory(temp.path());
    let binding = fresh_binding(3);
    let journal = RetainedJournal::open(&parent, binding).unwrap();
    let name = policy::name(JournalStage::PriorRetained, false).unwrap();
    let bytes = binding.bytes(JournalStage::PriorRetained).unwrap();
    let original = create_private_data_leaf(&parent, &name, bytes.clone()).unwrap();
    assert!(journal.revalidate(&parent).is_err());
    let journal = RetainedJournal::open(&parent, binding).unwrap();
    assert_eq!(journal.stage(&parent).unwrap(), JournalStage::PriorRetained);
    parent.rename(&name, &parent, "retained-original").unwrap();
    assert!(journal.revalidate(&parent).is_err());
    let replacement = create_private_data_leaf(&parent, &name, bytes.clone()).unwrap();
    assert!(journal.revalidate(&parent).is_err());
    original
        .require_contents(&parent, "retained-original", &bytes)
        .unwrap();
    replacement
        .require_contents(&parent, &name, &bytes)
        .unwrap();
}

#[test]
fn pending_restore_intent_never_authorizes_forward_recovery() {
    let temp = private_tempdir();
    let parent = directory(temp.path());
    let binding = fresh_binding(3);
    for (phase, pending) in [
        (JournalStage::PriorRetained, false),
        (JournalStage::Published, true),
        (JournalStage::RestoreRequested, true),
    ] {
        create_private_data_leaf(
            &parent,
            &policy::name(phase, pending).unwrap(),
            binding.bytes(phase).unwrap(),
        )
        .unwrap();
    }
    let journal = RetainedJournal::open(&parent, binding).unwrap();
    assert!(journal.stage(&parent).is_err());
    assert_eq!(parent.entries().unwrap().count(), 3);
}
