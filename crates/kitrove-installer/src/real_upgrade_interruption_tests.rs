//! Operator-only child for deterministic real-artifact cuts before version probing.
use super::*;
use std::fs;
use std::io::Write as _;

#[path = "../tests/support/public_release_pins.rs"]
mod pins;

fn hold_for_kill(root: &Path, leaf: &str, value: &str) -> ! {
    let mut ready = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(leaf))
        .unwrap();
    ready.write_all(value.as_bytes()).unwrap();
    ready.sync_all().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(60));
    panic!("parent did not interrupt retained transaction");
}

fn material(evidence: &Path, candidate: bool) -> AuthenticatedRecoveryMaterial {
    let index = usize::from(candidate);
    let (directory, bundle, tag, commit, digest) = (
        pins::DIRECTORIES[index],
        pins::BUNDLES[index],
        pins::TAGS[index],
        pins::COMMITS[index],
        pins::ARCHIVE_DIGESTS[index],
    );
    let mut sha = [0; 32];
    for (index, byte) in sha.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).unwrap();
    }
    crate::release_intake::LocalReleaseRequest {
        archive: &evidence.join(directory).join(pins::ARCHIVE),
        bundle: &evidence.join(bundle),
        expected: &kitrove_release_provenance::ExpectedReleaseIdentity::new(tag, commit).unwrap(),
        archive_sha256: sha,
    }
    .authenticate()
    .unwrap()
}

#[test]
#[ignore = "operator child only; parent must retain and kill this exact process"]
fn real_upgrade_cut_child() {
    let evidence = PathBuf::from(std::env::var_os("KITROVE_TEST_RELEASE_EVIDENCE").unwrap());
    let root = PathBuf::from(std::env::var_os("KITROVE_TEST_UPGRADE_CUT_ROOT").unwrap());
    let cut = std::env::var("KITROVE_TEST_UPGRADE_CUT").unwrap();
    let selected = match cut.as_str() {
        "before-exchange" => unix::UpgradeBoundary::BeforeExchange,
        "exchanged" => unix::UpgradeBoundary::Exchanged,
        "replaced-recorded" => unix::UpgradeBoundary::ReplacedRecorded,
        _ => panic!("unknown cut"),
    };
    let rollback = match std::env::var("KITROVE_TEST_REPLACEMENT_DIRECTION")
        .unwrap()
        .as_str()
    {
        "upgrade" => false,
        "rollback" => true,
        _ => panic!("unknown replacement direction"),
    };
    let prior = material(&evidence, rollback);
    let candidate = material(&evidence, !rollback);
    let destination = root.join("destination");
    let roots = [root.join("state-a"), root.join("state-b")];
    match std::env::var("KITROVE_TEST_CUT_ACTION").unwrap().as_str() {
        "prepare" => {}
        "recover" => {
            let subject = prior.executable().subject();
            let expected = kitrove_release_provenance::ExpectedReleaseIdentity::new(
                subject.release_tag(),
                subject.source_commit(),
            )
            .unwrap();
            PreparedReplacement::recover_direction_with(
                &destination,
                candidate.executable(),
                &roots,
                if rollback {
                    ReplacementDirection::Rollback
                } else {
                    ReplacementDirection::Upgrade
                },
                |staged| {
                    RetainedRollbackKit::reopen_material(
                        staged,
                        &expected,
                        subject.archive_sha256(),
                    )
                },
                |_, _| hold_for_kill(&root, "recovery-ready", "before-verification"),
            )
            .unwrap();
            panic!("recovery cut returned without interruption");
        }
        _ => panic!("unknown cut action"),
    }
    let prepared = if rollback {
        PreparedReplacement::prepare_rollback(&destination, candidate.executable(), &prior, &roots)
    } else {
        PreparedReplacement::prepare(&destination, candidate.executable(), &prior, &roots)
    }
    .unwrap();
    prepared
        .install_with_hooks(
            |_, _| panic!("cut child must never reach native verification or execution"),
            |boundary| {
                if boundary == selected {
                    // Retain transaction ownership and state guards until the parent
                    // kills this exact child. A timeout is failure, never acceptance.
                    hold_for_kill(&root, "cut-ready", &cut);
                }
                Ok(())
            },
        )
        .unwrap();
    panic!("selected interruption boundary was not reached");
}
