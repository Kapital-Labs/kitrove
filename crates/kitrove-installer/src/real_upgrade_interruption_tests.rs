//! Operator-only child for deterministic real-artifact cuts before version probing.
use super::*;
use std::fs;
use std::io::Write as _;

fn material(evidence: &Path, candidate: bool) -> AuthenticatedRecoveryMaterial {
    let (directory, bundle, tag, commit, digest) = if candidate {
        (
            "rc2-public-20260924",
            "rc2-public-attestations-20260924/kitrove-cli-aarch64-apple-darwin.tar.xz.bundle.json",
            "v0.1.0-rc.2",
            "11f2d7b7daa1115e23d95121a6f7c923153b3190",
            "45701c8b18120cb0906586eb8371b5041618d1cf226b2f9ab40b52689af86ca5",
        )
    } else {
        (
            "rc1-public-20260924",
            "rc1-public-attestations-20260924/kitrove-cli-aarch64-apple-darwin.tar.xz.corrected.bundle.json",
            "v0.1.0-rc.1.3",
            "31b4657a8742756f26aa0596e2c57a4f357c8295",
            "e8c32f13cd4d6a115a86cfe3192d8863b2e1b2e87fff9052486921c2ef771c3c",
        )
    };
    let mut sha = [0; 32];
    for (index, byte) in sha.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).unwrap();
    }
    crate::release_intake::LocalReleaseRequest {
        archive: &evidence
            .join(directory)
            .join("kitrove-cli-aarch64-apple-darwin.tar.xz"),
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
    let prior = material(&evidence, false);
    let candidate = material(&evidence, true);
    let prepared = PreparedReplacement::prepare(
        &root.join("destination"),
        candidate.executable(),
        &prior,
        &[root.join("state-a"), root.join("state-b")],
    )
    .unwrap();
    prepared
        .install_with_hooks(
            |_, _| panic!("cut child must never reach native verification or execution"),
            |boundary| {
                if boundary == selected {
                    let mut ready = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(root.join("cut-ready"))
                        .unwrap();
                    ready.write_all(cut.as_bytes()).unwrap();
                    ready.sync_all().unwrap();
                    // Retain transaction ownership and state guards until the parent
                    // kills this exact child. A timeout is failure, never acceptance.
                    std::thread::sleep(std::time::Duration::from_secs(60));
                    panic!("parent did not interrupt retained transaction");
                }
                Ok(())
            },
        )
        .unwrap();
    panic!("selected interruption boundary was not reached");
}
