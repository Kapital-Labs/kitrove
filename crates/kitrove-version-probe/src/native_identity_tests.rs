//! Operator-only native evidence using reviewed-source test code, never a download.
#![cfg(target_os = "macos")]
use super::apple_process_identity::{capture_self_candidate, verify_suspended_child};
use kitrove_macos_process::SuspendedSelf;
use kitrove_release_policy::native_signature::AppleProcessIdentityCandidate;

#[test]
#[ignore = "operator-only: requires native signed source-built test executable"]
fn bounded_native_verifier_binds_self_and_rejects_wrong_suspended_identity() {
    let identity = capture_self_candidate().unwrap();
    let child = SuspendedSelf::spawn().unwrap();
    let matched = verify_suspended_child(&child, &identity);
    let wrong = AppleProcessIdentityCandidate::from_display(
        b"CDHash=0000000000000000000000000000000000000000\n",
    )
    .unwrap();
    let refused = verify_suspended_child(&child, &wrong);
    // Explicitly kill/reap before assertions. Neither operation can resume it.
    child.terminate().unwrap();
    assert!(matched.is_ok(), "suspended child must match executing self");
    assert!(
        refused.is_err(),
        "wrong identity must fail native verification"
    );
}
