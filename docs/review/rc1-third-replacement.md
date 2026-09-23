# Third replacement candidate review

NS-07/NS-09: metadata-only preparation preserves credential and trust boundaries.
Release 35923739891 completed all four platform builds, signing, staging and
attestation, but source-archive validation blocked global assembly. No publication
occurred. PR #27 fixes the closed source-root family check; all its required checks
passed at 6542ced878581dac3e83fe6c2414539db0eb74a1, and the merged tree at
32d974db87ec3c38f9aea68237aeb398df0b119a is identical.

Candidate A becomes 0.1.0-rc.1.3, with no rollback predecessor. B remains
0.1.0-rc.2 only after successful A publication and independent verification.
Only workspace versions, corresponding lockfile records, compatibility metadata,
reviewed digests and release documents change. No external dependency, runtime,
state-format or protection-policy changes. Failed tags remain immutable. No
retained artifact is relabeled; fresh builds and provenance must match the new tag.

Full local stable and Rust 1.85 canonical validation passed, including tests,
Clippy, formatting, archive/workflow tests, governance and license review. Both
source-built executables report 0.1.0-rc.1.3. Pinned cargo-dist planning accepts
the exact prerelease tag for both products. The source-family fix's main CI passed.
Exact-head candidate checks must pass before merge, followed by green main before
tagging. Clean-machine Mac acceptance remains unproven.
