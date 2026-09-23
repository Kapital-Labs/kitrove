# Replacement candidate review

`v0.1.0-rc.1` failed before publication in run `35873721343`. Its tag remains
unchanged. The reviewed build-shell and manifest-handoff fixes are merged in
`c9b155d81283d68be71fcd44fd9a6e80b231da58`. This metadata change prepares
`v0.1.0-rc.1.1` as the replacement first candidate under the approved prerelease
path. RC2 waits for successful publication and independent verification of it.

NS-07/NS-09: no trust, credential, state-format or runtime behavior changes.
Only the workspace version, its 25 lockfile package records, the compatibility
version, reviewed digests and explanatory release documents change. Third-party
dependencies are unchanged. The replacement declares no rollback predecessor;
failed RC1 is not treated as an accepted release. Future RC2 compatibility must
name the actual accepted predecessor after review.

Pinned cargo-dist 0.32.0 planning accepts the exact replacement tag, classifies it
as a prerelease and assigns both products the replacement version. No existing
archive is relabeled. New source-built archives and fresh protected production
provenance are required. No release activation or tag is part of this change.

Full local stable and Rust 1.85 canonical CI passed, including tests, Clippy,
formatting, archive/workflow security tests, governance and license checks. Both
source-built executables report `0.1.0-rc.1.1`. The merged workflow-fix main CI and
secret scan also passed. Versioned archive checks and hosted candidate checks still
precede publication; clean-machine acceptance remains unproven.
