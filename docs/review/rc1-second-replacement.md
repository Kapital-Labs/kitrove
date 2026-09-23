# Second replacement candidate review

NS-07/NS-09: this metadata-only unit preserves credential and trust boundaries.
Run 35899392751 signed both Windows archives and cleared authentication, then
failed on Unix-style directory permissions in Git Bash. All other platform jobs
passed. Nothing was published; neither failed tag is moved or reused.

PR #25 fixes staging with the existing Windows security helper. Its exact head
45463c77ff9404ebbbb6541853decebbdd8ad893 passed native Windows canonical CI,
including the real staging handoff without credentials, plus all required checks.
The merged tree at a341f63693f95549d36dc4de90a68f532fc9351e is identical.

Candidate A becomes 0.1.0-rc.1.2; B remains 0.1.0-rc.2 only after A is published
and independently verified. Only workspace version records, compatibility metadata,
reviewed digests and release documents change. No third-party dependency, executable
behavior, state format, rollback predecessor or protection policy changes. Fresh
builds and production provenance must match the new tag; retained partial artifacts
are evidence only, not replacement release inputs.

Full local stable and Rust 1.85 canonical validation passed, including tests,
Clippy, formatting, archive/workflow tests, governance and dependency review. Both
source-built executables report 0.1.0-rc.1.2. Pinned cargo-dist planning accepts
the exact new prerelease tag for both products. The staging fix's main CI and
secret scan passed. Exact-head candidate checks must pass before merge, followed
by green main before tagging. Clean-machine Mac acceptance remains unavailable.
