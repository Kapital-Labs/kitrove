# Installer container provenance review

This checkpoint implements the library boundary from ADR-0043, not a runnable
download/bootstrap flow. The closed catalog determines the subject name. An owned
image snapshot is bounded before hashing or attestation work; its digest is never
accepted from a caller or checksum sidecar. Successful authentication retains that
same snapshot and the selected release identity. No filesystem or native tool runs.

The existing offline Sigstore boundary remains the sole signature verifier. It
continues to require the pinned repository and organization IDs, exact release
workflow, version tag, source commit, public hosted runner claims, one exact subject,
and trusted-root policy. No dependency, cryptographic parser, archive parser, or
relaxed manual-rehearsal identity was added. Opaque DMG bytes are not archive intake.

Review checked constructor privacy, immutable byte access, bounds before hashing,
closed subject selection, digest derivation, redacted debug output, and separation
from executable and application authority. The small result wrapper deliberately
does not generalize all product types into a permissive shared artifact type.
Compile-fail examples enforce the installer/application conversion boundary.
Synthetic tests cover both targets, empty/oversized boundaries, malformed/oversized
bundles, unrelated signed provenance and retained result fields. Private result
construction tests storage only, never cryptographic acceptance. The shared verifier
tests continue to cover signatures, identity claims and exact subjects/digests.

Real Kitrove production-tag provenance remains an acceptance gate. Hosted rehearsal
35224395532 passed both Mac signing/DMG paths, but its manual workflow cannot satisfy
the production identity policy. No downloaded product was executed. CLI intake,
native checks, authenticated embedded installer handling and clean-machine online/
offline launch still need acceptance. NS-07 and NS-09 are preserved; portable
capability state, fidelity, sync and ownership semantics are unchanged.

Local validation passed: 31 provenance unit tests and three compile-fail doc tests,
all-target/all-feature provenance Clippy, Rust 1.85 all-target provenance check,
governance, repository, formatting and diff checks. No signing or release run was
needed for this library-only checkpoint.
