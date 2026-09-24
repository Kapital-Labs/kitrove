# RC2 preparation review

Scope: candidate metadata and acceptance documentation; no new runtime behavior.

Compared published A (`31b4657a8742756f26aa0596e2c57a4f357c8295`) with the
candidate base (`3c469d5b8b86489bb44327db19abf0a651758baf`). Only the ADR-0044
provenance correction, its tests and documentation intervened. No application-state,
receipt, history, recovery, archive-manifest or lifecycle format changed. RC2 may
therefore declare RC1.3 as a rollback-compatible predecessor. This declaration is
not evidence that the real two-version transaction has passed; that remains pending.

The lock diff contains exactly 25 workspace version replacements and no dependency
changes. The compatibility catalog retains A with no predecessors and adds only B
with A as predecessor. Reviewed BLAKE3 guards bind those exact files. No workflow,
root of trust, signing identity, provider permission or protected gate changes.

DRY review: both products still inherit the shared workspace version and use the
shared compatibility catalog. No parallel version, archive or signature machinery
was introduced. Acceptance documentation distinguishes public attestation checks,
source-verifier native checks and actual arm64 installation from unobserved native
platform and clean-machine outcomes. The immutable A installer limitation is explicit.

NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12 are preserved. Discovery/adoption,
portable representation, native-variant preservation, fidelity classification,
capability receipts, synchronization and conflict behavior are unchanged. Credentials
and operator evidence stay local; public documentation contains no private state.
Canonical `cargo ci` and `cargo +1.85.0 ci` both passed locally before push,
including strict Clippy, workspace tests, release-security tests, governance,
dependency licenses and repository hygiene. Final diff review found no additional
blocking issues. Native CI must still pass on the exact pushed candidate head.
