# Signing rehearsal path fix

Run 34850626506 built all targets and verified their handoffs. Windows authenticated
successfully, then release preparation failed opening the cargo-dist manifest's
directory. Both Apple jobs imported their identity and reached archive preparation,
then failed with a suppressed diagnostic; both restored and deleted their Keychains.

The shared retained-file reader passed an empty parent to the filesystem library
for bare filenames such as `dist-manifest.json`. Treat that parent as `.` without
canonicalizing the file or bypassing no-follow, size, identity, or content checks.
The regression fails with the old code on macOS and passes with the fix. Windows
reported the matching directory-open failure. Actual hosted signing still needs
a successful rehearsal; this local result does not establish native acceptance.

An allowlisted Apple diagnostic now identifies this directory error without
printing provider output. A canary test verifies redaction.

Review: the fix is shared by preparation and verification for both products and
all targets. It adds no dependency, duplicate path workaround, credential access,
publication authority, or unsigned fallback. NS-07/NS-09 and INV-07/INV-12 remain
unchanged under ADR-0042. Discovery, adoption, portable/native preservation,
fidelity, provenance, receipts, synchronization, and conflicts are unaffected.
Signing credentials and transient files remain local to the protected runner.
Existing link and replacement tests remain applicable; the new regression also
checks the size bound and same-length content replacement without changing CWD.

Validation: full `cargo ci` passed on rerun, including formatting, Clippy, workspace
tests, 71 Python tests (one native Windows skip), governance, licenses, and hygiene.
The first full run failed in the unchanged version-probe suite; all 12 tests passed
in isolation and the full rerun passed without further code changes. Rust 1.85
`cargo check --locked -p xtask` passed. Native Windows execution and real hosted
signing remain pending. A fresh scoped code/security/consolidation review found no
additional required changes or duplicated implementation.
