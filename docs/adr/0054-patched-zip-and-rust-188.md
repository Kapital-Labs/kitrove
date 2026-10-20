# ADR-0054: Patched ZIP intake dependency and Rust 1.88 minimum

- Status: Proposed; validation in progress
- North Star: NS-05, NS-07, NS-09

## Context and decision

RUSTSEC-2026-0367, RUSTSEC-2026-0368 and RUSTSEC-2026-0369 affect the
locked ZIP 6.0.0 dependency. Their patched range starts at 9.0.0, whose
declared minimum Rust version is 1.88. The user approved raising KitRove's
source-build minimum from 1.85 to 1.88 rather than maintaining a security
backport.

Pin ZIP 9.0.5 with default features still disabled. Update current build
instructions, minimum-version checks and release checks together. Historical
validation records continue to describe the compiler used at that time.
This decision supersedes earlier ADR references to 1.85 as a future build gate,
not their historical evidence.

KitRove retains its independent bounded archive parser, ZIP cross-checks and
payload handling. Do not introduce library extraction, new archive features,
advisory exceptions or relaxed intake checks. Existing narrowly reviewed vendor
patches remain unchanged; removing them is outside this remediation.

Existing immutable application and package releases are untouched. This changes
the compiler required to build future source, not installation requirements for
already published binaries.

## Validation

Review the exact dependency and feature delta, licenses, provenance and source
changes. Run archive conformance tests, fresh advisory audit, canonical stable
and Rust 1.88 validation, and exact native platform CI before merging.
