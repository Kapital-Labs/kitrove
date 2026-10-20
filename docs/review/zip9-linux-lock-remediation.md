# ZIP 9 and Unix lock remediation

Scope: NS-05, NS-07, NS-09. ADRs 0053/0054 precede these changes. The user
approved Rust 1.88 as the new source-build minimum. No release/tag/signature
is changed.

## Dependency and API review

ZIP 9.0.5 is the published crates.io package at upstream commit
`0123ed144cfa7d672dae78b79a034d8900f9aaeb`, archive SHA-256
`6e04976da629d3b04204ba8105b396a193af8ad2583b2c79bfb3ab8af580a11e`.
Its MIT license remains unchanged. The patched RustSec range for
RUSTSEC-2026-0367/0368/0369 starts at 9.0.0; a fresh audit of this graph
reported no warnings or vulnerabilities.

The only new package is typed-path 0.12.4, upstream commit
`2b35969073aba78506455e3add808b1514a0f368`, archive SHA-256
`54ec2755506471f54baf5e4bb5499d8e510cc1caf271270e778a736bd2d7336c`.
It is MIT OR Apache-2.0, requires Rust 1.65, and has no dependencies or build
script. Reviewed package metadata, path/UTF-8 conversion implementation surface,
and ZIP call sites: ZIP uses its Windows path components for path helpers.
KitRove's intake continues comparing raw names against its independent parser,
not delegating containment to those helpers. ZIP adds a macOS/BSD-only `nix`
0.31.3 `fs` edge for no-follow permission handling in library extraction;
that package already existed in the graph. No library extraction call is added.
`arbitrary` and `derive_arbitrary` disappear. ZIP defaults remain disabled;
no optional compression, cryptographic or network feature is enabled.

Reviewed upstream changelog and reachable raw-reader API changes. Raw lookup
still calls `find_content`, which populates a checked data offset before returning.
KitRove requires that optional offset to equal `Some(expected)` (None refuses).
ZIP64 extensible data remains rejected through the renamed accessor. ZIP 9
preserves regular-file type bits on DOS read-only modes; the independent parser
now expects 0100444 instead of 0444. The accepted DOS flag set and rejection
of links/special entries/unknown creator systems remain unchanged. Raw Unix
special permission bits are not normalized by KitRove to match ZIP's new
sanitizer: mismatches remain refusals.

Release archive rewriting now propagates fallible filename decoding instead of
using an infallible name API. It does not substitute lossy names. Existing
deterministic rewrite tests cover the changed path.

## Lock and build review

The regression failed before explicit Unix unlock and passed afterward, including
contention and duplicate-handle lifetime assertions. The originally failing batch
test and full canonical local CI passed for the isolated lock change.
This establishes the mechanism, not the identity of any CI child process.
Unlock retries EINTR only; no later writer bypasses lock failure.

All current minimum-version CI/release checks and build instructions move to
1.88 together. The release workflow diff changes only those compiler version
strings, not permissions, triggers, signing or deployment. Historical validation
records and existing vendor patches remain intact.

Raising MSRV enables Clippy suggestions previously gated by 1.85. Mechanical
let-chain conversions preserve left-to-right short-circuiting and the existing
authority checks. Constant chunk conversions retain preceding length checks
and the old behavior of excluding remainders; fixed SHA-256 parsing still
requires exactly 64 bytes. Multiple-of checks use nonzero existing constants.
An inlined test-format argument preserves the synthetic fixture bytes. These
are compiler migration changes, not additional agent-interface behavior.

## Validation status

Canonical stable and Rust 1.88 CI passed locally, including tests, strict linting,
archive conformance, governance, licenses (385 third-party packages), and repository
hygiene. The additional special-permission regression passed on Rust 1.88.
Windows GNU all-target/all-feature strict Clippy passed as a cross-build, not
native Windows runtime evidence. Exact native public checks remain required
before merge. Early compile/test failures exposed changed ZIP APIs and DOS mode
semantics; corrections above preserve fail-closed checks rather than removing
tests. No advisory exception or CI rerun was used to hide a failure.

The first exact public run passed Linux, macOS and Rust 1.88, but native Windows
exposed two host-dependent test fixtures: ZIP 9's writer marks Windows-created
archives as DOS. Mutating only the upper attributes did not create a Unix-mode
fixture there. Both Unix-mode tests now explicitly set the creator-system byte
to Unix before changing its attributes. DOS-policy fixtures remain independently
covered. No intake policy or expected refusal was relaxed; fresh native checks
are required for this correction.
