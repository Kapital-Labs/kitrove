# Faster-hex advisory fix

The fresh release-readiness audit reported RUSTSEC-2026-0306 in the existing
`faster-hex` 0.10.0 Git dependency. The safe `hex_decode_unchecked` API could read
past its input on x86/x86_64 with AVX2. The advisory identifies 0.10.1 as patched.
Update the shared locked dependency rather than introducing a local decoder or
suppressing the warning. Published release candidates remain immutable.

## Dependency and code review

The crates.io 0.10.1 archive checksum is
`04839bdf9d8c10f66806fad16b852fc72aab80873aebc3cb69d85b4fa41543ed`.
Its package declares MIT, Rust 1.61, and the NervosFoundation/faster-hex repository.
Review of the AVX2 loop confirms that it now requires both 64 source bytes and
32 destination bytes before loading; the scalar remainder consumes complete input
pairs only. Upstream includes short-source/oversized-destination regression cases.

This patch release also contains ARM64 NEON checking/encoding, a corrected x86 AVX
feature bit, and limits encoder return strings to the initialized output prefix.
The reviewed NEON loops bound each vector load by the remaining source and use the
existing destination-capacity check for stores. Additive serde option helpers and
optional defmt formatting do not alter Kitrove's selected features. These changes
make local ARM64 and hosted x86/Windows tests necessary; a clean audit alone is not
runtime proof.

The lockfile additionally records optional `defmt` 0.3.100 (MIT OR Apache-2.0),
checksum `f0963443817029b2024136fc4dd07a5107eb8f977eaf18fcd1fdeb11306b64ad`,
which forwards to the already locked defmt 1.1.1. It is not enabled in the selected
normal/build graph. Existing autocfg 1.5.1 becomes a build dependency; the complete
build script only probes `core::error::Error` and emits its configuration flag.
No other package versions change. The reviewed lockfile BLAKE3 is
`4a447417235b0423ded20451233f3b82a423b0c3f1132c285c889977bd98349c`.

## Impact and validation

NS-07/NS-09 and INV-07/INV-12 remain unchanged. No new trust boundary, credential
use, telemetry, discovery/adoption behavior, portable/native representation,
fidelity classification, provenance, receipt, synchronization or conflict semantics
is introduced. Existing Git/object/transport and no-loss tests remain applicable.
This uses one upstream patch through the existing dependency graph; no duplicate
implementation or fallback is added.

The fresh advisory audit passes with no warnings. Rust 1.85 checks for core and
xtask pass. Full `cargo ci` passes: formatting, strict Clippy, workspace tests,
archive/workflow checks, governance, licenses and repository hygiene. Hosted
exact-head required checks must pass before merge. Local ARM64 checks do not
establish x86 AVX2 runtime behavior.
