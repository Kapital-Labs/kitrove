# Native DMG consumer review

Scope: ADR-0043 reviewed-source operator verification. North Star impact:
NS-07/08/09; no credentials, package-manager expansion or product execution.

The command authenticates the image and installer archive under one exact target,
tag and source commit. Both use the existing production Sigstore policy. No native
tool runs until both checks succeed. The image subject is computed from its owned
bytes, not an unauthenticated checksum sidecar. Input handles are retained and
revalidated before staging and after native verification.

Consolidation: build preparation and consumer verification share private payload
staging. Native signature, staple, image integrity, read-only exact inventory/byte
comparison and detach reuse the existing image verifier. No second archive or
signature parser was introduced. Temporary payload and image directories are
separate from the mountpoint; uncertain detach retains the mountpoint rather than
recursively cleaning it.

The lockfile adds only xtask's edge to the existing workspace provenance crate.
No package identity, version, source or checksum changed. The reviewed lock digest
was refreshed for that exact edge; the existing license inventory passes.

Local tests cover argument/host/identity/name refusal and malformed provenance
without native invocation or input mutation. Existing staging and native-step tests
cover exact payloads, replaced inputs, occupied leaves and detach uncertainty.
The operator-only real mount test remains ignored. This change has no production
attestation fixture, signed native end-to-end result, or clean-machine launch
evidence. Manual rehearsal artifacts cannot satisfy production provenance and are
not used to weaken it. Candidate publication and clean-machine acceptance remain
separate, approval/resource-gated work.

Validation: 54 xtask tests passed (one operator-only test ignored); 32 provenance
tests and three compile-fail doctests passed. Stable all-target xtask Clippy with
warnings denied, Rust 1.85 all-target xtask check, governance, repository hygiene,
locked dependency licenses and diff whitespace checks passed. Hosted platform
checks are still required before merge.
