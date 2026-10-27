# ADR-0065: Apple release host is separate from artifact target

Status: Accepted for implementation under RC5.3 repair authorization; validation pending

## Context

The RC5.2 Intel-hosted job failed while stapling its DMG after notarization was
Accepted. Its raw provider error was not retained, so the old cause is unknown.
The runner provider independently reports Intel CloudKit stapling failures while
Apple Silicon hosts succeed (actions/runner-images issue 14924). A privileged
firewall workaround is not part of KitRove's release authority.

## Decision

Run both existing Apple artifact targets on the reviewed Apple Silicon `macos-15`
host, in separate single-target jobs. Cross-compile the Intel product for
`x86_64-apple-darwin`; do not relabel an ARM binary as Intel. Install the pinned
cargo-dist archive for the actual reviewed host OS/CPU, independently of the
artifact target. Reject other host/target pairs before download or installation.
Keep the existing Linux and Windows target jobs and their pinned tools.

Signing remains native to macOS, as required by ADR-0042, not native to a CPU.
The existing protected environment, isolated Keychain, process ownership, exact
source/target/archive identity, signature verification, Accepted notarization,
staple validation, mounted image inspection and final attestation gates remain.
Do not execute cross-built products in the credential-bearing job. No new
permissions, provider, credential handoff, network/firewall changes, retries,
notary resubmission, partial-output reuse or release-tag mutation are introduced.

## Invariant and product impact

NS-07/NS-09 and INV-07/INV-12 remain enforced. Host selection grants no new
release or execution authority. Portable/native asset representations, identity,
provenance, fidelity, receipts, synchronization, adoption, and conflict semantics
are unchanged. Cross-build/static verification is not Intel runtime acceptance,
nor evidence that the old failure's provider cause has been established.

## Validation

Red-before-green tests bind the closed host/target pairs, checksum failure before
extraction, per-target job separation and exact runner configuration. Inspect
the pinned dist 0.32 plan and credential-free local cross-build for both products;
verify Intel Mach-O architecture and exact archive inventory without executing
those products. Require full stable/Rust1.88, source review and exact public
checks before merge, then exact green main before a newly authorized release.
Only real successful stapling and independent final public artifact verification
can establish production acceptance. Preserve old failed attempts unchanged.
