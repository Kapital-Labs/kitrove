# DMG publication wiring review

The disabled tag workflow now connects native preparation, exact publication
inventory, checksum authority and single-image attestation. Application/installer
archive types and consumer authentication policies are unchanged.

The hosted Apple wrapper accepts only an explicit container mode, reuses one
credential lifetime and runs no product binary. Its default archive-only rehearsal
behavior is unchanged. A new output directory cannot replace an existing path or
follow a redirected parent. After credential cleanup, the shared native verifier
checks retained image/checksum bytes and the exact staged payload before attestation.
Both preserved signed images passed this new verifier locally; no signing credential
or new notarization submission was used.

Linux staging uses shared bounded no-follow file hashing/copying for opaque DMGs.
It does not claim to validate their format or native signatures. Exact inventory,
individual sidecars and combined checksums cover all eleven artifacts. Checksum
completion refuses incorrect prior archive authority and creates a new file only.
Checksum parsing now shares bounded no-follow intake rather than unbounded reads.
No new archive parser, cryptographic protocol, dependency or unsigned fallback exists.

Pinned cargo-dist 0.32.0 source was inspected before wiring checksum completion:
[`generate_unified_checksum` and artifact-directory initialization](https://github.com/axodotdev/cargo-dist/blob/v0.32.0/cargo-dist/src/lib.rs)
use planned artifact metadata rather than discovering extra DMGs. The integration
therefore explicitly extends the validated checksum map. Its
[GitHub hosting branch](https://github.com/axodotdev/cargo-dist/blob/v0.32.0/cargo-dist/src/host.rs)
delegates publication to CI; the existing final verified-staging publication step
remains the release boundary. A hosted run is still required to test the complete
integration rather than treating source inspection as runtime acceptance.

Tests cover occupied and redirected outputs, early image/checksum refusal, exact
native verifier calls, explicit wrapper mode and cleanup after failures, missing or
substituted containers, malformed policy, unchanged prior checksum authority and
no-overwrite checksum output. Synthetic container bytes establish only transport
behavior, not native signing acceptance. The checked-in workflow remains inactive.

NS-07/NS-08/NS-09 and INV-06/INV-07/INV-08/INV-12 remain unchanged. Capabilities,
discovery/adoption, native preservation, fidelity, receipts, sync and conflicts are
untouched. A hosted integration rehearsal, trusted consumer bootstrap, clean-machine
online/offline launches and explicit candidate publication remain separate gates.

Validation: workspace all-feature tests, workspace all-target/all-feature Clippy and
76 Python tests (one skipped) passed. The aggregate run then caught the old four-call
workflow guard. The guard now requires four verification calls plus exactly one
checksum-completion call, with regression tests for missing, altered and extra calls.
After that guard-only fix, all 52 xtask tests passed (one native test ignored), as
did xtask all-target Clippy, governance, license, repository, formatting and Rust
1.85 checks. Both preserved signed DMGs passed native reverification. No additional
signing run or product execution occurred.
