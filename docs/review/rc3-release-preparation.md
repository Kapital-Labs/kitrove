# RC3 preparation and compatibility review

The maintainer approved preparing, signing and publishing `v0.1.0-rc.3` on
2026-10-06. This is a prerelease, not stable support or completion of acceptance.
The preparation base is `56e35c0a7cdff49452ae5fe0b365a0cc9bd3a19f`; its exact-main
CI and secret scan passed before preparation. Protected release reviewers and
security gates remain unchanged. Activation is temporary and must be removed
after the release attempt ends.

## Changes since RC2

RC3 includes authenticated installer payload staging, shared Mac native signature
policy, bounded helper ownership/transport/cleanup, native-gated Mac installer
publication and reopening, and explicit `prepare-installer` and
`verify-prepared-installer` commands. These commands do not launch their output
or establish trust in a downloaded verifier's own first execution.

The `faster-hex` dependency advisory correction is included; see
[the dependency review](faster-hex-advisory-fix.md). Additional tests cover
installer publication interruption, application state preservation and refusal,
upgrade/rollback interruption, repeated recovery interruption, and native Linux
lifecycle acceptance. Prior RC2 artifact results do not authenticate RC3 bytes.

## Compatibility decision

The comparison from RC2 (`11f2d7b7daa1115e23d95121a6f7c923153b3190`) to the
preparation base changes no files in the model, core application, CLI or adapter
crates. Application replacement transaction changes only add a test-only module.
There is no application state migration, persisted model change or change to
sync/conflict semantics. RC3 therefore declares RC2 as its sole reviewed rollback
predecessor. RC2's existing RC1.3 declaration remains unchanged. No transitive
rollback authority is inferred. Binary rollback is not application-data rollback.
Real RC2-to-RC3 upgrade and rollback acceptance must follow publication with exact
authenticated artifacts; this review does not claim those tests have run.

## Scope and validation

This preparation changes the workspace version, corresponding workspace lockfile
versions, compatibility catalog and their reviewed digest guards. It changes no
third-party dependency versions, release workflow or signing policy. Full local
`cargo ci`, Rust 1.85 locked workspace/all-targets validation, reviewed exact-head
PR checks and green merged main are required before tagging.

NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12 remain unchanged. Discovery/adoption,
portable representation, native preservation, fidelity, deployment receipts,
sync/conflicts and local-only credential boundaries are unchanged. No new trust
boundary or automatic execution is introduced by this metadata change.

Release inventory, provenance and native artifact verification must be performed
on RC3 itself. Clean-Mac quarantined online/offline first launch, remaining native
platform acceptance and the bounded two-machine product roundtrip remain open.
The existing signing host and Linux VM do not substitute for clean-Mac evidence.
