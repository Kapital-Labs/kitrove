# Installer DMG preparation review

The new operator-only `prepare-installer-dmg` command builds a fresh validated
payload, verifies the existing installer signature, creates a native image,
signs/notarizes/staples it, validates the ticket/signature/image and compares the
read-only mounted payload before final checksum creation. No product executes.
Production release inventory and workflow activation are unchanged.

Security review covered exact product/target selection, source and payload identity,
private no-overwrite outputs, post-stapling digest authority, native signature
requirements, notarization refusal and read-only mount cleanup. On uncertain detach,
preserve the mountpoint without recursive traversal. Report both the initial failure
and cleanup uncertainty; retain incomplete image output without claiming success.
The native test confirmed hdiutil's exact three-file HFS+ payload on this Mac.
This is not signed DMG or clean-machine offline consumer acceptance.

Consolidation: Apple team/signature/timestamp and notarization verification are
shared with existing executable signing. Executables still require hardened runtime;
containers require timestamp/team without that executable-only flag. Retained file
checks and archive bounds are reused. Payload inventory uses one bounded helper
for staging and mounted content. No new dependency, archive parser, signature
protocol or application replacement authority is introduced.

NS-07/NS-08/NS-09 and INV-06/INV-07/INV-08/INV-12 are unchanged. Credentials remain
local to existing signing configuration and provider output stays redacted.
Discovery/adoption, portable/native preservation, fidelity, capability receipts,
sync and conflicts are untouched. Hostile same-user processes and compromised
native tools remain outside ADR-0042's build-tool isolation boundary.

Tests cover failure at each native stage, no checksum on validation failure,
post-stapling bytes, late image substitution, mounted extra/changed/linked content,
changed payload before native invocation and retained uncertain mountpoints.
An explicitly invoked unsigned native round-trip test exercises actual image
creation, integrity check, mount, comparison and detach without signing credentials
or executable launch. Ordinary CI skips that native mount test.

Validation passed: full local `cargo ci`, the explicit unsigned native round-trip,
and `cargo +1.85.0 check --locked -p xtask`. The xtask suite passed 49 tests with
the operator-only native test ignored during its ordinary run.

Signed native acceptance, consumer bootstrap, production inventory/provenance
integration and clean-machine online/offline testing remain open release gates.
