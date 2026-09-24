# Production provenance identity correction

The first published candidate exposed two old assumptions in the certificate
subject check: a name-only repository and a tag context rather than the protected
release environment. ADR-0044 records the correction. Production accepts only
the immutable owner/repository IDs plus exact `release` environment, and now
requires the separate environment extension too. Legacy handling is compiled only
for the pre-existing external test fixture. No source-ref, commit, workflow,
signature, transparency, digest or repository claim is removed.

The retained public fixture is the arm64 CLI attestation from run 35941035846,
tag v0.1.0-rc.1.3, commit 31b4657a8742756f26aa0596e2c57a4f357c8295. Its SHA256 is
bcae9a1eb7827d8295bab6b62299c75ae89a8821842f132a10ecba7c2c577403. It contains public
certificate/signature evidence, not credentials or executable bytes. GitHub CLI
independently verified it with exact source and signer digest, workflow, tag and
hosted-runner pins before intake. The corrected library's full offline verification
passes without altering the trusted root or cryptographic dependencies.

Tests cover missing, duplicate, critical, malformed and incorrect environment and
subject extensions; legacy/name-only subjects; wrong immutable IDs; and wrong
environments. Shared certificate mutation helpers avoid duplicating test machinery.
All provenance tests/doctests and strict Clippy passed locally. Full stable and
Rust 1.85 canonical repository validation passed. Corrected source-built tools
selected the application, installer and DMG bundles from the public downloads.
Wrong tag, commit and digest selections failed with empty stdout and unchanged
archive bytes. Native arm64 DMG verification passed after independent provenance:
signature, staple, image integrity, exact mounted payload and detach. No findings
remain from the bounded code review; exact-head CI is still required before merge.

This is not clean-machine acceptance. The existing RC1.3 installer is immutable
and has the old verifier; use the reviewed-source corrected verifier for its
acquisition tests. No downloaded product has been executed during this review.
