# Installer container policy review

The two Mac DMGs now have a closed `InstallerContainerSpec` catalog, separate from
application and installer archive formats. Local preparation selects its exact
image name and embedded installer archive through this catalog rather than
reconstructing names and repeating the target allowlist. The existing bounded
image reads, signed preparation and three-leaf payload inventory are unchanged.

The canonical JSON policy reserves the same two mappings. Rust correspondence
tests and strict Python policy validation reject target/product aliases, malformed
entries and missing/duplicate targets. A compile-fail test prevents conversion to
application archive authority. No parser treats a DMG as a TAR or ZIP.

This is a preparation checkpoint, not publication integration. Python's active
publication set remains the same nine archives and controls; a test explicitly
asserts that reserving the container catalog does not allow DMGs into that set.
The release workflow is unchanged. Activation must extend native preparation,
exact publication/checksum inventory and attestations together in the next unit.

Review covered type separation, exact names, catalog drift, unchanged resource
bounds, malformed JSON values and the inactive publication boundary. The reviewed
policy fingerprint was updated only for the added reserved mappings. No signing
credentials, native tool behavior, dependency or execution path was added.

Validation passed: full local `cargo ci`, all 50 Python archive-verifier tests,
and Rust 1.85 checks for `kitrove-release-policy` and `xtask`. Native signing was
not repeated because neither signing behavior nor artifact contents changed.

NS-07/NS-08/NS-09 and INV-06/INV-07/INV-08/INV-12 are unchanged. Discovery/adoption,
portable/native preservation, fidelity, capability receipts, synchronization and
conflicts are untouched. Container specs are packaging selections, not provenance,
authenticated bytes or application replacement/rollback authority.
