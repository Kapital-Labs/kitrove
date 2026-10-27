# ADR-0066: Release archives carry reviewed third-party materials

Status: Accepted for implementation under the separate RC5.3 packaging authorization; validation pending

## Decision

Enforce the existing repository notice policy in both binary archive families.
Add exactly `THIRD_PARTY_NOTICES.md`, `THIRD_PARTY_LICENSE_INVENTORY.txt` and
`THIRD_PARTY_LICENSES.txt` to the closed archive companion catalog. Require
nonempty notice material; preserve all existing path, mode, type, resource,
executable, manifest, checksum, signature and provenance checks. No optional
legacy shape, wildcard or unsigned fallback is introduced. Existing published
assets and failed release tags remain immutable.

Check in deterministic inventory and license-text outputs. Generate them only
from the reviewed locked graph: retain the complete `cargo xtask licenses`
output, inspect checksum-authenticated registry crate archives without extracting
or executing them, and read tracked vendored license material. Retain all named
license, copying, copyright, authors and notice files, including nested material;
deduplicate identical text by SHA-256 with explicit per-package/path references.
Missing upstream archive material requires reviewed, source-revision-bound local
supplements, never a guessed license or a network fallback during signing.

Canonical validation and each credential-free release build must reproduce and
compare these checked-in files before packaging or credential exposure. The
release archive itself contains all three files before signing. Preparation
preserves them while replacing only executable and release metadata bytes.
DMGs continue to contain their exact verified installer archive, including these
materials, without expanding the three-leaf DMG bootstrap inventory.

## Impact

NS-07/NS-09 and INV-07/INV-12 remain intact. This is public distribution metadata,
not portable capability state or a new execution/signing authority. Discovery,
adoption, native preservation, fidelity, asset provenance, receipts, synchronization
and conflict behavior are unchanged. No credentials, cache paths or local identities
enter generated material. This implements internal policy; it is not a legal
compliance opinion or a claim about exploitable behavior.

## Validation

Prove missing/empty materials fail for both products and TAR/ZIP; exact expanded
inventories pass and extra files/links/duplicates still fail. Require deterministic
generation, wrong graph/hash/text/supplement refusal, unchanged lockfile and
credential-free real archive inclusion with exact source bytes. Regenerate the
shared adversarial corpus under the new closed shape, preserving each negative
case. Run full stable/Rust 1.88, source review, exact required public checks and
green exact main before normal separately authorized preview publication.
