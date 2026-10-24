# RC5.2 fresh-install preview preparation

The maintainer explicitly approved preparation and normal protected signing/tag/
publication of NEW 0.1.0-rc.5.2 on 2026-10-24 after repaired main is green.
RC5 and RC5.1 remain immutable failed attempts. This authorizes neither retrying
their runs nor updating APT/RPM, Homebrew or the RC4.2 WinGet submission.

## Scope and compatibility

Base b36f9cb9c0f9c5c6f2ad8a40f9e6ffdc4d0c872b contains reviewed repairs
PR78/79/82/80/81/83/84. Exact main CI40048279188 and secret40048279228 passed.
RC5.2 is a fresh-install evaluation snapshot, not stable support, an in-place
upgrade or a migration. Append an empty rollback-predecessor entry; retain every
older catalog entry unchanged. No state schema or lifecycle protocol changes.
RC4.2 still cannot deserialize authored-pack collections; an older executable
does not undo collection changes. Do not bypass compatibility refusals.

This preparation changes only workspace versions, matching reviewed lock/catalog
fingerprints, changelog and version-specific publication copy. All 27 locked
workspace packages change version together. A fresh audit additionally found
RUSTSEC-2026-0387: update crypto-bigint to 0.7.6 and its required ctutils to 0.4.5.
Only those two third-party versions/checksums change; dependency edges remain
unchanged. See the [targeted dependency review](rc52-dependency-review.md).
An unrelated tempfile/getrandom resolver selection was restored before final
validation. All dependency patches require fresh audit and license validation.

The reviewed Cargo.lock BLAKE3 is
`d05a78545ecc0cef68e5e3fdffcb2d8a27ff6b7010738a9af57b9099ccda9121`.
The appended compatibility catalog BLAKE3 is
`62510ff95f63a3d450104d233b52a96dd140de87028e36ef18241c5a264cb234`.

## Invariants and security

NS-05/NS-10 and INV-06/INV-08 require truthful compatibility and recovery claims.
NS-07/NS-09 and INV-07/INV-12 retain local-only credentials and explicit executable
trust. Discovery/adoption, portable/native representation, fidelity, provenance,
receipts, sync/conflict behavior and trust decisions are unchanged by versioning.
The repairs strengthen explicit loss reporting, validation and recovery without
granting broader authority. Cloud sync remains roadmap only.

No workflow, action pin, signer/provider permission, timeout or release inventory
is changed. No credentials are read during preparation. Temporary activation is
allowed only after exact candidate PR/main checks, with an exact-run cleanup
owner on terminal success or failure. Use normal protected approval; no bypass,
retag or blind retry. The actual prior Apple failure cause remains unknown.

## Validation and publication gates

Baseline release-policy tests pass on unchanged base. Before commit require full
stable and Rust 1.88 cargo ci, fresh audit, exact lock/license review, pinned
nonpublishing dist 0.32.0 plan, local unsigned archive/preparation/bundle/version/
help/JSON-error smokes and complete source review of this small metadata delta.
The full repository review remains risk-prioritized and incomplete; the recorded
low-level mixed MCP editor edge case has no current CLI plan path or fix scope.

Require fresh exact public PR checks and green latest main before guarded merge,
then exact merged-main checks before one new immutable tag. Record final source,
tag object and release run, retain failed evidence, and remove activation on
terminal result. Independently verify full inventory, all 17 attestations and
both native Mac images before production-artifact claims. Prior source-built
roundtrips and unsigned archives do not establish new packaged-binary acceptance.
No clean-Mac, live-harness, all-kind or provider support claim is introduced.
