# RC5.3 fresh-install preview preparation

The maintainer approved new 0.1.0-rc.5.3 preparation and normal protected
signing/publication after reviewed stapling, dependency and packaging repairs.
RC5/RC5.1/RC5.2 tags and failed runs remain immutable; their partial outputs are
not reused. No package-channel update, migration or stable-support scope is implied.

This preparation changes the workspace version and its 27 matching lock entries,
appends only an empty RC5.3 rollback-predecessor entry, refreshes exact reviewed
lock/catalog fingerprints and adds accurate versioned notes. The already-reviewed
crypto-bigint 0.7.10/ctutils 0.4.6 sources, every registry version/checksum, dependency
edge/feature, license material and workflow/signer policy must remain unchanged.
See the [dependency review](rc53-dependency-review.md) and ADRs 0065/0066.

The reviewed version-only Cargo.lock BLAKE3 is
`069fe829e4eb90ea0b28b8e9743a5adc160a0536bbff65090056b921d7f4489e`;
the append-only compatibility catalog BLAKE3 is
`daa6c2df94ab7ca500eb872a94e0a45a49b94347c1700a2cc29ca8ec917274c0`.
The original review-fingerprint refusals are retained as evidence before refresh.

## Compatibility and invariant evaluation

Use a new isolated collection and empty destination with disposable capabilities.
RC4.2 cannot read authored-pack collections; binary rollback does not restore
collection data. No rollback-compatible predecessor, in-place upgrade or migration
is promised. Existing installer refusals remain authoritative.

NS-05/NS-10 and INV-06/INV-08 require truthful compatibility and recovery claims;
NS-07/NS-09 and INV-07/INV-12 retain explicit executable trust and local credentials.
Discovery/adoption, portable/native representation, fidelity, provenance, receipts,
synchronization, conflict handling, schema and lifecycle protocols are unchanged.
Cloud-provider sync remains roadmap only. Versioning introduces no new ADR model.

## Required gates

Before commit, require full stable/Rust1.88, fresh audit/license checks, exact
workspace-only lock comparison, reproduced notices and manual source review.
Inspect pinned dist0.32's nonpublishing plan and fresh local unsigned archives;
check inventory, notice source bytes, preparation, version/help and JSON-error
smokes. These are not production-artifact or other-CPU execution acceptance.

Require exact PR checks and green latest main before guarded merge, then exact
merged-main checks before activation or a new annotated tag. Verify the new tag
and release are absent, record source/tag/run, use normal protected approvals and
remove temporary activation on terminal success or failure. Never bypass, retag,
retry a failed release or re-sign successful jobs. Preserve failures and evidence.

Independently verify the complete published inventory, all17 exact-source
attestations, notice bytes against the reviewed source and both native Mac images
before artifact acceptance claims. Source-built bounded Mac/Linux roundtrips and
unsigned archives do not prove fresh-install, all-kind, Intel runtime, concurrent,
live-harness or clean-Mac online/offline-first-launch acceptance. The repository
review remains risk-prioritized, not exhaustive assurance.
