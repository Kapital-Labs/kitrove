# Architecture Decision Records

ADRs document foundational decisions and their consequences. Accepted ADRs are authoritative unless superseded.

## Status values

- Proposed
- Accepted
- Superseded
- Rejected
- Deprecated

## Index

| ADR | Decision | Status | North Star |
|---|---|---|---|
| [0001](0001-portable-core-native-variants.md) | Portable core plus native variants | Accepted | NS-03, NS-10 |
| [0002](0002-harness-neutral-source-model.md) | Harness-neutral source model | Accepted | NS-01, NS-02 |
| [0003](0003-secrets-and-auth-remain-local.md) | Secrets and authentication remain local | Accepted | NS-07 |
| [0004](0004-content-addressing-with-blake3.md) | BLAKE3 content addressing | Accepted | NS-05, NS-06 |
| [0005](0005-receipt-backed-atomic-materialization.md) | Receipt-backed atomic materialization | Accepted | NS-05, NS-09 |
| [0006](0006-git-is-a-sync-backend-not-the-product.md) | Git is a backend, not the UX | Accepted | NS-06 |
| [0007](0007-packs-are-first-class-assets.md) | Packs are first-class assets | Accepted | NS-05 |
| [0008](0008-explicit-fidelity-model.md) | Explicit categorical fidelity | Accepted | NS-04, NS-10 |
| [0009](0009-no-general-package-management.md) | No general package management | Accepted | NS-08 |
| [0010](0010-tier-one-adapters-compiled-in.md) | Tier-one adapters compiled in | Accepted | NS-01, NS-02 |
| [0011](0011-authoritative-manifest-generated-lock.md) | Authoritative manifest and generated lockfile | Accepted | NS-05, NS-06, NS-10 |
| [0012](0012-versioned-read-only-adapter-observation.md) | Versioned read-only adapter observation | Accepted | NS-01, NS-02, NS-04, NS-07, NS-09, NS-10 |
| [0013](0013-canonical-portable-path-collision-key.md) | Canonical portable path collision key | Accepted | NS-01, NS-03, NS-05, NS-10 |
| [0014](0014-reusable-skill-source-layouts-and-identity.md) | Reusable skill source layouts and identity | Accepted | NS-01, NS-02, NS-03, NS-05, NS-10 |
| [0015](0015-versioned-asset-revision-identity.md) | Versioned asset revision identity | Accepted for Gate C3 implementation | NS-03, NS-05, NS-07, NS-10 |
| [0016](0016-versioned-origin-native-skill-object.md) | Versioned origin-native skill object | Accepted for Gate C3 implementation | NS-03, NS-05, NS-07, NS-10 |
| [0017](0017-portable-stored-skill-tree-envelope.md) | Portable stored skill-tree envelope | Accepted for Gate C3 implementation | NS-01, NS-03, NS-05, NS-07, NS-10 |
| [0018](0018-semantic-sync-with-local-base.md) | Semantic synchronization uses a machine-local base | Accepted for Gate D D1 implementation | NS-02, NS-03, NS-05, NS-06, NS-07, NS-10 |
| [0019](0019-component-provenance-for-semantic-merge.md) | Semantic merge requires component provenance | Accepted for Gate D D1 implementation | NS-03, NS-04, NS-05, NS-07, NS-10 |
| [0020](0020-bounded-sync-contract-identities.md) | Synchronization contracts use bounded versioned identities | Accepted for Gate D D1 implementation | NS-03, NS-05, NS-06, NS-07, NS-10 |
| [0021](0021-canonical-portable-snapshot-envelope.md) | Portable snapshots are canonical derived envelopes | Accepted for Gate D D1 implementation | NS-03, NS-05, NS-06, NS-07, NS-10 |
| [0022](0022-pure-conservative-semantic-merge.md) | Semantic merge is pure, component-aware, and conservative | Accepted for Gate D D1 implementation | NS-02, NS-03, NS-04, NS-05, NS-06, NS-07, NS-09, NS-10 |
| [0023](0023-exact-prior-explicit-update-adoption.md) | Explicit update adoption requires exact prior authority | Accepted for Gate D D2 implementation | NS-02, NS-03, NS-04, NS-05, NS-07, NS-09, NS-10 |
| [0024](0024-filesystem-sync-is-conditional-snapshot-transport.md) | Filesystem synchronization is conditional snapshot transport | Accepted for Gate D D3 implementation | NS-02, NS-03, NS-05, NS-06, NS-07, NS-09, NS-10 |
| [0025](0025-git-sync-is-an-https-only-cas-transport.md) | Git synchronization is a bounded HTTPS compare-and-swap transport | Accepted for Gate D D4 implementation | NS-03, NS-05, NS-06, NS-07, NS-09, NS-10 |
| [0026](0026-native-only-executable-variant-preservation.md) | Preserve native-only executable variants before trust | Accepted for Gate F implementation | NS-02, NS-03, NS-04, NS-05, NS-07, NS-09, NS-10 |
| [0027](0027-local-exact-content-executable-trust.md) | Executable trust is local exact-content authority | Accepted for Gate G implementation | NS-04, NS-05, NS-07, NS-09, NS-10 |
| [0028](0028-bounded-ssh-and-ambient-credential-providers.md) | SSH and ambient credentials are bounded local transport capabilities | Accepted for Phase 2 implementation | NS-03, NS-05, NS-06, NS-07, NS-08, NS-09, NS-10 |
| [0029](0029-managed-instruction-removal-is-receipt-backed-projection-mutation.md) | Managed instruction removal is receipt-backed projection mutation | Accepted for Phase 3 implementation | NS-02, NS-05, NS-07, NS-09, NS-10 |
| [0030](0030-prompt-commands-use-a-narrow-versioned-portable-core.md) | Prompt commands use a narrow versioned portable core | Accepted for Phase 3 implementation | NS-01, NS-02, NS-03, NS-04, NS-05, NS-07, NS-09, NS-10 |
| [0031](0031-portable-subagents-use-an-inert-common-core.md) | Portable subagents use an inert common core | Accepted for Phase 3 implementation | NS-01, NS-02, NS-03, NS-04, NS-05, NS-07, NS-09, NS-10 |
| [0032](0032-portable-mcp-v1-is-remote-https-with-local-auth-bindings.md) | Portable MCP v1 is remote HTTPS with local authentication bindings | Accepted for Phase 3 implementation | NS-01, NS-02, NS-03, NS-04, NS-05, NS-07, NS-09, NS-10 |
| [0033](0033-pack-removal-requires-local-application-claims.md) | Pack removal requires machine-local application claims | Accepted for Phase 4 implementation | NS-02, NS-05, NS-07, NS-09, NS-10 |
| [0034](0034-pack-rollback-uses-accepted-snapshot-history.md) | Pack rollback uses accepted snapshot history | Accepted for Phase 4 implementation | NS-01, NS-03, NS-05, NS-06 |
| [0035](0035-pack-distribution-adoption-uses-verified-snapshots.md) | Pack distribution adoption uses verified snapshots | Accepted for Phase 4 implementation | NS-01, NS-03, NS-05, NS-06, NS-07, NS-10 |
| [0036](0036-explicit-local-version-probes-bind-executable-policy.md) | Explicit local version probes bind executable policy | Accepted on Unix and Windows | NS-02, NS-04, NS-05, NS-07, NS-09, NS-10 |
| [0037](0037-quarantine-cleanup-requires-persisted-identity.md) | Quarantine cleanup requires persisted filesystem identity | Accepted for Phase 6 implementation | NS-03, NS-05, NS-06, NS-07, NS-09, NS-10 |
| [0038](0038-windows-private-state-requires-handle-bound-dacl-evidence.md) | Windows private state requires handle-bound DACL evidence | Accepted | NS-03, NS-05, NS-06, NS-07, NS-09, NS-10 |
| [0039](0039-windows-saved-project-trust-is-handle-bound-read-only-authority.md) | Windows saved project trust is handle-bound read-only authority | Accepted with native Windows evidence | NS-02, NS-04, NS-05, NS-07, NS-09, NS-10 |
| [0040](0040-application-upgrades-require-a-verified-rollback-kit.md) | Application upgrades require a verified rollback kit | Accepted for Phase 6 implementation | NS-03, NS-05, NS-06 |
| [0041](0041-installer-artifacts-are-not-application-authority.md) | Installer artifacts are not application replacement authority | Accepted for Phase 6 implementation; publication gated | NS-07, NS-09 |
| [0042](0042-platform-signing-precedes-release-authority.md) | Native signing precedes final release digest authority | Accepted for local Phase 6 implementation; hosted activation gated | NS-07, NS-09 |

Use [`0000-template.md`](0000-template.md) for new records.
