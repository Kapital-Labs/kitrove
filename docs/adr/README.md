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
| [0042](0042-platform-signing-precedes-release-authority.md) | Native signing precedes final release digest authority | Accepted; hosted product rehearsal passed, production activation gated | NS-07, NS-09 |
| [0043](0043-stapled-mac-installer-container.md) | Stapled Mac installer container supplements release archives | Accepted; local signed preparation passed, native consumer acceptance pending | NS-07, NS-08, NS-09 |
| [0044](0044-release-environment-provenance.md) | Pin protected release environment and immutable subject | Implementation correction; real production fixture and local native verification passed | NS-07, NS-09 |
| [0045](0045-consumer-native-verification-is-a-closed-process-boundary.md) | Consumer native verification is a closed process boundary | Accepted for staged implementation; runtime unavailable | NS-07, NS-09 |
| [0046](0046-homebrew-is-a-separate-distribution-authority.md) | Homebrew is a separate distribution authority | Proposed; local packaging only, publication gated | NS-07, NS-08, NS-09 |

| [0047](0047-guided-setup-preserves-explicit-authority.md) | Guided setup preserves explicit authority | Accepted for implementation | NS-01 through NS-10 |
| [0048](0048-native-packages-have-separate-distribution-authority.md) | Native packages have separate distribution authority | Proposed; package development authorized, publication gated by validation | NS-07, NS-08, NS-09 |

| [0049](0049-agent-materialization-approval.md) | Agent materialization requires exact batch approval | Proposed; implementation pending review | NS-04, NS-05, NS-07, NS-09, NS-10 |

| [0050](0050-agent-pack-authoring-approval.md) | Agent pack authoring requires exact plans and refuses recovery | Proposed; validation pending | NS-04, NS-05, NS-07, NS-09, NS-10 |

| [0051](0051-agent-removal-approval.md) | Agent removal approves complete receipt-backed batches | Proposed; validation pending | NS-05, NS-07, NS-09, NS-10 |

| [0052](0052-agent-adoption-approval.md) | Adoption approval refuses implicit recovery | Proposed; validation pending | NS-05, NS-07, NS-09, NS-10 |

| [0053](0053-unix-transaction-lock-release.md) | Unix transaction guards explicitly release locks | Proposed; validation in progress | NS-05, NS-07, NS-09 |

| [0054](0054-patched-zip-and-rust-188.md) | Patched ZIP and Rust 1.88 minimum | Proposed; validation in progress | NS-05, NS-07, NS-09 |

| [0055](0055-agent-pack-import-approval.md) | Pack import approval preserves verified authority | Proposed; validation pending | NS-04, NS-05, NS-07, NS-09, NS-10 |

| [0056](0056-locally-authored-packs.md) | Locally authored packs preserve member provenance | Accepted; bounded synthetic acceptance passed | NS-01, NS-03, NS-05, NS-06, NS-07, NS-10 |

| [0057](0057-agent-json-errors.md) | Opt-in versioned machine-readable errors | Accepted; exact public validation pending | NS-01, NS-05, NS-06, NS-10 |

| [0058](0058-release-archive-name-identity.md) | Explicit release archive name identity | Accepted for implementation; validation pending | NS-09 |
| [0059](0059-hosted-signing-failure-evidence-and-process-lifetime.md) | Safe signing failure evidence and owned child lifetimes | Accepted for implementation; validation pending | NS-07, NS-09 |
| [0060](0060-native-skill-field-loss-is-explicit.md) | Native skill field loss is explicit | Accepted for implementation; validation pending | NS-02, NS-03, NS-04, NS-05, NS-06, NS-07, NS-10 |
| [0061](0061-mcp-activation-switches-require-booleans.md) | MCP activation switches require booleans | Accepted for implementation; validation pending | NS-02, NS-04, NS-05, NS-07, NS-09, NS-10 |
| [0062](0062-atomic-rollback-resumes-durable-progress.md) | Atomic rollback resumes durable progress | Accepted for implementation; validation pending | NS-03, NS-05, NS-06, NS-07, NS-09, NS-10 |
| [0063](0063-profile-validation-is-stack-safe.md) | Profile validation is stack-safe | Accepted for implementation; validation pending | NS-03, NS-05, NS-07, NS-09, NS-10 |
| [0064](0064-instruction-insertion-respects-region-ceiling.md) | Instruction insertion respects the region ceiling | Accepted for implementation; validation pending | NS-05, NS-09, NS-10 |
| [0065](0065-apple-release-host-is-separate-from-artifact-target.md) | Apple release host is separate from artifact target | Accepted for implementation; validation pending | NS-07, NS-09 |
| [0066](0066-release-archives-carry-reviewed-third-party-materials.md) | Release archives carry reviewed third-party materials | Accepted for implementation; validation pending | NS-07, NS-09 |

| [0068](0068-private-native-inspection-mechanics.md) | Private native-inspection mechanics are shared without a public runner | Accepted for prerequisite implementation; validation pending | NS-07, NS-09 |
| [0069](0069-readonly-ticket-process-ownership.md) | Read-only ticket validation has a closed owned lifetime | Accepted for prerequisite implementation; validation pending | NS-07, NS-09 |

Use [`0000-template.md`](0000-template.md) for new records.
