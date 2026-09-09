# Domain Model

## Asset identity

An `AssetId` is stable within an environment and independent of its current destination path. IDs are lowercase, human-readable, and validated. Renaming an asset is an explicit operation because receipts, conflicts, and provenance depend on identity.

## Asset kinds

Initial kinds:

- `Skill`
- `Instruction`
- `Agent`
- `Command`
- `Hook`
- `Mcp`
- `Plugin`
- `Extension`
- `Pack`

The enum may expand through ADR review. Unknown future kinds must not be silently coerced.

## Harness identity

Tier-one IDs are `claude`, `codex`, `pi`, and `opencode`. Community adapters later receive namespaced IDs.

## Source

A source records how original content was acquired:

- adopted from a harness
- local path
- Git repository and optional subdirectory
- immutable archive later
- native marketplace/package reference later

Resolution converts a moving source to immutable revision plus exact captured hash. Each portable or native content component references a content-addressed `ComponentProvenance` record containing that resolution. Harness observations additionally retain their logical harness scope; local and Git provenance cannot claim one. A complete asset has no single source once independently changed components are merged.

## Portable content

Portable content is an explicitly modeled representation with its own schema version. It is not an arbitrary harness directory renamed `portable`.

For the skills vertical slice, portable content starts with an Agent Skills-compatible projection rooted at canonical `SKILL.md`. A native source may be a `Directory` package or policy-supported `Standalone` Markdown file. Exact source identity retains layout, original document name, paths, modes, and bytes. Equal portable projections do not erase distinct origin-native evidence.

## Native variant

A native variant records:

- target harness
- captured native content
- source layout, original document name, and adapter-native identity when they affect behavior
- native schema/version observation
- relationship to the portable core
- executable classification
- fidelity implications

## Fidelity result

```text
category
reasons[]
evidence[]
blocked_requirements[]
adapter_version
harness_version
```

Categories:

- `Native`: original native implementation is used.
- `Portable`: shared representation is consumed unchanged.
- `Adapted`: semantics are confidently translated.
- `Partial`: only some semantics are represented.
- `Unsupported`: no meaningful target representation exists.
- `Blocked`: representation exists but local requirements prevent application.

Blocked requirements are tagged portable names, not local decisions. `binding { name }` names one symbolic binding resolved by machine-local configuration; `executable_trust` states that exact executable content requires a future machine-local trust decision. Neither form can contain a resolved secret, trust decision, path, receipt, or machine identity.

## Trust metadata

Trust is local policy applied to content identity, not an assertion that content is harmless. The portable asset may carry executable classification and provenance; local state carries the trust decision.

## Deployment receipt

A receipt binds an asset and rendered output to a harness destination and `HarnessScope::User | HarnessScope::Project`. It supports safe update, drift analysis, removal, and rollback. Transient `RootTier` does not enter receipt identity.

## Environment

The environment contains desired assets, profiles, target defaults, and source declarations. It does not contain machine selection, resolved secret values, or deployment receipts.

## Lockfile

The lockfile is generated, portable, and deterministic. For assets it records complete asset identity, portable and native component provenance references, their immutable provenance records, and deterministic compatibility. Packs retain their source resolution until their later lifecycle gate. The lockfile may not contain machine-specific blocked states.

## Machine state

Machine state selects a profile, enables local targets, maps logical bindings, and records local paths. It is not part of the sync backend unless explicitly exported through a future sanitized mechanism.

## Version 1 persistence contract

Gate B implements three strict persisted roots:

| Root | Encoding | Portability | Contents |
|---|---|---|---|
| `EnvironmentManifest` | TOML | Portable | assets, packs, profiles, target selections, and symbolic binding requirements |
| `Lockfile` | JSON | Portable and generated | immutable asset and pack source revisions, qualified content hashes, membership, and deterministic compatibility results |
| `LocalState` | JSON | Machine-local | machine selection, harness roots, binding resolvers, receipts, trust decisions, and scan history |

All three roots use schema version `1`, reject unknown fields, validate after deserialization, and serialize ordered maps deterministically. The environment and lockfile APIs validate again before serialization so an invalid value assembled in memory cannot be persisted through the supported interface.

Portable schemas cannot represent a resolved secret, machine identity, deployment destination, receipt, or local trust decision. They may name a `BindingName`; `LocalState` may map that name to an environment-variable reference or a command resolver, but neither type has a resolved-value field or variant.

## Validated value objects

- `AssetId`, `ProfileId`, `BindingName`, `MachineId`, and `ReceiptId` are lowercase ASCII identifiers.
- Community `HarnessId` values contain at least two validated namespace segments, while `claude`, `codex`, `pi`, and `opencode` remain built-in peers.
- `PortablePath` uses forward-slash relative paths and rejects absolute paths, Windows drive prefixes, backslashes, empty segments, `.` segments, and `..` segments.
- `ContentHash` is exactly `blake3:` followed by 64 lowercase hexadecimal characters.
- `ProvenanceId` is exactly `provenance:blake3:` followed by 64 lowercase hexadecimal characters and must equal the versioned hash of its complete provenance record.
- `Revision` is a non-empty, single-line immutable observation identifier.
- `RepositoryUrl` accepts credential-free HTTPS URLs and SSH URLs with an optional username; queries, fragments, passwords, and user information in HTTPS URLs are rejected.

Every fidelity result requires evidence and an adapter version. `Partial`, `Unsupported`, and `Blocked` additionally require structured reasons, while `Blocked` requires one or more tagged local requirements. Non-blocked categories cannot carry blocked requirements. The result's fields are private so callers cannot mutate a validated claim into an invalid combination.

Custom Serde deserializers call the same parsers used by Rust callers. Hand-edited state therefore cannot bypass the value-object invariants.

## Cross-record validation

Manifest validation rejects:

- asset, pack, profile, or native-variant map keys that disagree with embedded identity;
- an identity declared as both an asset and a pack;
- a `Pack` hidden in the plain asset map instead of the first-class pack map;
- unknown pack members and profile asset references;
- unknown profile parents;
- asset or pack binding requirements not declared at the environment root;
- missing, mismatched, or unreferenced component provenance;
- cycles in pack membership or profile inheritance.

Traversal uses ordered collections, producing deterministic first failures. Lockfiles likewise require every map key to match the embedded locked asset identity.

## Deferred behavior

These schemas define data contracts only. Gate B does not inspect harness sources, resolve or store content objects, execute binding resolvers, make trust decisions, materialize destinations, write receipts, synchronize backends, or expose new production CLI commands. Gate C2 adds read-only inspection plus receipt scope and validation. It can run without an environment and writes no receipt or scan history. Later Gate C milestones retain the validation boundaries defined here.
