# Architecture

**Status:** Baseline architecture for review. `NORTH_STAR.md` and accepted ADRs are authoritative.

## System shape

```text
Claude / Codex / Pi / OpenCode
          | inspect and materialize
          v
+-------------------------------+
|        Harness adapters       |
+---------------+---------------+
                |
                v
+-------------------------------+
|       Resolved environment    |
| assets, packs, profiles,      |
| portable core, native variants|
| fidelity, provenance, trust   |
+---------------+---------------+
                |
      +---------+----------+
      |                    |
      v                    v
Local object/state       Sync backend
store and receipts       Git / filesystem
```

## Layering

- **Domain model:** pure types and invariants; no filesystem, network, CLI, or harness paths.
- **Core observation and planning:** shared bounded scan engine, optional desired/observed comparison, profiles, fidelity-aware plans, and reconciliation.
- **Adapter API:** observation policy, scope, root tier, version evidence, capability matrix, rendering, and validation contracts.
- **Harness adapters:** thin compiled policies for paths, layouts, native identity, precedence, version lines, exclusions, destinations, and reload behavior.
- **Source resolvers:** retrieve individual external assets.
- **Sync backends:** transport portable state; never interpret harness formats.
- **Local store:** content-addressed objects, receipts, trust, cache, and machine state.
- **CLI:** presentation and orchestration, not domain rules.

## Domain model

```rust
struct Asset {
    id: AssetId,
    kind: AssetKind,
    source: Source,
    revision: Revision,
    content_hash: ContentHash,
    portable: Option<PortableContent>,
    native_variants: BTreeMap<HarnessId, NativeVariant>,
    compatibility: BTreeMap<HarnessId, FidelityResult>,
    trust: TrustMetadata,
    metadata: AssetMetadata,
}
```

A pack is an aggregate asset with child capabilities and one lifecycle identity. Fidelity is categorical plus structured reasons; numeric scores are prohibited until a defensible model exists.

## State separation

### Portable state

May leave the machine:

```text
kitrove.toml
kitrove.lock
assets/
profiles/
portable metadata
native variants intentionally included in the environment
```

### Local state

Never synchronized by default:

```text
machine identity
active profile
local paths
secret-binding resolvers
authentication observations
deployment receipts
trust decisions
cache
scan history
last synchronization revision
```

### Transient state

Staging directories, locks, partial downloads, temporary render output, and process-local resolved secrets. Transient secrets are never serialized.

## Portable core and native variants

```text
asset/
  metadata
  portable/
  native/claude/
  native/codex/
  native/pi/
  native/opencode/
```

Materialization combines target-supported portable content, the target's native variant, and explicit adaptation output. Unsupported native variants remain preserved. Agent Skill native evidence includes the exact source layout, original document name, modes, and bytes. Equal portable projections do not collapse distinct native sources.

## Adapter contract

Conceptual observation policy and bidirectional operations:

```rust
trait HarnessObservationPolicy {
    fn harness(&self) -> HarnessId;
    fn profile(&self, version: VersionObservation) -> PolicyProfile;
    fn roots(&self, context: &RootContext, profile: &PolicyProfile)
        -> Result<Vec<ObservedRoot>>;
    fn discover_unusual_roots(&self, context: &RootContext, profile: &PolicyProfile)
        -> Result<RootHookReport>;
    fn related_roots(&self, context: &RootContext, profile: &PolicyProfile)
        -> Result<Vec<RelatedRoot>>;
    fn decide_candidate(&self, candidate: &CapturedSkillSource, root: &ObservedRoot,
        profile: &PolicyProfile) -> CandidateDecision;
    fn resolve_duplicates(&self, candidates: &[CandidateSummary],
        profile: &PolicyProfile) -> DuplicateDecision;
}

trait HarnessAdapter: HarnessObservationPolicy {
    fn capability_matrix(&self, version: VersionObservation) -> CapabilityMatrix;
    fn plan(&self, request: &MaterializationRequest) -> Result<AdapterPlan>;
    fn render(&self, plan: &AdapterPlan, staging: &Path) -> Result<RenderedOutput>;
    fn validate(&self, output: &RenderedOutput) -> Result<ValidationReport>;
}
```

The shared engine performs inspection. Policy code cannot run a process, access the network, write state, classify ownership, or replace bounded filesystem capture. Production scan supplies an unknown version unless a typed caller provides verified evidence. Rendering occurs in staging. Adapters return structured loss results, never update portable state, never serialize secret values, and never delete unmanaged files.

## Scan and adopt

Scan maps observed resources to capability inventory without mutation. It works without an environment and then reports valid candidates as unmanaged and failures as unknown. With a manifest and validated local receipt view, it emits managed unchanged, managed modified, unmanaged, missing managed, conflicting duplicate, or unknown. It never initializes or repairs state.

Adopt captures an original snapshot and source layout, decomposes the capability, extracts portable content, preserves native content and layout, classifies executable behavior, computes target compatibility, presents a plan, and atomically updates portable state.

## Materialization

Default deployment is receipt-backed atomic copy:

```text
resolve -> render staging -> validate -> compare ownership -> backup -> atomic replace/merge -> receipt -> validate installed
```

Symlink, hardlink, and reflink modes may become optional optimizations. Semantics cannot depend on them.

For Agent Skills, adapter policy selects a documented target layout. Rendered identity covers the target layout, document name, paths, modes, and bytes. Portable equality cannot prove destination ownership.

## Ownership receipts

A destination is managed only when Kitrove proves ownership. Receipt fields include asset ID, harness, scope, destination, source and rendered hashes, prior hash, adapter version, and environment revision. C2 validates receipt identity and shape in a read-only index; C4 creates and updates receipts.

Removal affects only matching owned output or content explicitly reconciled by the user.

## Content-addressed object store

Use BLAKE3 unless ADR-004 changes. Store immutable original snapshots, portable components, native variants, and rollback data under an XDG-compatible local data path.

## Lockfile

Records schema version, asset identity and kind, source specification, immutable resolution, content hash, relevant adapter/schema versions, and deterministic target fidelity. It excludes local paths, credentials, trust decisions, and deployment destinations.

## Synchronization

Initial backends: Git and filesystem directory.

```text
fetch remote
load base/local/remote
merge independent asset components
surface semantic conflicts
commit accepted local state
apply and validate
publish portable result
```

Git conflict markers are a fallback, not the primary user experience.

## Conflict granularity

Prefer asset metadata field, portable component, target-native variant, managed file, then raw text fallback. A portable skill edit and a Claude-native hook edit should merge independently.

## Source resolvers

Distinct from sync backends. Initial sources: local directory, Git repository, Git subdirectory, and later reviewed HTTP archives. Resolve moving sources to immutable content before lock updates.

## Secret bindings

Portable state names a logical binding. Machine-local state maps it to an environment variable, command, or later OS credential store. Resolved values are transient and redacted.

## Trust architecture

Classify content as data-only, agent-active, or executable. Trust may target exact hash, immutable revision, repository, or a future verified publisher. Trust decisions remain local by default.

## Transactions and recovery

Adopt, apply, sync, upgrade, and rollback use staging, durable operation records, atomic renames where available, recoverable backups, and explicit Windows tests.

## Extensibility

Tier-one adapters are compiled in. Later extensions may use declarative adapters or WASM Components. Native Rust dynamic-library ABI is not planned.

## Architecture proof sequence

1. Directory skill scan/adopt/apply across four harnesses plus standalone scan/adopt and policy-selected target rendering for Pi and verified OpenCode V2.
2. Two-machine synchronization and reverse edit.
3. Pack identity with multiple portable components.
4. Native-variant preservation.
5. Conflict between portable and native components.
6. Executable-content trust gate.
7. Windows receipt-backed materialization.
