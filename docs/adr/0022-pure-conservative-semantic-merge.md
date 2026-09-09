# ADR-0022: Semantic merge is pure, component-aware, and conservative

- **Status:** Accepted for Gate D D1 implementation
- **Date:** 2026-08-26
- **North Star invariants:** NS-02, NS-03, NS-04, NS-05, NS-06, NS-07, NS-09, NS-10

## Context

Gate D must combine independent portable and harness-native changes without selecting stale derived state, losing component provenance, executing received content, or allowing a backend to decide semantics. A merge that trusts stored content classes or compatibility results can silently upgrade a new byte combination. A merge that returns partial authority alongside conflicts can be mutated accidentally.

## Decision

`merge_manifests` is a pure three-way operation over validated base, local, and remote manifests plus a content-addressed catalog of already decoded immutable Agent Skills objects and the complete tier-one capability catalog. It performs no filesystem, network, process, adapter-policy, clock, environment, or local-state access.

Existing assets merge by stable ID and authored component. Asset kind, portable content plus provenance reference, and each native content plus provenance reference keyed by harness use ordinary three-way rules. Equal concurrent changes coalesce; one-sided changes win; divergent changes conflict. A selected component resolves its content-addressed provenance record from the three inputs, and the result prunes every unreferenced record. Stored compatibility, asset content class, native content class, required asset bindings, complete asset hash, and lock state are never selected as merge components.

For the accepted Agent Skills slice, derivation rereads verified portable and native object bytes. Portable `SKILL.md` must parse as strict standard Agent Skills content without native-only fields. Credential-shaped artifacts, private-key markers, malformed or secret-shaped metadata, and invalid native documents block derivation with compiled redacted errors. Portable and every native content class are recomputed; the aggregate asset class is their maximum. The current slice derives no asset binding declarations.

Compatibility is regenerated for all four tier-one harnesses from the compiled capability catalog and selected objects. A selected harness-native object is `Native`. A portable representation is `Portable` only when every retained native payload tree is byte-and-mode identical to it. Otherwise it is conservatively `Partial` with `sync.native_difference`; this prevents layout normalization or native extensions from being silently upgraded to exact equivalence. A target without either a native or portable representation is `Unsupported`. The complete asset hash is refreshed and `kitrove.lock` is generated from the validated merged manifest.

Base-present asset, portable-component, native-component, pack, or profile removal returns `sync.deletion_unsupported`. Changed packs and profiles return `sync.component_unsupported`; non-skill asset kinds and unsupported object formats do the same. Top-level required-binding membership uses ordinary three-way set rules. Identical concurrent additions coalesce only when complete asset identity is equal; different additions conflict.

Manifest components, decoded object count, individual and aggregate decoded object bytes, and conflicts are bounded by `SyncLimits`. Conflicts are sorted by typed identity, component rank, harness, and code and contain no authored bytes. A conflicted result contains neither a merged manifest nor a lockfile. Missing verified objects or failed derivation are redacted terminal errors rather than conflicts or inherited success.

## Consequences

- Independent portable and native changes retain their exact distinct provenance.
- Derived risk and fidelity may become more conservative after merge, but never silently more permissive without byte evidence.
- Conflict planning is deterministic and non-mutating; no partial portable authority is exposed.
- Packs, profiles, deletion, non-skill assets, and richer binding declaration extraction remain explicit later gates.
- Backend implementations can transport inputs and outputs but cannot influence reconciliation.

## Validation

- Independent portable and native changes merge while retaining only their selected provenance records.
- Same-component divergence, component deletion, changed packs, and differing additions return typed non-mutating conflicts.
- Conflict ordering and conflict-limit refusal are deterministic.
- Native execution fields recompute both native and aggregate executable risk.
- Stored derived values are replaced, lock state is regenerated, and missing objects block derivation.
- Secret-shaped native metadata is rejected without entering errors or debug output.

## Supersession

This ADR is superseded only by a reviewed merge version that preserves pure three-way ancestry, component provenance, derived-state recomputation, conflict-before-authority, and conservative fidelity.
