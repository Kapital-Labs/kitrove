# ADR-0007: Packs Are First-Class Assets

- **Status:** Accepted
- **Date:** 2026-08-22
- **North Star invariants:** NS-05

## Context

Real distributions may bundle skills, agents, commands, hooks, and extensions. Flattening them destroys provenance and lifecycle coherence.

## Decision

A pack is an aggregate asset with stable identity, child capabilities, source resolution, trust, compatibility, upgrade, removal, and rollback semantics.

## Consequences

Conflict and fidelity reporting must support both pack-level summary and component-level detail.

## Validation

The Gstack stress test must operate on one pack identity while preserving component fidelity.

## Gate E amendment: complete aggregate revision identity

Gate B's placeholder pack record stored only member IDs and reused the content hash as the resolved source hash. That shape cannot prove one lifecycle revision: a member can change while the pack identity remains unchanged, and the generated lock cannot bind the exact member revisions. Gate E replaces that ambiguity before any pack lifecycle command writes portable state.

A persisted pack has two distinct hashes:

- exact_source_hash identifies the captured bytes of the pack distribution before decomposition; and
- content_hash is framed as kitrove-pack-revision-v1, the complete aggregate lifecycle revision.

Direct membership is an ordered map from AssetId to the referenced member's complete content_hash, not a set of names. The map order is canonical serialization order only; member execution or materialization order is not implied. A later ordered workflow requires a separately reviewed field and identity-frame revision.

The complete pack revision binds:

1. pack ID;
2. source declaration, immutable revision, and exact source hash;
3. every direct member ID and exact complete member revision;
4. aggregate target compatibility;
5. aggregate content class; and
6. aggregate symbolic binding requirements.

Manifest validation requires every member reference to exist and match the referenced asset or nested pack revision. Packs are non-empty and acyclic. Nested pack identities are therefore a bounded directed acyclic graph of exact revisions rather than name aliases.

Content class is the maximum class of every direct member. Symbolic binding requirements are the exact union of direct members. Per-target pack fidelity is a deterministic lower-bound summary over member fidelity while each member's complete result remains authoritative detail. The summary order is Native, Portable, Adapted, Partial, Unsupported, then Blocked; a missing member result is Unsupported. A summary never upgrades a weaker member, and every non-exact summary carries a compiled pack reason. Blocked requirements are the union of blocked member requirements. Pack aggregation uses its own compiled adapter/evidence identity and never copies authored evidence into public diagnostics.

The generated lock records the aggregate pack hash, exact source resolution, and exact member revision map. It must reject a member revision mismatch even when names and source resolution are unchanged.

Synchronization merges authored pack source resolution and membership semantically. Direct member revision values and all aggregate fields are re-derived from the merged asset/pack graph. Independent member changes and independent additions may merge; same-field source divergence, member replacement divergence, deletion, cycles, missing members, and invalid derived metadata return typed conflicts without merged authority or mutation.

Gate E does not authorize pack setup scripts, member execution, installation order, removal, rollback, upgrade fetching, executable trust, or general package management. A pack containing executable members remains portable and synchronizable but blocked from materialization until the later trust workflow. Unmodeled source files are not silently claimed as captured pack content.
