# ADR-0019: Semantic merge requires component provenance

- **Status:** Accepted for Gate D D1 implementation
- **Date:** 2026-08-25
- **North Star invariants:** NS-03, NS-04, NS-05, NS-07, NS-10
- **Amends when accepted:** ADR-0015, ADR-0016, ADR-0017

## Context

Gate C records one `Asset.source` and `Asset.revision` for a complete adopted asset. Its portable object and origin-native variant are both derived from that observation, so asset-level provenance is sufficient before semantic merge.

Gate D must be able to merge an independently changed portable component with an independently changed harness-native variant. Keeping only one side's asset-level source and revision would silently misattribute the other component. Independently merging stored compatibility, content class, bindings, or the complete asset hash could also retain results derived from a different combination of bytes.

No released Kitrove version writes schema version 1, so Gate D may refine that unreleased schema before public compatibility is promised.

## Decision

Every content-bearing asset component carries a reference to immutable component provenance.

The portable asset record gains a sorted provenance map keyed by a versioned `ProvenanceId`. A provenance record contains:

- the harness-neutral `Source`;
- the immutable source or observation `Revision`;
- the exact captured source hash; and
- the origin harness and scope when the source is a harness observation.

`ProvenanceId` is serialized as `provenance:blake3:<lowercase digest>`. The digest uses the versioned binary frame `kitrove-component-provenance-v1\0`, followed by the complete `Source` using the source tags and length-prefixed text records defined by ADR-0015, the immutable revision, the exact captured source hash, and an optional origin-scope tag. Harness sources require an origin scope; local and Git sources reject one. A map-key mismatch, collision with different content, unreferenced record, or missing reference is invalid.

`PortableContent` and every `NativeVariant` reference one provenance record. Initial adoption creates one record shared by the portable projection and origin-native variant. Explicit update adoption creates a new record for changed components and retains any prior record still referenced by an unchanged component.

Semantic merge treats a content component plus its provenance reference as one indivisible value. Provenance maps union by ID only after equality validation. After merge, Kitrove removes unreferenced provenance records and deterministically orders the remainder.

The Gate C asset-level `source` and `revision` fields are replaced by the provenance map in the unreleased version-1 schema. The complete `Asset.content_hash` envelope becomes `kitrove-asset-revision-v2\0` before Gate D writes the new form, and its fixed vectors must distinguish every provenance field and component reference. A generated locked asset records the complete asset hash, optional portable provenance reference, native provenance references keyed by harness, the referenced provenance map, and derived compatibility. It does not invent a second source or revision. Packs retain their Gate B lock representation until their later lifecycle gate.

> **Gate F amendment:** ADR-0026 advances the complete asset envelope to `kitrove-asset-revision-v3\0` so tagged binding and executable-trust blocked requirements are framed without ambiguity. Version 3 otherwise retains the component-provenance structure accepted here.

Compatibility, content class, required bindings, and the complete asset hash are derived values. They are never selected independently from base, local, or remote. After authored components merge, Kitrove:

1. verifies every referenced portable and native object;
2. recomputes credential and executable risk;
3. recomputes required binding declarations supported by the skill slice;
4. reruns the compiled tier-one compatibility evaluator for all four harnesses;
5. reconstructs and validates the asset;
6. recomputes `Asset.content_hash`; and
7. derives the lockfile from the complete merged manifest.

If any derived value cannot be recomputed under current evidence, the result is `Blocked` or a structured merge conflict. Kitrove never carries forward stale derived success.

## Consequences

- Component merge retains exact provenance rather than choosing one asset-level origin.
- Gate D D1 includes an unreleased schema and asset-identity refinement before snapshot or merge implementation.
- Existing Gate C adoption, persistence, fixtures, receipts, and lock derivation require coordinated migration in the development branch.
- Deployment receipts continue to bind the complete asset revision hash; a changed provenance record therefore cannot reuse old ownership authority silently.
- Future packs may reuse provenance records but are not made mergeable by this ADR.

## Validation

- Portable and native components from different observations retain distinct provenance after merge.
- Changing source, revision, exact source hash, origin harness, or scope changes `ProvenanceId` and complete asset identity.
- Missing, mismatched, colliding, and unreferenced provenance records are rejected.
- Derived fidelity and risk are recomputed from the merged object combination.
- Portable serialization and every redacted output omit absolute machine paths, receipts, authentication, trust decisions, and secret values.

## Rejected alternatives

- **Keep one asset-level source after component merge:** silently misattributes at least one component.
- **Store merge parents only:** proves ancestry but not which source produced each surviving component.
- **Treat compatibility and content class as mergeable authored fields:** can retain stale or unsafe results for a new byte combination.
- **Defer provenance until Gate F:** Gate D would already permit silent provenance loss.
