# ADR-0015: Versioned asset revision identity

- **Status:** Accepted for Gate C3 implementation
- **Date:** 2026-08-24
- **North Star invariants:** NS-03, NS-05, NS-07, NS-10

> **Gate D amendment:** ADR-0019 replaces this asset-level version-1 frame with `kitrove-asset-revision-v2\0`, component provenance records, and per-component provenance references. This ADR remains the historical Gate C contract and the framing convention inherited by version 2.

## Context

Gate B gives every `Asset` a `content_hash`, while C1 and C2 define separate hashes for captured source trees, portable trees, and rendered targets. Those identities are deliberately not interchangeable. Before C3 writes an adopted asset, Kitrove needs one deterministic identity for the complete manifest asset revision so receipts, lock derivation, conflict checks, recovery journals, and later synchronization cannot overlook a changed portable object, retained native variant, fidelity result, source revision, content classification, or binding requirement.

Hashing serialized TOML would couple identity to presentation and would include the `content_hash` field itself. Reusing a portable or exact-source object hash would silently omit other revision-bearing fields.

## Decision

`Asset.content_hash` is derived from the versioned binary frame `kitrove-asset-revision-v1\0`. The frame excludes only the `content_hash` field itself and encodes, in order:

1. asset ID and kind;
2. complete declared source and immutable revision;
3. optional portable format, root, and object hash;
4. every native variant, ordered by harness ID, including format, root, object hash, and content class;
5. every target fidelity result, ordered by harness ID, including category, ordered reasons, ordered evidence, ordered blocked requirements, adapter version, and optional harness version;
6. aggregate content class; and
7. ordered required binding names.

Enums use explicit one-byte tags. Optional values use a one-byte absence/presence tag. Strings use an unsigned 64-bit big-endian byte length followed by exact UTF-8 bytes. Collections use an unsigned 64-bit big-endian item count. Ordered maps and sets retain their validated canonical order; fidelity vectors retain their persisted order in version 1.

The result is `blake3:<lowercase digest>`. Manifest validation recomputes every asset revision and rejects a mismatch. C3 constructors may assemble a candidate with a temporary value only inside the crate, then compute the final hash before returning a persistable asset. Deserialization cannot make an arbitrary hash authoritative.

This identity is distinct from:

- exact source identity (`kitrove-skill-source-v1`), which covers native layout, paths, modes, and bytes;
- portable object identity, which covers one portable tree;
- native variant object identity, which covers one retained native tree; and
- rendered destination identity, which covers one target representation.

## Consequences

- Any complete asset-revision change invalidates receipts and lock records that name the prior revision.
- Equal portable projections may still have different asset revisions because retained native evidence, provenance, fidelity, or bindings differ.
- Two asset IDs with otherwise equal fields have different revision hashes; renaming is an explicit new identity.
- The public schema remains version 1, but previously hand-authored placeholder hashes no longer pass manifest validation. The schema is unreleased.
- Packs require their own reviewed complete-revision frame before C3 writes or updates a pack.

## Security impact

The frame contains portable metadata already admitted by validated schemas. It never includes machine paths, receipts, trust decisions, resolved binding values, authentication state, transient version observations, or captured secret values. Error messages report only the asset ID and mismatch code, not authored field contents.

## Validation

- A fixed complete asset produces a golden hash.
- Repeated computation and different map insertion orders produce the same hash.
- Mutating each included field changes the hash.
- Mutating only `content_hash` does not change the recomputed expected value, but manifest validation rejects the stored mismatch.
- Portable and native object hashes cannot substitute for the asset revision hash.
- Manifest parsing and serialization reject mismatched asset revisions without echoing authored values.
