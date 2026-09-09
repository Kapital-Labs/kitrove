# ADR-0021: Portable snapshots are canonical derived envelopes

- **Status:** Accepted for Gate D D1 implementation
- **Date:** 2026-08-26
- **North Star invariants:** NS-03, NS-05, NS-06, NS-07, NS-10

## Context

Synchronization transports portable authority across hostile storage and backend boundaries. A receiver must not accept alternate manifest encodings, an independently authored lockfile, an incomplete object catalog, or a digest that omits authority-bearing fields. Backend evidence and machine-local state must not enter the portable snapshot.

## Decision

`PortableSnapshotV1` is an authority-free core value constructed from a validated `EnvironmentManifest`, not from filesystem traversal. Its canonical JSON contains schema version 1, canonical `kitrove.toml` text, the derived manifest revision, canonical generated `kitrove.lock` JSON, the lock byte digest, a sorted exact object descriptor catalog, and the complete snapshot digest.

The generated lock is always re-derived from the parsed manifest and compared for exact typed and canonical-byte equality. The manifest revision and lock digest are recomputed. Every portable and native object reference in the manifest must have exactly one descriptor with matching kind, root, and object hash; missing, extra, mismatched, duplicate, oversized, and aggregate-overflow descriptors are rejected. Object payload bytes are not embedded in this control envelope and remain subject to independent immutable-envelope verification before merge or persistence.

The snapshot digest uses the binary frame `kitrove-portable-snapshot-v1\0`. It hashes, in order, the canonical manifest bytes, manifest revision, canonical lock bytes, lock digest, descriptor count, and each sorted descriptor. Text values use an unsigned 64-bit little-endian byte length followed by exact UTF-8 bytes. The descriptor count and encoded length are unsigned 64-bit little-endian values; object kinds use fixed byte tags `1` for portable skill trees and `2` for native skill objects. The digest is serialized as `snapshot:blake3:<64 lowercase hexadecimal digits>`.

Strict verification applies caller-supplied `SyncLimits` before accepting control, manifest, lock, object, or component counts. It rejects unknown fields and any outer JSON, embedded manifest, or embedded lock encoding that differs from Kitrove's canonical serializer. Verification failures use compiled codes and messages; `Debug` reports only byte and object counts.

## Consequences

- Backends transport one deterministic control document and cannot supply generated state as independent authority.
- Semantically equal but noncanonical transport bytes are refused instead of creating multiple snapshot identities.
- Snapshot equality includes descriptor encoded lengths, so reviewed transfer budgets cannot be changed without changing identity.
- Immutable payload fetching and verification can be implemented separately without changing the snapshot control schema.
- Any future object kind, hash framing, or envelope representation requires an explicit new snapshot schema and digest frame.

## Validation

- A checked-in manifest fixture has a fixed complete snapshot digest vector.
- Manifest changes and descriptor-length changes alter the snapshot digest.
- Forged manifest revisions, generated locks, lock digests, snapshot digests, and noncanonical encodings are rejected.
- Missing, extra, mismatched, duplicate, and over-budget descriptors are rejected.
- Unknown-field and malformed-input canaries never enter errors or structural debug output.

## Supersession

This ADR is superseded only by a reviewed snapshot schema version that preserves manifest authority, derived lock state, complete object coverage, refusing limits, and redacted verification.
