# ADR-0011: Authoritative manifest and generated lockfile

- **Status:** Accepted
- **Date:** 2026-08-22
- **North Star invariants:** NS-05, NS-06, NS-10

## Context

Gate B defines strict `EnvironmentManifest` and `Lockfile` schemas but does not decide which document controls desired state, how Kitrove derives one from the other, or how a transaction recovers when a crash separates their writes.

Treating both documents as authorities would create ambiguous drift and unsafe synchronization. Trusting a copied manifest hash inside a lockfile would not detect a coordinated or accidental change to both the lock body and that copied value.

## Decision

`EnvironmentManifest` is Kitrove's portable desired-state authority. `Lockfile` is a deterministic, generated, and repairable projection of the manifest's immutable source resolutions and compatibility evidence.

Kitrove derives the expected lock structure and compares it in full with the stored lockfile. Version 1 does not require a manifest-hash field.

The environment revision is `manifest:blake3:<digest>`, derived from the deterministic UTF-8 serialization of the complete validated manifest. Journals and deployment receipts use this recomputable revision; Kitrove never trusts a copied revision without deriving it again.

A portable mutation commits in this order:

1. content referenced by the proposed manifest;
2. the authoritative manifest;
3. the generated lockfile.

A local recovery journal records old and new root identities before the authority commit. If a crash occurs before the manifest write, staged or unreferenced content has no authority. If a crash occurs after the manifest write and before the lock write, Kitrove reports lock drift and regenerates the lock. The lock never commits ahead of its manifest.

Synchronization will merge manifest assets and independently addressable components, validate the merged manifest, and regenerate the lockfile. A sync backend transports both files but does not interpret or merge lock records as desired state.

## Consequences

- Users can repair or regenerate a missing or corrupt lock without changing desired state.
- Status must compare the complete expected and stored lock structures and verify referenced content.
- Lock comparison covers the manifest-derived `LockedAsset` and `LockedPack` projection. Portable-core and native-variant objects are verified independently against identities in the manifest because the Gate B lock schema does not duplicate those roots.
- Portable mutations need a lock, staging, an ordered commit, and recovery evidence.
- Lockfile hand edits have no authority and will appear as drift.
- Future schema changes must define migration for both documents and preserve the authority relationship.

## Validation

- Equivalent manifests produce byte-identical lockfiles.
- A changed lock field produces drift even if other copied identity fields match.
- A corrupt portable or native object fails independent manifest-object verification even when the structural lock matches.
- A missing lock regenerates without changing the manifest.
- A crash before manifest commit leaves desired state unchanged.
- A crash after manifest commit and before lock commit recovers by deriving the lock.
- Sync tests merge manifest components and regenerate the lock rather than merging lock text.
