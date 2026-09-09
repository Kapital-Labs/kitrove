# ADR-0018: Semantic synchronization uses a machine-local base

- **Status:** Accepted for Gate D D1 implementation
- **Date:** 2026-08-25
- **North Star invariants:** NS-02, NS-03, NS-05, NS-06, NS-07, NS-10

## Context

Gate C establishes deterministic portable authority, immutable portable and origin-native objects, complete asset revision identity, and machine-local deployment receipts. Gate D must synchronize that state across machines without making Git the product workflow, merging generated lock records as desired state, moving local identity or secrets, or silently choosing a winner when both machines change the same semantic component.

A two-way comparison cannot distinguish a local deletion from an asset that never existed, or an unchanged side from a concurrent edit. Backend revision IDs are transport evidence, not semantic merge bases, and cannot replace a retained Kitrove snapshot.

## Decision

Kitrove synchronization is a three-way semantic reconciliation over a validated `base`, `local`, and `remote` portable snapshot.

The last accepted base is machine-local and keyed by a hash of backend kind plus remote identity. It retains the canonical manifest snapshot, referenced immutable object identities, and the last accepted opaque backend revision. It contains no credentials, authentication state, deployment receipts, trust decisions, resolved bindings, machine paths from harness state, or secret values.

A sync backend transports and conditionally publishes portable snapshots. It does not interpret manifests, merge assets, run adapters, resolve sources, apply harness output, or decide conflicts. The initial backend contract supports:

- read with an opaque revision;
- fetch of immutable objects referenced by the snapshot;
- compare-and-swap publication against the observed revision; and
- recovery-safe inspection of a previously published snapshot.

The manifest is the only desired-state authority. Kitrove validates every received manifest and referenced immutable object, performs semantic merge, recomputes complete asset hashes, validates the merged manifest, and regenerates the lockfile. The lockfile is transported for reproducibility checks but is never merged as authority.

Merge is deterministic and component-aware:

- independent asset IDs merge independently;
- an asset portable component and native variants keyed by harness merge independently;
- portable content and native variants carry component provenance under ADR-0019 and merge with that provenance as one value;
- authored component changes merge independently only when their retained provenance remains exact;
- compatibility, content classification, required bindings, complete asset identity, and generated lock state are recomputed from the verified merged content rather than merged as independent authority;
- asset kind and any non-derived metadata remain explicit components;
- identical concurrent changes coalesce;
- one-sided changes relative to the base win;
- divergent changes to the same component produce a structured conflict; and
- the complete merged asset identity is recomputed only after all components merge.

Gate D initially blocks asset, pack, and profile deletion with an explicit unsupported conflict. Deployment removal is not yet implemented, so propagating absence would strand local receipts or disguise lifecycle loss.

Any conflict, invalid snapshot, missing or corrupt object, stale local precondition, or failed compare-and-swap leaves the local portable environment, local sync base, harness destinations, and remote snapshot unchanged. A conflict is data returned by the plan; conflict markers never enter canonical portable state.

Sync apply publishes the reviewed merged snapshot conditionally only after the exact local commit and base artifacts are fully staged and a durable journal exists. Successful compare-and-swap publication is the distributed commit point: failures before it are non-mutating, while failures after it return `sync.recovery_required` and must roll forward the exact staged local snapshot and base. A durable local journal progresses through `Prepared`, `RemotePublished`, `LocalCommitted`, and `BaseCommitted`. Recovery never re-merges against unreviewed bytes. If another machine advances the remote after publication, the published snapshot remains the new local base and the later remote revision is handled by the next sync.

Reverse edits remain explicit. Updating an existing managed asset requires a fresh scan, exact expected prior asset revision, reviewed fidelity and loss results, and confirmation. Sync never infers a local harness edit from deployment bytes and never turns an unmanaged destination into portable authority.

## Consequences

- Filesystem and Git backends share one semantic merge engine and conflict format.
- Backend credentials and repository paths remain local configuration.
- Git history and refs can provide transport concurrency but not merge semantics.
- Sync planning is read-only and non-executing; received executable content stays preserved and blocked by the existing trust boundary.
- Local portable commit, base update, and remote publication require a dedicated recoverable transaction.
- A post-publication local failure cannot promise remote rollback; it is a committed, recoverable operation rather than a failed non-mutating plan.
- Automatic deletion and automatic conflict resolution are deferred rather than approximated.

## Validation

- Machine A adopts and publishes; machine B receives and applies without raw Git commands.
- Machine B explicitly adopts a reverse edit and publishes; machine A receives the new revision.
- Independent portable and native-variant edits merge without loss.
- Same-component divergence returns a stable conflict and mutates neither side.
- Remote compare-and-swap failure is non-mutating locally.
- Every journal phase recovers deterministically on Linux, macOS, and Windows.
- Secret canaries, local receipts, machine IDs, authentication state, and resolved bindings never enter a transported snapshot, conflict, log, or backend command argument.

## Rejected alternatives

- **Use Git merge as the semantic engine:** violates backend separation and exposes raw Git conflict UX.
- **Last writer wins:** silently loses capability behavior and provenance.
- **Two-way merge without a retained base:** cannot distinguish independent change, deletion, and concurrency safely.
- **Synchronize local state:** violates the portable/local boundary and risks credential movement.
- **Merge lockfiles:** creates a second desired-state authority.
