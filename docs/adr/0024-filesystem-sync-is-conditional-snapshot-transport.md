# ADR-0024: Filesystem synchronization is conditional snapshot transport

- **Status:** Accepted for Gate D D3 implementation
- **Date:** 2026-08-27
- **North Star:** NS-02, NS-03, NS-05, NS-06, NS-07, NS-09, NS-10
- **Invariants:** INV-02, INV-03, INV-05, INV-07, INV-08, INV-09, INV-11, INV-12

## Context

D1 provides canonical portable snapshots, bounded local-base records, verified immutable object catalogs, and pure conservative three-way merge. D2 provides the only reverse-edit mutation authority. D3 must move those snapshots and objects between two isolated machine states without turning the filesystem backend into a semantic authority, copying machine-local state, guessing ancestry, or allowing a stale writer to replace a newer remote snapshot.

A filesystem directory is hostile shared state. Its entries may be links, reparse points, special files, aliases, partial writes, or concurrently replaced objects. Checking a pointer and replacing it in separate unlocked operations would make conditional publication a last-writer-wins race. Naming a remote revision only by snapshot digest would also permit an ABA publication to evade change detection.

## Decision

### Transport boundary

D3 introduces a sealed core `SyncBackend` contract whose operations exchange only:

- a validated canonical `PortableSnapshotV1` envelope;
- exact `ObjectDescriptor` values and verified portable or native object envelopes;
- a bounded opaque `RemoteRevision`;
- a bounded opaque `PublicationIntent` plus a typed `PublicationStatus`; and
- stable structural backend errors.

The backend has no asset, manifest-merge, receipt, trust, binding-resolution, adapter, materialization, or conflict-resolution method. Planning and semantic merge remain in core. The first implementation is a caller-selected filesystem directory; D4 may implement the same contract with Git after a separate review.

After core has produced a verified staged snapshot, the backend's mutation-free deterministic `prepare_publication(expected, publication_id, snapshot)` returns the exact opaque intent that must be persisted before publication begins. `publish(intent, snapshot)` conditionally executes only that intent. `reconcile(intent)` returns only `Published(revision)` when positive backend-private evidence proves the exact intent is selected, `Ready` when the exact expected authority is current and the same intent may be retried, or `Uncertain`; it never reports non-publication after an attempt may have begun. Intent decoding, validation, history walking, and retry remain backend-private, bounded operations, so core neither constructs filesystem heads nor depends on their layout. The intent has strict canonical persistence owned by the backend, exact equality, a redacted `Debug`, and no renderer.

The sealed contract also exposes an exclusive apply session. Core acquires it only after the local environment and local sync-state locks, then performs remote reinspection, any bounded fetch needed for exact revalidation, intent preparation, journal durability, and the one publish or reconcile attempt through that same session. The filesystem implementation owns the lock handle and verified directory capability for the session lifetime. Read-only planning does not create an apply session or backend files.

### Filesystem remote layout

The verified remote root contains only this versioned backend layout:

```text
.kitrove-sync/
  lock
  current.json
  heads/<generation>-<head-hex>.json
  snapshots/<snapshot-hex>.json
  objects/<portable object root...>
  staging/<publication-id>/...
```

Each immutable head record is strict canonical JSON containing schema version 1, a caller-chosen publication ID derived from the confirmed plan digest, an unsigned generation, the selected snapshot digest and filename, and the exact prior head path, generation, and `RemoteRevision`. The initial head binds the compiled absent token and has no predecessor path; every successor generation must equal the prior generation plus one. A head filename is derived from its generation and the digest of its complete canonical bytes, and validation requires the stored predecessor path to equal the filename derived from the bound predecessor generation and revision. `current.json` contains only the selected head path and its revision. The filesystem `RemoteRevision` is a versioned digest of the complete head record; the absent state has a separate compiled revision token. Because every head binds an exactly locatable predecessor and generation, publish A -> B -> A does not recreate the earlier revision and recovery never enumerates the hostile `heads/` directory to guess ancestry.

The selected heads form an append-only authenticated chain. A staged but never selected head is not publication evidence. If a process loses the publication acknowledgement and a later writer advances the remote, recovery can walk the bounded immutable head chain from `current.json` to determine whether the exact journal-bound publication was selected. D3 extends the unreleased `SyncLimits` with a non-zero `max_backend_history` budget, charges every decoded head and its control bytes to the one request-global meter, and refuses before following a head beyond that budget. A broken, cyclic, over-budget, aliased, or missing chain is uncertain and blocks recovery without discarding evidence.

Snapshot files and object envelopes are immutable. Their complete typed identity, canonical encoding, declared byte length, and content hash are verified before installation. An existing exact object is reused; an existing different or malformed object at the same root blocks publication. D3 never overwrites an immutable snapshot or object with different bytes.

### Safe access and conditional publication

The backend opens one verified directory capability rooted at the caller-selected remote and performs all later access relative to it. Every ancestor and entry must be an ordinary directory or regular file as appropriate. Symlinks, Windows reparse points, special files, traversal, device/UNC ambiguity, non-portable aliases, and identity changes between inspection and open are refused without following the replacement.

Inspection is mutation-free. It takes a shared lock only when an initialized backend lock already exists; an absent remote is inspected without creating files. Snapshot and object fetches remain bound to the inspected revision, and planning revalidates the exact pointer after all fetches so any concurrent publication refuses the plan. Publication creates or opens the backend lock as part of the authorized apply operation and holds it exclusively for the complete compare-and-swap sequence, then:

1. re-reads and validates the current pointer;
2. requires its exact revision to equal the caller's expected revision;
3. stages and verifies every missing immutable object, the complete snapshot, and the deterministic successor head beneath the publication-ID directory derived from the confirmed plan digest;
4. installs immutable entries without replacement;
5. installs and syncs the immutable successor head; and
6. atomically replaces `current.json` using the existing identity-bound guarded control-file mutation boundary.

The pointer replacement is the remote publication commit point. The exclusive lock serializes cooperating writers; the identity-bound replacement also refuses an uncooperative change between pointer validation and replacement. A stale expected revision returns `sync_backend.remote_stale` without changing the pointer. A crash before pointer replacement leaves only an unselected successor head plus unreferenced exact staging or immutable content; those are not evidence of publication. A crash after pointer replacement is provable from the selected head chain even if the caller never received the acknowledgement or a later writer has advanced the pointer. Backend recovery removes only staging whose digest and filesystem identities it can prove. Generation overflow blocks publication.

### Local key and retained base

The filesystem remote path is normalized only inside the backend and hashed with the framed backend kind to derive `RemoteKey`; the path never enters a plan, journal, error, debug, text, or JSON surface. Local synchronization state uses the accepted D1 layout beneath the machine-local state root:

```text
sync/<remote-key>/
  base-current.json
  bases/<base-generation-id>/
    base.json
    base-manifest.toml
    objects/...
  journal.json
  staging/...
```

The retained base is one immutable, complete generation: base record, exact canonical base manifest, and every descriptor-named object needed to reproduce the base merge input. Its `base-generation-id` is a domain-separated digest of the complete canonical base record, including both snapshot identity and exact opaque backend revision, so recurrence of the same snapshot at a later generation cannot alias an earlier base. `base-current.json` binds and selects that full generation identity and is the only mutable base authority; it is replaced only after the complete generation verifies. A partial, mismatched, unselected, or noncanonical base blocks planning rather than degrading to bootstrap. This refines the unreleased D1 illustrative layout so a base update has one control-file commit point on every supported platform.

### Planning and bootstrap

`kitrove sync plan --filesystem <root>` is read-only. It validates the exact local manifest, generated lock, referenced objects, local base, remote pointer, remote snapshot, and fetched remote/base objects under one request-global `SyncLimits` meter. It then applies only the D1 bootstrap rules or pure semantic merge. A plan binds exact local manifest and lock bytes, local snapshot digest, base digest and backend revision, remote revision and snapshot digest, merged snapshot digest, transfer sets, conflicts, and a stable plan digest.

With no base, only these states plan successfully:

- remote absent: publish the non-empty validated local snapshot;
- local manifest empty and remote present: receive the validated remote snapshot; or
- local and remote snapshots identical: establish the base without changing portable authority.

Distinct non-empty local and remote snapshots return `sync.bootstrap_ambiguous`. Conflicts and blocked plans are renderable but cannot be confirmed and create no journal or staging.

`kitrove sync apply --filesystem <root> --confirm <plan-digest>` recomputes the plan from fresh inputs and requires the supplied digest. It then acquires locks in the fixed order: local environment, local sync state, filesystem backend apply session. Remote reinspection and complete precondition revalidation occur through that session after all locks are held and before staging or intent preparation.

### Distributed transaction and recovery

The durable local journal contains only typed digests, phases, generation/revision evidence, the exact bounded opaque backend-owned publication intent, digest-derived relative staging paths, and compiled categories. It never contains the remote path, authored content, native IDs, receipt destinations, object bytes, or secret-shaped values. `Prepared` durably binds the exact prior remote revision, publication ID, canonical publication intent, proposed successor revision, and proposed generation before the backend may stage or publish anything.

The phases are:

1. `Prepared`: the exact merged snapshot, required objects, prior local authority hashes, prior base hashes, proposed immutable base generation, and deterministic publication intent are durably staged locally.
2. `Publishing`: the intent is durable and backend publication may be in progress; no absence of an acknowledgement is treated as proof of non-publication.
3. `RemotePublished`: recovery or the original caller proved the successor head is in the selected remote chain, and the proposed revision is durable in the journal.
4. `LocalCommitting`: the existing portable transaction may be in progress.
5. `LocalCommitted`: the portable transaction recovered or committed all immutable objects, manifest, and generated lock, and exact merged authority verifies.
6. `BaseCommitting`: the complete immutable base generation is installed and `base-current.json` may be in replacement.
7. `BaseCommitted`: the selected complete base generation names the published snapshot and revision.
8. `Complete`: all identities verify; journal and staging may be removed.

Recovery in `Prepared` may discard only before `Publishing` is durable. Once `Publishing` is durable, recovery never interprets absence from the selected chain as proof that publication never occurred: a noncooperating writer could have selected the proposed head and later selected an alternate valid branch. Core asks the backend to reconcile only the exact journal-bound intent:

- `Ready` permits recovery to idempotently resume the same journal-bound conditional publication; it does not discard evidence;
- `Published(revision)` proves the exact proposed successor is current or is contained by its valid selected successor chain and advances recovery to `RemotePublished`; and
- `Uncertain`, including any alternate, divergent, missing, broken, exhausted, or otherwise unproven chain, retains all evidence and returns `sync.recovery_blocked`.

After proven remote publication, recovery only rolls forward from the journal-bound staged snapshot; it never replans, republishes, rewinds a newer remote, or advances a base without first verifying local authority. If exact staged recovery evidence is missing or unknown, recovery blocks without exchanging it into live state.

Local commit delegates to the existing portable object/manifest/lock transaction and its own lower-level journal. D3 recovery completes or reconciles that transaction before marking `LocalCommitted`; it never treats a D3 phase label as proof that every nested replacement finished. Base commit installs one immutable generation and then performs one guarded `base-current.json` replacement under the local sync lock. Recovery classifies every live, staged, and backup control file as exact old, exact new, absent, or unknown; unknown content blocks without exchange. A remote that advances after Kitrove's successful publication remains untouched and appears as a new remote change on the next plan.

## Security and validation requirements

D3 acceptance requires:

- a shared backend contract suite covering absence, exact fetch, immutable reuse, stale publication, ABA resistance, selected head-chain proof, interruption, alias/link/reparse/special-file refusal, aggregate limits, and redacted errors;
- two isolated machine fixtures covering publish, receive, unchanged base establishment, independent semantic merge, bootstrap ambiguity, and conflict without mutation; each machine begins with distinct byte-identifiable machine configuration, receipts, trust, bindings, destinations, and scan history, and its exact `state.json` bytes must remain unchanged through every sync plan, publish, receive, merge, conflict, refusal, and recovery path;
- fault injection immediately before and after successor-head installation, pointer replacement, and the `RemotePublished` journal write, including recovery after a third-party successor advances the selected chain and refusal without evidence loss when a valid alternate branch excludes the proposed head;
- fault injection on both sides of every durable portable control-file replacement, base-pointer replacement, and individual immutable-object installation; tests require exact old/new/absent/unknown reconciliation, no lock ahead of manifest, no base ahead of verified local authority, no hostile staging exchange, and all prior objects intact;
- stale local manifest/lock/object, base, remote pointer, remote snapshot, and fetched-object refusal before unauthorized mutation;
- the explicit per-surface canary matrix below;
- proof that no harness process, capability code, installer, network client, Git command, hook, filter, or received executable is launched; and
- stable and Rust 1.85 canonical validation plus native Ubuntu, macOS, and Windows CI and fresh independent architecture, security, and test review.

### Canary allow/deny matrix

The backend revision is required internal concurrency evidence, while transported objects necessarily contain authored bytes and a native envelope may contain its native identity. Tests therefore use this exact matrix rather than asserting universal absence:

| Surface | Values permitted | Values forbidden |
|---|---|---|
| Portable snapshot JSON | snapshot/manifest/object digests and portable roots | authored content, native ID, absolute or remote path, receipt destination, backend revision, object bytes, secret canary |
| Transport/base immutable object payload | exact authorized authored and native object bytes; bounded hostile received bytes may exist only in untrusted staging while they are classified | absolute source path, remote path, receipt destination, backend revision; local publication refuses credential-classified content, and received credential-classified content never becomes snapshot, local, or base authority |
| Internal typed plan | exact opaque base/remote revisions and structural transfer metadata | remote path, receipt destination, raw object bytes, authored content, native ID, secret canary |
| Persisted base and journal control JSON | exact opaque revisions and publication intent, digests, phases, generation, publication ID, digest-derived relative paths | absolute or remote path, receipt destination, raw object bytes, authored content, native ID, secret canary |
| Debug and error values | structural counts, categories, presence flags, stable codes | every raw canary, including backend revision and publication ID |
| Conflict records | bounded typed asset/component identities and compiled messages | every raw canary, including backend revision and publication ID |
| Human CLI and CLI JSON | operation, disposition, counts, stable codes, plan/snapshot digests, component identities approved by D1 | authored content, native ID, absolute or remote path, receipt destination, backend revision, publication ID, object bytes, secret canary |

Every value marked forbidden is a distinct canary. Internal serialization tests additionally prove that required revision evidence round-trips exactly without appearing through `Debug`, errors, conflicts, or renderers.

## Consequences

- Filesystem synchronization has a real compare-and-swap boundary rather than a check-then-write convention.
- Backend generations make revision evidence ABA-resistant while snapshots remain content-addressed.
- Remote publication precedes local/base commit, so recovery has one explicit distributed commit point and must retain exact staged evidence.
- The filesystem backend transports validated envelopes but cannot choose semantic winners or create reverse-edit authority.
- D3 adds local and remote mutation surfaces and therefore requires focused approval before implementation.

## Rejected alternatives

- **Use snapshot digest as the remote revision:** misses A -> B -> A publication history and weakens stale-writer detection.
- **Compare the pointer without a backend lock:** leaves a race between validation and atomic replacement.
- **Copy the environment directory directly:** transports generated and machine-local state and bypasses snapshot validation.
- **Let the backend merge manifests:** makes transport a semantic authority and duplicates D1 conflict rules.
- **Commit local state before remote publication:** a failed compare-and-swap would leave local authority claiming an unpublished merge.
- **Replan during recovery:** can commit a different merge than the snapshot that crossed the remote commit point.
- **Store authored remote paths in journals or diagnostics:** leaks machine topology and makes backend identity non-portable.
