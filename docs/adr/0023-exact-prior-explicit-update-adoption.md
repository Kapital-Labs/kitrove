# ADR-0023: Explicit update adoption requires exact prior authority

- **Status:** Accepted for Gate D D2 implementation
- **Date:** 2026-08-26
- **North Star invariants:** NS-02, NS-03, NS-04, NS-05, NS-07, NS-09, NS-10

## Context

Gate C can adopt a new Agent Skill or repair the exact same adopted revision. It intentionally blocks a different observation that collides with an existing asset ID. Gate D needs a separate reviewed operation that turns a managed reverse edit into a new portable asset revision without treating discovery, synchronization, or an arbitrary unmanaged source as mutation authority.

An update cannot overwrite the existing portable or native object roots. Those roots retain immutable envelopes, and replacing them would destroy the prior exact native object and invalidate recovery evidence. A managed reverse edit also cannot simply change the manifest: the deployment receipt would continue naming the old desired revision and old rendered bytes, so a later apply could overwrite the edit that the user just adopted.

## Decision

D2 adds an explicit update-adoption form. It is not inferred by scan or sync and is distinct from first adoption and idempotent repair.

Every update requires:

- an existing skill asset ID;
- the exact expected prior `Asset.content_hash` supplied by the user or calling API;
- a fresh accepted observation selected by exact `ObservationId`;
- one typed source authority described below;
- complete current manifest and generated-lock preconditions;
- freshly verified objects for every component retained in the proposed asset;
- a deterministic plan digest and exact confirmation; and
- immediate pre-commit revalidation under the existing environment and local-state lock order.

The expected prior revision must equal the current manifest asset revision. A receipt-backed update additionally requires its receipt `source_hash` and `environment_revision` to match that same current manifest authority. A stale receipt never authorizes a reverse update.

### Typed source authority

The core constructs an update source from a complete classified scan rather than accepting a caller-supplied classification flag.

`ManagedModified` authority requires exactly one accepted observation and exactly one valid receipt-backed scan entry with the same observation, asset, harness, scope, normalized destination, receipt identity, and exact captured source hash. The entry must be `ManagedModified`, not ambiguous, unknown, missing, unmanaged, or merely accompanied by a stale desired-state receipt. The strict machine-local `LocalState` receipt must recompute to the same receipt ID and match the scan evidence.

An explicitly reviewed source is allowed only when the selected accepted observation came from one exact caller-supplied explicit root. It still requires the asset ID, expected prior revision, plan review, and confirmation. It carries no receipt ownership authority and therefore does not rewrite local receipts. An implicitly discovered unmanaged source cannot authorize an update.

### Component replacement and derivation

The update replaces the portable component and the selected harness-native component with newly captured immutable objects and one new component-provenance record. Native components for other harnesses remain exact and retain their original provenance. Any old provenance record still referenced by a retained component survives; other unreferenced provenance is pruned.

Update-created objects use lowercase hash-qualified sibling roots:

```text
assets/<asset-id>/updates/portable/blake3-<64 lowercase hex>
assets/<asset-id>/updates/native/<harness>/blake3-<64 lowercase hex>
```

These paths do not nest beneath the legacy immutable object roots. A repeated exact object may reuse an already verified identical root, but a different object never overwrites an existing root. Prior portable and native objects remain recoverable local content even after they are no longer referenced by current manifest authority.

The current portable projection and selected native object are rebuilt from the fresh observation. Every retained native object is independently verified. The shared conservative derivation path recomputes credential and executable risk, binding declarations supported by the current skill slice, four-harness fidelity, aggregate content class, complete asset identity, and generated lock state. No stored derived field is copied as authority. Executable-policy bypass, credential content, unavailable portable projection, unsupported formats, non-skill assets, invalid retained objects, or a proposed revision equal to the expected prior revision blocks the plan.

### Receipt rebasing

A managed reverse update proposes one exact replacement receipt for the same receipt identity and destination:

- `source_hash` becomes the new complete asset revision;
- `rendered_hash` becomes the freshly captured exact edited target identity;
- `prior_hash` becomes the prior receipt rendered identity;
- `environment_revision` becomes the proposed manifest revision; and
- the adapter version comes from the current compiled target policy.

The receipt is machine-local and never enters the portable asset, lockfile, snapshot, provenance, or sync conflict.

Planning records the exact old local-state bytes and the proposed canonical local-state bytes. Commit acquires the environment lock before the local-state lock, matching materialization lock order. It revalidates the selected observation, current asset revision, manifest bytes, generated lock, strict local state, receipt identity, and target exact identity before creating a journal.

The recoverable commit stages and verifies new objects, manifest, generated lock, and optional local-state replacement before writing a durable journal. It installs immutable objects, commits manifest authority, commits generated lock, then advances the receipt only after a final exact target recapture still equals the reviewed rendered identity. A target mismatch before manifest commit refuses without changing authority. A target change after manifest commit can never receive the new receipt: recovery completes the exact portable revision while retaining the old receipt and reports that receipt rebasing still requires attention. It does not roll back or overwrite the target and never claims false ownership.

The journal binds old and new hashes for manifest, lock, optional local state, both new object identities, the expected prior asset revision, receipt identity, reviewed target identity, and plan digest. Recovery never rescans into a different proposal and never deletes a preexisting or manifest-referenced object.

### User interface

The initial CLI form extends adoption with an explicit update mode:

```text
kitrove adopt --update <asset-id> --expected-prior <asset-content-hash> <observation-id>
```

`--update` is incompatible with `--id`. The rendered plan identifies the operation, old and new asset revisions, component changes, fidelity results, source-authority category, whether one receipt will be rebased, and the plan digest. It does not render native IDs, authored content, machine paths, receipt destinations, or secret-shaped values. Confirmation is required before any journal or staging mutation.

## Consequences

- Reverse edits become new reviewed portable authority rather than implicit drift or last-writer-wins state.
- Exact native objects from prior and other harness revisions are not overwritten or silently discarded.
- Managed destinations remain managed after a successful uncontended receipt-backed update.
- Concurrent target edits cannot acquire a false new receipt, even after portable authority commits.
- Explicit sources are possible without confusing review intent with receipt ownership.
- D2 extends the portable transaction and recovery protocol but grants no synchronization backend authority.

## Validation

- A managed-modified destination updates portable and selected native components, retains other native components and provenance, advances exactly one receipt, and rescans as `ManagedUnchanged`.
- An explicit-root observation updates portable authority without changing any receipt.
- Wrong expected prior revision, stale manifest, stale receipt, unmanaged implicit source, ambiguous duplicate, stale observation, target race, credential canary, executable content, missing retained object, and unavailable projection are non-mutating refusals.
- A native-only reverse edit changes the selected native component while keeping conservative cross-target fidelity.
- Every journal phase recovers with the prior objects intact; post-manifest target divergence completes portable authority without advancing receipt ownership.
- Plan, journal, error, debug, text, and JSON canaries expose no authored content, native ID, absolute path, destination, or secret value.
- Stable and Rust 1.85 canonical CI plus native Ubuntu, macOS, and Windows CI pass before D2 acceptance.

## Rejected alternatives

- **Treat any colliding observation as an update:** turns discovery into mutation authority.
- **Overwrite the existing object root:** destroys immutable prior evidence and makes rollback dishonest.
- **Replace the whole asset from first-adoption output:** silently drops native variants and provenance from other harnesses.
- **Leave the managed receipt unchanged after success:** makes the adopted edit appear stale and allows a later apply to overwrite it.
- **Advance the receipt without a final target check:** can falsely claim a concurrent edit.
- **Store prior revisions in the portable asset:** mixes mutable history into desired-state authority; immutable objects and synchronization history already retain evidence.

