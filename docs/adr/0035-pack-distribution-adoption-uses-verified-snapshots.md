# ADR-0035: Pack Distribution Adoption Uses Verified Snapshots

- **Status:** Accepted
- **Date:** 2026-08-31
- **North Star invariants:** NS-01, NS-03, NS-05, NS-06, NS-07, NS-10

## Context

Pack creation can group capabilities that already share one exact non-harness source, but it cannot
bring a pack into a new environment. The product also needs discovery before adoption so a user can
review available lifecycle objects without changing portable or machine-local authority.

Treating an arbitrary filesystem directory or Git checkout as a pack would require a separately
versioned distribution descriptor, a complete bounded source-snapshot object, format dispatch for
every member kind, and a source resolver distinct from synchronization. None of that authority
exists yet. Inferring membership from filenames would silently claim unmodeled files and violate
INV-05 and INV-09.

The existing filesystem, Git HTTPS, and Git SSH backends already expose bounded, immutable,
internally verified Kitrove snapshot history and exact object envelopes. They are sufficient for a
safe first distribution workflow without executing content or inventing source provenance.

## Decision

`pack discover` lists packs only from the verified current head of an explicitly selected Kitrove
distribution backend. It is read-only and reports the selected backend revision, snapshot digest,
pack revisions, content classes, and direct-member counts. It does not fetch capability objects.

`pack adopt --pack <id>` selects that exact head pack and plans a selective graft of its complete
transitive closure into current portable authority:

1. The remote history, head snapshot, manifest, lock, and object catalog must already satisfy the
   bounded synchronization verification contract.
2. The selected pack must exist at the verified head. Adoption does not search older history or
   silently choose among revisions.
3. Existing identical closure members may be shared. Any asset/pack identity collision with
   different authority refuses the entire plan.
4. Unrelated local and remote records are excluded. The proposed manifest and generated lock are
   re-derived and validated after the graft.
5. Every object referenced by the selected closure is fetched by exact descriptor. The history is
   re-inspected before confirmation and must remain byte-for-byte equivalent.
6. Confirmation binds the selected backend revision and snapshot, exact pack revision, complete
   closure, object catalog, current manifest revision, and complete proposed manifest and lock.
7. Commit installs the verified immutable objects and portable authority through the existing
   crash-recoverable manifest transaction. It does not apply the pack or execute any member.

The initial command accepts the same explicit filesystem, smart-HTTPS Git, and smart-SSH Git
providers as synchronization and rollback. Authentication remains operation-local under ADR-0028.

Arbitrary repository source resolution remains separate future work. A normal Git repository is not
a Kitrove distribution merely because it contains familiar filenames, and the fixed Kitrove sync
ref is not a general package registry.

## Consequences

- A developer can discover and adopt a complete mixed-capability pack across environments without
  first importing or recreating its members individually.
- Exact native and portable objects, component provenance, fidelity, bindings, aggregate identity,
  and executable classification survive adoption unchanged.
- Executable members may be preserved, but materialization remains subject to exact machine-local
  trust and version policy. Distribution adoption grants no execution authority.
- Source-provider expansion can reuse the graft planner only after it produces the same verified
  snapshot-and-object contract; it cannot bypass that contract with a checkout path.

## Validation

- Discovery is read-only and uses only verified head authority.
- Missing packs, malformed history, incomplete object catalogs, identity collisions, stale history,
  stale local manifests/locks, wrong fetched objects, and unconfirmed plans are non-mutating.
- The selection and plan digests change with every remote, snapshot, pack, closure, object, local
  base, proposed manifest/lock, or affected aggregate field.
- Adoption imports only the selected closure, preserves unrelated local authority, installs the
  exact object set, and leaves no recovery journal after success.
- Filesystem, Git HTTPS, and Git SSH use one generic workflow over the shared backend contract.

## Rejected alternatives

- **Infer a pack from arbitrary directory structure:** silently claims files and lacks immutable
  whole-source preservation.
- **Treat sync as a general Git checkout:** crosses the transport/source-resolver boundary and could
  activate ambient Git behavior.
- **Import the entire remote environment:** overwrites unrelated desired state instead of adopting
  one lifecycle object.
- **Adopt only the pack record:** leaves member and immutable-object authority incomplete.
- **Apply immediately after adoption:** combines portable authority and destination ownership into
  one unreviewed confirmation.
