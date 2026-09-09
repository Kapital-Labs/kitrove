# ADR-0040: Application upgrades require a verified rollback kit

Status: Accepted for Phase 6 implementation

## Context

Kitrove releases contain a security-sensitive executable that can read and change local harness
configuration. An application upgrade must not turn an unverified network response into executable
authority, and a failed installer must not leave the operator guessing which version is installed.
The generated installers are useful distribution controls, but installer transport, application-data
compatibility, and recovery after a partial replacement are separate concerns.

Kitrove's persisted application state currently has one supported schema, `V1`. A future release
that performs an irreversible state migration cannot honestly promise binary rollback merely because
an older executable is still available.

## Decision

Installation, upgrade, and rollback are explicit, version-pinned operations. Kitrove does not
self-update and does not download or execute an updater from within the application.

Every supported procedure must:

1. acquire artifacts for one exact release tag;
2. verify the selected platform archive and any installer before execution using GitHub artifact
   provenance constrained to the release workflow, exact tag ref, and independently resolved release
   commit, with the archive's published SHA-256 as an additional integrity check;
3. confirm that the archive contains the documented single `kitrove` executable and release
   companions before installation;
4. retain a locally verified rollback kit for the currently installed version before replacing it;
5. derive the candidate executable from the same verified archive handle into a private, no-follow
   staging directory on the destination filesystem; retain identity throughout the copy and
   revalidate the candidate digest immediately before guarded replacement (atomic exchange
   on supported Unix platforms; the recoverable Windows procedure below);
6. fail closed on a staging, identity, digest, replacement, or cleanup mismatch, preserving the
   prior executable or an identity-bound recovery record rather than deleting ambiguous state;
7. verify both the installed digest and `kitrove --version` after replacement; and
8. treat any installer error or unexpected installed version as an indeterminate replacement until
   the installed executable is inspected, then restore and verify the retained version when needed.

The rollback kit consists of the exact prior platform archive, its checksum, an authenticated expected
digest, and a retained attestation bundle that can be verified offline. It is stored outside the
replacement path with permissions appropriate for executable authority. Recovery reopens the retained
archive without following links, verifies its current bytes against the bundle and expected digest,
and applies the same identity-stable staging and replacement procedure. A past verification result or
`--version` output does not authenticate bytes at restoration time. A network fetch attempted only
after an upgrade fails is not a rollback plan.

The verifier may produce an opaque in-memory recovery-material value from an already
authenticated release subject. It must revalidate the exact bounded archive and bundle bytes
against that subject before retaining them, and reuse the existing archive/manifest/executable
validator. This value is not proof of durable storage or installed-binary ownership. Persisting
it still requires private filesystem authority; reopening it for recovery requires fresh offline
attestation verification. Debug output must not include archive, bundle, or executable bytes.

Lifecycle preflight may retain a bounded, read-only state-document snapshot under an
exclusive lifecycle guard. The snapshot binds the root and file identities and exact bytes;
revalidation requires the matching root and a live exclusive guard, validates private
permissions without repair, and rejects changed bytes or namespace authority. It is not a
state-schema validator or a substitute for the complete control-file inventory. Snapshot
contents stay local and are omitted from debug output.

Complete state preflight extends that evidence to a bounded tree of private directories
and regular files under each configured state root. It retains every inspected object,
exact file bytes and directory inventory; links, special files and resource-limit excess
fail closed. Private executable payload files may be inspected without execution; this
does not relax the data-only permission rule for `state.json` or lifecycle locks. A
machine-local fingerprint binds lossless paths, ancestry/object identities, file modes
and content digests. Revalidation requires the matching exclusive lifecycle access and
unchanged inventory, identities and bytes. This filesystem snapshot is not schema or
recovery-journal approval: the installer must separately apply the shared state schema
and control-inventory policy before replacement.

Persisted-state format validators are shared with the application rather than copied
into the installer. In particular, the retained sync-base selector keeps its exact
version-1 canonical JSON shape when exposed through the model library. Extracting its
bounded parser does not migrate state or turn a selector into filesystem authority.

The installer acquires all explicitly configured state roots exclusively before reading
their snapshots, with bounded root count and aggregate bytes. The common `LocalState`
parser owns V1 document validation. Stable locks must be empty; outstanding journals or
staged control files block upgrade. Retained quarantine bytes are preserved, not treated
as current state or deletion authority. Sync selectors, retained-base records and
manifests use their shared parsers; referenced immutable payloads remain preserved and
fingerprinted and are not adopted by preflight. The application retains responsibility
for verifying those objects before later use. Empty historical staging directories do
not by themselves indicate an unfinished transaction. Guard/snapshot acquisition alone
is not durable upgrade readiness until root evidence is recorded in the transaction.

Read-only upgrade preconditions bind the existing executable's retained native identity,
size and digest to the authenticated prior release, and require the candidate manifest's
explicit rollback compatibility declaration. This inspection does not execute either binary,
persist a rollback kit or authorize replacement. The transaction must retain that evidence,
revalidate it under its installer/lifecycle locks and complete state preflight before mutation.

Before upgrade replacement, the prepared operation retains a private `rollback-kit`
directory with exactly two fixed leaves: `archive` and `attestation.json`. Contents come
only from authenticated recovery material and are identity/digest checked after durable
writes. The held installer lock and complete staging authority remain required during
creation and revalidation. Partial/unknown kit contents are preserved on error. This
storage primitive alone does not make the operation upgrade-ready: the prior-leaf and
state evidence must still be bound into a durable upgrade record and freshly authenticated
recovery must precede any later use of retained executable bytes.

An additional bounded `upgrade.json` preparation record binds the canonical candidate
operation-record digest, authenticated prior release/provenance, observed prior native
identity and all retained rollback-kit identities. Its initial schema/phase is explicitly
`rollback_material_retained`, not permission to replace an executable. Parsing does not
grant authority: the complete record must match independently reconstructed authenticated
inputs and retained filesystem evidence. State preflight and the replacement/recovery
transaction remain required before upgrade readiness may be claimed.

The next preparation-record schema is `2`, with phase `state_preflight_retained`.
It additionally binds the complete selected root list: losslessly encoded absolute
native paths (at most 2 KiB each before hex encoding) and the versioned state-tree
fingerprints. At most 16 roots fit inside a 128 KiB record limit. Root paths remain
machine-local private data and are omitted, including their encodings, from Debug.
The record is reconstructed only from live, revalidated exclusive-root evidence;
all roots are checked again after persistence. Schema-1 records cannot be promoted
by parsing or by supplying an empty root list. This phase is still preparation,
not replacement authorization or proof that crash recovery is implemented.

An internal owning preparation transaction retains the staged application and its
installer lock, authenticated prior-leaf evidence, rollback kit, state-bound record,
and all exclusive lifecycle guards together. It acquires and validates selected
state roots before staging writes. Failure before staging creates no installer
artifacts; failure after staging preserves the partial operation and reports recovery.
Dropping a successful preparation closes its artifact capabilities before releasing
the state guards. Preparation does not execute either release or replace the prior
leaf; the subsequent replacement transaction must revalidate this retained evidence.

Fresh recovery of complete preparation uses a distinct exact inventory from
first-install recovery: the staged candidate and operation record plus the rollback
kit and state-bound upgrade record. It does not accept or clean pending phase writes.
The caller supplies a freshly authenticated candidate, independently selected prior
release identity and checksum, and the complete state-root selection. Retained prior
archive and bundle bytes are reopened privately, bounded, and freshly verified by
the shared offline verifier before reconstructing prior-leaf and state evidence.
The saved upgrade record must exactly match that reconstructed evidence. Neither
record paths nor remembered verification results select filesystem or release authority.

### Approved Windows availability tradeoff (2026-09-07)

The maintainer explicitly approved journaled two-step Windows replacement. This relaxes
gap-free executable availability, not verified ownership, preservation or recovery.
The main CLI path may be absent between moves, including after an interruption until
the separately retained installer performs guarded recovery. Do not call this atomic
replacement, promise uninterrupted launches, or use the main CLI to recover itself.
Unix atomic exchange remains unchanged.

Before the first move, authenticate both releases, retain and synchronize the prior
rollback kit and preparation record, and hold installer and selected-state locks.
Move the exact prior executable into a distinct private retained name using the shared
handle-bound no-replace primitive. Synchronize retained file and affected directories,
then durably record prior retention before moving the exact staged candidate into the
absent destination. Revalidate both identities, bytes and security after each move.
No absent-name precheck authorizes an overwriting operation. A competing destination
or backup, even with equal bytes, must remain untouched and require recovery.

Fresh recovery reconstructs authenticated filesystem layout and canonical journal
evidence; journal names, checksums alone and historical status never confer authority.
An interrupted gap restores the verified prior instead of guessing that publication
was authorized. A published candidate requires a fresh contained probe before success.
Before withdrawing a failed candidate, durably record restoration intent. Recovery must
honor that intent even if interruption left the candidate installed; it must not retry
the forward upgrade. Restoration moves the candidate back to its absent staging name,
then the retained prior to the absent destination, preserving both releases throughout.
An already restored pair is not upgraded again merely because recovery was requested.
An explicitly requested recovery may resume a fully prepared, unchanged original pair
with no phase records through the same guarded publication path as initial replacement.
This is not permission to resume forward from an interrupted gap or restoration intent;
those layouts retain the restoration rules above. Read-only reopening and placement
inspection do not initiate publication.
Explicit rollback uses the same mechanism with independently selected direction and
compatibility evidence; restoring a failed operation is not a new explicit rollback.

Native Windows acceptance must cover interruption before/after each move, file and
directory synchronization, journal creation/publication, and contained probe; a second
interruption during recovery; occupied names; identity/bytes/ACL substitutions; running
executables and sharing failures; current-state changes; and exact preservation on every
refusal. Public replacement commands remain gated on those tests and complete recovery,
retirement and history integration. Approval of the approach is not runtime acceptance.
NS-07/NS-09 and INV-06/INV-07/INV-08 remain enforced. Portable assets, native variants,
fidelity, receipts, discovery/adoption and synchronization semantics are unchanged.

### Windows journal format

Windows phase records use a separate closed namespace: `windows-upgrade-` followed by
`prior-retained`, `published`, `verified`, `committed`, `restore-requested` or `rolled-back`,
with `.pending` during writing and `.json` after publication. Schema 1 contains exactly
`schema`, `protocol` (`windows_two_move`), `phase` (the corresponding hyphenated name),
`preparation_sha256`, `candidate_identity` and `prior_identity`. Expected bytes are
reconstructed from fresh preparation/release evidence and compared canonically, never
accepted merely by parsing. Records are bounded to 2048 bytes. Completed forward records
must form a prefix; at most its next forward record can be pending. Restoration intent
may coexist with that preserved forward prefix/pending evidence, and terminal rollback
requires completed restoration intent. No phase has both pending and complete names.
Pending bytes must be an exact canonical prefix and may only be appended through an
identity-checked handle. Publication is no-replace, followed by directory synchronization.
These records cannot be interpreted as Unix exchange or first-install evidence.

### Unix replacement transaction

The Unix replacement transaction uses the reviewed `rustix` atomic exchange primitive
on Linux and macOS. The displaced prior remains at the staged `application` name;
the candidate is accepted for probing only if both resulting identities and digests validate.
It synchronizes both retained executables and both directories before recording
replacement. Separate upgrade phase records bind the preparation digest and both
executable identities. Each phase is privately written and synced under a pending name,
then published with no-replace rename and a directory sync; uncertain pending bytes
remain for guarded recovery. A contained version-probe failure exchanges the same verified
pair back and records rollback. Unexpected edits, unavailable primitives or uncertain
durability preserve both names and require recovery; they never authorize deletion
of the displaced file. Public upgrade remains gated on post-replacement crash recovery
and equivalent native Windows acceptance.

Fresh Unix transaction recovery independently authenticates the candidate record at
either fixed executable location, then freshly verifies retained rollback material,
the opposite prior leaf, selected-state evidence and every phase record. Phase names
only select a bounded candidate inventory; exact canonical phase bytes must bind the
reconstructed preparation and both native identities. Missing replacement or rollback
markers may be completed only when the complete authenticated pair proves that layout.
Unknown, pending or contradictory evidence is preserved. Recovery repeats contained
candidate probing before committing; a verified restored pair is never upgraded again
merely because recovery was requested. First-install inventory remains distinct.

A pending upgrade phase may be completed only when its bounded private single-link
file contains an exact prefix (including empty) of independently reconstructed canonical
phase evidence and its phase fits the authenticated executable layout. Completion only
appends the missing suffix through an identity-checked no-follow handle; it never truncates
or overwrites retained bytes. Publication uses no-replace rename. Candidate probing still
precedes verified/committed publication. If that probe fails, earlier pending evidence is
retained while the authenticated pair is restored; bounded distinct phase names let a
later recovery finish an interrupted rollback without discarding the earlier evidence.
Non-prefix bytes, conflicting names, changed identities or impossible phases require
manual recovery and remain untouched.

Explicit rollback is a new replacement transaction, distinct from restoring a failed
transaction's starting executable. Preparation schema 3 binds a closed `upgrade` or
`rollback` direction selected by the caller, never inferred from persisted data. For
upgrade the candidate must declare compatibility with the installed predecessor; for
rollback the installed newer release must declare compatibility with the requested
older candidate. Equal versions, undeclared pairs and cross-target/schema/protocol
pairs remain ineligible. The same private replacement, probe and failure-restoration
machinery applies in either direction, with a freshly verified recovery kit for the
version being replaced and fresh current-state preflight. Older preparation schemas
are not silently promoted to directional authority. Completed-operation retention and
reuse remain a separate gate before this becomes a public rollback workflow.

Completed replacement operations may be retired into a private sibling history root
using an atomic no-replace directory move. Retirement freshly verifies the supplied
release pair, retained kit, exact terminal phase evidence and both executable identities,
and preserves the complete operation without deleting history. Current selected state
roots are separately locked and inspected. Historical state fingerprints are bounded
opaque evidence for retention only: their paths are never opened, and their values
cannot become live replacement authority. A distinct terminal-record type enforces
that separation. Retirement is allowed only for a committed candidate or a recorded
restoration, never an incomplete operation. Files and both directory sides are synced;
starting later staging also syncs any existing private history root to cover an
interrupted retirement. Unknown evidence or competing history entries remain untouched.

The same retention boundary applies to terminal first installations. Freshly supplied
authenticated release evidence must reconstruct either the committed installed layout
or the completed failed-install rollback layout before archiving. Pending first-install
records are not discarded by retention; they require the separate recovery workflow.
First-install and replacement retirement share directory identity, no-replace move and
durability rules, while retaining their distinct executable and phase-record validation.

Before public first-install execution, a distinct owning preparation must retain all
selected application-state guards and a private `install-state.json` record. Its
schema is `1`, containing `schema`, `candidate_record_sha256` (the canonical candidate
operation-record SHA-256) and `state_roots` using the same bounded path/fingerprint
entries as replacement preparation. The total record is bounded to 128 KiB. Even an
explicitly empty root selection requires this record; absence is never inferred to
mean no state. Construction and reopening compare exact canonical bytes reconstructed
from independently authenticated candidate evidence and freshly locked selected roots.
Record contents cannot select filesystem paths or authorize execution on their own.
Fresh recovery must validate this evidence before reconciling pending phase records
or changing executable placement. This format and preparation are prerequisites;
execution, recovery and terminal-history integration must retain/revalidate the same
state guards before the public command is enabled.

State-bound first-install recovery uses the same prefix-preserving journal rule as
upgrade recovery: pending bytes must be a bounded private exact canonical prefix;
completion appends only the missing suffix and publishes with no-replace rename.
Fresh recovery repeats the contained candidate probe before accepting an installed
candidate, including when earlier verified or committed evidence exists. A failed
probe restores the absent-install precondition only while executable identity and
selected-state authority still validate. Earlier complete and pending phase evidence
is retained, not erased to make the restored layout resemble a shorter history.
The state-bound layout validator must explicitly authenticate those earlier records
alongside the rollback transition. An already restored layout is never installed
again merely because recovery was requested. Tests must cover a second interruption
during journal completion and rollback, including retained pre-failure evidence.
This is a required recovery integration gate, not a claim that reopening alone
implements those transitions.

State-bound first-install retirement must separate historical state evidence from
live recovery authority, just as replacement retirement does. It validates the exact
candidate-operation binding and bounded canonical historical state-record shape,
without opening roots selected by stored paths or requiring historical fingerprints
to equal newly inspected current state. Fresh caller-selected roots remain locked
through archival. A completed rollback may retain authenticated pre-failure forward
pending records as history; those records are never completed or discarded by retirement.
An incomplete current transition, including a pending rollback record without completed
rollback evidence, still requires recovery before archival. Shared no-replace history
movement and location validation apply without weakening ordinary staging inventories.

Rollback authority must not be reconstructed from historical status records. Historical
inspection uses an explicit caller-selected operation identifier and independently
authenticated release inputs, accepting only exact canonical bounded record bytes.
The resulting historical record type has no conversion to live preparation or
replacement authority. Saved filesystem identities are inert comparison context for
historical journal bytes, not proof of current executable placement or past execution.
Filesystem history inspection must separately retain and validate the selected private
history namespace and its leaves; parsing alone does not establish a completed archival.

Release documentation must distinguish binary rollback from application-data rollback. Binary
rollback is supported only when the release notes declare the prior state schema compatible. Any
future incompatible or irreversible migration requires its own pre-upgrade backup, migration, and
restore design before that release may claim rollback support.

The shell and PowerShell installers remain convenience entry points. They are not the accepted
security workflow until release tests prove that each supported path fails closed when archive
integrity cannot be checked and restores or preserves the prior executable on every reported
failure. Until then, the verified-archive procedure is authoritative.

### Offline replacement command contract

The separately retained installer exposes explicit `upgrade` and `rollback` commands,
with corresponding `preflight-`, `recover-` and `retire-` commands. Directional
`upgrade-history-status`, `rollback-history-status`, `upgrade-history-sync` and
`rollback-history-sync` keep history inspection distinct from executable recovery.
Every command requires exact candidate archive, bundle, tag, full commit and SHA-256
inputs. Initial replacement and preflight additionally require the same five independent
inputs prefixed with `--prior-` for the executable being replaced. Recovery, retirement
and history instead require only `--prior-tag`, `--prior-commit` and `--prior-sha256`:
the retained kit supplies bytes, not the expected release identity or checksum.
Unexpected prior-file options are rejected rather than silently ignored.

History status is read-only and accepts no state-root selection. Every other command
requires all current configured state roots or an explicit no-state-roots declaration.
History requires an explicit operation identifier. Neither command names nor retained
records infer direction, select release pins, discover state roots or authorize fetching.
Preflight is an instantaneous read-only check, never a reusable replacement permit.
The public Windows replacement gate still requires the native acceptance above.

## Consequences

- Users have an offline recovery artifact before application authority changes.
- A successful download is not confused with a verified release.
- A failed installer cannot be assumed to have preserved either the old or new binary.
- Automatic update checks, background replacement, and unchecked `curl | sh` or remote PowerShell
  execution remain out of scope.
- Release artifacts can be generated on version tags without adding paid jobs to ordinary CI.

## Rejected alternatives

- **Enable the generated standalone updater:** its executable acquisition is not independently
  checksum-bound by the generated installer path reviewed for Phase 6.
- **Fetch the prior version after failure:** recovery would depend on network and remote retention at
  the moment it is needed most.
- **Promise rollback across every future version:** an irreversible state migration could make the
  older binary unsafe even when executable replacement succeeds.
