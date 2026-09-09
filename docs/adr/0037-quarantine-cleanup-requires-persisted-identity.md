# ADR-0037: Quarantine cleanup requires persisted filesystem identity

- **Status:** Implemented on cleanup-capable Unix and Windows; inspection-only elsewhere
- **Date:** 2026-08-31
- **Deciders:** Kitrove maintainers
- **North Star invariants:** NS-03, NS-05, NS-06, NS-07, NS-09, NS-10

## Context

Kitrove removes managed files and directories by moving the already opened object to a private,
randomized quarantine name and rechecking its filesystem identity. Unix removal files are truncated
through their verified handles. Windows removal files retain their bytes until exact-handle deletion.
On Unix, directories can normally be removed through an opened handle; Windows directory sharing
rules require retaining the verified moved directory. Removing the randomized name after verification
would otherwise restore a name-swap race. A later authorized mutation therefore needs independently
persisted authority to reclaim those objects; interruption or unprovable state can leave
`.kitrove/removal-quarantine` tombstones retained.

A later process cannot infer authority from the random prefix alone. It must distinguish a tombstone
Kitrove actually moved from a colliding, replaced, or malformed entry without reading unbounded
directory state or deleting a concurrent replacement. Cleanup is mutation and must never occur while
building a read-only plan.

## Decision

Cleanup-authoritative removal tombstone names encode their kind, a versioned lossless platform
filesystem identity, and a 128-bit random nonce. On Unix, the identity is the complete device and
inode pair. Windows cleanup authority uses the volume serial number and the complete 128-bit file
identifier; the shared Unix `u64` inode representation is not sufficient on filesystems such as ReFS.
Canonical Windows removal and cleanup-batch names persist that complete identity. The earlier
versioned retained name containing only kind and nonce remains recognizable but permanently grants
no deletion authority. Unknown names and older random-prefix legacy names still fail closed. Encoded
identities and retained names are machine-local control data and never leave the machine-local
control directory.

After the source-to-quarantine rename, Kitrove continues to compare the destination metadata with
the still-open handle before reporting success. A removed regular file or directory is eligible for
later cleanup only when its no-follow metadata exactly matches the identity encoded in its name.
Unknown names, links, special files, malformed identities, and identity mismatches block cleanup
without deleting anything. On Unix, a non-empty removed file can remain after a crash between rename
and truncation; after validating the complete cleanup set, cleanup truncates it through the
identity-matching reopened handle and syncs it before moving it into the cleanup batch. Because Unix
truncation affects every hard link to an inode, file removal and recovery require a reliable link
count of exactly one before the rename and recheck it through the opened handle immediately before
truncation. Windows preserves authoritative file bytes through staging and instead requires one link
on the exact final deletion handle. An external alias or unavailable link-count evidence fails
closed.

Cleanup runs only inside an authorized mutation after every affected root's root-local
`.kitrove/environment.lock` is held. A transaction first opens all roots without mutation, obtains
their lossless identities, deduplicates aliases, sorts those identities by their canonical encoded
bytes, and acquires every root lock in that order. Transaction paths that currently lock only the
origin environment or private state must adopt this protocol before they can clean an external
target. Read-only `ObjectStore::open`, private-state inspection, scan, planning, and sync inspection
never create, repair, enumerate for deletion, or clean quarantine state.

Repository governance grants filesystem-mutation APIs to exactly the existing object-mutation
module and the dedicated quarantine cleanup batch module. The inspection and budget modules retain
no mutation allowlist entry, and look-alike paths remain rejected. This keeps the cleanup state
machine reviewable without reopening filesystem authority throughout the core crate.

The implementation uses the shared deterministic bounded-directory collector and threads one
mutable `QuarantineCleanupBudget` through the complete transaction. Its compiled limits separately
bound roots, top-level tombstones and cleanup-batch containers, recursively visited descendants, and
recursion depth. Every root opened, quarantine entry enumerated, batch child, and descendant visited
is charged exactly once to that single transaction-wide budget; opening another root or interrupted
batch does not reset an allowance. The descendant limit must be at least the maximum tree work that
one accepted mutation can leave behind. Creation and removal share the same accounting contract.
Before the first mutation, the transaction coordinator computes with checked arithmetic and reserves
the worst-case tombstone and descendant work for every participant and root across both the forward
path and a complete rollback after the latest possible failure. Cleanup consumes only its allocated
portion; forward removals and rollback consume distinct pre-reserved portions, so successful early
participants cannot exhaust authority needed to undo later work. A transaction whose complete
forward-and-rollback reservation does not fit is rejected before mutation. Overflow,
checked-arithmetic failure, or depth exhaustion likewise fails closed before cleanup mutation. This
deliberately treats over-budget state created outside those invariants as requiring explicit repair
rather than performing partially validated cleanup.

After validating the complete bounded set, Kitrove creates an empty private directory named
`.kitrove-cleanup-pending-v1-<nonce>` with create-new semantics and opens it without following links.
While it is still empty, Kitrove obtains its identity and renames it without replacement to the final
platform-specific `.kitrove-cleanup-v1-<platform>-<identity>-<nonce>` name. An interruption before
that rename can therefore leave only an empty pending directory. On a cleanup-capable platform, a
later transaction may remove such a pending directory only after opening it, proving it is empty,
and deleting it through the same identity-bound mechanism; a non-empty or malformed pending directory
blocks cleanup. An interruption after the rename leaves a recoverable identity-bearing batch,
including when it is empty.

On Unix, each eligible file is first reduced to a synced zero-length tombstone through its verified
handle. Windows preserves the file bytes. Each eligible tombstone is then moved without replacement
into the final batch and immediately revalidated against its open handle and encoded identity. A
mismatch leaves the batch intact and returns an error. Validation records an exact identity/kind
snapshot, requires canonical authority for every immediate batch child, and rejects filesystem or
mount-boundary crossings. Only after all root-local batches pass that bounded validation is their
exact tree work precharged twice. A second bounded pass matches the snapshot while securing every
source directory; only after every root passes does a third bounded, handle-relative pass remove
entries. Both passes must match the snapshot entry for entry; additions, replacements, or boundary
changes stop before the changed entry is deleted.
Interrupted batches undergo the same complete validation before removal resumes. Cleanup never
interprets paths outside the opened quarantine capability.

On Unix, nested regular files are not unlinked through names in their original tombstone directories.
The deletion pass opens and revalidates each file, moves it without replacement into the private
batch root under `.kitrove-cleanup-leaf-v1-unix-<device>-<inode>-<nonce>`, revalidates it against the
still-open handle, and syncs both parent directories. Before evacuation begins, a separately budgeted
snapshot pass restricts every opened source directory to its verified owner, rechecks the filesystem
and mount boundary, and syncs the permission change. The file's source name is checked again against
the open handle immediately before rename. It performs one final identity check immediately before
unlinking the isolated name, then syncs the batch root. An interruption can therefore leave a
canonical identity-bearing cleanup leaf that the next bounded batch validation can resume. Cleanup
leaves do not require a single link or zero length: nested files derive removal authority from the
validated top-level directory tombstone, cleanup only unlinks one verified name, and never truncates
through a cleanup leaf. Directory removals and every file removal are parent-synced individually, so
a reported interruption resumes from a durable remainder rather than assuming the whole recursive
pass completed.

On macOS, POSIX mode bits alone do not exclude extended ACL grants. Kitrove reads the native extended
ACL through each already-open private control, removal-quarantine, batch, and source-directory
descriptor during nonmutating inspection and again before and after permission restriction. It fails
closed without changing an ACL-bearing directory when any entry or ACL-level flag is present. The
narrow safe descriptor wrapper is a pinned macOS-only dependency; path-based ACL inspection is not
accepted as cleanup authority. Linux relies on owner validation plus `chmod(0700)`, whose ACL mask
update removes non-owner effective access. Other Unix targets fail closed until they have equivalent
native owner and ACL evidence.

Unix deletion remains handle-relative and identity-bound through the final removal operation.
Windows cleanup uses native operations isolated in `kitrove-windows-security`. Cross-parent moves
resolve both names through already-open parents, refuse replacement, prove current-user ownership and
complete identity, and attempt to return the same object to its source parent if destination
validation fails, reporting rollback failure distinctly. Deletion opens the selected child relative
to its already-open parent, rejects reparse points and identity/kind mismatch, and marks that exact
open handle for deletion. Authoritative top-level files must still have exactly one link on the
deletion handle; nested files remove only the selected link and never truncate shared
content. Core releases ordinary Rust handles before these namespace operations so Windows sharing
rules do not invalidate recovery. Unsupported Windows filesystems or APIs fail closed.

The ordered root locks exclude concurrent Kitrove operations over the same roots. As in ADR-0036, a
malicious process running under the same operating-system account is outside Kitrove's isolation
boundary; it already has the account's ambient deletion authority. Ordinary concurrent replacement
is detected before cleanup commits to the batch and again when final deletion reopens and revalidates
the exact selected object. Unix leaf isolation and Windows exact-handle deletion provide their
respective final authority boundaries. No claim is made that a same-account hostile process cannot
race the final system call.

Legacy tombstones that predate identity-bearing or canonical retained names are not guessed at or
automatically deleted. Kitrove reports them as unrecognized retained state. No public release has
used the legacy format, so Phase 6 may adopt the versioned formats without an automatic migration. A
future manual repair workflow would require its own explicit authority and confirmation design.

Transactions expose this boundary through stable, redacted, namespaced error families. A code in the
`cleanup_limit` family means the complete forward plus rollback/crash-recovery reservation or
retained inventory cannot fit the compiled ceiling. A code in the `cleanup_failed` family, or the
transaction's existing redacted storage-failure code where that surface deliberately coalesces
storage failures, means cleanup inspection or mutation could not prove safe completion. Neither
result authorizes retry logic to delete, rename, truncate, repair permissions on, or partially
enumerate the retained state. The operator boundary is documented in
`docs/QUARANTINE-RECOVERY.md`; Kitrove has no destructive manual-repair command in this phase.

## Alternatives considered

### Delete by randomized name after the original removal

Rejected because a replacement can occupy that name after identity verification.

### Treat the prefix and private directory as sufficient authority

Rejected because names alone do not prove which filesystem object Kitrove moved.

### Delete a bounded prefix while ignoring overflow or unknown entries

Rejected because partial cleanup makes outcome depend on enumeration order and can hide malformed
retained state. The complete initial set must fit before staging, and every staged batch must validate
before deletion.

### Clean during every store open

Rejected because inspection and planning are nonmutating contracts.

### Store a separate tombstone manifest

Rejected because a crash between moving the object and writing the manifest strands authority. The
name and metadata form one immediately revalidated identity record.

## Consequences

### Positive

- Cleanup authority is derived from the exact object originally moved, not a filename prefix.
- Enumeration, recursive traversal, interrupted-batch recovery, and retained entry count are
  explicitly and transaction-globally bounded.
- Read-only planning remains byte-for-byte nonmutating.
- One shared cleanup path covers portable environments, private state, and external target roots.

### Negative

- Tombstone names expose opaque local platform filesystem identifiers inside a private control
  directory.
- A malformed, legacy, unknown, or over-budget quarantine blocks mutation until explicitly repaired.
- Legacy Windows retained tombstones remain recognizable but non-authoritative and require explicit
  repair if they block mutation.

### Follow-up

- Keep unsupported platforms inspection-only until they receive lossless native identity and
  identity-preserving deletion evidence.
- Add a separately confirmed repair workflow only if legacy public installations ever require one.

## Validation

- Exact-bound and allowance-plus-one fixtures prove roots, tombstones, descendants, and depth share
  transaction-global bounds and overflow is nonmutating.
- Multi-root and maximum-tree/maximum-batch fixtures prove allowances do not reset per root or batch
  and every accepted mutation leaves recoverable work within the cleanup limits.
- A near-limit multi-participant fixture fails after several forward mutations and proves the
  pre-reserved rollback completes without encountering cleanup-budget exhaustion.
- File and directory fixtures prove only identity-matching tombstones are moved into cleanup batches.
- Hard-link fixtures prove removal and interrupted-file recovery never truncate an external alias,
  including when another link appears after the quarantine rename.
- Swap hooks prove replacements survive and cleanup returns a redacted failure.
- Final-unlink swap hooks prove an evacuated cleanup leaf is revalidated and a replacement at its
  canonical name survives untouched.
- Native macOS extended-ACL fixtures on both private boundaries and a staged source directory prove
  inspection or cleanup fails before changing permissions and retains the ACL-bearing state.
- Interrupted-pending and identity-bearing-batch fixtures prove deterministic resume after proving
  pending directories empty and validating each final batch and every descendant.
- A Unix identity-matching non-empty regular-file tombstone fixture is reopened, truncated, synced,
  and cleaned. The corresponding Windows fixture preserves the bytes through staging and deletes the
  exact authoritative single link without truncation. Unknown-name, malformed-identity, link,
  special-file, identity-mismatch, and non-empty pending-directory fixtures fail closed.
- Read-only store opening and planning snapshots prove cleanup never occurs outside mutation locks.
- Unix tests exercise identity-bound final removal. Platform-neutral tests prove canonical
  non-authoritative retained names survive under the shared bound while unknown and legacy names
  fail closed. Native Windows tests exercise complete identity-bearing names, cross-parent no-replace
  moves, exact-handle file and directory deletion, hard-link policy, interrupted batch recovery,
  coordinator integration, and legacy nonmutation.
- The Phase 6 acceptance record identifies the implementation heads and exact local runtime evidence.

## Supersession

This records the cleanup counterpart to ADR-0005's retained recovery evidence and the shared mutation
boundary. Supersede it only if a platform-independent API can atomically unlink an already-open file
or directory without returning to name-based authority.
