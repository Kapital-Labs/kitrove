# Retained quarantine recovery

Kitrove may retain removal tombstones under a root-local `.kitrove/removal-quarantine` when a safe
transaction is interrupted or when the platform cannot preserve filesystem identity through final
deletion. Retention is a safety outcome: these objects are not portable data and are never sync
content.

On cleanup-capable Unix and Windows, a later authorized mutation inspects recognized state and
reclaims only identity-authoritative tombstones while holding every affected root lock and one
transaction-global work budget. Planning, scanning, and other read-only operations never repair
permissions or perform cleanup. On other platforms without the required native identity and deletion
evidence, Kitrove performs bounded inspection and reserves capacity for retained work but does not
delete it.

## Stable failure behavior

Mutation surfaces report a redacted, namespaced code in the `cleanup_limit` family when the complete
retained inventory or the transaction's forward plus rollback/crash-recovery cleanup reservation
exceeds the supported ceiling. Examples include `transaction.cleanup_limit`,
`instruction_apply.cleanup_limit`, `apply_batch.cleanup_limit`, `trust.cleanup_limit`,
`sync.cleanup_limit`, and `sync_portable.cleanup_limit`. Most surfaces report the corresponding
namespaced `cleanup_failed` family when cleanup cannot validate or complete safely. Instruction and
atomic batch surfaces intentionally coalesce that condition into their existing redacted storage
codes, `instruction_apply.storage_failed` and `apply.batch_storage_failed`.

These failures occur before new authority mutation whenever validation or reservation detects the
problem. Live committed state remains authoritative until a durable journal exists. Once present,
the exact durable journal controls transaction direction and recovery. A validated identity-bearing
Unix or Windows tombstone authorizes only bounded cleanup of that exact retained object; a canonical
legacy Windows retained name remains recognizable but grants no deletion authority. Each later
recovery attempt creates a fresh bounded budget and must reprove its exact journal, root, object, and
quarantine identities before continuing.

## Repair boundary

Do not rename, truncate, copy over, or recursively delete quarantine entries based only on their
names. A malformed name, legacy name, link, special file, identity mismatch, unexpected batch child,
unsafe permission boundary, or over-budget inventory blocks automatic cleanup without deleting the
unknown state. Repeated retries do not expand Kitrove's authority.

Kitrove intentionally provides no destructive quarantine-repair command in the public-alpha scope.
An operator who encounters a blocked quarantine should first preserve the root and its `.kitrove`
control state for diagnosis, stop concurrent Kitrove mutations for that root, and restore from a
known-good backup or seek a reviewed, case-specific recovery procedure. Removing retained state by
hand abandons Kitrove's recovery evidence and is outside the guarantees of the transaction that
reported the failure.

A future general repair workflow must have a separate design, explicit confirmation, bounded work,
and independently reviewed deletion authority. It must not infer ownership from a prefix or turn an
inspection-only platform into a destructive one.

## Preserve device-mismatched retained files on macOS

When a storage check reports that a retained file's device ID changed and its
file ID still matches, open `kitrove` and choose **Check collection storage**.
The check shows a preview when there are eligible directories to preserve.
Review the counts for each listed root. Type `y` and press Enter to preserve
those directories, or press Enter alone to leave them in place.

Kitrove moves each approved directory intact into its own private holding
location, then checks storage again. If an earlier move completes and a later
one fails, the completed move remains in place. After storage checks pass,
return to the operation you were attempting and review its new preview.

To choose an explicit collection path or review one root at a time, use the
following commands. Start with the read-only plans:

```sh
kitrove recover plan --environment "$HOME/Kitrove" --root collection
kitrove recover plan --environment "$HOME/Kitrove" --root private-state
```

The plan checks the collection, lock, object hashes and private state, and
requires both roots to be clear of pending transactions. It inspects all the
retained entries in the selected root. It accepts recognized completed
tombstones whose file ID matches, including device-only mismatches. It stops
on file-ID changes, unknown entries, unsafe filesystem boundaries, or unfinished
cleanup batches.

After reviewing the counts, preserve one root by passing its plan digest:

```sh
kitrove recover preserve --environment "$HOME/Kitrove" --root collection --confirm '<digest>'
```

Plan again for the private state before confirming that separate operation.
Use the same collection path and private-state location for both operations.
Each confirmation moves one entire retained directory into
`.kitrove/removal-quarantine-preserved-v1` under the chosen root. The move keeps
the directory and files intact, including their original retained names. Keep
this private holding directory in place. Kitrove will refuse a second move to
the same holding location.

Run `kitrove doctor` once both roots have been reviewed. If it reports a blocker,
pause and share the report. If preservation reports `recover.preserved_needs_review`,
check the holding directory with a recovery reviewer before attempting another
write. The rename may have completed before final verification failed.
