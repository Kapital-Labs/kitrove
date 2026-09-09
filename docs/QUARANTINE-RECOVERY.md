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
