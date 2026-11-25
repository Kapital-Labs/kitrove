# ADR-0079: Preserve retained cleanup after a device ID mismatch

- **Status:** Implemented for source review
- **North Star:** NS-01, NS-04, NS-07, NS-09, NS-10
- **Related:** ADR-0037, ADR-0038, ADR-0062, ADR-0078

## Context

A Mac reports the same file ID and a different recorded device ID in the first
retained entry under both the portable collection and private state. The full
identity check must continue blocking automatic deletion. A read-only doctor
report does not establish the reason for a device ID change or ownership of a
file whose recorded identity no longer matches.

## Decision

Add a separate, opt-in macOS preservation operation. It moves one entire
root-local quarantine directory to a fixed private sibling using a single
descriptor-relative, no-replace rename. It preserves all directory entries and
their recorded names. Collection and private state are separate approvals.
An occupied holding slot requires further review. Normal cleanup never consumes
that slot. Sync and all ordinary write authority, including the full device/file
check, keep their existing rules.

A read-only plan validates the collection manifest, lock, referenced objects,
private state, and absence of pending recovery markers. It checks the complete
bounded quarantine inventory. Matching file IDs and a device-only mismatch
qualify a recognized, structurally valid entry for preservation. That
observation grants no deletion authority. Unknown entries, file-ID changes,
unfinished cleanup controls and unsafe boundaries refuse the operation.

Apply requires the digest of that exact scope, locks the two authority roots
and takes the existing exclusive private-state lifecycle lock. It rechecks
the plan and pinned directory, then moves the directory and syncs its parent.
There is no partial move within one role. A post-rename finish error leaves
the preserved data in the private sibling for inspection. Repeating apply
cannot replace preserved evidence.

The initial operator review and all tests must use disposable roots. A new
published version and use on actual data require their own decision. No
manual rename or cleanup of individual retained entries is part of the design.
