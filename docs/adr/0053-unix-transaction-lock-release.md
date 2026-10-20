# ADR-0053: Unix transaction guards explicitly release their locks

- Status: Proposed; validation in progress
- North Star: NS-05, NS-07, NS-09

## Context

Main's Linux recovery test failed when a completed transaction's lock was still
occupied. Unix `flock` belongs to an open-file description, not an individual
descriptor: `dup` and `fork` can keep it alive after the original descriptor
closes. Close-on-exec does not eliminate the interval between fork and exec.

A deterministic regression duplicates the guard's descriptor, drops the guard,
and attempts immediate reacquisition while the duplicate remains alive. The old
implementation fails this test. This reproduces a mechanism consistent with the
CI failure; it does not prove which concurrent child held the original CI lock.

## Decision

On Unix, explicitly unlock when the transaction guard drops, before closing the
descriptor and releasing parent-directory protection. Retry interrupted unlock
calls. If the OS rejects unlock for another reason, field destruction still
closes the owned handle; it cannot justify retries or bypasses in a later writer.
Windows retains its existing handle-close semantics.

This changes lock lifetime, not transaction authority, acquisition order or
contention policy. No lock files are deleted, no lock errors become success, and
no recovery checks are weakened.

## Validation

The regression must fail before the fix and pass afterward. It also proves a
second writer remains blocked while a new guard is held and dropping the old
duplicate does not release that new lock. Existing batch recovery, complete
local CI/MSRV, and native Linux/Windows public checks remain required.

Reference: [Linux flock semantics](https://man7.org/linux/man-pages/man2/flock.2.html).
