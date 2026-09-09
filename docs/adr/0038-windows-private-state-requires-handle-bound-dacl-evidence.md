# ADR-0038: Windows private state requires handle-bound DACL evidence

## Status

Accepted. Native Windows runtime evidence is recorded in
`docs/review/decisions/2026-09-01-phase6-windows-private-state-acceptance.md`.

## Context

Kitrove treats machine-local state, receipts, executable trust, and recovery journals as private
authority. Unix implementations verify ownership and permissions through already-open capability
handles. Windows has no equivalent mode-bit contract: a directory can appear ordinary through the
shared metadata API while its discretionary access-control list grants another principal access.

Read-only operations must never repair permissions. Mutating operations may repair a directory only
after proving that the selected handle still names a non-reparse directory owned by the current
process user. Path-only ACL inspection or repair would reopen the ancestor and replacement races
that the capability-root design otherwise excludes.

The shared metadata inode is also not complete Windows identity authority: ReFS can expose a
128-bit file identifier. Any later Windows identity-bearing cleanup or executable trust must use the
native handle identity rather than truncating it into the Unix-shaped metadata type.

## Decision

Add one Windows-only, non-published workspace crate that contains the minimum Win32 FFI needed to:

1. read a complete volume serial number and 128-bit file identifier from an already-open handle;
2. read the owner and DACL from an already-open file or directory handle;
3. require an owner equal to the current process user and a protected, canonical DACL containing
   only the exact current-user and Local System full-control entries; and
4. atomically create new empty objects with current-user ownership plus the exact DACL, and
   replace only the DACL on an existing current-user-owned object during authorized mutation.

Ownership is never taken from or rewritten on an existing object. Create-time owner assignment is
required because an elevated Windows token may otherwise assign its Administrators group as the
default owner even though the object was created by the current process user.

The safe public wrapper owns every returned allocation and handle and exposes only structural
success or failure. Raw pointers, SIDs, ACL buffers, and Win32 status values never enter Kitrove's
core types or user-visible errors. The crate pins `windows-sys` exactly and enables only the Windows
API features used by this boundary.

Core read-only state opening requests `READ_CONTROL`, verifies the exact private directory
descriptor, and fails closed without mutation. Every nested private directory and authority file is
verified from its opened no-follow handle before its bytes are trusted. Directories require the two
full-control ACEs with object-and-container inheritance flags; regular files require the same exact
trustees and masks with no inheritance flags. Already-authorized mutation requests
`READ_CONTROL | WRITE_DAC`, first proves owner and safe object identity, installs only the matching
exact protected DACL if needed, and then re-reads and verifies it. New directories and files are
created relative to the open parent with the final owner and protected DACL supplied atomically to
the native create operation. Its rollback-capable creation handle verifies the kind and exact
descriptor; any initialization failure marks that same still-empty object for deletion before the
handle closes, without reopening its name, and reports a distinct failure if deletion could not be
scheduled. A verified directory then closes the creation handle and reopens a confined,
no-delete-share capability handle, accepting it only when its complete native identity and exact
descriptor still match. A replacement during that handoff is never returned or mutated. No
create-time or repair handle needs `WRITE_OWNER`, and no post-creation owner rewrite occurs. A new
private file is secure before any authority bytes are written.

The shared bounded tree capture accepts a same-handle validator so retained sync-base generations
reuse the existing no-follow traversal while checking every opened root, descendant directory, and
both file handles. Private object-tree staging threads the store security policy through the existing
directory and file creation helpers. Inspection-only private stores also reject creation, rename,
exchange, quarantine, and removal at their shared mutation boundaries.

Pi's saved project-trust file remains read-only. Windows support may be enabled only after the file
and each existing ancestor are opened without following reparse points and their owner/DACL evidence
is verified. This ADR does not by itself authorize Windows harness execution.

## Non-goals

- Windows quarantine deletion, handle-relative rename, or recursive cleanup;
- Windows Pi/OpenCode process execution or job-object containment;
- accepting Administrators, Everyone, inherited, deny, callback, object, or unknown ACEs as private
  user authority;
- taking ownership of or changing ownership after creation, enabling privileges, or using
  path-based ACL setters; and
- weakening the current fail-closed behavior on unsupported filesystems or APIs.

## Evidence required

- native Windows tests for exact private directory and file creation, read-only refusal without
  repair, authorized repair, foreign ACEs, inherited/unprotected DACLs, malformed bounded ACEs,
  reparse points, handle replacement, and identity-bound creation rollback;
- a fixed 128-bit identity vector plus same-handle and replacement tests;
- Windows cross-target compilation, canonical local CI, and independent clean-code and adversarial
  security review; and
- an exact-head native Windows run before the public-release checklist item is closed.

## Consequences

Kitrove gains a reusable native Windows identity and ACL primitive without spreading unsafe FFI
through product code. Windows private-state mutation can become evidence-backed while process
execution and destructive cleanup remain separately fail closed until their own contracts and native
tests are accepted.
