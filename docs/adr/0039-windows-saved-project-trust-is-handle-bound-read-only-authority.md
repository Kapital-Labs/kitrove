# ADR-0039: Windows saved project trust is handle-bound read-only authority

- **Status:** Accepted with native Windows evidence
- **Date:** 2026-09-02
- **Deciders:** Kitrove maintainers
- **North Star invariants:** NS-02, NS-04, NS-05, NS-07, NS-09, NS-10

## Context

Pi project extensions execute only when Pi's saved trust store contains an effective affirmative
decision for the selected project or its nearest recorded ancestor. Kitrove already parses this
bounded file on Unix and binds its exact path, bytes, selected decision, and project anchor into
planning and confirmation. Windows currently refuses the same workflow because portable metadata
cannot establish who may replace the trust file or its ancestors.

This is integrity authority over an external, read-only harness file. It is not Kitrove private
state: Kitrove must not require its exact protected private-state DACL, change its owner, repair its
permissions, or write a trust decision. Path-only ACL inspection would separate the bytes from the
authority that justified reading them.

## Decision

Extend the existing non-published Windows security boundary with one bounded integrity-read operation.
Reuse the executable validator's canonical local-DOS path parser and component-by-component handle
traversal rather than adding a second path walker. Every component is opened without following a final
reparse point, checked against its canonical path, and retained with `FILE_SHARE_READ` only—never write
or delete sharing—until the bounded file read finishes. Native handles remain private to that operation.

Directory owners may be the current user, Local System, Administrators, or TrustedInstaller. The
regular-file leaf must be owned by the current user, matching the Unix trust-file rule. For every
directory and the leaf, require a present non-NULL DACL, reject a malformed or unrecognized DACL entry, and reject any effective untrusted
grant that permits changing ACL/owner/attributes or deleting the object. Also reject untrusted child
deletion on ancestors, child creation/deletion in the immediate parent, and file data append/write on
the leaf. Deny entries and untrusted read-only grants do not create mutation authority and may remain.

The operation returns only `Bytes`, `Missing`, `Limit`, or `Unsafe`. Read the at-most-one-megabyte
trust store through the retained leaf handle whose owner/DACL was validated. Read-only sharing on
every retained handle means a conflicting pre-existing writer/deleter prevents inspection and no new
one can appear during the read. Hash and parse only those handle-derived bytes. `Missing` maps to the
existing `Unknown` status, `Limit` retains the existing limit error, and every other native or
authority failure maps to the existing unsafe error without a second core path/stat read.

Separately handle-canonicalize the already-existing project directory without following reparse
points, producing the actual local-DOS component spelling that Pi's
`canonicalizePath(resolvePath(cwd))`/`realpathSync` lookup uses. Preserve Windows trust-store keys as
raw strings during parsing. Walk the canonical project path and its parents using backslash-separated
Windows strings and exact key lookup, matching Pi's `data[currentDir]` behavior; portable slash
normalization must not participate. A differently cased or slash-variant key never grants trust. If a
stored key is Win32 ordinal-equivalent to a candidate but not exactly equal, reject the store as
ambiguous rather than silently giving it authority. A reparse alias project anchor is rejected by
Kitrove's no-follow target policy even though Pi itself would resolve it.

The trust-store namespace rejects UNC, verbatim/device, alternate-stream, dot-component, reserved-name,
and opened-path-spelling disagreement forms. Ordinary case-insensitive local-DOS input remains
supported and is bound to the opened canonical path. Hard links are not claimed to be aliases this
walker rejects: the current-user leaf-owner rule, DACL policy, read-only sharing, retained identity,
and same-operating-system-user threat boundary govern alternate hard-link names.

Confirmation and transaction commit continue to call the existing full trust inspection, so they
reopen and revalidate the complete path, canonical project anchor, bytes, and effective decision
before destination mutation.

Core receives only the four semantic read outcomes plus the canonical project path and retains the
existing redacted public error taxonomy. No raw handle, SID, ACL, or operating-system status enters
product models or output.

## Alternatives considered

### Require Kitrove's exact private-state DACL

Rejected because Pi owns this file and may legitimately use inherited user-profile ACLs. Kitrove
needs integrity, not exclusive private-state ownership.

### Inspect ACLs after the portable read

Rejected because a replacement can make the inspected path differ from the file that supplied the
trusted bytes.

### Repair the trust store during planning

Rejected because planning is read-only and Kitrove has no authority to change Pi's trust state or
permissions.

### Accept the current user as the whole threat boundary without ACL inspection

Rejected because Windows ACLs may grant another principal write, delete, or replacement authority.

## Consequences

### Positive

- Windows project-scoped Pi extension planning can consume the same exact saved-trust contract as
  Unix without introducing a Windows-only product policy.
- Executable paths and external integrity files share one bounded native path-authority implementation.
- Read-only planning never repairs or creates harness state.

### Negative

- Non-local-DOS paths, reparse-based profile/project layouts, unsafe inherited ACLs, and files with an active
  writer/deleter remain unsupported and fail closed.
- The current-user leaf-owner requirement may reject centrally provisioned trust stores even when
  their DACL is otherwise restrictive.

### Follow-up

- Reassess owner and namespace policy only with concrete native evidence and a new threat review.

## Validation

- Native unit tests cover ordinary inherited user-profile ACLs, bounded handle-derived reads, Unicode
  canonical paths, present empty versus absent/NULL DACLs, malformed/unknown ACEs, untrusted file
  write/delete, immediate-parent replacement authority, ancestor deletion authority, reparse and
  unsupported namespace paths, active writer/deleter handles on the leaf/immediate parent/ancestor,
  and proof that refusal never repairs ACLs. Owner-policy tests prove current-user leaf acceptance and
  System/Administrators/TrustedInstaller leaf rejection while retaining those directory-owner options.
- Native project-path tests cover exact handle-canonical casing, slash and component-case key variants,
  reparse aliases, and a nearer canonical decline alongside an aliased affirmative entry.
- Core tests prove missing, declined, malformed, oversized, unsafe, and exact trusted outcomes retain
  the existing error/status semantics and that confirmation-time revocation refuses before mutation.
- A real Windows CLI fixture proves saved-trust project plan/apply and post-confirmation trust-decision
  and ACL refusal through the
  production adoption, trust, version-probe, confirmation, receipt, and transaction paths.
- Formatting, strict linting, stable and Rust 1.85 compilation, governance, native Windows evidence,
  and fresh clean-code and adversarial-security review pass before acceptance.
- Final implementation/evidence head `46b6e3f1e5847446936fd27c41136d1daaa069bf` passed focused
  native Windows run `33653086327`, including all five focused Windows saved-project-trust core
  tests, all six CLI integration tests, and complete CLI compilation on Rust 1.85.0, after unanimous
  clean-code and adversarial-security approval. The final evidence additionally proves
  least-privilege structural traversal without DACL-read authority, exact-parent trust inheritance,
  and project-scoped successful receipts.

## Supersession

This completes the saved-project-trust follow-up in ADR-0036 and the explicit exclusion in ADR-0038.
It should be superseded if Pi changes its trust-store contract or Kitrove adopts a different signed
project-authority mechanism.
