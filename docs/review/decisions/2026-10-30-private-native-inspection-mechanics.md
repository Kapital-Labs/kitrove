# Private native-inspection prerequisite review

Approved scope: prerequisite to narrowly bounded read-only ticket recovery, with
signing/releases/readiness off. This change moves shared mechanics only; it does
not add a ticket caller, native request, retry, permission, dependency or lock edit.

## Product, architecture and security

NS-07/NS-09 release-inspection boundary only. Identity/secrets stay local; a failed
inspection never grants acceptance. Discovery/adoption, portable/native content,
fidelity, provenance/receipts and synchronization/conflict semantics do not change.

One physical private source for lifecycle, output and failure types avoids copying
cleanup policy. Including private modules does not expose an arbitrary-command API.
Existing version-probe public entry points and Windows contained launch remain
unchanged. Probe-specific tests stay with their caller. The production governance
scanner includes the common source directory; only its exact Unix lifecycle path
inherits the former launch exception. Retired/adjacent paths remain denied.

Shared-only source edits also select the existing OS-sensitive CI path. The exact
inline classifier regression is red before adding this one path alternative and
green afterward; lookalike roots remain excluded. No permissions, job inventory,
protection summary, signing workflow or timeout changes. The preliminary full
stable/MSRV pair passed on the extraction-only tree; final validation must repeat
after this classifier addition rather than substituting the earlier passes.

Review the moved source and all callers, including normal exit, Drop, timeout,
descendants, output limits and private IO diagnostic conversion. Do not describe
the existing reaping/signal result as stronger than its original contract. Any new
ticket adapter must separately meet its stronger per-attempt cleanup contract and
the outer supervisor's cancellation boundary before it can be wired into runtime.

## Evidence and conditions

Before extraction, 31 Rust probe tests passed with5 pre-existing ignored tests;
61 ticket Python and14 owned-process Python baseline tests passed. New shared-source
tests failed because no common private source existed. The exact governance test
failed with the former source exception, then passed with the narrowly moved
exception. The initial overly specific Rust selector ran0 tests and is not red
evidence. Moving output tests initially omitted three lexical imports; the compile
failure is retained and imports restored without changing assertions.

One existing governance-positive fixture still named the retired lifecycle path;
it now names the exact moved path, while retired and adjacent negative assertions
remain. The new scanner fixture's omitted test-local imports were corrected before
its actual red/green assertion proof. No source error or invalid selector counts
as a regression test. All initial failures and preliminary passes are retained.

Complete full stable/MSRV, fresh audit/notices/governance/secret scan, full-diff and
caller review, then exact public checks before any guarded merge. This is manual
review, not an independent-agent/exhaustive repository sign-off. Source tests and
mechanical equivalence are not proof of Apple provider recovery. Do not run another
signed diagnostic, publish an image, resume maintenance or implement Intel scope
changes from this prerequisite alone.
