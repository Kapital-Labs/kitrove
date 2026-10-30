# Library probe fixture isolation

## Actual failure and scope

PR100's supplemental run41116900442 failed Ubuntu's existing
`bounded_probe_binds_the_entry_hash` with closed `Launch / ExecutableFileBusy`.
This current errno is known; the historical October28 hosted errno remains
unknown. Its earlier repair covered CLI fixture writers, not the library's two
test helpers, which still wrote the soon-executed script in the parallel parent.

Linux documents [ETXTBSY](https://man7.org/linux/man-pages/man2/execve.2.html) when
an executable is open for writing. A [forked child](https://man7.org/linux/man-pages/man2/fork.2.html)
shares open file descriptions until close/exec; close-on-exec does not eliminate
the pre-exec interval. The earlier native reproduction and deterministic held-
writer regression establish that mechanism. The exact short-lived holder in this
run was not captured; do not claim its PID, a timeout, OS regression or Apple cause.

This separate CI remediation is test-only under the approved diagnosis/repair
scope. It does not reopen or change the completed CLI repair. Signing stays off;
no release, image check, provider/account call, permission or channel action.

## Repair and safety

Move the library's synthetic script creation into an exact child-only test entry,
following the reviewed CLI pattern. The parent selects only its fixed test binary,
allowlisted fixture basenames and bounded synthetic body; the child writes the
same bytes/mode and exits. Reap that exact writer before the real production probe.
Only the isolated child holds the script for writing. No fabricated version or
hash evidence replaces the original probe.

Also isolate the Linux intentional held-writer case from unrelated parallel
spawns. Its exact refusal, closed launch-kind assertion, holder kill/reap and real
success afterward remain unchanged. That intentional writer now exists only in
the single selected child case, not the parallel test parent. The new ignored
entry is a child-only writer invoked by normal parent tests, not a skipped product
regression. Windows has no new fixture runtime; the module is test-only/Unix-only.

A mechanical proof confirms all pre-test production source bytes are unchanged
after removing the exact cfg(test) declaration. Probe entry points, error policy,
five-second production/one-second test deadline, environment minimization,
identity/hash and cleanup/output checks are unchanged. No production retry,
dependency/lock/version, trust, signing workflow or permission change.

## Tests and review

The new creator regression failed before implementation at the explicit fixture-
publication assertion, then passes with real bytes/version/hash-bound evidence.
An initial new four-probe stress topology hit the existing one-second test budget;
that log is preserved, not a proven scheduler/load attribution. The corrected
test targets writer inheritance: four concurrent writers feed one real probe
consumer. All40 byte/version/hash assertions remain; every writer is joined before
asserting results. This does not claim new parallel inspection performance or
extend any deadline. Focused crate validation passes33 tests, with the five existing
ignored tests plus one child-only writer entry. Linux's held-writer regression
still must refuse a busy executable rather than retry or accept it.

Manual full-diff/caller review, not independent-agent/exhaustive review. This is
the existing ADR0036 test-isolation boundary, not a new product architecture. No
discovery/adoption, portable/native fidelity, provenance/receipt, sync/recovery or
machine-local authority changes. Require full stable/Rust1.88, fresh audit/license/
notices/governance/secret scans, exact public checks and green exact main. Hold the
owned-ticket feature until this separate remediation is accepted; do not blind-
rerun a failed unchanged candidate or weaken assertions to manufacture green.
