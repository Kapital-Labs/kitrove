# Immediate setup navigation review

Maintainer approved immediate single-digit selection for the two existing 1-5
menus, readable multiline questions and immediate adoption decisions on November6.
No adoption-conflict behavior changes. Same-name observations
remain ambiguous, and occupied names remain protected; `from TOOL` is still a
one-time explicit selection rather than equivalence or a canonical preference.

Digits return immediately, Enter retains the existing finish default, and
cancellation never grants consent. At a complete nonempty adoption preview only,
Enter or y confirms that exact set. n/s/r/d/q act immediately; individual review
also accepts its existing Enter/y/n/r/q actions immediately. Empty Enter chooses
again, never approves. Initialization, trust, Apply, sync and all other defaults
are unchanged. Paths, names, source filters and multi-item selection retain
bounded line input. Questions and aligned choices occupy distinct lines. The
same input buffer is used throughout, so buffered bytes are not bypassed by an
independent keyboard reader. Mode restoration precedes the next prompt, operation
and error reporting; failure stops setup. The guard also attempts restoration
on unwinding. An uncatchable process termination cannot guarantee restoration.
Real terminal questions discard queued input and accepted-read lookahead so
typing r+Enter cannot approve the first individual preview, or y+Enter advance
another decision. A new PTY regression reproduced this unpublished-draft hazard
before the type-ahead barrier and now requires unchanged fixture bytes. Pasted
selection+Enter cannot approve a preview not yet shown. No confirmation or input
boundary is weakened to make the tests pass; scripted test input stays line based.

Unix uses the already locked rustix1.1.4 termios API; Windows uses a narrow safe
wrapper in the existing reviewed native boundary, owning a duplicate of the input
console handle and restoring the exact original mode bits. The same existing
native APIs discard only pending input on the terminal. No new registry packages
or upgrades: Cargo.lock adds only the CLI's direct rustix edge. Enable
only existing termios and Win32_System_Console APIs. CLI/domain unsafe-code
prohibitions and native-wrapper safety documentation remain intact.

All registry identities/versions/checksums/license expressions and resolved
registry feature sets compare unchanged against the exact parent. Retain the
expected pre-review fingerprint refusal. Reviewed Cargo.lock BLAKE3:
`d3d374914dd20fee5067ea6b30cc5b4c25fbe1bb2e030c941e67f0c650c5af48`.
The existing release notice inventory/material must still reproduce byte-for-byte.

NS-07/NS-09 and ADR0047 remain enforced. No identity, provenance, fidelity,
portable/local state, receipt, lifecycle, trust, Apply, sync, workflow, permission,
signing, version, release, channel or personal-data mutation is introduced.

Baseline43setup tests passed with two existing ignored child fixtures. A real PTY
regression first failed because pressing1 without a newline did not advance.
After implementation the same case advances to a normal line-based path prompt.
Tests also cover immediate cancellation, finish/default navigation, original
terminal-mode restoration and byte-identical disposable initialized collections.
Additional regressions first failed on the old bulk Enter behavior, paragraph
prompt and non-immediate adoption actions. The positive Enter case proves exact
selected-only adoption, untouched native sources, no receipts and no trust grant.
EOF/n/quit tests use a genuinely eligible unique source, not an ambiguous empty
preview. Race injection now also covers Enter-confirmed stale source refusal;
its trigger follows the new real approval row rather than obsolete copy.
Darwin's documented PENDIN retype-state bit is normalized in the test comparison;
all other flags, controls and speeds are exact. The initial strict comparison and
syntax/fixture-initializer failures are retained, not counted as product success.
Full stable/Rust1.88, licenses/notices/audit and complete manual source review are
required before commit; exact public checks and green latest main precede merge.
No native Windows execution or complete release acceptance is claimed here.

Initial hosted Linux validation caught a test-fixture precondition, not a failed
menu assertion: Python's default temporary directory placed local authority under
shared /tmp, which the existing ancestry guard correctly refuses. The same
initialization refusal was reproduced locally with TMPDIR=/private/tmp. The PTY
test now receives an owned trusted_tempdir from the existing testkit, matching
other CLI authority fixtures; Python creates every child beneath that root.
Production path/ancestry checks and all terminal assertions/deadlines are unchanged.
