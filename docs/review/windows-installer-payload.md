# Windows installer payload review

The existing payload sequence now uses small Windows native bindings rather than a
second staging transaction. Authentication and compiled-target checks remain shared.
The result retains installer authority only, with no application conversion, launch,
executable publication, state-root access or CLI command.

Windows bindings reuse validated ancestry, private ACL creation, synchronized writes,
identity-bound read-only reopen, exact inventory, single-link inspection and guarded
directory flushing. The retained read lease denies competing write access. Unix mode
0600 is a closed data-policy input, not a Windows permission promise: only that value
is accepted by the adapter, while actual security uses the existing Windows ACL rules.
No new archive parser, signature verifier, dependency or permission repair is added.

Tests cover private exact output, sharing refusal, occupied output, preservation after
drop, retained partial state at each shared boundary and a competing payload before
write. The positive retained-payload test is also selected by the existing standard-user
runner. Native runtime and ordinary-user results are required before merge; a Mac
cross-check cannot establish ACL or sharing behavior. There is no new signing job.

The local MSVC cross-check cannot run because the Mac lacks `ml64.exe`; the installed
GNU Windows target passed all-target compilation and strict Clippy. Canonical host
validation and governance passed. The test-module declarations use the conventional
separate platform and test attributes so governance recognizes hostile test fixtures
without exempting production code. Canonical Rust 1.85.0 validation also passed.
Focused native Windows runtime and standard-user evidence remain required before merge.

NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12 are unchanged. Files remain local and
partial failures are preserved. Discovery/adoption, portable/native content, fidelity,
capability receipts, synchronization and conflict behavior are unaffected. This is
data preparation, not completed bootstrap or native executable acceptance.
