# Core probe writer isolation, 2026-11-19

PR152's corrected head29cee976 failed Linux job135828658163 in run44600027900.
The existing interrupted_extension_restore_returns_to_the_exact_missing_target
case reached its real probe and received the closed diagnostic
Launch/ExecutableFileBusy at apply_batch_transaction_tests.rs:2155. Other core
cases passed. The exact short-lived writable-handle holder was not observed.
This is distinct from the user's unresolved remote batch-storage failure.

The core unit helper wrote its soon-executed pi script in the parallel parent.
Linux refuses execution while a writable handle remains open. A parallel child
may retain an inherited open file description until exec despite the parent's
close-on-exec writer being closed by fs::write. Earlier CLI/library repairs and
the deterministic library held-writer test establish this mechanism; they do not
identify this CI run's holder. Source inventory found one other core real-probe
writer, the extension_materialization integration helper caching two versions.
Its OnceLock does not prevent unrelated process spawns inheriting its writer.
Ordinary data writers and inert shell byte fixtures are outside this repair.

One shared Unix test-only module now publishes both core fixtures through an
exact ignored child entry in the current test binary. Only that selected child
opens/writes/chmods the pi script. The parent clears its environment, supplies
only the absolute fixture root and closed0.83.0/0.84.0 version choice, and waits
for that exact writer to exit before calling the unchanged real probe. Script
bytes and mode0700 are preserved; opaque version/hash evidence remains mandatory.
The integration cache and every existing rollback/restore assertion are unchanged.
The ignored writer entry is invoked by normal tests, not a skipped regression.

On macOS the existing cooperative launch guard is held only around spawn using
its existing five-second acquisition budget, then released before child wait.
The target-macOS core dev-dependency points to the existing workspace process
package; normal Rust1.89 offline Cargo metadata added exactly one root-lock edge,
kitrove-core -> kitrove-macos-process. No package/version/source/checksum changed.
The root owns reviewed-lock binding and complete validation. This creates no
production feature, retry, timeout extension, process authority, global test
serialization or permission change. Native production guards and cleanup remain
untouched. Removing the cfg(test,unix) module inclusion leaves core production
source bytes identical to the reviewed parent.

The hosted failure log is retained as RED evidence. Local focused default-parallel
checks pass: two publication/concurrent-writer regressions, two interrupted
extension restore/update cases including the failed CI case, and all11 extension
materialization integration cases. The creator checks both versions, exact bytes,
mode and real hash-bound evidence. Four writer threads publish40 independent
fixtures to one real probe consumer, targeting writer inheritance without extra
simultaneous probe load. All outcomes and writer joins are collected before
assertions. The existing deterministic Linux held-writer refusal stays unchanged.
The pre-existing unused workspace kitrove-installer warning remains.

These are focused native Mac checks, not a Linux reproduction or full-suite claim.
Require normal stable/Rust1.89, lock/license/notice/governance checks and fresh
public native Linux/Mac/Windows results for the exact final candidate. No blind
rerun of the failed unchanged candidate, signing, release or publication follows
from this repair note. No broader product architecture or ADR change is needed:
this applies the existing test-fixture isolation boundary to two missed callers.
