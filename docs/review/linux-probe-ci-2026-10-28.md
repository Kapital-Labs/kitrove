# Linux probe CI diagnosis and fixture isolation

## Scope and evidence

Separate from the held nonpublishing Apple diagnostic. Signing stays off and
no release/version/tag/channel or environment-policy action is authorized here.
PR93's unchanged renderer fixture failed on Ubuntu24.04.5 with a generic
`version.probe_failed`; the original operation/errno was discarded. Its
historical cause remains unknown, not a proven Ubuntu26/load/timeout regression.

Native Linux reproduction of the original write/chmod/probe fixture pattern
under eight parallel workers returned one failure in800 probes. Closed
diagnostics identified `Launch / ExecutableFileBusy`. This demonstrates a real
fixture failure mechanism, not recovery of the historical hosted errno.
Ten full traced CLI suites and forty focused traced runs passed; passing
repetitions do not disprove the separately reproduced failure.

Linux refuses exec while another process holds the executable open for writing.
Forked children inherit the parent's open file descriptions until close/exec,
including the interval before a close-on-exec writer is closed. See the primary
[execve](https://man7.org/linux/man-pages/man2/execve.2.html) and
[fork](https://man7.org/linux/man-pages/man2/fork.2.html) manuals.

## Repair and boundaries

- Only Unix CLI fixture creation moves into a test-only child that creates two
  fixed synthetic scripts and exits. The parent reaps that exact writer before
  the real production probe. No parent writable executable descriptor can be
  inherited by concurrent parent spawns. There is no fabricated version proof.
- Both existing CLI fixture users retain all original plan/rendering assertions.
  A normal parallel regression verifies actual bytes, version and hash-bound
  opaque evidence. The ignored entry is a child-only writer, not a skipped
  regression; all executable materialization still uses the real probe.
- A deterministic Linux regression keeps a writer in an owned child, proves
  launch still refuses as busy, kills/reaps that holder, then verifies success.
  Production does not retry or accept a busy executable.
- Private failure diagnostics retain only a fixed operation, standard closed
  I/O `ErrorKind`, or fixed channel outcome. Raw errors/paths/content/environment
  are discarded. Public code/message/Display and CLI JSON remain unchanged;
  debug can distinguish launch, wait, reader creation/read and channel outcomes.
- Five-second production timeout, output bound, environment minimization,
  executable identity/hash checks and process-group/Job cleanup are unchanged.
  Cleanup failure still takes precedence over a wait I/O failure. No ownership
  guard, timeout assertion or original assertion is weakened.

## Architecture and security review

ADR0036 is amended. NS-07/09 and INV-10/12 remain intact. No discovery/adoption,
portable/native representation, fidelity/loss semantics, provenance, receipts,
synchronization/conflict or machine-local authority change. No dependency,
lockfile, signing workflow, permission or credential change. All new fixture
writing is test-only and the tests never execute capability-provided code.

Manual full-diff/caller review, not independent-agent sign-off. Require full
stable/Rust1.88 canonical validation, fresh audit/license/governance and exact
public required checks with fresh green prior main before guarded squash;
verify exact repaired main before resuming the separately reviewed diagnostic.
No production-artifact, clean-Mac, Intel-runtime or exhaustive-review claim.
