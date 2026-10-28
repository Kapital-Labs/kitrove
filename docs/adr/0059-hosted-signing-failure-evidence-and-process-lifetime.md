# ADR-0059: Hosted signing retains safe evidence and owns child lifetimes

Status: Accepted for implementation under the signing repair authorization; validation pending

## Context

An Intel Mac preparation failed during notarization after other platform signing
jobs succeeded. Generic error redaction discarded structured submission identity,
preventing safe diagnosis of a pending or rejected submission. Separately, a
synthetic timeout demonstrated that killing the Python wrapper's immediate child
can leave native descendants alive during Keychain cleanup.

## Decision

Retain only validated, bounded notarization receipt fields: submission UUID,
known provider status or fixed failure category, exact submitted artifact digest,
reviewed target, and source commit when supplied by the approved hosted context.
Never emit raw provider output, arbitrary messages, account identifiers, credential
values or machine paths. A receipt is diagnostic evidence only: it does not grant
signature, acceptance, publication, retry or resubmission authority. Failure still
refuses preparation and preserves existing signed artifact authority.

The hosted operator wrapper owns an isolated process group for each native
operation. Timeout, cancellation, abnormal exit and surviving descendants require
bounded group termination and direct-child reaping before credential cleanup.
Unconfirmed cleanup refuses success. Signal handling must not leak provider
output or allow an interrupted operation to continue using signing credentials.
The ephemeral hosted-runner boundary remains required for abrupt termination
that cannot execute cleanup handlers.

No automatic signing retry, notarization resubmission, release tag change or
publication is introduced. The existing protected release approvals remain.

### Cleanup diagnostic refinement (2026-10-23)

An exact merged-main cancellation test failed in the process-group existence
probe; generic redaction hid the OS error class. Retain a closed category for
probe permission denial, interruption, other OS error, cleanup deadline or
unclassified failure. The exception message remains constant, arbitrary category
inputs collapse to unclassified, and no raw OS/provider text, identifiers or
paths leave the boundary. These categories are evidence only, never proof of
absence or authority to continue credential cleanup. Add fault-injection tests
and repeated harmless Mac process-tree checks before interpreting hosted failure.

A local Darwin fixture confirms a zombie-only group yields permission-denied
until its owner reaps it. During bounded cleanup, such a probe is unknown, not
absent. Continue reaping and probing within the existing TERM/KILL deadlines;
signal only a positively observed group. Success still requires both direct-child
reaping and an absent-group result. Persistent denial or other probe errors
refuse cleanup and retain private state; no permissions, deadlines or retry/
submission authority are broadened. This reproduced failure mode is consistent
with the hosted stack; its original suppressed errno cannot be recovered.

## Invariant and product impact

### Repair-only ticket and prerequisite diagnostics (2026-10-27)

For the two fixed Apple ticket operations only, preserve a closed launch category
(`not-found`, `permission-denied`, `other`), abnormal termination, or numeric
nonzero exit status in 1..255. The Python boundary forwards only an exact complete
xtask error line with the fixed label and allowed status suffix, including its
known incomplete-image wrapper while discarding that wrapper's path. Never emit arbitrary stderr,
stdout, argv, OS error text or provider messages. Ambiguous/malformed evidence is
discarded; the original failure still refuses preparation. No ticket/signature
gate, cleanup deadline, notarization submission or signing retry changes.

Before authentication, the two unchanged checksum-pinned Windows prerequisite
downloads may make at most three fresh attempts for typed transport interruption
(`ResponseEnded`, connection/name-resolution error, timeout). Use bounded
connection/operation timeouts, fixed package/attempt/category diagnostics and
fresh attempt files. Unknown errors, HTTP status errors, hash mismatch, extraction
or Microsoft publisher failures do not retry or fall back. Existing TLS, digest,
Authenticode, protected approval and credential-cleanup gates remain mandatory.
No signing/release/rehearsal is authorized by these source repairs. Historical
RC5.3 ticket-validation exit codes and the interrupted download identity remain
unknown; synthetic tests prove the repaired boundaries, not provider recovery.

NS-07/NS-09 and INV-07/INV-12 are reinforced. Signing credentials and diagnostic
evidence stay outside capability portable state. Discovery, adoption, asset
identity, portable representation, native variants, fidelity, deployment receipts,
synchronization and conflict semantics are unchanged. No broader execution API,
new platform guarantee or loss of retained native behavior is introduced.

## Validation

Synthetic structured response tests cover accepted, pending, rejected, malformed,
oversized and secret-bearing provider output. Real harmless subprocess fixtures
cover normal completion, timeout, cancellation and descendants that ignore TERM;
assert cleanup completes before the caller resumes credential cleanup. Run full
stable and Rust 1.88 validation, review the combined tree and require public checks
before merging. These tests use no credentials, signing provider or release upload.
