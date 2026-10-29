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

### Credential-free hosted ticket control (2026-10-27)

A manual-only main workflow may validate the two exact hash-pinned, previously
authenticated public RC4.2 images on the existing ARM macos-15 hosted runner. It
has contents-read only, no protected environment, secrets, OIDC, artifact upload,
inputs or signing activation. Refuse non-hosted/non-Mac/non-main/non-dispatch
contexts and any present production signing activation. Fetch bounded HTTPS
without downgrade; verify pinned bytes before native parsing and retain no-follow
file identity through signature/team and read-only ticket validation. No mounting,
product execution, signing, stapling, notary submission, Keychain/trust mutation,
network workaround or retry is introduced. Emit only known target/hash, source
commit, closed failure category/numeric status and unchanged-byte evidence.

Use the existing owned-process boundary. Cancellation/unconfirmed cleanup stops
further controls, and only public control inputs remain until ephemeral-runner
destruction. These checks are diagnostic controls, not installation, provenance,
new release authority or acceptance of failed/partial RC5.3 artifacts. A passing
control cannot prove why fresh tickets failed inside the credential-bearing job;
any later credential-bearing investigation still requires separate approval.

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

### Explicit protected fresh-image diagnostic (2026-10-28)

The operator separately approved a nonpublishing fresh Apple image diagnostic and
temporary main access to the existing protected release environment. Retain its
required reviewer and no-admin-bypass rule; remove temporary main access and the
exact diagnostic SHA after success or failure. Production signing activation stays
absent. This approval creates no release tag, version, publication, channel update,
retry of failed release jobs or authority to reuse their partial outputs.

A separate manual/main/exact-SHA workflow builds both Apple targets on independent
ARM macos-15 runners, with no credentials or OIDC. Source version comes from the
reviewed workspace manifest and must already exist in the compatibility catalog;
using that label as a tool argument does not create or overwrite a Git tag. Use
the existing pinned host tool, notice reproduction and target-bound handoff.
Each signer receives its expected inventory digest directly from its named build
job, not from the downloaded artifact. Signers use only the existing Apple helper
and protected credentials, with contents-read only and no OIDC or publication jobs.

An optional operator-local cleanup observer runs only after the original Keychain
search list was restored, the temporary Keychain is absent, and its private
directory removed. It does not alter ordinary release behavior or grant success
to a failed primary operation. Cleanup uncertainty or cancellation prevents
subsequent controls and all diagnostic evidence upload. A primary preparation
failure remains a failed job even if a later read-only control passes.

Only after confirmed cleanup may the diagnostic retain the exact expected image
leaf in a fresh evidence directory: reject redirected parents/leaves, nonregular
or multiply linked files, oversized data, changed identity/bytes and occupied
destinations. Record an independently checked copy digest. Run read-only signature
and ticket checks against that copy with raw native output discarded; do not
mount or execute a failed image, re-sign it or resubmit it. Successful preparation
still requires the original final archive/container verification commands.

Upload only a fixed-name diagnostic JSON record and image, for one day, after
the explicit evidence-ready output. Never upload credential directories, raw
provider/account/path output or arbitrary runner files. Safe existing receipt
records are revalidated for exact source/target before inclusion. The record is
always marked diagnostic-only and unpublished; incomplete images confer no
release or installation authority. Old passing image controls and current
Accepted notary logs do not establish the historical failed artifact's cause.

### Approved existing-ARM-image attachment diagnostic (2026-10-29)

The maintainer separately approved one hosted, credential-free ticket attachment
diagnostic after the exact retained ARM image passed local attachment. Use the
original standard ARM macos-15 runner label and the same fixed diagnostic image;
do not rebuild, sign, submit to notarization, mount or execute the product.

A manual/main/configured-actor-only workflow may grant contents-read and the
built-in repository-scoped Actions-read token to its input-fetch step. This is
not an artifact-ID-specific server permission: code additionally pins exactly one
producer run/attempt/source/repository, artifact ID/name/size/ZIP digest, component
hashes, expiry and Accepted image receipt. No local token or presigned URL is
transferred into CI. Never forward Authorization to blob redirects, log credentials
or raw response bodies, or accept unchecked extraction paths. Refuse expired or
unavailable inputs, unknown inventory, links, oversized data and changed bytes.

The native step receives no token, protected environment, secrets, OIDC or signing
activation. Preserve the original snapshot; attach the existing ticket exactly
once to a fresh private copy, then require the existing full strict Developer ID
and ticket checks. Retain only closed native error-domain/code/status/elapsed/hash
observations. No new image upload, retry, firewall/TLS/trust change, release or
publication authority. Attempt-one/context/one-run guards and an exclusive operator
dispatch record prevent reuse of this scoped approval. A passing control does not
recover the historical underlying error or establish production acceptance.

NS-07/NS-09 and INV-07/INV-12 remain enforced. Capability discovery/adoption,
portable/native content, fidelity, provenance/receipts and synchronization/conflict
behavior are unchanged. Other readiness monitoring remains paused by the human.

## Validation

Synthetic structured response tests cover accepted, pending, rejected, malformed,
oversized and secret-bearing provider output. Real harmless subprocess fixtures
cover normal completion, timeout, cancellation and descendants that ignore TERM;
assert cleanup completes before the caller resumes credential cleanup. Run full
stable and Rust 1.88 validation, review the combined tree and require public checks
before merging. These tests use no credentials, signing provider or release upload.
