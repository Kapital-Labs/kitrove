# Release provider diagnostics and prerequisite transport repair

## Scope and evidence

Repair only, based on public main a9199d84900c7924e7a8faef0585eed2f68ff735.
No new version, tag, release retry, signing activation, signing rehearsal or
publication. The failed RC5.3 tag/run remain immutable. Signing remains disabled.

Run 40573389165 passed source validation and Linux preparation, but both Apple
jobs failed ticket validation after six Accepted notarization receipts. The
native tool runner and Python wrapper discarded exit/launch details. No failed
image was retained, so the historical native status and provider cause remain
unknown. Do not infer a specific Apple error or network fault. Accepted
notarization is not proof of successful ticket validation or image acceptance.

Windows preparation stopped before authentication/signing: Invoke-WebRequest
reported ResponseEnded. The old log does not identify which prerequisite.
The shared provisioner made one attempt, lacked explicit HTTP timeouts and did
not retain a safe package identifier. A loopback-only HTTP fixture that cuts off
two responses reproduces the typed ResponseEnded failure and exercises recovery
through the real PowerShell HTTP client, without contacting any provider.

## Changes and preserved gates

- Only the fixed Apple ticket labels retain a numeric nonzero exit (1..255),
  closed launch category or abnormal termination. Python accepts only a complete
  fixed error line (including the known image-error wrapper with its path discarded),
  rejects duplicate/nonexact records and bounds captured input.
  Neither boundary prints argv, paths, raw output or provider exception text.
- Windows logs only sdk/client, attempt and closed category. Three fresh attempts
  maximum, two/four-second waits, 30-second connection and 120-second operation
  timeouts. Retry only typed interrupted-response/connection/name-resolution/
  timeout errors, not HTTP status, digest, extraction or publisher failures.
- Refuse occupied attempt files, discard only owned regular attempt leaves, and
  reverify the same pinned digest before extraction. Existing Microsoft publisher
  verification, tool versions/URLs/digests, TLS, credential lifetime, protected
  environment, source identity, ticket/signature gates and permissions unchanged.
- All credential-free tests use harmless commands, synthetic exception objects or
  a loopback server. No native signer, notary submission or Azure login is used.

## Architecture and security review

ADR-0059 is amended. NS-07/NS-09 and INV-07/INV-12 are reinforced, not weakened.
No discovery/adoption or harness behavior changes. Portable representation,
native preservation, asset identity/provenance, fidelity classification,
deployment receipts, ownership, synchronization/conflict semantics and local
credential boundaries are unchanged. This is operator release tooling, not a
general runtime/package installer. No capability data or secret enters diagnostics.
No changed dependency, compatibility catalog or supported-platform guarantee.

## Verification and limits

Test-first failures demonstrate lost Apple status at both boundaries and refusal
of an interrupted download by the original provisioner. Rust tests use harmless
real exit, missing-tool, permission-denied and terminated children. Python tests
exercise the process wrapper, malformed/out-of-range/duplicate record refusal,
and provider canaries. PowerShell tests cover recovery/exhaustion, known versus
unknown failure types, HTTP errors, digest/extraction refusal, fresh files and
occupied-file preservation; the actual HTTP client is tested against loopback.
Run full stable/Rust 1.88 canonical CI and exact native Windows/public checks
before merging. Manual source/caller review, not an independent-agent sign-off.

These tests verify diagnostics and bounded download recovery, not recovery of
Apple's historical failure. No production artifact, fresh-install, clean-Mac,
Intel-runtime or exhaustive repository-review acceptance claim. A future
credential-bearing investigation or release requires separate human approval.
