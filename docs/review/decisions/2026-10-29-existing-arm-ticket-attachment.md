# Existing ARM ticket attachment on the original hosted runner

## Decision and conditions

The maintainer approved one hosted, credential-free attachment diagnostic on the
same retained, already-notarized ARM image after local copy-only attachment passed.
Use the original standard ARM macos-15 label, not a speculative OS switch. Keep
other readiness monitoring paused. This changes only a disposable diagnostic copy;
it grants no new signing, notarization, release, version or channel authority.

## Product and architecture review

This is not new portability/configuration functionality. No discovery, adoption,
native preservation, fidelity, capability identity, provenance, trust, receipt,
sync, conflict, rollback or local-only behavior changes. Intel is outside the
upcoming preview scope, but production target/catalog removal is separate and is
not implemented by this diagnostic-only change. No dependencies or lock change.

## Security and implementation review

Manual/main/configured-maintainer/attempt-one controls and an exact checkout bind
execution. The fetch step has contents-read and explicitly approved repository-
scoped Actions-read. Code pins the producer run/attempt/source/repository, one
artifact ID/name/size/expiry and ZIP/component digests; this is not a narrower
server-side grant. A fixed HTTPS API path may redirect only to the closed GitHub
artifact blob host, using a new request without Authorization. No local token or
signed URL is transferred to CI, printed or persisted.

Decode only the exact two bounded regular ZIP members in memory; reject traversal,
duplicates, links, unknown inventory, changed hashes or receipt/source mismatch.
Refuse unavailable or expired input without substitution, refresh or reupload.
Write exclusive private originals/bindings only after authentication. Native work
checks the binding and original identity/hash and uses a separate private copy.
The native child environment has no token, secrets or account credentials. Require
the canonical full Developer ID literal, make one bounded attachment call, and
then require strict signature and native ticket validation. The existing owned-
process helper controls cancellation/descendant cleanup; uncertainty stops work.
No raw native/provider/account/path output enters logs, only fixed observations,
closed error domains/numeric codes/statuses, timing and image/context hashes.

No protected release environment, OIDC, signing activation, Keychain/account
lookup, signing/new submission, mount/product execution, artifact upload,
firewall/TLS/trust change or automatic retry. Single workflow history and an
exclusive operator dispatch record prevent approval reuse. The original stays
unchanged; partial/failed diagnostic output is never release authority.

## Evidence and validation

Synthetic tests exercise input pins, expiry, source/context/first-run binding,
Accepted receipts, bounded ZIP parsing, private file/exclusive write behavior,
token-free redirects, fetch-before-write refusal, native command sequence,
signature refusal, original mutation, primary native failure, cancellation and
cleanup uncertainty. No network or Apple operation runs during these tests.
Full stable/Rust1.88 checks, fresh audit/notices/governance/secret scan and manual
complete source/caller review are required before commit. Exact public required
PR checks and fresh green prior main precede guarded merge; exact merged main must
be green before the single dispatch. This record is a manual review, not an
independent-agent or exhaustive repository sign-off.

## Unresolved concerns and reassessment

The exact image was accepted by Apple and its strict signature passed; local
copy-only attachment now succeeds. Historical hosted attachment exit68 and its
missing-ticket consequence65 do not identify a service/transport root cause. A
failure here can expose the underlying error for this new invocation, not prove
the historical cause. If the hosted test passes, historical failure remains
unreproduced/unknown; do not claim a speculative repair or publish another RC.
If input expires, refuse rather than generating another image. Any further
experiment or production change must follow discriminating evidence and scope.
