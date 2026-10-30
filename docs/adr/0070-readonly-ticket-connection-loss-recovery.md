# ADR-0070: Read-only ticket recovery is bounded by evidence and ownership

Status: Accepted for the approved source repair; exact validation pending

## Context

A fresh nonpublishing Apple Silicon diagnostic completed signing, three accepted
notarizations, attachment and earlier validation. Its final read-only validation
returned68 with NSURLErrorDomain/-1005, CFNetwork/-1005 and connection-lost evidence
on unchanged bytes. Apple QA1941 describes disconnected requests and distinguishes
retrying idempotent operations from repeating side effects. This observation does
not diagnose every historical attachment failure, an HTTP protocol or network actor.

The maintainer approved narrowly bounded validation recovery and its separate
ADR-0068/0069 ownership prerequisites. Signing and further provider diagnostics
remain disabled during source work. Readiness monitoring remains paused.

## Decision

Only the existing closed `/usr/bin/xcrun stapler validate -v` caller may recover.
At most three total calls, with1s then2s backoff, share one original absolute
CLOCK_MONOTONIC deadline and one retained regular-file/name/byte baseline. The
existing20s cleanup reserve stays INSIDE that deadline. No per-attempt restart,
extra grace or baseline recapture is permitted. Check the same identity before
and after calls and backoffs. A late result or changed image is failure even if
the last native code is0.

Recovery requires native68, confirmed owned cleanup, complete bounded private
output, a connection-lost observation and NSURLErrorDomain/-1005. The only other
permitted error is CFNetwork/-1005; the only optional observation is the known
CloudKit unexpected-response phrase. Unknown/malformed error markers, HTTP status,
other error codes, ticket/signature denials, launch failure, termination, timeout
or cleanup uncertainty refuse recovery. Never infer this class from exit68 alone.

Reuse the approved opaque lifecycle proof before another call. Outer cancellation
and uncertain completion retain the existing credential-preservation/refusal
contract. No promise is made to contain hostile detached processes or to kill an
inner group after uncatchable outer termination. Signing, notary submission/wait,
attachment and their parent preparation calls are NOT retried.

Enable the ARM recovery path only with explicit valid source/target metadata;
hosted metadata must match the actual public-repository source. Fresh diagnostic
metadata additionally keeps its existing exact-source/context guards. Metadata
binds evidence; it grants no signing, dispatch, trust or publication authority.
Unbound standalone callers and existing Intel paths keep single-attempt behaviour.
Intel removal from the upcoming preview is separate pending target/catalog work.

## Evidence and acceptance

Add closed KITROVE_APPLE_TICKET_V2 validation evidence, bound to source, ARM target,
retained image SHA256, original window, ordered attempts and requested backoffs.
Retain original failures even after recovery. Output only known categories,
numeric codes and bounded timings; raw account/path/provider text stays private.
Keep V1 historical inspection strict and separate. Fresh diagnostic callers must
not downgrade validation to V1 or mix/duplicate/reorder phase evidence.

Python revalidates the complete V2 schema and exact expected source/image. Ticket
success alone is never complete acceptance: require the full verifier's exit0
and all existing strict Developer ID, image, archive, payload and provenance checks.
An eventual native0 cannot override identity failure, exhausted ownership or a
later signature/payload refusal. Missing/invalid evidence refuses, not a fallback.

## Verification and product impact

Pure classifier/queue/clock tests cover conservative refusal, max3, exact backoffs,
no deadline extension and unchanged identity. A shared Rust/Python corpus binds
the producer and consumer. Real harmless child fixtures exercise retained bytes,
one deadline and opaque cleanup without any Apple request. Final-verifier tests
cover strict-signature refusal, expected-image binding, downgrade and original
failure preservation. Portable parser/schema cases remain enabled on Windows;
POSIX-only fixtures declare their platform.

Require full stable/Rust1.88, audit/licenses/notices/governance/secret scans,
manual full-source/caller review, fresh exact public checks and green main. No new
dependency, lock, workflow permission, version/catalog/target/channel change is
bundled. NS-07/NS-09 and INV-07/INV-12 remain intact; portable assets, fidelity,
provenance, receipts, sync, adoption and rollback behaviour do not change.

Synthetic success is not provider recovery or production-artifact acceptance.
Any fresh native diagnostic and any later preview release require separate scope;
old failed tags/runs/images and spent approvals are not reusable release authority.
