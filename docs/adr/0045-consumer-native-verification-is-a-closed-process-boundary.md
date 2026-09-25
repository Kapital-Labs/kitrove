# ADR-0045: Consumer native verification is a closed process boundary

- **Status:** Accepted for staged implementation; runtime verification remains unavailable
- **Date:** 2026-09-24
- **Deciders:** Implementation within the approved Phase 6 bootstrap scope
- **North Star invariants:** NS-07, NS-09

## Context

ADR-0041 separates authenticated installer data from executable publication. Native
signature rules now live in `kitrove-release-policy`, but the operator signing tool
uses unbounded process output collection. Copying that invocation into the consumer
would introduce another process implementation and would not provide deadlines,
bounded output or descendant cleanup. Pure inspection text is not signature proof.

The existing version probe owns bounded Unix process-group handling and output
collection. On Windows it uses `kitrove-windows-process` for contained launch and
whole-Job cleanup. Governance currently permits compiled process launch only in
the reviewed version-probe source. This restriction must not become a blanket
exception for installer code.

## Decision

Separate reusable process lifecycle mechanics from closed verification policy.
Extract the existing bounded mechanics without changing version-probe behavior
before introducing a native-verification caller. Preserve the existing Windows
contained-process implementation rather than creating another Windows launcher.
Any governance allowlist adjustment names exact reviewed source files, retains
negative tests for adjacent files, and accompanies the extraction review.

The consumer-facing verifier accepts only an opaque retained installer payload.
It exposes no arbitrary command, script, argument list, environment or caller-selected
verification executable. The implementation selects a fixed native verification
operation on the compiled target and applies the shared release signature policy.
It never executes the downloaded installer to determine whether it is trustworthy.

Required boundaries:

- Authenticate the exact installer archive and target before native inspection.
- Retain and revalidate ancestry, private permissions, file identity and exact bytes
  before and after every native operation. A path or earlier successful check is
  insufficient. Preserve partial state on refusal.
- Resolve verification tools through the reviewed system location and validate their
  ownership, identity and ancestry. Do not use ambient PATH or caller tool overrides.
- Clear inherited environment, supplying only reviewed native-system requirements.
  Do not inherit signing credentials, module overrides or publisher configuration.
- Bound wall time and both output streams. Own the process until it is reaped and
  descendants are terminated; timeout, excess output and cleanup failures refuse
  readiness. Errors must not expose raw command output or credential-bearing paths.
- Pin the reviewed Windows publisher independently of the operator signing
  environment. Refuse unavailable native evidence; never fall back to checksum-only
  or timestamp-text-only verification. Apple verification retains the shared
  Developer ID team, hardened-runtime and secure-timestamp requirements.
- Linux still requires authenticated bytes and retained filesystem checks; lack of
  a native signer is not permission to skip provenance.

Return only retained, nonserializable installer readiness, with no conversion into
application staging, rollback or install authority. Do not expose readiness until
all checks complete. Executable publication must separately revalidate this retained
state and use no-overwrite native helpers; this ADR does not implement publication,
reopening, automatic launch, PATH changes or self-update.

## Implementation order and acceptance

### Apple same-object evidence binding

The Mac helper uses one Security.framework static-code object: validate it with the
shared Developer ID requirement and strict validation, then obtain documented signing
information from that same object. Compare both its CDHash and raw CMS fingerprint
with the captured candidate, require typed hardened-runtime flags and a secure
timestamp, and refuse missing or malformed fields. Captured code pages and supported
embedded metadata must independently match their CodeDirectory hashes. CDHash alone
does not bind a CMS wrapper or timestamp.

Reuse security-framework/Core Foundation wrappers for existing APIs. Isolate the
missing public signing-information binding in a narrow Mac-specific crate, with
explicit ownership and type checks; never use internal-information flags or private
framework fields. This low-level operation grants no retained readiness and must not
be wired into consumer operation before the fixed helper protocol, deadline/output
bounds, retained-object checks and adversarial native tests are complete. No Swift
compiler dependency is introduced for consumers. This implementation detail does not
relax the process-launch allowlist or any acceptance gate.

### Sequence

1. Consolidate process lifecycle and bounded output mechanics, retaining current
   version-probe regression tests, error behavior and environment policy.
2. Add closed native-verification operations with synthetic refusal tests. Reuse
   the shared native-signature rules and native filesystem identity helpers.
3. Bind those operations to retained authenticated installer payloads. Test tool
   substitution, payload changes, redirected ancestry, output overflow, timeouts,
   descendant cleanup and failed cleanup. A failed check grants no readiness.
4. Verify unchanged public candidate artifacts without executing them, with recorded
   independent provenance and native evidence. Require native Windows and ordinary-user
   results for Windows behavior; cross-compilation alone is insufficient.
5. Implement and separately review no-overwrite executable publication. Keep the
   trusted first-verifier requirement and ADR-0043 clean-machine launch gates open
   until observed; the existing signing Mac cannot establish offline first launch.

Each implementation unit receives focused tests, canonical validation, consolidation
review and exact-head hosted checks appropriate to the changed boundary. No signing
rehearsal, new release or credentials are needed to test read-only verification of
already published candidates.

## Alternatives and consequences

Directly importing xtask would couple consumers to signing credentials and operator
tooling. Duplicating process handling would duplicate timeout and cleanup bugs.
A generic public installer command runner would broaden authority beyond verification.
Using existing version-probe entry points unchanged would incorrectly force native
tools into a `--version` protocol. Extracting mechanics first keeps these policies
separate, at the cost of a separately validated refactor before consumer integration.

## Invariant impact

NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12 remain unchanged. Credentials stay local;
trust precedes use; failed operations preserve evidence. Portable capability formats,
native fidelity, ownership receipts, synchronization and rollback are unaffected.

## Evidence status

This is an implementation contract, not runtime or launch evidence. PR #33 established
native Windows private-data staging; PR #34 consolidated signature policy. Neither
implements this consumer verification boundary or closes release acceptance.
