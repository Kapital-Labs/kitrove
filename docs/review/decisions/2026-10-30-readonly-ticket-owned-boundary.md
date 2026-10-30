# Read-only ticket ownership prerequisite review

Scope: the explicitly approved process-boundary prerequisite, not automatic
recovery or a live Apple diagnostic. Parent source is PR99's reviewed extraction
tree36e6b5b7, now merged unchanged as176ca517. Keep signing, releases and readiness
monitoring off. This review is manual, not independent-agent or exhaustive review.

## Authority and data flow

Only macOS read-only `stapler validate -v` uses the new closed private adapter.
Signing, notarization/wait and attachment keep their existing single-pass calls.
The fixed native environment omits credentials and caller tool/module overrides.
Existing strict Developer ID, image, checksum, payload and provenance checks remain
after ticket validation. The existing version-probe entry points and Windows
contained launcher do not change behaviour. No public arbitrary execution API.

The shared opt-in completion method requires its retained independent anchor,
direct reaping and actual group absence. Queries after anchor reaping never send
a real signal. Denial/unknown presence cannot mint proof. Output is bounded and
complete before a confirmed finish record; raw native text remains private.

The exact outer preparation and final-diagnostic supervisors opt into serial
owner reconciliation. A completed owner record is cleanup proof only. Timeout,
cancellation, abnormal exit, missing/truncated/ambiguous proof or IO uncertainty
stops processing and becomes the existing `ProcessCleanupError`; credential state
is preserved and no cleanup observer/subsequent control runs. A harmless fixture
actually leaves an inner group alive after outer termination to prove the refusal,
then stops that group explicitly in finally. This is NOT a containment guarantee
for hostile tools or a promise to kill all children after uncatchable termination.

All selected clocks are explicit CLOCK_MONOTONIC integer nanoseconds. Python
chooses the parent deadline before Popen. Rust chooses one at-most60-second window,
clamped to that parent. Image revalidation, native waiting, bounded output and
cleanup consume it; even a late otherwise-successful result refuses.20seconds
are reserved INSIDE that window for existing finite cleanup/Drop paths, not added
to an outer timeout. Default unrelated Python operations keep their old lifetime.
Shell release/rehearsal/operator verifier invocations still must check the complete
xtask exit and have no credential cleanup lifetime here; they gain no acceptance
from a partial owner record. No such workflow is dispatched by this source change.

## Dependency review

Only xtask's macOS target gains the existing internal macOS-process and locked
rustix dependencies, plus rustix's time feature. Cargo.lock changes exactly two
xtask dependency edges; every package source/version/checksum and all other fields
are unchanged. A normalized metadata comparison confirms identical package
identities/licenses/MSRVs and no aggregate resolved feature delta. The internal
path IDs differ by worktree and are normalized before comparing—an initial direct
ID comparison failed and is preserved, not accepted as evidence.

Reviewed lock BLAKE3 changes from
`069fe829e4eb90ea0b28b8e9743a5adc160a0536bbff65090056b921d7f4489e` to
`f07327abbfe36a3d0496ea89d03fa31cdfe875c702be28ab99d83f38286ed7de`.
The old fingerprint refused as designed before refresh.385 third-party license
checks and the exact existing release notices pass unchanged. No dependency
upgrade, registry checksum, release workflow permission, version/catalog/target
or package-channel change is bundled.

## Verification before acceptance

Retain red-before-green command/deadline/framing/retained-file/cleanup/callsite
proofs, including the unanchored-proof and late-result review findings. Golden
corpus tests bind portable Rust producer/Python consumer. Harmless native tests
cover exit0/68, exact child reaping, live descendants, timeout, invalid/combined
output bounds, equal-byte name replacement and existing lifecycle refusals.
Real outer timeout/cancellation and credential preservation/observer refusal are
tested without accounts, signing tools or Apple requests. Pure policy/schema
tests remain portable on Windows; only actual native ownership fixtures are
platform-gated. Existing default supervisor and probe tests must still pass.

Run complete stable/Rust1.88 serially on the final frozen tree, fresh audit,
notices/governance/secret scans, manual full diff/caller review and exact public
checks. Parent-only rebase onto PR99's identical squash tree must preserve the
validated candidate tree. No feature merge before exact latest main is green;
guarded squash and exact new-main verification precede owned-worktree cleanup.

## Hosted compatibility corrections

Original head2149 passed the local full pair, but exact PR41116856046 and normal
full-platform supplement41116900442 exposed distinct failures. Linux rejected
the new262145-byte fixture's single command argument with errno7/E2BIG. The
fixture now constructs those bytes inside a small child expression and asserts
the exact size, retaining a valid owner start/finish prefix before excess bytes.
The argv budget and closed cleanup-refusal category are tested; no evidence
bound is relaxed. Current hosted Rust also deprecates AtomicU8.fetch_update under
warnings-as-errors. A single strong compare_exchange now allocates ordinals1..8;
contention/invalid/exhausted counters refuse before launch, with no spin, wrap or
ordinal reuse. This keeps Rust1.88 compatibility without a warning allowance.
Both corrections have retained failing-then-passing focused proofs.

The existing Ubuntu library probe failed separately with the closed
Launch/ExecutableFileBusy category. Test-only PR101 isolates its fixture writers
without production probe changes; its reviewed squash468a622 is incorporated by
a normal merge, not a published history rewrite. Its exact PR/full-platform
checks passed; its new-main validation must pass before this feature can merge.
The corrected combined tree needs a NEW full stable/Rust1.88 pair, manual review,
secret/audit checks and fresh exact public PR/full-platform checks. Original local
passes do not count as validation of these changes. Historical failures/logs
remain; no unchanged failed run is rerun to hide them.

No provider recovery, final retry fix, production artifact, fresh install, Intel
runtime or release acceptance is claimed. The separate approved max3 exact-1005
policy and versioned attempt evidence come only after this boundary is accepted.
