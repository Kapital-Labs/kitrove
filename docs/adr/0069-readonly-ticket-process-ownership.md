# ADR-0069: Read-only ticket validation has a closed owned lifetime

Status: Accepted for the approved prerequisite implementation; validation pending

## Context

The observed final validation failure was native68 with connection-loss-1005,
after successful signing, notarization, attachment and earlier validation. A
validation retry requires completed cleanup between attempts. ADR-0068 extracts
private mechanics but does not by itself establish the ticket caller's ownership
or its outer supervisor's cancellation contract. The maintainer approved this
separate prerequisite before narrowly scoped recovery. No live call is authorized.

## Decision

Use those shared private sources from a private macOS-only xtask caller. Its only
production request is `/usr/bin/xcrun stapler validate -v <retained image>`.
Clear inherited environment overrides and credentials; supply only system PATH
and C locale. Retain/revalidate the named regular file and exact bytes before and
after the call. No arbitrary command, signer, notary or attachment API is exposed.

Retain the native group's suspended anchor before signaling it. Require direct
child reaping and actual group absence, not just a successful signal or child
exit. After anchor reaping, only query the numeric group; never signal it again.
Denial or uncertain probes are not absence. An opaque private cleanup proof is
available only after these checks. Existing probe entry points and Windows launch
behaviour are unchanged; the stronger completion method is opt-in.

The opted-in outer Python supervisor chooses one integer CLOCK_MONOTONIC
nanosecond deadline before launch. Rust clamps it to at most one60-second window;
a standalone verifier without the parent value also gets exactly one such window.
Malformed, expired or excessive supplied bounds refuse. Reserve20 seconds INSIDE
that window for existing finite lifecycle cleanup/Drop bounds. Native waiting,
group confirmation and output collection consume that same deadline. Never grant
a late result or extend the outer60-second verification/1500-second preparation
timeout or existing outer cleanup grace. Too little remaining time refuses launch.

Bound both private output streams to256KiB each, reject invalid UTF-8, and accept
only combined output at most256KiB. No raw provider output is emitted. An ordinary
native nonzero status is distinct from unconfirmed lifecycle/output completion.

Emit/flush a closed versioned start record before nested launch, followed by a
confirmed finish only after completed bounded output and cleanup. Records contain
only schema version, serial ordinal1..8, event and the confirmed cleanup flag—no
PID, path, account or native text. These are cleanup evidence, never signature,
ticket, byte-identity or product-readiness authority. Unknown/duplicate/extra/
reordered/truncated/unbalanced records refuse at the exact opted-in Python sites.

Outer cancellation, timeout, abnormal exit or uncertain inner completion becomes
`ProcessCleanupError`. The existing credential lifetime preserves its private
directory and refuses restoration/deletion and subsequent observation. This does
NOT promise an inner group disappears after uncatchable outer termination. It
prevents a false cleanup claim when that cannot be established. Trusted tools
must keep their group; this is not containment of hostile same-user code or
detached system daemons. Other native operations retain their default supervisor.

## Dependency and authority impact

Add only the already locked internal macOS-process/rustix dependencies to xtask
on macOS, with rustix's time feature. Cargo.lock changes only those two xtask
edges; no package version/checksum, workspace version or registry upgrade. Review
the lock fingerprint, full graph/licenses and notices normally before acceptance.
No workflow permissions, signing implementation, retry policy, release targets,
catalog, version, tags or channels change. All original signature/image/payload/
provenance checks remain mandatory. Intel preview scope is separate pending work.

## Verification and limits

Red-before-green deadline/command/cleanup/framing/retained-file/callsite tests;
portable producer/consumer golden corpus; harmless native output/descendant/
timeout tests; real outer cancellation with a surviving nested fixture group;
credential-state preservation and observer refusal; unchanged default supervisor
tests. Every deliberately surviving fixture is stopped afterward. Run full stable
and Rust1.88, audit/notices/governance/secret scans, manual source/caller review,
then exact public PR/main checks. No real Apple call or new diagnostic follows.
This single-attempt boundary is NOT the later max3 exact-1005 recovery policy and
does not establish provider recovery or solve every historical failure.
