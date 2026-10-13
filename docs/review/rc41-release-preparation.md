# RC4.1 replacement candidate review

RC4 release run 38444489717 failed during Intel Mac installer container
preparation after both application and installer archive preparation passed.
Cleanup passed, publication was skipped, and signing activation was removed.
The immutable RC4 tag remains unchanged. The maintainer approved continuing the
diagnostic fix and replacement RC4.1 path. The underlying native failure is not
yet known and is not claimed fixed or transient.

## Bounded diagnostic change

The hosted signing wrapper recognizes a fixed allowlist of existing xtask error
labels for image creation, signing, notarization, stapling, signature checks,
mounting, payload validation and cleanup. It emits only constant categories,
never provider output, arguments, paths, accounts or credentials. Unconfirmed
detach takes precedence over an accompanying primary error. Unknown failures
remain generic. Tests inject multiline secrets and require exact redacted output.
Native commands, deadlines, verification, cleanup and release gates are unchanged.
No retry, shipping bypass, new dependency or added signing authority is introduced.

This supports NS-07/NS-09 and preserves INV-06/INV-07/INV-08/INV-12 and the
ADR-0043/0046 release trust boundaries. It changes neither persisted product
state nor runtime behavior; the existing RC4 onboarding review and ADR-0047
continue to govern those features.

## Version and rollback review

Workspace package versions alone change in Cargo.lock; third-party identities,
versions, checksums and licenses are unchanged. RC4.1 adds RC3 as its sole
reviewed rollback predecessor, retaining historical declarations unchanged.
RC4 was not published and is not a new rollback authority. RC4.1 has the same
persisted formats and application-layout behavior reviewed for RC4. Complete
pending nested-home application transactions before rollback to RC3. Binary
rollback does not undo application data changes.

## Required evidence

Full local CI, MSRV, exact-head protected checks, normal merge and green main
precede a new annotated RC4.1 tag. Normal protected signing is temporary; any
terminal failure requires cleanup and diagnosis, not a blind rerun. Independently
verify published inventory, digests, provenance and native Mac images before
bounded RC3/RC4.1/RC3 acceptance and Homebrew update. None of these future checks
is claimed complete by this review. Warm-host evidence cannot replace clean-Mac
offline launch or remaining native-target and two-machine acceptance.
