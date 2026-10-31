# Release DMG verification carries its own exact source binding

## Observed failure and bounded conclusion

RC5.4 run41215536114/source57607b81 passed validation, planning, Linux and Windows.
Apple preparation also passed: three exact-source Accepted notarizations, ticket
attachment, source-bound validation0 in one attempt, and Keychain cleanup. The
later production staging step verified both archives and bundles, then failed
its independent `verify-installer-dmg` call with native exit68. Nothing published;
the temporary activation was removed and tag-only reviewer protection retained.

The preparation wrapper inserts KITROVE_NOTARY_SOURCE_COMMIT only into its own
child environment. GitHub steps do not inherit that Python child's mutations.
The later staging step lacked that metadata, so the existing Rust binding selector
returned None and used its single-attempt path, without V2 recovery evidence.
The successful diagnostic's source-bound final verification did not cover this
different production workflow boundary. That was an integration/coverage gap.

Native68 alone does not identify the later provider error or prove eligibility
for recovery. No claim is made that recovery would have made RC5.4 succeed.
The immutable failed tag/run remain evidence, not candidates for another attempt.

## Correction and caller review

Pass `${{ github.sha }}` as KITROVE_NOTARY_SOURCE_COMMIT in the existing
credential-free `verified-local` step. DIST_TARGET already comes from its exact
single-target matrix. The existing Rust selector still verifies the source shape,
target, actual hosted source and public repository before selecting ADR-0070.
No diagnostic marker, signer credential, account lookup, workflow permission,
protected-environment change, release version or publication authority is added.

Production preparation already supplies this metadata privately. The separate
Apple diagnostic explicitly supplies its stricter diagnostic context at its own
final verifier. The generic manual rehearsal and standalone downloaded-image
consumer retain their existing unbound/single-attempt behavior; they are not the
production staging boundary repaired here. Linux host/global jobs copy and check
opaque DMG bytes, not native Apple tickets, and require no source-binding change.

All native signing, notary submission and ticket attachment remain single-attempt.
Existing validation-only recovery is unchanged: max3 calls only for positively
classified complete bounded connection-loss evidence, same retained image and
original deadline/cleanup reserve, strict signature and remaining verification.
Unknown native68, denial, identity change, cancellation, deadline or cleanup
uncertainty still refuses. Do not broaden that classifier to make this run pass.
The exact reviewed workflow fingerprint is refreshed after reviewing the one-line
workflow delta; its mismatch guard is retained, not bypassed or suppressed.

## Regressions and limitations

- Execute the actual production verification Bash body using the actual step's
  environment declarations, isolated synthetic files and stand-ins only at the
  archive/native verifier boundaries. Its staging, copies and output writes are
  real; no product, signer, Apple tool or network request is executed. Missing
  source fails at the later image gate. Valid source reaches that gate once;
  verifier failure65/68 still prevents its container output, with no shell retry.
- Read the checked-in workflow declaration in a Rust regression and feed its
  source metadata into the real binding selector. Before the fix it returned
  Ok(None); after the fix it selects the source-bound path. Existing real policy
  tests still cover malformed/mismatched metadata, wrong repository/target,
  contradictory evidence, ownership, identity, deadline and signature refusal.
- Both regressions were red before the production edit and green afterward.
  An initial synthetic fixture omitted the independent Python archive-verifier
  stand-in; its failure is preserved but not counted as regression evidence. An
  initial overly exact Rust selector ran zero tests and is likewise not counted.
  Corrected explicit runs demonstrated the intended missing-binding failures.
- This is credential-free integration evidence, not a fresh native signing run,
  provider-recovery success, published artifact acceptance or clean-Mac claim.

Require full stable/Rust1.88 canonical checks, fresh audit, notices/licenses,
governance, secret scan, exact public PR checks and exact repaired main green.
Review is manual full-diff/caller review, not an independent-agent or exhaustive
repository sign-off. Signing stays disabled; another release is not authorized.

## North Star and threat-model impact

NS-07/NS-09 and INV-07/INV-12 remain intact. Exact public source metadata is not a
secret or an authority grant. No portable/native representation, discovery,
adoption, preservation, fidelity/loss classification, provenance policy, deployment
receipts, synchronization/conflicts, local-only data, package/channel, supported
target or schema changes. This implements the existing ADR-0070 binding contract
at a missed caller, rather than changing that decision or a trust boundary.
No new dependency, lockfile change, raw provider logging, deadline extension,
cached-success/unstapled fallback, security exception or unreviewed semantic TODO.
