# Credential-free Apple ticket runner control

## Scope

The user approved targeted diagnostics and repairs while keeping signing disabled
and forbidding another release. Both prior authenticated public RC4.2 images
still pass local ticket validation with their original hashes. Add a manual-only,
credential-free hosted control to compare the same ARM macos-15 runner type used
by the failed RC5.3 jobs, before requesting any credential-bearing experiment.

No protected environment, secrets, OIDC, signing activation, new tag/version,
publication, upload, new tool/runtime dependency, Keychain/trust change, network
workaround or permission expansion. The new workflow has contents:read only.
It does not run on pushes/PRs or replace any required CI check. Its entry point
refuses callers outside this exact public workflow on hosted Mac/main/manual
context and refuses a present production activation variable. No caller inputs.

## Data and authority

Only the two exact public RC4.2 DMGs are fetched from their immutable release URL;
their SHA256 pins match the original authenticated public inventory. Bounded
HTTPS, no downgrade, no extraction or native parser before digest matching. Native
signature/Developer-ID/team verification precedes one read-only ticket validation.
No product is mounted or executed, no keys imported, no image stapled or signed,
and no provider credentials or submission are used. Capture no-follow file
identity/hash before and after each native command. Never emit raw native/provider
output, exception text, machine paths or redirected URLs. Results are diagnostic
only, never release/installation authority or a replacement for attestations.

Use existing owned POSIX process groups. On cancellation or uncertain cleanup,
stop further controls. Newly owned public control files remain only for the
ephemeral runner lifetime; no recursive cleanup, artifact upload or output reuse.
Hosted success requires both signatures/tickets to pass with unchanged bytes;
any closed diagnostic failure returns nonzero.

## Product and review impact

ADR0059 amended; NS-07/NS-09 and INV-07/INV-12 reinforced. No discovery/adoption,
portable schema, asset identity/provenance, native-variant preservation, fidelity,
deployment receipt, ownership, sync/conflict or local credential changes. No
broader package-management or supported-platform claim. This is not a fresh/clean
Mac, Intel-runtime, failed-artifact acceptance or exhaustive repository review.
Manual source review only, no independent-agent review claim.

## Tests and remaining gates

Test-first policy/absence assertions; typed transport/oversize/hash/exclusive
download refusals; missing expected pin refuses before native tools; signature
precedes ticket and failure stops that image; mutation refuses; HTTPS downgrade
refuses; raw canaries never escape; cancellation/uncertain cleanup stops the next
image. Cross-platform tests do not add an insecure Windows no-follow fallback.
Full stable/Rust1.88 CI and exact public checks before merge, exact green latest
main before manual control dispatch. Record the exact source/run and safe result.

Old-image outcomes may narrow host/trust/network conditions but cannot establish
the historical fresh-ticket cause. No signing/release permission is inferred from
a successful diagnostic; stop for the human if further evidence needs credentials.
