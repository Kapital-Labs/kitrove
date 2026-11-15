# Notarization authentication diagnostics — 2026-11-15

## Evidence and remaining uncertainty

Protected RC5.13 run [43513943162](https://github.com/Kapital-Labs/kitrove/actions/runs/43513943162)
at `8013513d6bff2be60f8b46e05f229c9df333a892` passed identity import, then
failed before application archive preparation. Search-list restoration and
Keychain deletion passed. The intervening operation is `notarytool
store-credentials` through the no-echo terminal wrapper. Its exception and native
response were discarded. This establishes the failing boundary, not the native
exit status or underlying cause. It is not a demonstrated stapling failure,
signature failure or rejected notarization submission.

The credential wrapper, process helper and identity importer are byte-identical
to successful RC5.12. GitHub reports the notarization secret's last update as
2026-09-09, before that successful run. This excludes a recent secret edit; it
does not establish current account validity, service health or terminal behavior.
No provider or account lookup was used to obtain these facts.

## Production diagnostic change

Authentication now emits fixed operation boundaries and closed failure fields:
the failing terminal phase, native exit/termination, whether the complete
credential input was sent, and an observed allowlisted HTTP response category
when present in bounded private output. Conflicting, unsupported or oversized
responses remain unclassified. These fields are observations, not automatic
root-cause findings. The original RC5.13 response cannot be recovered from them.

Raw response text, credentials, command arguments, account values and paths are
never forwarded or included in these exceptions. Invalid diagnostic fields map
to constants. The success condition remains complete input delivered only after
terminal echo is disabled, native exit zero, direct-child reap and confirmed
process-group disappearance. The 90-second authentication bound, 256-KiB capture
limit, cancellation, cleanup precedence and no-retry behavior are unchanged.

## Prepared credential-only probe

`apple-notary-validation.yml` is a manual, attempt-one, exact-main-SHA workflow
using the existing protected `release` environment and `contents: read` only.
Both its job and Python entry point require the exact expected source and
`KITROVE_NOTARY_VALIDATION_SHA`; both production and signing-rehearsal activation
must be absent. The dedicated marker cannot arm an existing signing workflow. The helper
is compiled before the credential-bearing step. That step references only the
three existing notarization account/team/password secrets, not the signing
identity or its wrapping password. This is a source restriction; GitHub's
environment protection is still the server-side credential boundary.

A small native helper creates and unlocks an empty private Keychain, preserving
the original default and search list and matching production's temporary
search-list membership. It imports no key or certificate. The same production
authentication wrapper invokes `store-credentials --validate` once against that
explicit store. The password travels only through the no-echo terminal.
Restoration and deletion occur on success or failure. Unconfirmed process cleanup
retains the private state and fails closed; abrupt termination relies on the
ephemeral hosted runner's destruction, as in ADR-0042.

There is no product build, execution, signing, notarization submission, ticket
attachment, artifact upload, OIDC, release creation or channel change in this
workflow. Only closed diagnostic lines enter the job log. Local tests use fake
credentials and harmless children; compiling the empty-Keychain helper does not
run it or modify a local Keychain.

## Execution gate

The current environment permits only `v*` tags. This source change does not alter
that policy or authorize bypassing it. Before one credential-only probe, the
operator must explicitly approve temporary `main` access for the exact reviewed,
green source, keeping the required reviewer and administrator bypass disabled.
An owning controller must remove that temporary policy and matching diagnostic
marker on terminal success or failure. Production activation stays absent.

Do not dispatch a known-blocked job, create a diagnostic release tag, reuse an old
signed-run approval, transfer credentials to a workstation or infer account/key
changes. Collect discriminating evidence before selecting an authentication
repair or starting the separately approved next preview. RC5.13 and all earlier
release tags remain immutable; partial outputs are not release inputs.

## Validation

Regression tests first reproduced the missing diagnostics on the unchanged
wrapper. Real harmless PTY children cover accepted/rejected input, a closed HTTP
401 observation, exit before a prompt, refusal to send while echo is enabled,
timeout and cleanup uncertainty. Synthetic response tests cover closed categories
and redaction. Credential-only orchestration tests cover exact context refusal,
one authentication, restoration/deletion and retained state on cleanup uncertainty.
Workflow tests constrain secrets, permissions, source guards and operation order.
These tests do not reproduce or resolve the historical Apple account response.
