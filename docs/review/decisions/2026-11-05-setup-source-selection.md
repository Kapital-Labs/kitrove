# Setup source selection and empty previews

- Decision: accept the bounded setup-only repair under ADR-0047.
- Scope: source selection, skipped-item presentation and empty-preview routing.
- Review: complete manual product/architecture/security/implementation diff and
  caller review; not an independent-agent or exhaustive repository review.
- Publication: unreleased; no version, signing, release or channel change.

## Diagnosis and North Star impact

The recommendation loop selects every eligible observation before omitting all
same-name occurrences. Shared discovery roots make that common even without
separate copies. This is conservative refusal, not proof of equivalent content.
The UI printed every omission and approved the resulting empty list as success.

NS-02 improves bidirectional intake usability. NS-03/04/05/07/09/10 are retained:
the user explicitly chooses one tool's observations for this scan. No harness
becomes canonical, no native sources are combined or declared equivalent, and
no occupied identity is updated or renamed automatically. Exact native objects,
portable projection, fidelity/loss reasons, provenance and trust remain unchanged.
No new public/domain type, adapter interface, schema or persisted preference.

## Safety review

`from TOOL` filters existing bounded scan indices; exclusions use original indices.
It cannot supply a path, invoke a tool/provider or mutate a source. Unrecognized
tools, malformed/mixed/out-of-range exclusions reprompt. Remaining same-name
ambiguities still omit every occurrence. All ready plans are fully displayed;
only skipped-item details are sampled, with counts/reasons and full details on d.

Choose-again reuses the inventory, not previous approval. Every new preview reloads
the manifest and every commit uses the unchanged exact-digest Confirm path and
fresh capture. Stale source/state/recovery failures still stop later work and
report completed progress. Empty previews never authorize writes; y is rejected.
EOF/q stop. Apply, sync, receipt ownership, trust and local-only state boundaries
are unchanged. No resolver, process, filesystem write or credential API added.

## Evidence and conditions

Six initial new real scripted regressions failed against baseline for the expected
empty-approval, noisy-output and missing-source-selection behavior, then passed.
Eight source/empty/detail/input/native-preservation tests and all setup tests pass
(43 passed, two existing child-fixture ignores). Existing stale-source/state/
journal/partial-progress coverage additionally exercises the source filter.

One older executable-block fixture initially supplied y to its empty preview and
then reached EOF. The log is retained; it now supplies y then n, explicitly
asserting refusal/no empty approval while retaining all trust/secret assertions.
No gate/assertion/timeout was weakened.

Require canonical full stable and Rust1.88 CI, fresh audit/secret scans, exact PR
checks and green main before landing. No published-version or installed-copy claim
from source validation. Reassess if future intake merges native variants, updates
existing identities, persists a source preference or changes approval semantics.
