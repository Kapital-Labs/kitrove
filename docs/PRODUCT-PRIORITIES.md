# Product gaps and launch priorities

November 18, 2026. Recommendations for maintainer review, not approved implementation
or a claim that a listed feature has shipped. Read with the
[positioning](PRODUCT-POSITIONING.md) and [release claims](launch/CLAIMS.md).

The [delivery plan](superpowers/plans/2026-11-18-product-gap-delivery.md) maps these
gaps to separate acceptance criteria, code boundaries and review decisions. It
does not claim that the gap implementations have shipped.

## Before expanding the preview audience

| Priority | User question | Completion evidence |
| --- | --- | --- |
| P0: first useful placement | "What do I do after collecting, and did the other tool find it?" | A new user completes a disposable collection-to-second-tool journey without coaching. Count attempts with consent. Explain an existing shared copy before suggesting a duplicate. Record placement and tool loading as separate observations. |
| P0: status and next action | "Why did scan show available items but apply has none ready?" | One vocabulary connects observed, collected, already current, changed, blocked and script-review states. A user can identify the reason and next action for each row. Avoid a second collection or another overwrite as an unexplained remedy. |
| P0: repeat-run and recovery acceptance | "Can I run this again after collecting more or interrupting it?" | Retain RC5.18's four-tool unchanged-file regression. Add explicit user-facing acceptance for stale plans, pending recovery, changed owned files and overlapping packs. Refuse unknown states; do not suggest deleting journals or state. |
| P0: truthful scope | "Which release, platform and capability can I rely on?" | The claims ledger, current docs and download page agree. Preview status and the remaining acceptance gaps remain visible. Do not use design-spec example commands as proof of released CLI commands. |

These should precede another broad integration. RC5.18 fixes a real repeat-run
planner bug, but one regression does not complete user acceptance.

## Before stable support

| Priority | Work | Definition of done |
| --- | --- | --- |
| P0 | Supported collection-version policy and upgrade/recovery | Name a supported version pair, prove backups and interrupted operations with real artifacts, and distinguish executable replacement from collection migration and data rollback. No such promise follows from a Homebrew upgrade. |
| P0 | Native tool and clean-machine acceptance | Test supported tool versions loading placed capabilities, plus the promised online/offline first launch on clean machines. Record what each harness actually loads; file presence is not runtime parity. |
| P1 | Drift and source-update review | Show local edits, collection edits and upstream changes separately, then preview an exact-prior update. Explain conflicts without selecting a winner. This strengthens the core distinction more than a registry search page. |
| P1 | Two-computer setup and ownership handoff | A user can choose a Kitrove backend, authenticate through the supported provider, inspect transfer effects and complete a bounded reverse edit. Test both the empty second computer and existing-content cases. Do not treat any Git repository as an initialized backend. |

## Useful next increments

- **Grok Bot controller:** a read-only conversational pilot using existing CLI
  contracts, followed by a separately reviewed write boundary. Keep it a way to
  understand the collection and preview changes, not a substitute for the core.
- **Small starter pack and reproducible walkthrough:** public, licensed sample
  content and a short collect/preview/apply demonstration. A deliberate test pack
  provides more launch value than a large unreviewed catalog.
- **Environment health and support export:** report versions, structured error
  codes and recovery state without printing raw command lines, environment
  variables, credentials, skill bodies or private paths. Require consent before
  including private identifiers or sending any report. This is proposed work.
- **Compatibility maintenance:** maintain dated upstream evidence and fixtures.
  Block unsupported native fields rather than translating them from guesses.
  Scope a new target by capability and version, not by adding a logo.
- **Pack provenance, licenses and prerequisites:** help users inspect source,
  changes and runtime requirements. Detection does not authorize installing a
  runtime or running a helper. Optional policy/scanning integrations need their
  own contract; an audit label is not a safety guarantee.

Keep general package management, credential storage, a hosted account service,
automatic background mutation and enterprise administration outside this first
cohort. Existing tools already cover parts of installation and configuration;
each addition should improve the managed collection workflow.

## Proposed first cohort

Recruit a small opt-in group of multi-tool developers. Ask them to use synthetic
or disposable skills first. Observe a first collection, a second-tool preview,
a repeat run after a new collection item, and an edited managed copy. Record
where they hesitate and which refusal they understand. Publish a reproducible
procedure and anonymized findings only with participant consent.

The launch criterion is a user completing and understanding the workflow. Number
of adapters, collected skills, repository stars or a Bot demo do not replace it.
