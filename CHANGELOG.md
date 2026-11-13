# Changelog

Notable changes to Kitrove are recorded here.

## Unreleased

### Fixed

- Commands end quietly when the reader of a pipe closes it early, such as
  `kitrove scan --json | head`, instead of reporting a panic.
- Directory walks refuse a Windows root that spells a parent segment inside a
  verbatim path component.

## 0.1.0-rc.5.12

Evaluation preview for Apple Silicon macOS, x86-64 Linux and Windows.

### Fixed

- Guided Git setup advances from the HTTPS username prompt to the hidden
  access-token prompt.

### Changed

- Git sharing offers instructions to create an empty private repository on
  the Git host, then returns to the clone URL prompt.

## 0.1.0-rc.5.11

Evaluation preview for Apple Silicon macOS, x86-64 Linux and Windows.

### Changed

- Terminal scans open with a compact inventory and single-key choices for
  available skills, items to review, and diagnostics. Browse lists in pages.
- Scanning stays read-only. Redirected text, verbose reports, and JSON retain
  their existing behavior.

### Fixed

- SSH synchronization applies matching host-key refusal policies before
  authentication. Exact and standalone hashed pins still establish trust.

## 0.1.0-rc.5.10

Evaluation preview for Apple Silicon macOS, x86-64 Linux and Windows. Earlier
tags and assets remain unchanged. No migration, supported in-place upgrade,
rollback predecessor, stable support or APT/RPM/WinGet update is included.

### Fixed

- When duplicate names across tools leave nothing ready to collect, setup offers
  numbered source choices. Selecting a source preserves exclusions and opens a
  new preview; collection still needs separate confirmation.
- Skipped items are summarized by reason. Press `d` for full details. Names
  already in use are reported separately, without assuming matching content.

## 0.1.0-rc.5.9

Evaluation preview for Apple Silicon macOS, x86-64 Linux and Windows. RC5.8 and
all earlier assets remain immutable. No migration, supported in-place upgrade,
rollback predecessor, stable-support or APT/RPM/WinGet update is included.
Homebrew and website follow-up requires independently verified publication.

### Changed

- Numbered setup menus accept a valid key immediately on an interactive terminal.
  Collection selection uses short questions and separate choice lines. Enter or
  `y` accepts an already displayed, nonempty adoption preview; skipped-item details,
  individual review and choose-again remain available. Text entry stays line-based.
  Queued input cannot approve a later, unseen prompt. Other confirmation defaults,
  exact per-item authority and separate trust, Apply and sync approvals stay intact.
- Guided sharing offers one Git repository choice. Explicit HTTPS/SSH URLs select
  the transport; a missing scheme prompts for it. Setup explains that the remote
  repository must already exist and does not inspect ambient project configuration
  or create repositories. SSH keeps explicit host verification and agent-only auth.

### Fixed

- Large collections no longer reuse a single skill's directory ceiling when
  verifying a retained synchronization base. Exact expected files/directories and
  existing byte/file/no-follow checks remain enforced; unexpected entries refuse.
  Disposable interrupted-base recovery tests finish from retained staging without
  publishing twice. This is not recovery of a real user's interrupted transaction.
- Local checkout spellings receive the intended Git URL guidance on Windows as
  well as Unix, without relaxing canonical URL or actual known-hosts path checks.

## 0.1.0-rc.5.8

Evaluation preview for Apple Silicon macOS, x86-64 Linux and Windows. RC5.7 and
all earlier assets stay immutable. No migration, supported in-place upgrade,
rollback predecessor, stable-support or APT/RPM/WinGet update is included.
Homebrew and website follow-up requires independently verified publication.

### Fixed

- Empty guided collection previews no longer request adoption approval or report
  "Adopted 0" as success. Choose again without restarting or rescanning setup.
- Repeated names can be selected by one explicit source tool with `from codex`
  (or another displayed tool), optionally excluding original inventory numbers.
  No tool wins silently; native copies are not merged and occupied names remain
  protected. All ready plans retain full fidelity/loss details and fresh checks.
- Skipped collection items show reason counts and at most 20 examples by default;
  `d` shows complete details. Collection still grants no trust, Apply or sync.

## 0.1.0-rc.5.7

Evaluation preview for Apple Silicon macOS, x86-64 Linux and Windows. Existing
RC5.6 assets stay immutable. No migration, supported in-place upgrade, rollback
predecessor, stable-support or APT/RPM/WinGet update is included. Homebrew and
website follow-up requires independently verified publication.

### Changed

- Separate guided setup questions, previews and command results with clear labels,
  indentation, spacing and an input marker. Recognized interactive ANSI terminals
  use cyan questions, subdued hints and labeled success/warning/error colors;
  `NO_COLOR`, unknown/dumb terminals and redirected output remain plain text.
  JSON and confirmation defaults are unchanged.
- Use goal-based setup navigation, including “Choose skills to add to your AI
  tools.” Sharing and one-time copying remain separate operations; storage choices
  appear only inside those paths and offer “Not now” before selecting a location.

### Fixed

- Guided `init` detects an existing collection or machine-local state before
  asking for a new machine identity or initialization approval. A valid setup
  offers explicit continuation into the normal setup menu without re-creating
  state or automatically collecting, applying or synchronizing anything.
  Incomplete, invalid or in-use setup stops with inspection guidance; nothing
  is deleted or repaired implicitly. Scripted initialization remains unchanged.

## 0.1.0-rc.5.6

Evaluation preview for Apple Silicon macOS, x86-64 Linux and Windows. Use isolated
collections and disposable destinations. No migration, supported in-place upgrade,
rollback-compatible predecessor, stable-support or APT/RPM/WinGet update is included.
RC5.5 remains immutable; its successful release is the preceding preview.

### Changed

- Guided skill collection previews a recommended eligible set before writing.
  Select numbered observations, or use `all,-3,-8` / `-3,-8` to exclude specific
  entries. `v` shows the complete scan. One `y` approves only the displayed ready
  set; individual review supports Enter/y to adopt, n to skip and r to rename.
- Show source identity, per-tool fidelity and loss reasons. Ambiguous names,
  occupied/invalid names and blocked plans are omitted rather than silently chosen.
- Preserve fresh exact-plan checks for each sequential adoption. A stale source,
  changed state or failed commit stops later items and reports completed work.
  Adoption grants no execution trust, Apply or sync authority.

Full source checks and local unsigned smokes are not published-artifact or
clean-machine acceptance. Candidate-specific verification is recorded separately.

## 0.1.0-rc.5.5

Fresh-install evaluation preview only: Apple Silicon macOS, x86-64 Linux and
Windows. No Intel Mac build, supported in-place upgrade, rollback predecessor,
migration, stable-support or package-channel update is included. All earlier
RC5 tags and failed attempts remain immutable; none produced a public release.

### Fixed

- Bind the final production Mac image verifier to its exact release source, as
  the preparation verifier already does. Existing validation-only recovery still
  requires positively classified connection-loss evidence, unchanged bytes and
  the original deadline. Unknown failures still refuse publication.
- Correct isolated CI fixture launch sequencing without changing production
  process ownership, cleanup, timeout or safety checks.

RC5.4 completed Apple signing, notarization, ticket attachment and initial native
validation, then failed its later independent image validation before publication.
The missing source binding is repaired; the underlying native error remains
unknown. Source checks and earlier diagnostics are not RC5.5 artifact acceptance
or proof that intermittent provider failures are eliminated.

## 0.1.0-rc.5.4

Fresh-install evaluation preview only. macOS binaries are Apple Silicon only;
x86-64 Linux and Windows remain selected. Historical Intel archives remain
verifiable, but no new Intel preview is built, signed or published. No supported
in-place upgrade, rollback predecessor, migration, stable-support or package-channel
update is included. All earlier RC5 tags and failed attempts remain immutable.

### Fixed

- Preserve closed native-provider diagnostics and use bounded, typed prerequisite
  transport retries without changing Windows tool pins or verification.
- Keep read-only Apple validation retries limited to confirmed connection loss,
  the same retained image and original deadline. Signing, notarization and ticket
  attachment remain single-pass; native signature and full verification still
  must succeed. Uncertain ownership refuses progress and preserves private state.
- Correct diagnostic signature requirements and isolated CI process fixtures.

The fresh nonpublishing Apple Silicon diagnostic passed all native phases on the
preceding reviewed source, without a connection-loss error or retry. It is not
RC5.4 artifact acceptance or proof that intermittent service faults are eliminated.
Includes the reviewed RC5-line features, recovery and notice fixes below.

## 0.1.0-rc.5.3

Fresh-install evaluation preview only, with no rollback-compatible predecessor.
Includes the reviewed RC5-line changes below. RC5, RC5.1 and RC5.2 are immutable
failed attempts; none produced a public release. No migration or stable-support
promise and no APT/RPM, Homebrew or WinGet channel update is included.

### Fixed

- Build the distinct Apple Silicon and Intel Mac artifacts in separate jobs on
  Apple Silicon hosts, selecting the pinned build tool by host rather than payload
  CPU. Keep native signature, notarization, stapling and final image checks intact.
- Replace withdrawn crypto-bigint 0.7.6 with 0.7.10 and required ctutils 0.4.5
  with 0.4.6 after narrow source/identity/license review; no unrelated upgrades.
- Include required third-party notices, the complete locked license inventory and
  exact license/attribution texts in both product archives. Reproduce them offline
  from authenticated source inputs before building or exposing signing credentials.

The old Intel Mac provider failure cause remains unknown. Host selection and
cross-compilation are not Intel runtime or clean-Mac acceptance evidence.

## 0.1.0-rc.5.2

Fresh-install evaluation preview only, with no rollback-compatible predecessor.
Includes the RC5/RC5.1 changes below. Both earlier tags remain immutable failed
attempts; neither produced a public release.

### Fixed

- Preserve safe notarization submission diagnostics and confirm owned signing
  descendants are stopped before credential cleanup; uncertainty fails closed.
- Report omitted native-only skill fields as partial cross-harness fidelity while
  retaining the original native source.
- Refuse malformed MCP activation switches instead of treating them as absent.
- Resume interrupted atomic-batch rollback from its durable checkpoint.
- Validate deeply chained profiles without exhausting the native thread stack.
- Refuse an added managed instruction region at the existing parser ceiling;
  updates to existing regions remain allowed.
- Apply reviewed ctutils and Tokio security patches without suppressing advisories.
- Update crypto-bigint to 0.7.6 and required ctutils to 0.4.5 for
  RUSTSEC-2026-0387; retain Rust 1.88 and existing dependency edges.

This preview adds no cloud-provider sync, migration, stable-support or new package
channel claim. Existing RC4.2 package-manager channels remain separate.

## 0.1.0-rc.5.1

Fresh-install evaluation preview only, with no rollback-compatible predecessor.
Includes the RC5 changes below and explicit release archive filename-identity
verification independent of timestamp changes. RC5 stopped during validation;
no RC5 application artifacts were published. Its tag remains unchanged.

## 0.1.0-rc.5

### Added

- Exact plan/approval CLI interfaces for applying, adopting, updating and removing
  tools, and for pack creation, import and rollback. Stale approvals are refused.
- Explicit locally authored packs that preserve each member's provenance rather
  than assigning a shared upstream origin.
- Opt-in versioned JSON errors for agent integrations, without embedding raw
  error details or local paths in the error envelope.

### Fixed

- Release Unix locks correctly and update ZIP to 9.0.5 for reviewed security fixes.
- Update certificate trust dependencies to address reviewed security advisories.

### Changed

- Source builds now require Rust 1.88 or newer.
- Signed Linux APT/DNF preview repositories and platform-specific setup guidance
  are available for the existing RC4.2 packages.

RC5 is a fresh-install evaluation preview, not a stable release or supported
in-place upgrade. Cloud-provider sync is roadmap work only. RC4.2 cannot
deserialize the new `authored_pack` source kind;
do not assume an older binary can read collections containing locally authored
packs. Binary rollback does not roll back collection data. The next release's
compatibility catalog deliberately declares no rollback-compatible predecessor.
Use a new isolated collection and destination; do not reuse irreplaceable state.

## 0.1.0-rc.4.2

### Security

- Update rustls to 0.23.46 for RUSTSEC-2026-0346 through RUSTSEC-2026-0349.
  Keep the existing TLS provider and feature selection; do not suppress advisories.

### Added

- Product website and getting-started guide, with a gated static deployment workflow.

Includes RC4.1's interactive onboarding, configure flow and second-computer setup.
Declares RC4.1 format-compatible for explicit rollback because no application-state,
lifecycle or sync format changes. Compatibility is not a recommendation to return
to an older dependency version. Publication and exact-artifact validation remain
pending; clean-machine and remaining native-platform acceptance gates stay open.

## 0.1.0-rc.3

### Added

- Authenticated installer payload staging on Unix and Windows.
- Mac native-signature-gated installer preparation and fresh verification through
  `prepare-installer` and `verify-prepared-installer`, without automatic launch.
- Bounded Mac inspection helpers with retained process ownership and explicit cleanup.

### Fixed

- Updated `faster-hex` to address the reviewed x86/AVX2 out-of-bounds-read advisory.

### Validation

- Expanded real-artifact Mac and Linux lifecycle tests for state preservation,
  refusal, interrupted upgrades/rollbacks and repeated recovery interruption.

Declares RC2 rollback-compatible: no application-state migration or sync/conflict
format change. RC3 publication and exact-artifact acceptance are pending. A trusted
starting verifier remains necessary; clean-Mac first launch, remaining native
platform acceptance and the two-machine product roundtrip remain open.

## 0.1.0-rc.2

### Fixed

- Production provenance verification accepts the pinned repository's immutable-ID
  release-environment identity while retaining independent tag, commit and signature checks.

Declares RC1.3 rollback-compatible: no application-state or lifecycle format changed.
Publication and two-version native acceptance remain pending. This is not a stable release.

## 0.1.0-rc.1.3

Replacement for the unpublished RC1.2 build. Earlier failed tags remain unchanged.

### Fixed

- Shared source archives accept either known release product name, matching the packager's output.

Public-artifact and clean-machine acceptance remain pending. No earlier version
is declared rollback-compatible.

## 0.1.0-rc.1.2

Unpublished: source-archive validation failed after all platform builds passed.

Replacement for the unpublished RC1.1 build. Earlier failed tags remain unchanged.

### Fixed

- Release staging uses native private-directory permissions on Windows instead of Unix chmod.

Public-artifact and clean-machine acceptance remain pending. No earlier version
is declared rollback-compatible.

## 0.1.0-rc.1.1

Unpublished: Windows staging failed after signing, before publication.

Replacement for the unpublished RC1 build. The failed RC1 tag is unchanged.

### Fixed

- Release builds use Bash consistently, including Windows, so the version tag is passed correctly.
- Planning-only manifests no longer override archive paths in build manifests.

Public-artifact and clean-machine acceptance remain pending. No earlier version
is declared rollback-compatible.

## 0.1.0-rc.1

Unpublished: the release workflow failed before publication.

First release candidate, not a stable release. Public-artifact acquisition and
two-version installer lifecycle acceptance are still pending. Clean-machine Mac
online/offline first launch has not been established. No earlier application
version is declared rollback-compatible.

### Release preparation

- Separate CLI and installer archives for Apple Silicon, Intel Mac, x86-64 Linux
  and x86-64 Windows, with production provenance verification.
- Mac signed, notarized, stapled installer images and a reviewed-source native
  consumer verifier that authenticates artifacts before mounting.
- Ordinary-user installation, upgrade, recovery and rollback interfaces with
  retained prior-version evidence; candidate acceptance remains required.

### Added

- Product North Star and governance model
- Initial product, architecture, threat-model, and implementation planning documents
- Rust workspace scaffold and tier-one adapter boundaries
- Governance checks and review templates
- Gate B domain model with strict portable manifest, deterministic lockfile, and machine-local state contracts
- Qualified BLAKE3 hashes, portable path validation, explicit fidelity evidence, and pack/profile graph validation
- Credential-free portable and lockfile fixtures exercised through public persistence APIs
- Read-only four-harness discovery with deterministic six-state classification
- Explicit first and exact-prior update adoption with immutable portable and native objects
- Receipt-backed install, no-op, restore, and managed-update materialization
- Portable agent observation, six-state receipt classification, adoption, exact-prior update, and
  atomic apply/remove recovery for Claude, Codex, and OpenCode
- Strict portable remote-MCP name, HTTPS endpoint, symbolic bearer-binding, content identity, and
  storage primitives plus compiled Claude, Codex, OpenCode V2, and unsupported Pi target policies
- Component-aware filesystem and bounded HTTPS Git synchronization with conservative conflicts
- First-class pack identity and a deterministic Gstack-scale stress corpus
- Exact Pi native-extension preservation without parsing or execution
- Machine-local exact-content executable trust, redacted audit, and recoverable Pi user-extension materialization
- Safe `init` bootstrap with a read-only four-harness inventory and complete manifest, lock, and private local-state authority
- Repeatable asset and target selection with explicitly sequential multi-item materialization
- End-to-end first and exact-prior update adoption for native Pi extensions in non-empty catalogs
- Dual MIT OR Apache-2.0 project licensing with fail-closed locked dependency-license validation and release notices
- Tag-only four-platform release packaging with SHA-256 checksums, shell and PowerShell installers,
  commit-pinned GitHub Actions, and public-release provenance attestations

### Security

- Fail-closed path, link, reparse-point, special-file, stale-input, journal-tamper, and crash-recovery coverage
- Cross-machine tests proving receipts, trust, credentials, and machine identity remain local
- Stable, Rust 1.85, Ubuntu, macOS, Windows, public Git-over-TLS, and locked dependency-advisory validation
- Cross-transaction recovery interlocks, replacement-root capability checks, credential-shaped content refusal, path redaction, and continuous checksum-pinned secret scanning
- Shared credential-shape detection across skill capture, authored capability adoption,
  materialization, rendering, and MCP validation
