# Roadmap

Dates are intentionally omitted. Progress is gated by evidence, not calendar pressure.

## Phase 0 — Foundation

Governance, product review, harness research, threat model, domain ADRs, and synthetic fixtures.

## Phase 1 — Skills vertical slice

Read-only inventory before initialization, six-state receipt-backed scan, directory and policy-supported standalone skills, adopt, plan, apply, compatibility, and four compiled tier-one adapters.

## Phase 2 — Cross-machine continuity

Git/filesystem backends, reverse edits, semantic conflicts, active-profile application, and local
bindings. Active-profile application and atomic multi-target batches are implemented. A bounded SSH
Git implementation now includes canonical URLs, explicit known-host authority, agent-only
authentication, shared smart-Git validation, fixed service commands, and CLI composition. Phase 2
also includes an explicitly selected, fixed-name HTTPS environment credential provider without
Kitrove storage or helper execution. Native Windows OpenSSH named-pipe evidence closes ADR-0028;
Pageant and ambient Git helper discovery remain explicitly unsupported.

## Phase 3 — Broader portable capabilities

Instructions, commands/prompts, agents/subagents, and basic MCP declarations, including consistent
adopt, inspect, apply, update, remove, conflict, and fidelity-reporting workflows where supported.
Standing instructions, prompt commands, and inert subagents have complete local lifecycles. ADR-0032
completes the phase with remote HTTPS declarations, local authentication bindings, and structured
shared-document ownership. Phase 3 is accepted at implementation head `4d5d343`. OpenCode V2
projection remains fail-closed until Phase 5 obtains trustworthy harness-version evidence; that
version acquisition does not reopen the completed portable lifecycle.

## Phase 4 — Packs and native preservation

Aggregate identity; complete pack create/adopt, list, inspect, apply, update, local removal, and
rollback workflows; native hooks/plugins/extensions at user and project scope; and the Gstack stress
test. Deterministic read-only pack list/inspect, shared bounded component traversal, and confirmed
atomic creation from existing members with one shared exact non-harness distribution source are
implemented. Plan/apply can also select one or more packs, expand their nested leaf assets through
the shared bounded resolver, and commit the resulting multi-target projection through the existing
atomic batch transaction. Exact-prior pack update replaces direct membership, re-derives and reports
every affected parent aggregate, and atomically commits the complete manifest/lock graph through the
shared crash-recoverable mutation transaction. ADR-0033 adds bounded machine-local pack application
claims to the same atomic receipt transaction; overlapping packs share ownership, while direct and
profile application takes retention precedence. This is the fail-closed prerequisite for coherent
removal. Exact-prior removal now atomically releases historical claims; deletes exclusively owned
skill, prompt-command, instruction, and MCP projections; coalesces mixed retained/removed regions
and entries once per physical document; retains receipts shared by another pack; and preserves
portable pack authority. Exact native-extension removal and rollback recovery are implemented for
existing claims without requiring continued executable trust. Explicit executable-bound Pi evidence
now authorizes new claims, and saved read-only Pi trust additionally gates project-scope application.
`pack remove` is the local deactivation
workflow: it releases local application claims and projections while preserving portable pack
authority. Bounded filesystem, Git HTTPS, and Git SSH history inspection now selects an exact prior
pack revision, plans a selective graft while preserving unrelated current authority, fetches and
installs only the required verified historical objects, and commits through the shared
crash-recoverable portable transaction. The confirmed `pack rollback` CLI exposes that workflow
with redacted text and JSON plans. Portable agents now use their existing typed policies and atomic
batch participant for confirmed first adoption, exact-prior update, direct/profile/pack application,
receipt-backed ownership, and exact direct or pack removal without a parallel mutation path.
Read-only distribution discovery and confirmed selective adoption now import one exact pack closure
from verified filesystem, Git HTTPS, or Git SSH Kitrove snapshot authority. Arbitrary third-party
repository resolution remains a separate source-provider feature rather than a sync-backend shortcut.
Project-scope Pi executable materialization is implemented behind exact local content trust,
executable-bound supported version evidence, and Pi's effective saved project trust.

ADR-0034 fixes the remaining rollback boundary: select an exact prior pack revision only from
bounded verified accepted snapshot history, graft its complete component closure into current
authority, re-derive affected aggregates, and commit through the existing portable transaction.
Backend history selection, exact historical-object recovery, and the rollback command are implemented.
Snapshot catalogs and the filesystem, Git HTTPS, Git SSH, retained-base, and local transaction
paths now carry exact portable and native instruction, prompt-command, agent, and MCP envelopes
through one shared bounded document-object dispatcher. This closes the history-object prerequisite
for rolling back mixed-capability packs.

## Phase 5 — Trust and ecosystem

Executable trust, provenance verification, trusted harness-version acquisition, and only then an
adapter/registry proposal if demand exists. Pi's explicit executable-bound probe is implemented and
fails closed unless version, exact-content, and target-scope authority agree. OpenCode V2 uses its
separately published `opencode2` identity; exact probe evidence now unlocks version-gated
instructions, commands, agents, and MCP targets and is bound into confirmation digests. Portable
skills retain the conservative current-policy fallback because current and V2 destinations and
formats are identical. Phase 5 is complete on Unix and Windows. Windows uses retained executable
and ancestor authority plus atomic Job Object containment, while saved Pi project trust uses a
bounded handle-derived read with current-user file ownership and DACL authority. Focused native
probe, user/project CLI plan/apply, confirmation revalidation, and Rust 1.85 evidence include the
complete CLI dependency graph.

## Phase 6 — Public alpha

Fresh public repository; license; reproducible, signed macOS/Linux/Windows packages; install,
application-upgrade, and rollback workflows; docs; examples; and security disclosure. Tag-only
four-platform archive, checksum, installer, and public-attestation generation is implemented without
pull-request release jobs. Native hosted build evidence, platform code signing/notarization, and the
remaining operational workflows are still required.
ADR-0040 now defines application installation and upgrade as an external, version-pinned transaction
with offline rollback material. Archive intake, guarded replacement, crash recovery,
terminal retention/history and explicit offline upgrade/rollback command routing are
implemented. Windows terminal-history acceptance passed at `c97f2ea`; the command and
untouched-preparation recovery checkpoint at `bf3267f` passed full local validation and
focused native Windows run `34139864182`, including all 183 fresh-process invocations
and the command workflows. Final cross-platform release rehearsal,
authenticated bootstrap, the refreshed public-source approval and platform
signing/notarization remain open. The maintainer selected `Kapital-Labs/kitrove`,
and its empty public repository was created with separate approval. Local release
verification now pins its repository and organization IDs. Installer-specific offline
authentication shares the application verifier while retaining a separate opaque
result. Read-only commands now select exactly one authenticated application or
installer bundle from bounded GitHub JSONL collections. Trusted first acquisition
and signed bootstrap acceptance remain unfinished.
These implementation checkpoints
do not mean Phase 6 or public production support is complete.

Signing checkpoint (2026-09-09): local Apple Silicon CLI/installer notarization and
scoped native Windows Authenticode, publisher, timestamp and archive verification
have passed. The Windows rehearsal's temporary federation and signing role are
removed. See `docs/RELEASE-SIGNING.md` for evidence and the outstanding Intel Mac,
key-custody, offline bootstrap/container, production provisioning, public-source,
provenance and two-version acceptance gates. None of those is waived by signing
success, and no release activation or public publication has occurred.
Subsequent credential checkpoint: the operator approved Apple credential custody;
isolated hosted check `34365796564` passed. Only its minimal workflow was published,
not Kitrove product source or private history. Temporary test access is removed.
Explicit signing Keychain selection is implemented for both Apple native tools;
the subsequent tiny-fixture rehearsal `34378308650` passed signing/notarization and
cleanup. The temporary Keychain lifecycle now wraps existing CLI/installer archive
preparation in the disabled workflow. Real hosted product archive acceptance and
Windows production provisioning remain open; no product source or release is public.
ADR-0037's identity-bearing, mutation-lock-only, globally bounded quarantine cleanup is implemented
for Unix transaction coordinators at implementation head `40b1a6f` and for Windows at implementation
head `b6b0492`. Windows uses complete 128-bit native identity plus handle-relative, no-replace move
and exact deletion primitives; legacy retained names remain permanently non-authoritative. ADR-0038's
handle-bound private directory/file ACL enforcement and shared retained-tree validation are accepted
with native Windows runtime evidence. Stable failure behavior and the explicit operator repair
boundary are documented in `docs/QUARANTINE-RECOVERY.md`.

## Engineering sustainability gate

Large-module splitting and shared filesystem-traversal utilities are required engineering work rather
than user-facing phases. Establish tested shared traversal and validation contracts first, then split
modules along demonstrated planning, validation, mutation, recovery, and persistence boundaries.
Refactors must remove verified duplication, preserve platform-specific security handling, and complete
before additional feature work enlarges an affected area.

## Explicitly unplanned until after v1

Hosted cloud, desktop GUI, enterprise policy server, marketplace monetization, general package
management, and credential storage. Using an operating-system or Git credential provider is in scope;
persisting credential values in Kitrove is not.
