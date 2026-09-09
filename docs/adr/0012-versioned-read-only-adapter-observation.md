# ADR-0012: Versioned read-only adapter observation

- **Status:** Accepted
- **Date:** 2026-08-22
- **Amended:** 2026-08-23 for the Gate C2 design and explicit home availability; 2026-08-24 to preserve unsafe project-boundary termination and exact explicit-file request authority; 2026-08-28 to enforce version evidence at destructive target selection
- **North Star invariants:** NS-01, NS-02, NS-04, NS-07, NS-09, NS-10

## Context

The scaffold adapter API accepts roots and homes as raw strings and returns discoveries without scope, source tier, version policy, content identity, risk, or structured findings. Gate C needs to inspect user and project skill roots across four harnesses without making one host canonical or leaking machine paths into portable state.

Native harnesses differ in root discovery, duplicate policy, source layout, frontmatter extensions, symlink behavior, trust prerequisites, and unknown-version behavior. Codex also exposes user, project, admin, and bundled system sources. A separate scanner in each adapter would repeat filesystem and classification rules and could produce different safety behavior.

Scan must also work before `kitrove init`. Managed-state classification needs optional manifest and receipt evidence, but inventory does not.

## Decision

Gate C2 uses one shared observation engine with thin compiled harness policies. The engine owns bounded root walking, source enumeration, capture dispatch, observation identity, optional ownership comparison, classification, ordering, and report rendering. Each adapter policy owns documented roots, source layouts, native identity, name handling, exclusions, duplicate resolution, version-policy selection, and native findings.

The policy contract has a narrow read-only discovery hook for roots that static descriptors cannot express, such as a caller-supplied bundled system source or Claude's bounded nested project roots. The hook may return validated roots and findings. It cannot run a process, access the network, mutate a path, parse portable state, classify ownership, or replace the shared walker.

The shared walker constructs a safe candidate locator before opening content. The adapter classifies that locator as capture, bounded-frontmatter-hint capture, unsupported, or documented ignore; the post-capture decision receives the same locator. Adapters also return a separate closed set of user/project receipt anchors. Receipt containment never infers write authority from an arbitrary observed, compatibility, admin, system, or explicit root.

Caller-supplied native roots select a key from a closed adapter-owned descriptor catalog. The caller may select user or project scope only where the descriptor permits it; the compiled descriptor supplies tier, layout, precedence, and evidence. Project trust enters only through typed transient observations keyed by harness and validated project anchor; production scan does not inspect harness trust stores.

An explicit standalone-file candidate root is authorized against one exact request item, not merely a parent directory shared by multiple requests. Its compiled path authority must pair with a request-indexed logical authority that includes the exact authored file name. The shared engine validates the harness, scope, request index, parent, and file name against that same request item before walking the returned parent root. Related-root and receipt-anchor catalogs cannot use this candidate-only authority. This contract is harness-neutral; policies cannot obtain authority by choosing the first request with a matching parent.

The generic scan request and borrowed root context preserve home availability explicitly as `Option<PathBuf>` and `Option<&Path>`. An unavailable home is never replaced with the working directory or another sentinel path. Every policy omits its implicit home-derived user roots, related roots, and user receipt anchors when home is absent. Project roots remain available from the validated working directory and project boundary; static administrator or system sources and exact caller-authorized explicit or supplied native roots remain governed by their normal scope and descriptor rules.

Project-boundary discovery preserves three distinct typed outcomes: a validated repository root, ordinary repository absence, and termination at an unsafe repository marker. Ordinary absence may enable an adapter's documented ancestor behavior. Unsafe termination permits inspection rooted at the working directory but grants no shared-ancestor search, project receipt, or destination authority. Every policy and shared authority helper consumes this distinction; no adapter repeats CLI marker detection or converts unsafe termination back into absence.

Tier-one policies remain in compiled workspace crates under ADR-0010. A new adapter implements the policy contract and the shared contract suite. Gate C2 adds no community ABI.

`HarnessScope` remains a validated two-value domain:

```rust
enum HarnessScope {
    User,
    Project,
}
```

`RootTier` is transient observation evidence:

```rust
enum RootTier {
    User,
    Project,
    Admin,
    System,
    Compatibility,
    Explicit,
}
```

Scope answers where a capability applies. Tier records the harness source family. A compatibility or explicit root may have either scope. Admin and system roots have user scope because their capabilities apply outside one project, while the tier preserves their native distinction. `RootTier` may appear in local scan output but never enters portable asset identity or a deployment receipt.

The Codex policy enumerates repository, user, admin, and bundled system tiers. If the process cannot resolve a bundled system source without execution, the report includes a `scan.root_unresolved` system-tier finding. It never treats silence as evidence that the tier does not exist.

Scan accepts `VersionObservation::Unknown` or caller-supplied verified version evidence. Production `kitrove scan` supplies `Unknown`. Detection and inspection never launch `claude`, `codex`, `pi`, `opencode`, or another harness binary. A future diagnostic command may probe versions under a separate command, consent model, and threat review. Tests and embedding callers may provide verified evidence through the typed API.

An adapter selects a conservative policy profile for `Unknown`. Version-specific behavior requires evidence that names the matching policy line. OpenCode V2 standalone files and later-source-wins precedence require verified V2 evidence because the official V2 page does not publish a numeric release cutover. Unknown OpenCode scans the documented common directory form and reports V2-only layouts as unsupported.

Each root carries a machine-local path, `HarnessScope`, `RootTier`, ordered policy rank, logical root ID, enabled layouts, and evidence reference. Paths remain transient or local. Adoption converts a selected observation to a logical `Source::Harness` origin.

Adapters return every discovered candidate and finding. They do not discard equal names across roots or layouts. The version-bound duplicate policy may select an effective candidate, declare coexistence, or report ambiguity. Shadowed candidates remain in the report with `scan.candidate_shadowed` and the winning observation ID.

Every candidate with a safe locator receives a transient `ObservationId`. Accepted candidate IDs include harness, scope, root tier, policy rank, logical root identity, source-relative path, adapter-native identity, source-layout tag, original document name, and exact content identity. Location-level failures use explicit absence tags for unavailable native or exact fields. Adoption accepts only an accepted observation with native and exact identities, rereads the candidate, and rejects stale inputs. Portable provenance retains a logical origin and origin-native evidence, never the observed absolute root.

Discovery and capture have request-global entry, file-attempt, and byte budgets in addition to per-candidate limits. Overlapping roots consume the global budget again rather than amplifying work without charge. Once capture capacity is exhausted, remaining safe locators stay visible as `Unknown` and no more candidate content is opened.

ADR-0014 defines `Directory` and `Standalone` skill source layouts. Adapters delegate bounded capture, parsing, exact hashing, portable projection, and content classification to the shared Agent Skills crate. The shared engine does not impose a container/name rule. Each policy returns an acceptance, rejection, or explicit-loss finding.

Scan accepts optional read-only inputs:

```rust
struct ScanInputs<'a> {
    environment: Option<&'a EnvironmentSnapshot>,
    receipts: Option<&'a ReceiptIndex>,
}
```

Without an initialized environment, valid candidates are `Unmanaged` and failed candidates are `Unknown`. Duplicate and shadow findings remain attached, but inventory mode does not claim managed or conflicting state. With valid manifest and local receipt inputs, the core can emit all six classifications: `ManagedUnchanged`, `ManagedModified`, `Unmanaged`, `MissingManaged`, `ConflictingDuplicate`, and `Unknown`.

A missing manifest selects inventory mode. A present invalid manifest yields a report finding and `Unknown` for candidates whose ownership cannot be established. A valid manifest without local state can report unmanaged candidates but cannot claim a managed or missing deployment.

Gate C2 adds the required `scope: HarnessScope` field to `DeploymentReceipt`. It also adds a read-only receipt index that validates each receipt's key, identity frame, normalized destination, scope, hashes, adapter version, and environment revision before the receipt can prove ownership. A malformed receipt yields `Unknown` for its destination or the smallest safely identified harness/scope partition; valid sibling receipts remain usable. An unreadable or invalid top-level local-state document yields a report-level finding and disables ownership claims. C2 creates, repairs, removes, or rewrites no receipt.

For Agent Skills, receipt `source_hash` means the complete manifest asset revision's `Asset.content_hash`, not `PortableContent.object_hash`. C3 must define and test the versioned asset-content envelope before it writes adopted assets. Receipt `rendered_hash` and optional `prior_hash` use the layout-aware `kitrove-skill-source-v1` exact-source frame over the target representation. The receipt destination is the package directory for `Directory` or the authored Markdown file for `Standalone`. C2 derives layout from the no-follow destination filesystem kind and uses generic capture rather than current version-policy acceptance before comparing rendered identity.

The receipt index is a diagnostic reader, not a tolerant `LocalState` constructor. Gate B strict deserialization and every mutating command still reject an invalid local-state root. The diagnostic reader never returns a value that a caller can persist.

Inspection is read-only. It does not create an environment, update portable state, repair a lock, write scan history, create cache entries, update receipts, normalize harness content, or execute capability content. The engine reports unsafe roots and continues with independent roots.

Unknown versions permit conservative inventory with a finding. They block later materialization when the adapter lacks evidence for the target format, destination, or reload behavior.

Destructive target selection now accepts the same typed `VersionObservation` boundary as
inspection and records the selected `PolicyLine` in target and plan authority. An adapter may map
`Unknown` only to an explicit conservative compiled line when official evidence supports a common
destination and format across the unknown range. It cannot select version-specific behavior from
`Unknown`: for example, OpenCode uses its current directory package rather than V2-only behavior.
A target without documented conservative destination and reload evidence fails before destination
observation or mutation. Pi native extensions currently take that fail-closed path; their plan and
apply workflow requires `VerifiedVersionEvidence` selecting `PiLatest`.

The adapter contract retains inspection and materialization directions. An adapter without a deterministic representation returns structured `Partial` or `Unsupported` fidelity. Machine version, destination, and resolver blockers remain transient apply findings. Persisted `Blocked` fidelity remains reserved for declared symbolic `BindingName` requirements under the Gate B model.

## Consequences

- The adapter API gains path, scope, root-tier, policy, layout, version-evidence, observation, and finding types.
- The unreleased local schema version 1 gains receipt scope and receipt identity validation.
- C2 can inventory a machine before Kitrove has an environment.
- C2 classification uses ownership evidence without taking ownership or repairing state.
- Root, candidate, and receipt failures remain local to their report entries when the engine can continue.
- Portable schemas cannot depend on observation paths, root tiers, or harness installation state.
- Community adapter ABI work remains deferred.

## Validation

- Every tier-one policy runs the shared contract suite against versioned fixtures.
- Contract tests prove root order, scope, root tier, layouts, duplicates, shadow retention, exclusions, and unknown-version behavior.
- Project-boundary tests prove ordinary absence retains documented ancestor behavior while an unsafe marker prevents every adapter and shared authority helper from crossing it.
- Explicit-file tests prove sibling requests under one parent retain independent authority in either request order, reject unkeyed or non-candidate authority catalogs, and produce deterministic canonical reports.
- Codex tests cover project, user, admin, and system tiers, including an unresolved system source.
- Process-spawn sentinels prove scan launches no harness binary.
- Aggregate capture tests prove many candidates and overlapping roots cannot multiply work past the request budget.
- Pi trust fixtures use typed transient inputs and prove scan does not inspect or mutate the host trust store.
- Before-and-after filesystem snapshots prove scan makes no writes with or without environment inputs.
- A symlinked source never causes Kitrove to read the target.
- Inventory-only tests produce `Unmanaged` and `Unknown` without creating Kitrove files.
- Missing-home tests cover default all-scope project inspection, user-scope explicit roots, project-only inspection, and suppression of every policy's implicit home-derived roots and receipt anchors.
- Classified tests cover all six states with manifest and receipt fixtures.
- One malformed candidate and one malformed receipt do not hide valid siblings.
- Receipt validation recomputes the receipt ID from asset, harness, scope, and normalized destination evidence.
- Receipt comparison uses complete manifest asset revision identity for `source_hash` and layout-aware target identity for `rendered_hash`; unknown current policy does not prevent generic recapture of an already receipted destination.
- Portable serialization tests contain no machine path, root tier, or local version observation.
- Text and JSON golden tests use the same sorted report and exit-status decision.

## Supersession

The 2026-08-23 amendment replaces the earlier per-adapter scanner shape, active version-probe assumption, mandatory-environment scan path, and one-layout capture assumption. The accepted read-only, evidence, no-follow, unknown-version, and portable/local boundaries remain in force.
