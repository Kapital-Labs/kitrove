# ADR-0026: Preserve native-only executable variants before trust

- **Status:** Accepted for Gate F implementation
- **Date:** 2026-08-28
- **North Star invariants:** NS-02, NS-03, NS-04, NS-05, NS-07, NS-09, NS-10
- **Amends:** ADR-0008, ADR-0019, ADR-0023

## Context

Gate C preserves the exact origin-native form of an Agent Skill beside its portable projection, Gate D merges portable and harness-native components independently, and Gate E derives aggregate pack authority. Those proofs do not yet show that Kitrove can retain a capability whose useful behavior exists only in one harness and is executable.

Gate F must prove this boundary before implementing executable trust. A representative capability must be discoverable and adoptable without running it, remain exact through synchronization and reverse update, stay visibly unsupported on other harnesses, and refuse materialization until local trust exists. Treating the capability as a portable skill would flatten behavior; refusing to adopt it would make preservation impossible.

Pi extensions provide the initial proof. Official Pi documentation defines user and project auto-discovery for standalone TypeScript files and directories rooted at `index.ts`, states that extensions run with full system permissions, and gates project-local extensions behind Pi project trust. Gate F does not install Pi packages, dependencies, or runtimes and does not invoke Pi.

ADR-0008 currently represents every blocked requirement as a `BindingName`. Executable trust is a local requirement but not a secret binding. Encoding it as a fake binding would corrupt both the fidelity and secrets models.

## Decision

### Representative capability

Gate F adds read-only observation and explicit adoption/update support for `AssetKind::Extension` from Pi's documented auto-discovery roots:

- user standalone: `~/.pi/agent/extensions/*.ts`;
- user directory: `~/.pi/agent/extensions/*/index.ts`;
- project standalone under the selected working project's `.pi/extensions/*.ts`; and
- project directory under the selected working project's `.pi/extensions/*/index.ts`.

The shared engine performs bounded, no-follow filesystem discovery and capture. It does not parse or import TypeScript, resolve imports, inspect `node_modules`, invoke Pi, read Pi's trust store, launch a process, access the network, or write state. Package and settings-array sources remain visible related capability evidence but are outside the Gate F adoption boundary.

The initial accepted shapes are one standalone `.ts` file or one directory tree containing root `index.ts`. Directory capture retains all bounded regular files and canonical executable modes. Links, reparse points, special files, supported-platform path collisions, credential-shaped paths, private-key markers, missing entrypoints, unsupported extensions, and exhausted request budgets refuse before portable authority is proposed.

### Exact native object

A captured Pi extension becomes format `kitrove-native-pi-extension-object/v1`. Its strict `metadata.json` records schema version `1`, harness `pi`, layout (`standalone` or `directory`), exact entrypoint, path-derived native ID, and the ordered payload path/mode map. `payload/` contains the exact captured bytes.

The object hash uses the frame `kitrove-native-pi-extension-object-v1\0`, followed by the harness tag, layout tag, length-prefixed entrypoint, length-prefixed native ID, and qualified canonical payload-tree hash. Standalone objects contain exactly one file and the entrypoint equals that file. Directory objects contain root `index.ts`. Any future layout or semantic envelope requires a new format and frame version.

The asset has no portable component, exactly one Pi native variant, exact component provenance, `ContentClass::Executable`, and no resolved local data. The path-derived default asset ID is used only when it satisfies `AssetId`; otherwise adoption requires an explicit ID.

### Typed blocked requirements

`FidelityResult.blocked_requirements` becomes an ordered collection of a new portable `BlockedRequirement` enum:

- `binding { name }` for an unresolved symbolic `BindingName`; and
- `executable_trust` for local exact-content trust required before materialization.

The enum names requirements only. It never stores a trust decision, machine identity, path, receipt, credential, or resolved secret. Existing binding requirements migrate mechanically to the tagged binding form.

Because the complete fidelity frame changes, asset revision identity advances to `kitrove-asset-revision-v3\0`. Version 3 retains every field from version 2 and frames each blocked requirement with an explicit tag. Pack identity needs no new frame: it already binds exact member revisions and derived fidelity fields, so changed member revisions propagate normally. The persisted schema remains unreleased version 1 and all checked-in fixtures move atomically.

The Pi result for an extension is deterministic `Blocked` with `executable_trust`, exact native object evidence, and the compiled Pi adapter evidence. Claude, Codex, and OpenCode are `Unsupported` with explicit native-only reasons. Pi project trust is checked only by a future local materialization plan because compatibility is portable and target scope is machine-local; Gate F records project-trust uncertainty as scan evidence and never reads or changes Pi trust state.

### Adoption, update, and synchronization

The existing reviewed `scan -> adopt` authority model is extended rather than bypassed. A native extension observation receives a deterministic observation ID over its kind, harness, scope, logical root, source-relative path, layout, native ID, and exact source hash. First adoption requires the exact observation and confirmation. Exact-prior update uses the same explicit-root authority, expected prior asset revision, fresh observation, plan digest, confirmation, immutable object staging, manifest/lock preconditions, and recovery protocol as ADR-0023.

An extension update replaces only the selected Pi native component and its provenance. It does not invent a portable component. Prior immutable objects remain recoverable. Receipt rebasing is deferred because Gate F cannot materialize an extension and therefore cannot create a valid extension receipt.

Semantic merge continues to merge native variants by harness as one component plus provenance. Kind-specific re-derivation verifies the Pi extension envelope, recomputes executable classification and four-harness fidelity, prunes unreferenced provenance, recomputes the version-3 asset revision, validates the manifest, and derives a fresh lock. Identical changes coalesce, one-sided changes win, and same-component divergence or deletion returns the existing typed non-mutating conflict.

The production apply planner recognizes the preserved extension and returns `apply.executable_trust_required` before destination selection, staging, receipt mutation, adapter rendering, Pi invocation, or any capability execution. Gate F adds no path that can satisfy this requirement.

## Consequences

- Kitrove can preserve and synchronize useful harness-native behavior before it can safely execute or materialize that behavior.
- Fidelity distinguishes native representation blocked on trust from unsupported targets without abusing secret bindings.
- Scan and adoption gain a second capability kind while retaining Agent Skills as a separate parser and projection boundary.
- Asset revision fixtures and persisted fidelity fixtures change before public schema compatibility is promised.
- The shared transaction and merge layers must dispatch object verification and derivation by asset kind rather than assuming every native object is an Agent Skill envelope.
- Pi packages, dependency installation, settings mutation, extension execution, trust approval, and receipt-backed extension materialization remain deferred.

## Security impact

The new path increases the amount of executable content that portable state can retain but does not increase execution authority. Capture is bounded and no-follow, credential-shaped artifacts and private-key markers are refused, diagnostics remain structural, and TypeScript is never parsed by a runtime or imported. Trust decisions and Pi project-trust state remain local and absent from sync. Every production materialization attempt fails before filesystem mutation or process execution.

## Validation

- Fixed object and version-3 asset identity vectors change for every framed field and remain insertion-order independent.
- User/project and standalone/directory fixtures discover deterministically under one request-global refusing budget.
- Symlink, reparse, special-file, traversal, collision, credential, private-key, oversized, and changing-source fixtures refuse without disclosure or mutation.
- Process and network sentinels prove scan, adoption, update, merge, status, and apply planning do not execute or resolve the extension.
- First adoption persists exact bytes, executable classification, typed Pi blocking, explicit unsupported results, provenance, manifest, and generated lock.
- A native-only reverse update changes only the Pi component and provenance, retains prior immutable objects, and is stale-safe and recovery-safe.
- Two machines round-trip the exact object. An independent portable-skill edit and extension edit merge; divergent extension edits conflict without mutation.
- Real apply planning returns `apply.executable_trust_required` before creating a destination, receipt, journal, or staging path.
- Stable, Rust 1.85, Ubuntu, macOS, Windows, public-Git, advisory, architecture, security, and integration/test-evidence gates pass before Gate F acceptance.

## Rejected alternatives

- **Represent the extension as an Agent Skill:** flattens executable native behavior into an unrelated portable schema.
- **Store executable trust as a binding name:** conflates security authorization with secret resolution and makes fidelity dishonest.
- **Reject executable adoption until trust exists:** prevents safe preservation and synchronization, making trust availability a source-loss condition.
- **Parse or import TypeScript to infer behavior:** can execute or misinterpret untrusted code and is unnecessary for exact preservation.
- **Install dependencies during adoption:** violates NS-08 and the fetch/inspect/trust/apply boundary.
- **Store Pi project-trust decisions in portable fidelity:** moves machine-local security state and makes compatibility nondeterministic.
