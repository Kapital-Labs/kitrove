# ADR-0027: Executable trust is local exact-content authority

- **Status:** Accepted for Gate G implementation
- **Date:** 2026-08-28
- **North Star invariants:** NS-04, NS-05, NS-07, NS-09, NS-10
- **Amends:** ADR-0005, ADR-0008, ADR-0026

## Context

Gate F preserves native-only executable Pi extensions but deliberately refuses every materialization attempt. Gate G must provide a complete executable-trust workflow without turning adoption, synchronization, planning, or inspection into execution authority. A portable trust bit would let one machine authorize another. Trusting an asset ID or moving source would let changed bytes inherit approval. Letting apply create trust as a side effect would collapse review and execution into one confirmation.

The machine-local schema already stores `TrustDecision` values keyed by `ContentHash`. That unused shape is sufficient for the first exact-content workflow if the key is the verified native extension object hash and every mutation is planned, confirmed, stale-safe, atomic, and auditable.

## Decision

### Authority and state boundary

Executable trust targets one verified `kitrove-native-pi-extension-object/v1` object hash. It does not target an asset ID, mutable source path, repository, branch, package name, native ID, manifest revision, publisher, or provenance label. Equal exact object hashes may reuse the same machine-local decision; any byte, path, mode, layout, entrypoint, or native-ID change produces a new object hash and therefore returns to unreviewed.

The decision remains only in machine-local `state.json` as `Trusted` or `Denied`. Portable manifests, locks, snapshots, backends, semantic merge, receipts, plans intended for publication, and adapter evidence never contain or infer the decision. Gate G generates a fixed structural rationale (`explicit_exact_content_review`) rather than accepting authored rationale through command arguments. Diagnostics never render stored rationale or local-state bytes.

### Trust workflow

The CLI exposes separate non-mutating and mutating phases:

- `kitrove trust plan --asset <id> --decision trusted|denied [--environment <path>] [--json]`
- `kitrove trust apply --asset <id> --decision trusted|denied --confirm <plan-digest> [--environment <path>] [--json]`
- `kitrove trust audit [--asset <id>] [--environment <path>] [--json]`

Planning requires a valid manifest and local state, selects an extension asset explicitly, loads and verifies its exact Pi native object, recomputes executable classification, and derives a digest over the operation version, asset ID, object hash, requested decision, manifest revision, and exact observed local-state hash. It does not write, create a journal, select a destination, invoke Pi, or execute content.

Apply rebuilds the plan after receiving the exact digest, refuses a changed manifest, object, local state, or decision, then updates only the exact object-hash decision through a restrictive-permission atomic local-state transaction. Recovery may complete only the exact staged state whose old/new hashes and decision tuple match the journal. Unknown, malformed, conflicting, or concurrently changed state fails closed without deleting evidence.

Audit loads and verifies each selected executable object and reports only asset ID, harness, exact object hash, and `trusted`, `denied`, or `unreviewed`. A stale decision whose object is no longer selected remains local evidence but grants no authority; audit may report it only as an orphan count, never silently delete it.

### Trust consumption and materialization

Trust changes no portable compatibility result. Pi remains portably `Blocked(executable_trust)` because another machine still needs its own decision. A local apply plan may satisfy that requirement only after independently loading the verified object and finding `Trusted` under its exact hash. `Denied` returns `apply.executable_trust_denied`; absence returns `apply.executable_trust_required`.

The initial executable materialization target was the documented Pi user extension root. ADR-0036
extends that boundary to the documented project root when all ordinary exact-content authority is
present, the explicitly selected Pi executable yields reviewed version evidence, and Pi's saved trust
store grants effective trust to the exact project anchor. Kitrove reads that store with bounded,
no-follow, restrictive-permission checks and binds its exact hash and selected ancestor decision into
the plan. It never creates, repairs, or changes Pi trust, and neither a command-line assertion nor Pi's
global/default or one-run trust modes grant Kitrove authority. Claude, Codex, OpenCode, packages,
settings arrays, npm/Git/HTTP extension sources, dependency installation, and extension execution
remain unsupported.

After trust, planning still performs ordinary receipt-backed destination observation and ownership checks. It renders the verified extension tree exactly, uses the native extension object hash as the layout/native-ID-aware rendered identity, binds the complete asset revision as receipt source identity, and stages beneath the compiled Pi extension anchor. Apply never launches Pi, imports TypeScript, resolves modules, or installs dependencies. Writing into Pi's auto-discovery root is the authorized security-sensitive effect and therefore requires both the prior trust decision and the ordinary fresh apply confirmation.

Revocation prevents future install, restore, or managed update immediately. It does not silently delete an already materialized destination; removal requires a separately planned receipt-backed workflow.

## Consequences

- Preservation, trust, and materialization are three distinct confirmations and authority transitions.
- Exact content changes cannot inherit trust through stable asset or source identity.
- Trust remains machine-local and synchronization-independent.
- The accepted Gate F portable fidelity remains truthful across machines.
- Gate G initially supported user-scope Pi extension materialization; ADR-0036 adds the separately
  gated saved-trust project scope.
- Repository- or publisher-level trust, expiry, signatures, policy servers, automatic trust, removal, and rollback UX remain deferred.

## Security impact

This ADR introduces the first path that can place executable capability bytes into an auto-discovered harness root. The path is limited to an already preserved and verified exact object, a prior local exact-content trust decision, a fresh destination plan, explicit confirmation, compiled Pi policy, no-follow bounded capture, proven ownership for replacement, restrictive local state, and recoverable mutation. Extension content is never executed by Kitrove. ADR-0036 separately requires an explicit bounded Pi version probe before installation planning. Trust mutation and materialization each re-read their complete authority after confirmation.

## Validation

- Trust plans and audits are non-mutating and never execute content.
- Trusted, denied, absent, malformed, orphaned, and concurrently changed decisions have distinct fail-closed outcomes.
- Every object-identity field change invalidates prior trust.
- Trust never appears in portable serialization, snapshots, backend traffic, merge output, receipts, or redacted diagnostics.
- Trust transaction crash points recover only exact staged authority on macOS, Linux, and Windows.
- Untrusted or denied extensions refuse before destination selection or mutation.
- Trusted user-scope Pi standalone and directory extensions install exactly, become receipt-owned, no-op, restore, and managed-update through existing ownership rules, without launching Pi.
- Project-scope materialization reads only the bounded saved Pi trust decision, refuses unknown or
  declined authority, binds exact trust-store and version evidence, and never changes Pi trust.
- Stable, Rust 1.85, native Ubuntu/macOS/Windows, advisory, architecture, security, and integration/test-evidence gates pass before acceptance.

## Rejected alternatives

- **Portable trust:** moves machine-local execution authority through synchronization.
- **Trust asset or source identity:** lets changed executable bytes inherit approval.
- **Trust during apply confirmation:** conflates content review with destination mutation.
- **User-authored rationale on argv:** adds unnecessary unbounded and process-visible input to a security boundary.
- **Mutate Pi's trust store or accept unsaved/default trust:** would create or invent harness authority
  rather than verify Pi's documented saved decision.
- **Treat project apply confirmation as Pi project-trust evidence:** claims fidelity without verifiable authority.
- **Delete on revocation:** turns a trust decision into an implicit destructive operation.
