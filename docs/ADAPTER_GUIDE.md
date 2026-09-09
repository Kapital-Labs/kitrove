# Compiled Adapter Guide

Kitrove's tier-one adapters are compiled policy, not dynamically loaded plugins. This guide defines the evidence and implementation boundary for maintaining Claude Code, Codex, Pi, and OpenCode support.

## Before changing an adapter

1. Update the matching `docs/research/<harness>.md` with the observed harness version, source, date, and confidence.
2. Update `docs/03-HARNESS-CAPABILITY-MATRIX.md` when a capability, layout, precedence rule, or fidelity result changes.
3. Identify affected North Star and architecture invariants, especially source fidelity, no silent loss, local secrets, and executable trust.
4. Decide whether the change fits an accepted ADR. New authority, mutation, transport, trust, or package-management behavior requires an ADR before implementation.

## Adapter responsibilities

An adapter may provide only bounded, deterministic policy:

- documented user and project roots;
- supported directory or standalone source shapes;
- precedence and exclusion rules;
- evidence-backed compatibility and fidelity results;
- destination layout and adapter version identity; and
- typed findings with compiled messages.

The shared engine owns walking, capture, budgets, object identity, classification, receipts, planning, mutation, synchronization, and rendering. Adapter code must not launch a harness, probe a runtime, access the network, mutate the filesystem, inspect credentials, or create trust authority.

## Evidence and fixtures

Never copy a real harness home into the repository. Create minimal synthetic fixtures under `crates/kitrove-testkit/fixtures/harnesses/<harness>/` and include a `PROVENANCE.md` describing the documented shape and version evidence. Fixtures use synthetic names, paths, bytes, identities, and credential canaries.

Every changed root or layout needs coverage for:

- absence, valid content, malformed siblings, and duplicates;
- user/project precedence and repository-boundary behavior;
- bounded depth, entry count, file size, and aggregate bytes;
- links, unsafe ancestors, special files, and Windows alias/reparse cases;
- credential-shaped files, private-key markers, and redacted output;
- exact source/native identity and deterministic ordering; and
- honest fidelity on every tier-one target.

Executable shapes additionally require preservation-before-trust, exact-object local trust, non-execution sentinels, and destination recovery coverage. Supporting a newly executable harness is a separate security design, not an ordinary adapter edit.

## Validation and review

Run `cargo ci` and the matching adapter contract tests. Phase or authority changes also require native Ubuntu, macOS, and Windows CI plus independent architecture, security, and test-evidence review. Document deliberate unsupported behavior; do not infer support from a similar harness or silently normalize an unverified layout.
