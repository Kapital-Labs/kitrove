# ADR-0060: Native skill field loss is explicit

- **Status:** Accepted for implementation; validation pending
- **Date:** 2026-10-23
- **North Star:** NS-02, NS-03, NS-04, NS-05, NS-06, NS-07, NS-10
- **Invariants:** INV-03, INV-04, INV-05, INV-07, INV-11, INV-12

## Context

The skill parser retains native-only frontmatter and the portable projection
intentionally emits only standard fields. First adoption currently derives
cross-harness fidelity solely from adapter-supplied reasons. A native `model`
field can therefore disappear from the portable representation while other
targets are labeled `Portable`. The immutable native object is preserved, but
the loss report violates the explicit-fidelity contract. A real CLI regression
reproduces this mismatch.

## Decision

The shared skill projector adds a fixed, bounded
`skill.native_field_omitted` reason whenever parsed native-only fields are
omitted. The reason contains no authored field names, values, identities or
paths. Existing adapter reasons are retained. Adoption must consume the reasons
returned by the actual projection rather than only the inputs supplied to it.

The exact origin-native target remains `Native`; other targets consuming this
lossy portable projection are `Partial`. Standard-only content keeps its current
classification. No unknown field is reinterpreted as portable configuration,
executed, or copied into another harness's configuration.

Reverse updates and synchronization retain ADR-0022/0023's existing conservative
derivation from independently verified portable and native payloads. They must
not promote a native-only omission back to `Portable`. Tests cover these paths
alongside first adoption and exact native-byte preservation.

## Identity and safety

Portable and native payload bytes, object formats, source provenance, local trust,
receipt ownership, scan authority and synchronization conflict rules do not
change. Revised fidelity contributes to the complete asset revision and generated
lock as already specified; approval remains bound to the recomputed proposal.
Existing environments are not silently rewritten or migrated by this change.
No new runtime, provider, secret resolver or executable authority is introduced.

## Validation

- Watch the real CLI first-adoption regression fail before implementation.
- Project native-only fields with a fixed redacted reason while preserving
  standard optional fields, supporting content and exact native bytes.
- Exercise all four origin harnesses and their cross-target classifications.
- Prove native-only reverse updates and sync rederivation remain partial.
- Run full stable/Rust 1.88 validation and independent review before committing;
  exact hosted checks and green merged main precede any release work.
