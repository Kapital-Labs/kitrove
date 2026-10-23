# ADR-0061: MCP activation switches require booleans

- **Status:** Accepted for implementation; validation pending
- **Date:** 2026-10-23
- **North Star:** NS-02, NS-04, NS-05, NS-07, NS-09, NS-10
- **Invariants:** INV-04, INV-05, INV-07, INV-11, INV-12

## Context

ADR-0032 permits only the narrow remote HTTPS MCP intersection. The native
parser currently conflates an absent activation switch with a present value of
the wrong type. Codex `enabled = "false"` and OpenCode V2 `"disabled": "true"`
can consequently become portable enabled declarations. A bounded parser
reproduction confirms this classification error; no server was contacted or
started and no claim is made about how a live harness handles malformed input.

## Decision

An optional Codex `enabled` or OpenCode V2 `disabled` value must be a boolean
when present. A present non-boolean blocks portability with the existing fixed
`MalformedEntry` reason. Absence retains existing defaults; actual disabled
booleans retain the existing `Disabled` block reason. Valid enabled booleans
retain the current portable intersection and credential checks.

The same parser validation applies to exact native storage and decoding. An
old malformed object cannot gain authority merely by having consistent hashes.
Authored values are not echoed in diagnostic reasons. Exact observed native
bytes remain available as read-only evidence, not eligible portable content.

## Boundaries

This is a validation correction, not a new schema, transport, authentication
mode or execution capability. Observation remains read-only. Adoption approval,
provenance, object hashing, local credentials, receipts, synchronization and
conflict rules are unchanged. No existing environment is silently migrated,
rewritten or repaired. Kitrove does not launch a harness or connect to an MCP
endpoint; materialization still requires the existing exact approval contract.

## Validation

- Observe failing real-parser regressions before production changes.
- Cover strings, numbers, containers and JSON null, plus absent/true/false
  controls and preserved exact native bytes.
- Reject malformed exact-native objects even with internally consistent hashes.
- Prove CLI scan/adoption refuses malformed intake without source or manifest
  mutation and without disclosing authored switch values.
- Run full stable/Rust 1.88 checks, source review and exact public checks before
  merge; green merged main remains required before any later release.
