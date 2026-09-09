# Review Process

The process prevents a clean implementation of the wrong product.

## Review order

### Product review

Is this capability portability or configuration deployment? Does it improve bidirectionality? Could an existing project solve it more rationally? Does it create package, credential, or runtime creep?

### Architecture review

What is the asset identity? What is portable? What remains native? What is fidelity? What provenance/trust remain? What is local versus synchronized? What happens in conflict and rollback?

### Security review

Does remote content execute? Can secrets enter portable state or logs? Can unmanaged files be mutated? Can paths escape staging? Can stale receipts cause deletion?

### Implementation review

Are domain rules outside adapters and CLI? Are errors structured? Are operations transactional and deterministic?

### Evidence review

Official harness documentation, versioned fixtures, golden output, round-trip tests, explicit-loss tests, and cross-platform tests.

## Phase-gate record

Each gate creates a dated record under `docs/review/decisions/` with decision, evidence, unresolved concerns, conditions for proceeding, and reassessment triggers.

## Competitive reassessment

Repeat before packs, public alpha, and v1. The question is not feature count; it is whether bidirectional, provenance-aware, native-preserving portability remains distinct and useful.
