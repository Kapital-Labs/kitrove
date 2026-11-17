# Interactive scan collection handoff

## Purpose and invariants

A person who has just browsed skills can add them to a collection without leaving
scan and starting configure. Candidate counts no longer imply that every source
can be added to an existing collection. NS-01, NS-02, NS-03, NS-04, NS-05, NS-06,
NS-07, NS-09 and NS-10 retain their existing boundaries; no package-management or
harness-runtime behavior is added (NS-08).

ADR-0047's scan handoff amendment documents the explicit transition out of
read-only browsing. JSON, verbose, non-terminal output and the observation engine
keep their existing non-mutating contracts. Existing observation identities and
capture selection feed the original planner, and fresh commit retains digest,
source/state, no-follow, lifecycle and recovery checks. Initialization has its own
confirmation. Empty previews never grant adoption approval. Matching names do not
prove matching content. No Apply, sync, trust, credential access or execution is
implicitly authorized.

## Validation

A real synthetic terminal regression first failed because scan had no direct
collection action. A separate real planner regression first failed on the opaque
occupied/blocked/excluded summary. Synthetic terminal coverage now exercises
existing and new collections, explicit initialization and adoption approval,
project and explicit-root capture selection, skip/cancellation, stale-source
refusal and terminal restoration. Full-machine scan non-mutation and existing
exact-plan/recovery/fidelity tests remain part of the canonical checks.

Required pre-commit checks: full stable and Rust1.89 canonical validation,
manual complete source review, current advisory audit and secret scans. Results
are attached to the change review. This is not an independent-agent review or an
exhaustive audit. ADR-0072 records the explicit handoff boundary. No release,
version, tag, signing, distribution, migration or installed-state change is part
of this feature change; a separately authorized release must ship it.
