# ADR-0067: Upcoming Mac previews are Apple Silicon only

Status: Accepted maintainer scope decision, 2026-10-29; implementation under RC5.4 authorization, validation pending

## Context

The maintainer explicitly dropped Intel Mac support for upcoming previews. This
reduces initial distribution scope; it is not a workaround for Apple Silicon's
ticket failures. Earlier published evaluation snapshots and
retained forensic evidence remain immutable.

## Decision

Upcoming preview publication targets are `aarch64-apple-darwin`,
`x86_64-unknown-linux-gnu`, and `x86_64-pc-windows-msvc`. Do not build, sign,
publish or advertise a new Intel Mac preview. This decision does not promise
Linux arm64 binary publication, migration, backward compatibility, stable support,
or package-channel updates.

Implement publication selection separately from historical archive recognition.
Keep old Intel snapshots verifiable under their exact reviewed source/policy;
do not delete old assets, repoint old links to ARM executables, relabel an ARM
binary, or weaken strict inventory checks to accept an incomplete old release.
Update the complete active build/inventory/attestation/notes chain together before
another preview. RC5.4 implements a closed three-target publication selection
alongside the unchanged four-target recognition catalog. Native and hosted Intel
signing refuse before credentials; historical read-only verification remains.
Complete staging and generated installer maps require exactly the selected set.

No signing or publication authority comes from a platform entry. The maintainer
separately authorized RC5.4 preparation and protected publication after the narrow
read-only connection-loss repair, green source checks and fresh successful ARM
diagnostic. That diagnostic needed no retry; historical attachment causes remain
unknown. No broader permission or service/firewall workaround is included.

## Impact and proof

NS-07, NS-09, NS-10 and INV-07/INV-12 remain intact. Unsupported platforms are
reported explicitly rather than silently receiving an incompatible binary.
Discovery, adoption, portable/native content, fidelity semantics, provenance,
receipts, synchronization/conflicts and local-only state are unchanged.

Require a credential-free dist plan with exactly three target jobs, explicit
Intel publication refusal before credentials/network signing, Rust/Python policy
correspondence, strict complete inventory tests, and historical artifact
verification controls. Full stable/Rust1.88, source review, fresh exact PR and
green-main checks precede merge. This document records the decision, not completed
release-selection implementation or production artifact acceptance.
