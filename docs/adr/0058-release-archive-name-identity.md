# ADR-0058: Release archive name identity is checked explicitly

Status: Accepted for implementation under the RC5.1 repair authorization; validation pending

## Context

The RC5 tag validation failed a rename/replacement regression. The verifier retained
the original no-follow file handle for inspection and staging but compared only
initial/final handle metadata. Rename refusal therefore depended on incidental
metadata change. Original-handle staging did not copy the replacement bytes, but
that alone did not meet the intended name-replacement refusal contract.

## Decision

Archive validation opts into a final no-follow stat of the original leaf relative
to the retained parent directory handle, before successful context completion.
The leaf must still be regular and match the opened file's device and inode.
Missing, replaced or symlink leaves fail closed, independent of timestamp changes.
Existing handle metadata checks and same-handle copying remain mandatory.

This is a bounded final observation, not a namespace lock or a guarantee against
changes after it. It does not authenticate a subsequently reopened pathname.
Staged bytes still come from the retained original handle. Failure preserves
staged evidence and does not authorize publication or delete competing files.
The low-level handle reader retains its existing optional name-stability policy;
archive validation explicitly requires it.

## Impact and evidence

NS-09 and INV-12 are reinforced without relaxing any invariant. No discovery,
adoption, portable representation, native preservation, fidelity, provenance model,
receipts, sync/conflict or local-secret behavior changes. No new execution or
signing authority. Tests simulate equal-byte, different-byte, missing and symlink
replacement while forcing handle metadata comparisons equal, and assert original
staged bytes and retained evidence. Full stable/MSRV and public checks are required.
