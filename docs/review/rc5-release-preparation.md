# RC5 release preparation

The maintainer approved preparation of 0.1.0-rc.5 and its conservative rollback
policy on 2026-10-21, then explicitly approved fresh-install preview scope and
normal protected signing/tag/publication after green checks. Existing releases and the pending RC4.2 WinGet submission stay
unchanged. Public installation pages continue to describe published RC4.2.

## Scope and compatibility

RC5 includes exact plan/approval CLI interfaces for adoption, update, apply,
removal, pack creation, import and rollback; locally authored packs preserving
member provenance; opt-in versioned JSON errors; reviewed ZIP and TLS dependency
fixes; and the Unix transaction-lock correction. Source builds require Rust 1.88.
Cloud-provider sync remains roadmap work only.

RC4.2's tagged Source enum cannot deserialize authored_pack. RC5 therefore declares
no rollback-compatible predecessor. Installing an older executable does not undo
collection changes; do not promise RC4.2 can reopen an authored-pack collection.
This catalog entry does not alter the existing state schema or lock protocol, and
does not rewrite provenance or provide a collection downgrade migration.
The guarded installer requires an explicitly compatible prior version, so this
policy also blocks its RC4.2-to-RC5 upgrade path. Do not bypass that check or
advertise a supported in-place upgrade. A separately reviewed migration/recovery
design is needed before that upgrade path can be supported.

## Invariants and threat-model impact

NS-05 and NS-10 require truthful provenance and explicit compatibility limits.
NS-07 and NS-09 remain intact: credentials and local authority stay local, and
publication remains gated. This preparation changes version metadata and rollback
authority only. Discovery/adoption, portable representation, native variants,
fidelity classifications, receipts, synchronization and conflict behavior are
unchanged from reviewed main. No trust bypass, data conversion, package-manager
expansion or unsupported platform guarantee is introduced.

## Evidence and outstanding gates

Baseline c94ee53b6101d459e84f5523b7cf611635f997c8 passed full stable/Rust 1.88
validation, public platform checks, and a real bounded source-built Mac/Linux
skill/filesystem-backend roundtrip. It covered adoption, authored packs, import,
apply, member updates, reverse transfer, provenance preservation, stale approvals,
unmanaged-file refusal, removal, rollback and local-authority exclusion.
That is not evidence for all asset kinds, live harnesses, cloud/Git providers,
concurrent writers, RC5 packaged binaries or binary downgrade compatibility.

Before committing this preparation, validate its exact tree on stable/Rust 1.88,
review the compatibility catalog and matching governance digest, inspect the
version-specific nonpublishing dist 0.32.0 plan, and smoke-test local development
archives. Require exact public checks and green latest main before merge.
After separate publication approval, verify production artifact provenance and
native lifecycle behavior before updating distribution channels or support claims.

## Final publication copy

The publication job now requires nonempty regular version-specific notes from the
reviewed checkout and appends the exact workflow source commit. It refuses missing,
empty or symlink notes before GitHub writes rather than publishing generated
download-and-execute guidance. Credential-free shell regressions cover those
refusals, literal note handling and draft-before-publication ordering. This does
not change artifact identity, signing, permissions, attestations or review gates.
Fresh installation is the only approved RC5 scope; no migration work is planned.
