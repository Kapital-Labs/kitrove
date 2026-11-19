# RC5.19 release preparation

Scope: the next protected evaluation preview, its reviewed version/catalog and
current documentation. The baseline is the separately reviewed dependency tree
`9ef670573e30abbf7a342bb54d9ba476a6748140`. Exact validation and publication
records accompany the pull request; this document does not grant new authority.

## Source boundary

The candidate includes the read-only doctor and saved-item guidance from PR152,
its test-writer isolation repair, and the reviewed heapless compatibility work.
Doctor reuses inspection validators, observes machine-local state-file metadata
without parsing it, and retains an unlocked/not-tested distinction. Static
storage-stage messages and same-collection doctor guidance do not establish the
cause of the user's failure on another Mac. That incident remains undiagnosed.

The tracked faster-hex 0.10.1 override selects heapless 0.9.4 without changing
faster-hex's upstream Rust sources. Its existing reviewed lock graph and retained notices are
the baseline for this version edit. No new resolution, source/checksum edit,
feature contract, compiler-floor change, warning ignore or license waiver is
introduced here. See `docs/review/heapless-compatibility-repair.md` for the scoped
preparation and unsupported-feature limits; its targeted evidence is not final
combined release acceptance.

## Exact version and authority edits

- Root workspace package version becomes `0.1.0-rc.5.19`. Only the 27 local
  workspace version fields change in Cargo.lock; all other bytes, including
  dependency lists, source identities and checksums, remain unchanged.
- The compatibility catalog appends one empty RC5.19 predecessor entry.
  Previous entries and schema stay intact. No rollback or migration support
  follows from the new version, and binary rollback does not restore data.
- Current installation/site links and their version expectations target RC5.19.
  Historical scan/handoff introductions, published RC5.18 acceptance, RC4.2
  package channels and the legacy RC3 staging cask retain their identities.
- The doctor guide identifies RC5.19 availability and preserves the fact that
  RC5.18 does not include the command. New notes do not claim clean-Mac/offline,
  stable, Intel, live-agent/helper-runtime or in-place migration acceptance.

Normal license/governance commands must first produce their expected fingerprint
refusals. Only the reviewed resulting lock and catalog fingerprints may then be
bound in xtask. Existing signing workflow, dist policy and package-channel
metadata are outside this version edit.

## Required gates before any publication

Full stable and Rust 1.89 canonical validation, complete manual source/authority
review, fresh advisory/secret checks, website validation and unsigned packaging
must cover the exact approved final version tree. Exact public PR/main checks
and guarded merge precede one protected immutable RC5.19 attempt. Independent
public inventory, exact-source attestations, notice bytes and native identity
verification precede Homebrew promotion and the matching website. Retain normal
reviewer/no-admin-bypass/tag-only protections, one-attempt records and owned
activation cleanup. This preparation supplies no permission to dispatch, tag,
sign, publish, replace assets, touch a personal install or change user state.
