# RC1 preparation review

The maintainer authorized the sequential prerelease path on 2026-09-23:
`v0.1.0-rc.1`, followed by `v0.1.0-rc.2` only after RC1 verification. This change
prepares RC1; it is neither publication evidence nor stable-release acceptance.

North Star impact: NS-07/NS-09. Existing release identity, credential custody,
protected environment, archive authentication and ordinary-user installer controls
are unchanged. No product behavior, state format, parser or credential flow changed.

The workspace and all 25 corresponding lockfile package records change from
`0.0.0` to `0.1.0-rc.1`. Third-party versions, sources, checksums and dependency
edges remain unchanged. The compatibility catalog declares only RC1 with an empty
predecessor list. Historical `0.0.0` rehearsal fixtures remain synthetic fixtures,
not compatibility authority. Exact lockfile/catalog review digests are refreshed
for these reviewed changes; no guard is removed or relaxed.

The checksum-pinned cargo-dist 0.32.0 plan identifies the tag as a prerelease and
both products as version `0.1.0-rc.1`. Its inventory contains eight native archives,
one source archive, their checksums, the combined checksum and four convenience
scripts. The reviewed release workflow adds two signed Mac DMGs and their checksums
before final inventory verification and attestation. Convenience scripts do not
replace independent first-download authentication.

No rollback compatibility with unpublished `0.0.0` builds is claimed. RC2 must
separately review compatibility with RC1. Candidate source pins must be the actual
merged versioned commits. Require green main before tagging; verify RC1's complete
published inventory and provenance before proceeding to RC2. Clean-Mac first
launch and native lifecycle results remain explicit pending acceptance evidence.

Validation: full local `cargo ci` and `cargo +1.85.0 ci` passed, including Rust
tests, Clippy, formatting, Python archive/workflow security tests, governance,
license inventory and repository hygiene. Both source-built executables report
`0.1.0-rc.1`. Pinned cargo-dist planning and diff whitespace checks passed. Hosted
checks, versioned local packaging and public-artifact acceptance are still separate
steps; no signed download has been executed as part of this review.
