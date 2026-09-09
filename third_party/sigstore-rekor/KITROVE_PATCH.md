# Kitrove offline-verification patch

This directory contains the complete published source of `sigstore-rekor` 0.11.0 from crates.io
(Apache-2.0, upstream repository `prefix-dev/sigstore-rust`). The published crate archive has
SHA-256 `9b97c5a866f849a9445ae657bef0caa2db053a82827e6dae3a2b3de9c15a6a1a` and records upstream commit
`ef17cacdbd357befea4c1c768ef02ed9bf52672c`.

The packaged README's final line says `BSD-3-Clause`, but that is stale upstream documentation:
the published crates.io metadata, the source workspace package metadata at the recorded commit, and
the repository's root `LICENSE` all declare Apache-2.0. The authoritative Apache-2.0 text is retained
here as `LICENSE-APACHE`; the upstream README remains unchanged so the discrepancy stays auditable.

`sigstore-verify` needs only Rekor's signed-entry body types for offline bundle verification, but the
published package unconditionally compiles and exports its HTTP client and depends on `reqwest` and
`url` even with default features disabled. Kitrove's patch adds an off-by-default `client` feature,
makes those two dependencies optional, and gates only `client.rs` and its public exports. The body,
entry, cryptographic, serialization, and verification-related code is unchanged. Default users of
the patched crate retain the upstream client behavior; Kitrove's `default-features = false` path has
no HTTP-client dependency or API.

Remove this patch once an upstream release offers the same client/verification feature split, after
re-running the exact dependency, offline provenance, MSRV, and license reviews.
