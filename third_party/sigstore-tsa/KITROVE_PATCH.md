# Kitrove offline-verification patch

This directory contains the complete published source of `sigstore-tsa` 0.11.0 from crates.io
(Apache-2.0, upstream repository `prefix-dev/sigstore-rust`). The published crate archive has
SHA-256 `b58fe92d4d8cf4b7215b927b70bc1245b6e0d70d801febdfe0cd265ad97ebf8b` and records upstream commit
`ef17cacdbd357befea4c1c768ef02ed9bf52672c`.

The packaged README's final line says `BSD-3-Clause`, but that is stale upstream documentation:
the published crates.io metadata, the source workspace package metadata at the recorded commit, and
the repository's root `LICENSE` all declare Apache-2.0. The authoritative Apache-2.0 text is retained
here as `LICENSE-APACHE`; the upstream README remains unchanged so the discrepancy stays auditable.

`sigstore-verify` uses this crate's offline RFC 3161 timestamp verifier, but the published package
unconditionally compiles and exports its HTTP timestamp client and depends on `reqwest` even with
default features disabled. Kitrove's patch adds an off-by-default `client` feature, makes `reqwest`
optional, and gates only `client.rs` and its public export. ASN.1 parsing and timestamp verification
are unchanged. Default users of the patched crate retain the upstream client behavior; Kitrove's
`default-features = false` path has no HTTP-client dependency or API.

Remove this patch once an upstream release offers the same client/verification feature split, after
re-running the exact dependency, offline provenance, MSRV, and license reviews.
