# Kitrove compatibility patch

This directory contains the published library source, tests, benchmarks,
manifests, README, and license of `jsonc-parser` 0.32.1 from crates.io (MIT,
upstream repository `dprint/jsonc-parser`). The original crate archive has
SHA-256 `8de0ffda8def4eb16ed430641db8056c2509b20e38f2dd327bdb4c83239f88c4`
and records upstream commit `7128d44e441355719c3976cc319849035cecefc9`.
Kitrove needs the strict JSONC parse controls introduced by this release line
while supporting Rust 1.85.

The upstream source uses let-chain syntax whose compiler support is newer than
Kitrove's declared minimum. The local patch rewrites those conditions as
equivalent nested conditionals in:

- `src/parse_to_ast.rs`
- `src/scanner.rs`
- `src/cst/mod.rs`

No parser policy, data structure, public API, or dependency was changed. The
upstream library source and license are retained so the patch is reviewable and
builds do not depend on mutable external fork state. The nine rewritten
conditions are the complete difference from the published `src` directory.

When Kitrove raises its MSRV to a compiler accepted by the upstream crate,
remove `[patch.crates-io]` and this directory after re-running the parser's
hostile-input tests and dependency review.
