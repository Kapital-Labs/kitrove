# Kitrove compatibility patch

This directory contains the complete published library source and manifests of
`pageant` 0.2.0 from crates.io (Apache-2.0, upstream repository
`warp-tech/russh`). The original crate archive has SHA-256
`1b537f975f6d8dcf48db368d7ec209d583b015713b5df0f5d92d2631e4ff5595`
and records upstream commit `f6b9e6479664696db4cd9c507c6725c1ab7c8aeb`.
Kitrove receives this Windows-only package through `russh` 0.62.0. The package
declares Rust 1.85 support, but one condition uses let-chain syntax stabilized
in Rust 1.88.

The local patch rewrites that one condition as equivalent nested control flow
in `src/interface.rs`. No transport policy, data structure, public API, feature,
or dependency changed. The upstream source and Apache-2.0 license are retained
so the patch is reviewable and builds do not depend on mutable external fork
state. That one rewritten condition is the complete difference from the
published `src` directory.

When the selected `russh` release no longer pulls a `pageant` version with this
MSRV mismatch, remove its `[patch.crates-io]` entry and this directory after
re-running the Windows SSH and dependency reviews.
