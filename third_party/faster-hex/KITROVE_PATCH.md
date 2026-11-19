# Kitrove maintained dependency override

This directory preserves every file from the complete published faster-hex0.10.1
crate, including Rust source, build script, original manifest, README, upstream
nested lockfile, workflow, VCS metadata and all three MIT attribution/license files.
The authenticated crates.io archive is:

- URL: https://static.crates.io/crates/faster-hex/faster-hex-0.10.1.crate
- SHA256: `04839bdf9d8c10f66806fad16b852fc72aab80873aebc3cb69d85b4fa41543ed`
- Recorded upstream commit: `c817979830ea5be2eafe0b0c99cb83b017ae2b8f`.
- Package declaration: MIT, edition2018, source Rust floor1.61.

`UPSTREAM_FILES.sha256.json` records every archive member's upstream and local
SHA256. Exactly one existing file differs: the active `Cargo.toml` changes two
fields, heapless requirement `0.8` to `=0.9.4` and package rust-version `1.61.0`
to `1.88`. `Cargo.toml.orig` remains the original
published manifest and is retained only as provenance. The nested upstream
Cargo.lock remains historical; Kitrove resolves with its workspace-root lock.
Standalone contract tests must use disposable dependent manifests and locks,
never regenerate the preserved upstream lockfile.
The root excludes this package from the workspace and selects it through an
explicit crates.io path patch. It remains third-party code, not a Kitrove crate.

Heapless0.9.4 archive SHA256 is
`411fdef4df93751117bd9ef8caa0e7f99c65dafec5bd84313eb8e2fdd75e32f2`.
It declares MIT OR Apache-2.0 and Rust1.88. The local override's effective
dependency floor is therefore1.88, reflected in the active package metadata and
within Kitrove's unchanged1.89 floor. The original1.61 declaration is preserved
only in Cargo.toml.orig and upstream provenance.
The package-level patched range for RUSTSEC-2026-0574 through0582 is>=0.9.4.
This is a local maintained source override, not a new upstream release or an
advisory exemption. Fresh audit of the targeted repaired lock removes all nine
unsound warnings, with only the existing chrono informational record remaining. Preparatory
Rust1.89 feature contracts and normal license/notice checks pass; final combined
source and native release validation remain separate gates.

No Rust/build/decoder/SIMD/unsafe implementation or source guard changes. Existing
std, alloc, serde and defmt feature definitions are unchanged. Selected gix
consumers use std/alloc; their slice APIs and allocated-string code are unchanged.
For noalloc, source inspection finds the required Vec/String operations in0.9.4
with default length type usize. The public return spelling String<N>, fixed
capacity and intended value behavior remain, but its nominal dependency type
changes from heapless0.8 to0.9.4. This patch does not promise compatibility with
external code explicitly requiring heapless0.8 types. Disposable dependent
Rust1.89 contracts pass for noalloc typed0.9.4, alloc, std, std+serde,
noalloc+defmt03 and allfeatures, including the retained short-source decoder case.
The extra serde-without-std profile reproduces the same missing Vec/Cow errors
in an authenticated unpatched registry0.10.1 control. It remains outside this
repair's accepted profile boundary; no source or feature fix is included.

The preserved Rust Project Developers and fast-hex MIT texts under
`LICENSE-THIRD-PARTY/` must be included in generated release notices with their
exact bytes and source paths, alongside the upstream LICENSE. No signing or
publication follows from this source preparation.

Remove the path patch, workspace exclusion and this directory after a maintained
published upstream route removes the affected heapless version while preserving
the required Rust1.89 floor and selected APIs/features. Review exact source,
lock/audit, notices, feature behavior and native checks before removing it. Never
restore an affected decoder or retain an ignore merely to retire the override.
