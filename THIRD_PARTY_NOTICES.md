# Third-party notices

Kitrove uses third-party Rust packages. Copyright in those packages remains
with their respective authors and contributors, and each package is distributed
under its own license terms.

The authoritative dependency set for a source revision is `Cargo.lock`.
`cargo xtask licenses` verifies every locked third-party package against
Kitrove's approved SPDX-expression policy and prints the package, version, and
declared license expression used to prepare release notices.

Release archives and binaries must include this file, the Kitrove license files,
and the complete output of `cargo xtask licenses` for the released `Cargo.lock`.
Packages requiring additional attribution or bundled license text must have
those materials included before a release is signed.

Both binary archive families contain `THIRD_PARTY_LICENSE_INVENTORY.txt` (the
complete command output) and `THIRD_PARTY_LICENSES.txt` (package/path references
and exact license/attribution text). Identical text is stored once with SHA-256
references, not discarded. The inventory conservatively covers the complete
locked graph, including build, test and other-platform packages; it does not
claim every listed package is linked into each executable.

Reproduce the checked-in documents with `python3 scripts/release_notices.py
--check`. An intentional reviewed update uses `--write`. Registry text comes
from crate archives authenticated against the reviewed lockfile; local patched
text comes from tracked source. Packages whose published archives omit license
text use the explicitly reviewed, source-pinned supplements described in
`release/license-supplements/index.json`. Those records distinguish license-text
provenance from crate source identity. No network lookup or license guessing
occurs during notice generation or signing. These are repository policy checks,
not a legal compliance opinion.

The source tree includes reviewed patches for `jsonc-parser` 0.32.1, `pageant`
0.2.0, `sigstore-rekor` 0.11.0, and `sigstore-tsa` 0.11.0, plus a maintained
`faster-hex` 0.10.1 dependency override under `third_party/`.
Their upstream license declarations, complete published sources, provenance,
and patch descriptions are retained in those directories. The Sigstore patches
only remove HTTP-client code and dependencies from the offline verifier build;
their verification logic is unchanged. Each packaged Sigstore README contains
a stale `BSD-3-Clause` footer; the crates.io metadata, source-workspace
metadata, and upstream root license at the recorded commit all authoritatively
declare Apache-2.0, whose full text is retained with both patches.

The faster-hex copy preserves every published archive file, including its MIT
LICENSE and the Rust Project Developers and fast-hex MIT attributions under
LICENSE-THIRD-PARTY. Only its active Cargo.toml heapless requirement and declared Rust floor differ;
all Rust source and build-script bytes remain exact. Its original manifest,
nested upstream lockfile and VCS/workflow metadata are retained as historical
provenance. The noalloc return type uses heapless 0.9.4 rather than 0.8; this is
a maintained local override, not an upstream release or advisory exemption.
Dependency and validation status is recorded in
[`docs/review/heapless-compatibility-repair.md`](docs/review/heapless-compatibility-repair.md).

These directories preserve upstream library and license material, not byte-exact
crate archives. Vendored packaging omits upstream VCS metadata and, for
`jsonc-parser`, upstream workflow/configuration files. The nested `jsonc-parser`
lockfile also differs from its published archive; Kitrove builds use the reviewed
workspace-root `Cargo.lock`, not that nested lockfile. The Sigstore copies contain
non-semantic whitespace/manifest formatting differences. Their optional `client`
feature is enabled for default upstream-style use and disabled by Kitrove's
`default-features = false` configuration. Original archive hashes and source
revisions remain recorded in each `KITROVE_PATCH.md`.

The current policy and approved license families are documented in
[`docs/DEPENDENCY_LICENSE_POLICY.md`](docs/DEPENDENCY_LICENSE_POLICY.md).
