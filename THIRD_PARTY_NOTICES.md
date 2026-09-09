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

The source tree includes audited patches for `jsonc-parser` 0.32.1, `pageant`
0.2.0, `sigstore-rekor` 0.11.0, and `sigstore-tsa` 0.11.0 under `third_party/`.
Their upstream license declarations, complete published sources, provenance,
and patch descriptions are retained in those directories. The Sigstore patches
only remove HTTP-client code and dependencies from the offline verifier build;
their verification logic is unchanged. Each packaged Sigstore README contains
a stale `BSD-3-Clause` footer; the crates.io metadata, source-workspace
metadata, and upstream root license at the recorded commit all authoritatively
declare Apache-2.0, whose full text is retained with both patches.

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
