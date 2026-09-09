# Dependency license policy

## Scope

Every third-party package in the locked Rust dependency graph must declare a
license expression. Kitrove does not accept a package that provides only an
unreviewed license file or no license metadata.

The repository check accepts only the exact SPDX expressions currently reviewed
for the locked graph. Those expressions are composed from these approved
licenses and exception:

- Apache-2.0
- BSD-3-Clause
- BSL-1.0
- CC0-1.0
- CDLA-Permissive-2.0
- ISC
- LGPL-2.1-or-later
- MIT and MIT-0
- Unicode-3.0
- Unlicense
- Zlib
- LLVM-exception

An expression's presence in this list is not advance approval for a new
dependency. Any lockfile change requires review of the package's source,
license expression, compatibility, provenance, security advisories, feature
graph, and whether the dependency is shipped in source or binary form.

The macOS-only `calcifer-macos-acl` 0.1.0 dependency is pinned exactly after
review of its complete source. It is MIT licensed, declares Rust 1.85 support,
adds no transitive Rust dependencies, and isolates system-libc ACL calls behind
a bounded safe descriptor API. Kitrove uses only its read API to fail closed on
extended ACLs attached to already-open cleanup directories.

The Windows-only `windows-sys` 0.61.2 dependency is pinned exactly and was
already present in the reviewed locked graph. Its MIT OR Apache-2.0 licensing
is approved. Kitrove's direct edge enables only the Foundation, Security,
Security Authorization, Globalization, FileSystem, and Threading bindings needed by the
non-published handle-bound security wrapper; no new third-party package entered
the graph.

The macOS-only `unicase` 2.9.0 and `unicode-normalization` 0.1.25 dependencies
were already present in the reviewed locked graph. Both are MIT OR Apache-2.0
licensed. Kitrove's new direct edges use their safe, deterministic Unicode case
folding and normalization APIs when rejecting overlapping private authority
roots on case-insensitive macOS filesystems. The lockfile change adds only those
two dependency edges: it changes no package, version, source, checksum, or
transitive package.

The Windows-only `pageant` 0.2.0 dependency is pulled unconditionally by the
exact-pinned `russh` release even though Kitrove does not use Pageant for SSH
authentication. Its Apache-2.0 license is approved. The crate declares Rust
1.85 support but contains one let-chain that requires Rust 1.88. Kitrove retains
the exact published source under `third_party/pageant` and rewrites only that
condition into equivalent nested control flow; the package version, public API,
features, and dependency graph remain unchanged. Provenance and the complete
source difference are recorded in `third_party/pageant/KITROVE_PATCH.md`.

Phase 6 offline release verification adds the exact-pinned Apache-2.0 `sigstore-*` 0.11.0
verification family, together with its ASN.1/X.509, canonical JSON, Merkle, and AWS-LC cryptographic
dependencies. The maintained verifier, rather than Kitrove code, owns certificate-chain, SCT,
transparency-log, timestamp, DSSE signature, and artifact-digest verification. AWS-LC builds audited
native cryptographic code and declares the combined ISC, Apache-2.0, MIT, BSD-3-Clause, and MIT-0
expressions now listed explicitly by the fail-closed license check. The complete graph builds on Rust
1.85 and its direct packages declare Rust 1.70 or compatible floors.

Upstream `sigstore-rekor` and `sigstore-tsa` 0.11.0 compile reachable HTTP clients even when their
default features are disabled. Kitrove vendors their complete published Apache-2.0 sources and
feature-gates only the client modules and network dependencies. Offline parsing and verification code
is unchanged. Exact crates.io hashes, upstream commit identity, source differences, and removal
conditions are recorded in `third_party/sigstore-rekor/KITROVE_PATCH.md` and
`third_party/sigstore-tsa/KITROVE_PATCH.md`. The release-provenance crate exposes no Sigstore or
network types. It pins the embedded public-good trust-root bytes to SHA-256
`6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` and requires an explicit
reviewed update before different trust material can become authority.

## Enforcement

Installer provenance boundary tests add a dev-only edge to the already reviewed
exact-pinned `zip` 6.0.0 dependency, using the workspace's disabled default features.
The complete lockfile delta adds only that edge; no package identity, version,
source, checksum or transitive dependency changes. It builds synthetic stored ZIP
fixtures in memory and adds no production dependency or new license expression.

The installer preflight adds a workspace-only edge to `kitrove-state-lifecycle`.
The accompanying dependency review updates the withdrawn RustCrypto `wnaf` 0.14.0
to 0.14.1 (Apache-2.0 OR MIT, Rust 1.85). The complete published source delta was
reviewed against upstream PR 1913: scalar endianness now uses `PrimeFieldExt` and
associated bounds. The only added transitive edge points to already-locked `primefield`
0.14.0; no other third-party version changes. Package checksum is
`795ca18b3fdb5e62bf982199278341ddcf7ebf7d32e25e212ad05d496e95f6fa`, source commit
`f722e37cee96e31e1b98b970f58bde43ef1a7b88`. Native compilation and Rust 1.85 Windows
compilation accept the changed bounds through `primeorder`, P-256/P-384/P-521,
`ssh-key` and `russh`. Fresh RustSec audit reports no warnings or vulnerabilities.
The earlier withdrawn-package warning below records historical evidence, not an
outstanding warning on this new graph.

The state-lifecycle snapshot edge reuses the existing exact-locked RustCrypto `sha2`
0.11.0 package (MIT OR Apache-2.0, declared Rust 1.85). Its workspace configuration
enables no new features. The reviewed lockfile delta adds only that direct edge:
no package, source, checksum, version or transitive dependency changes. State-tree
fingerprints use its safe incremental SHA-256 API without custom cryptography or
execution. Rust 1.85 Windows compilation passes; a fresh RustSec audit exits successfully
with the existing `wnaf` 0.14.0 yanked-package warning in the SSH graph, unrelated to this
edge. Its replacement requires separate compatibility review before release. The complete
locked SPDX inventory passes the existing fail-closed license command (382 packages).

`cargo xtask licenses` first binds the complete reviewed `Cargo.lock` bytes to a
checked-in BLAKE3 digest. Any package, version, source, checksum, dependency
edge, or other lockfile change therefore fails until the complete graph receives
fresh dependency and license review and the reviewed digest is updated. It then
reads the exact locked graph through Cargo metadata, rejects missing or newly
introduced license expressions, verifies that every Kitrove workspace package
declares `MIT OR Apache-2.0`, and prints a stable third-party inventory. The
canonical `cargo ci` check runs the same policy.

Before signing a release, save that inventory with the release evidence and
include all attribution and license text required by the packages actually
distributed. A dependency update is incomplete until the policy and
`THIRD_PARTY_NOTICES.md` remain accurate.
