# Installer payload staging review

Scope: Unix-only, library-only non-executable preparation under ADR-0041. No CLI,
Windows staging, native-signature-gated executable publication or launch is added.

The public entry point consumes authenticated installer authority, checks the
compiled target and ordinary-user context, and retains the authenticated object.
Compile-fail tests prevent application inputs or conversion to application staging.
No public raw-byte constructor or executable path is exposed. Drop closes handles
without granting cleanup authority.

Filesystem operations reuse the existing ancestry, private-directory, create-new,
no-follow, single-link, bounded digest and sync helpers. Review added child identity
and empty-inventory checks before writing, as well as namespace checks around final
digest validation. After creating output, errors preserve partial data and report
recovery required. There is no retry, permission repair or recursive deletion path.

Tests cover mode 0600, exact bytes, retained output after drop, occupied and redirected
names, unsafe permissions without repair, changed bytes/identity/permissions/inventory,
hardlinks, child and ancestor replacement, and injected failure at creation/write/sync
boundaries. Boundary injection proves failure retention, not every possible native
I/O failure. Existing shared-helper tests provide additional filesystem coverage.

An ignored, operator-only arm64 Mac integration test pins the real RC2 installer
archive digest, tag and commit, then performs full offline provenance verification
before passing the opaque result through the public staging API. It accepts only
local files, uses bounded snapshots and never executes the payload. It is not a
clean-machine, native executable launch or Windows ACL test.

Final canonical `cargo ci` and `cargo +1.85.0 ci` passed locally, including the
additional review regressions and compile-fail type checks. The ignored real-artifact
test also passed on the existing arm64 Mac without executing the payload. The MSRV
lint pass caught an inefficient hex-formatting pattern in that test; it was corrected
before both final canonical runs. Hosted native checks remain required for the exact
pushed head; these results do not establish Windows staging or clean-machine launch.

NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12 are preserved. Local staging does not
affect discovery/adoption, portable/native content, fidelity, capability receipts,
synchronization or conflict behavior. No dependency, cryptographic policy, signing
configuration or platform support guarantee changes. SECURITY wording now acknowledges
public prereleases without promising stable support or maintenance of old candidates.
