# Installer DMG payload review

This unit implements only the private payload boundary in ADR-0043. It accepts
exact Mac installer archives on macOS, validates the existing archive/manifest,
checksum and cargo-dist authority, and stages three fixed leaves in a fresh private
directory. It does not sign, mount, execute, install or publish. Structural build
evidence is not public signature/provenance authentication.

Review covered product/target confusion, archive bounds and path handling, unchanged
inputs, no-overwrite output, directory/file permissions, durability and revalidation.
The new directory initially inherited tempfile's broader default; a regression test
caught this and creation now explicitly requests mode 0700. The payload writer uses
create-new and private modes. Errors drop only the owned temporary payload; success
retains it and reports the path. Future consumers must freshly validate the payload,
not trust the path or this past staging result.

Consolidation review: reuse existing installer archive parsing, manifest validation,
checksum rendering, cargo-dist validation and retained-file identity checks. Fixture
construction is shared with existing installer archive tests. No new dependency,
signature parser or application/installer authority conversion was introduced.

NS-07/NS-09 and INV-06/INV-07/INV-08/INV-12 remain unchanged. Portable/native
representation, discovery/adoption, fidelity, receipts and sync/conflicts are untouched.
No credentials or network are needed. Existing release inventory and activation
policies are unchanged. Native signature checks belong to subsequent DMG preparation,
not this structural staging step; unsigned development inputs are not mislabeled.

Focused tests cover both Mac targets, exact private inventory, source preservation,
wrong host/target/product/version, corruption, redirected archive and occupied leaves.
Local staging also passed against both actual Mac installer archives preserved from
rehearsal `35118722213`; no staged product was executed. Full cargo ci, xtask Clippy,
Rust 1.85 xtask check and diff hygiene passed locally. Native DMG/offline acceptance
is still open.
