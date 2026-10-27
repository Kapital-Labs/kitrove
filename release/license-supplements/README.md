# Reviewed license-text supplements

The current 385-package locked graph includes 16 registry packages whose published
crate archives have no named license/notice text. `index.json` maps each exact
package/version to retained, checksum-pinned upstream text. Generation never
downloads these files. The original downloaded bytes are preserved, including
line endings and absent final newlines; `.gitattributes` disables conversion.

Most entries use workspace-root license files at the crate's recorded
`.cargo_vcs_info.json` revision. Important limitations are recorded explicitly:

- `cms` 0.2.3 declares Apache-2.0 OR MIT but omits license files in both its crate
  and source subdirectory. Its supplement preserves the same RustCrypto formats
  project's Apache/MIT texts under `der/` at the exact recorded source revision,
  including the RustCrypto Project Developers copyright. It does not claim the
  CMS crate itself contained those files.
- `russh-util` records `dirty=true`. Its recorded source revision identifies the
  workspace license text, not uncommitted crate-source identity.
- The two winapi target crates record no VCS revision. Their MIT/Apache-2.0
  declarations and author are present in their checksum-authenticated manifests.
  Supplements preserve their declared upstream project's Apache/MIT texts at the
  pinned 0.3.9 repository commit, including the winapi-rs Developers copyright.
  This is the text's provenance, not a fabricated source revision for those crates.

Review these mappings and publisher declarations whenever their package versions
change. Text SHA-256, exact source URL and these limitations travel in the generated
bundle. This operational repository-policy review is not a legal opinion, a new
license grant, or proof of legal compliance. No older release asset is changed.
