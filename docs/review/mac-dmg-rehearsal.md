# Mac-only DMG rehearsal review

The existing manual workflow gains one explicit `mac-dmg` scope. Its default remains
the three-platform archive rehearsal. The DMG scope has only two build/sign targets,
skipping Windows costs; its matrix is selected directly rather than relying on
exclusions that could be reintroduced by matrix include entries.

Both Mac builds must succeed before either signer can proceed. Windows may be
skipped only in the Mac-only scope. Cancellation blocks signing. The source SHA,
main-only dispatcher, protected environment, nonpublishing permissions and prebuilt
digest-bound handoff remain unchanged. No runner or signing job has been started.

Native preparation remains in the production Apple wrapper. Scope validation is
shared between context and evidence verification. After credential cleanup, exact
container inventory is copied into the fresh evidence directory and reverified by
the existing native verifier against the copied installer archive/build manifest.
Failure creates no success record and the upload step cannot run. Evidence names
its scope and remains explicitly unpublished, with one-day retention.

Review covered scope refusal, Windows exclusion, skipped/failed build handling,
cancellation, credential cleanup ordering, no product execution, copied-byte
verification and unchanged archive-only behavior. Synthetic tests exercise both
Mac targets, extra output refusal and native-verifier failure. They do not establish
real hosted signing, production provenance or clean-machine acceptance.

Validation passed: 77 Python tests (one skipped), actionlint on the dispatcher and
reusable build workflow, governance, repository and diff checks. No Rust runtime
code changed, so a redundant full local Rust suite and signing run were not needed.

The subsequent main Windows check exposed an unused mutable directory builder in
the previously merged native-image tooling. Mutation is now scoped to the Unix
permission-setting block; Windows uses the immutable builder. This preserves Unix
mode 0700, exclusive directory creation, and failure handling without suppressing
warnings or duplicating the creation path. Follow-up review found no behavior or
authority change. All 11 automated DMG tests passed (one operator-only native test
remained ignored), along with all-target/all-feature xtask Clippy on the Mac host
and the Windows GNU cross target. Cross-target linting is not Windows runtime
evidence; hosted main validation remains required.

NS-07/NS-09 and INV-07/INV-12 remain unchanged. Capability discovery, adoption,
portable/native preservation, fidelity, receipts, synchronization and conflicts are
untouched. Activation and an actual signing run require separate approval.
