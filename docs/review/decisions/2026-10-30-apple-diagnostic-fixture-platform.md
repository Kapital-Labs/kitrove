# Diagnostic copy fixtures declare their POSIX boundary

## Cause and narrow correction

PR97 introduced two synthetic end-to-end Apple diagnostic tests that exercise the
real no-follow POSIX image-copy helper. Unlike the existing corresponding copy
tests, they omitted the POSIX-only declaration. Windows has no os.O_DIRECTORY;
these fixtures are not portable Windows tests. The public diagnostic entry point
already refuses non-macOS hosts before copying/signing; no production platform
behavior or native check needs to change.

Declare ONLY those two copy fixtures POSIX-only, matching the established suite.
Their actual filesystem/identity/error assertions still run on every POSIX test
host. Keep the pure final-verifier and source/closed-record tests cross-platform.
A metadata regression checks both required declarations and that the pure final
verifier is not skipped. Its absence fails red, then the two declarations pass.

## Evidence and gates

An isolated Python API-surface emulation (not native Windows evidence) reproduces
AttributeError at the exact os.O_DIRECTORY copy operation. Hosted original main
CI is retained without rerun. Native Windows verification of the corrected exact
source is required before remediation merge; regular Required CI still applies.
Run full stable/Rust1.88, manual diff/caller review, secret scan and normal public
PR checks. This test-only remediation is not a feature merge over broken main;
require exact repaired main green before any signing or diagnostic activation.

## Scope

NS-07/NS-09 semantics unchanged; no product, signer, workflow, permissions, source
guard, archive, signature, ticket, cleanup, retry, timeout, dependency, version or
catalog edit. No source/verification bypass or live Apple operation. This is a
test-fixture portability mistake introduced during diagnostics, NOT the cause of
historical Apple stapling68. Signing and both markers stay off, original tag-only
release policy/reviewer/no-admin-bypass intact. Other readiness remains paused.
Manual review only; no independent-agent/exhaustive repository claim.
