# Native release staging

North Star impact: NS-09 (safety precedes convenience). No product capability or
release authorization change.

The replacement prerelease run reached Windows archive signing and successful
credential cleanup, then Git Bash rejected `mkdir -m 700`. Both Mac targets and
Linux completed their local artifact jobs; nothing was published.

The staging creator now uses Unix mode 0700 or the existing
`kitrove-windows-security` atomic private-directory API. Windows gets the same
protected current-user/System ACL validation already used by Kitrove, rather than
a second PowerShell ACL implementation or a best-effort chmod. Existing paths
fail closed; no permission repair or destination reuse is attempted. The fixed
relative directory is used only inside the trusted ephemeral build workspace.

Archive selection, metadata/checksum verification, staged bundle revalidation,
attestation, and publication gates are unchanged. The remaining Bash handoff uses
portable basename/copy/output operations; the new test executes that exact body
with real directory creation and copies, stubbing only separately tested archive
verifiers. It also proves a collision stops before copying or verification.
Rust tests check native private permissions, write access, and preserved file and
directory collisions. Existing canonical Windows CI runs both suites without
signing credentials. Native Windows CI must pass before another release attempt.

Dependency review: one target-specific edge from xtask to the existing in-workspace
Windows security crate. No new external packages, package versions, or licenses.
The workflow digest is refreshed only for the reviewed staging command change.

Local validation: 56 xtask tests passed (one native-image operator test ignored),
80 Python tests passed (one platform-specific test skipped), strict xtask Clippy,
workflow lint, formatting, governance, dependency-license and repository checks.
These are Mac results, not Windows runtime evidence. Required Windows CI remains
the gate for this fix.
