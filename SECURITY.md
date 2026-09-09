# Security Policy

Kitrove is not publicly released and should not be used in production or with irreplaceable agent environments.

## Supported versions

No public version is supported yet. During the release-candidate period, security fixes are made only on the current reviewed development line; older commits and unreviewed branches are unsupported. A versioned support table will replace this paragraph before the first public release.

## Reporting a vulnerability

Do not include credentials, private capability content, machine paths, or exploit details in a public issue.

Use [GitHub's private vulnerability reporting form](https://github.com/Kapital-Labs/kitrove/security/advisories/new) to report a suspected vulnerability. Sign in to GitHub to submit a report. Private vulnerability reporting is enabled for this repository; reports are not public issues. If the form is unavailable, open a minimal issue asking the maintainer to establish private contact without disclosing the vulnerability.

Please include the affected revision, platform, impact, a minimal reproduction using synthetic data, and whether exploitation may execute content, disclose local data, cross a receipt/trust boundary, or corrupt portable authority. You should receive an acknowledgement within five business days; remediation and disclosure timing will depend on severity and whether a safe release is available.

## Security boundary

- Portable state never contains harness credentials, decrypted secrets, machine identity, deployment receipts, or executable trust decisions.
- Remote executable content is preserved but never automatically trusted or executed.
- Executable materialization requires machine-local exact-object trust plus a separate fresh destination confirmation.
- Mutations require exact ownership and stale-input evidence and use fail-closed recovery journals.
- Unsupported transformations are reported rather than silently approximated.
- Human output, JSON, errors, and routine debug surfaces must redact authored content, native identity where required, machine paths, and secret material.

The current threat model is in [`docs/04-THREAT-MODEL.md`](docs/04-THREAT-MODEL.md). Security-sensitive changes must follow [`docs/REVIEW_PROCESS.md`](docs/REVIEW_PROCESS.md).
