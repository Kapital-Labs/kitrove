# Offline installer development workflow

The `kitrove-installer` executable is under development. Separate installer packaging
is implemented and has been exercised locally, but an attested public release download
is not yet available. This guide describes the implemented first-install and replacement
interfaces, not a claim of complete release acceptance. Use [RELEASES.md](RELEASES.md) for
the currently accepted release-verification procedure.

The installer runs as the current ordinary user. It does not download releases,
discover a latest version, elevate privileges or repair unsafe permissions. The
destination directory must already exist and be controlled by the current user.
Artifact and destination paths must pass the shared no-follow security checks.

## Exact release inputs

Every command requires the exact release inputs below. Bundle selection forbids
`--destination`; installation, replacement and history require it.

| Option | Input |
|---|---|
| `--archive` | Exact platform application archive, retaining its published basename |
| `--bundle` | The archive's offline attestation bundle |
| `--tag` | Exact release tag, such as `v1.2.3` |
| `--commit` | Independently resolved full source commit for that tag |
| `--sha256` | Published archive SHA-256, an additional assertion rather than signature authority |
| `--destination` | Existing installation directory, not the executable filename |

`--bundle` accepts one UTF-8 JSON Sigstore bundle, bounded to 256 KiB. A JSON array
or a file containing multiple JSONL bundle records is not accepted. Do not assume
an attestation-download output can be passed directly without checking its format;
use the separate selection commands below to establish the exact matching bundle.

The installer always verifies the offline signature and release identity itself.
A checksum, version string or previous verification receipt cannot bypass this.
First obtain and verify the installer itself using the eventual supported bootstrap
procedure; verification performed by an untrusted installer would not establish trust.
The offline provenance library supports installer-specific verification under the
`Kapital-Labs/kitrove` identity, separate from application authority. Read-only bundle
selection is implemented; first-download trust and signed bootstrap acceptance remain
release gates.

## Select one downloaded attestation bundle

An independently trusted installer (or one built from reviewed source with
`cargo build --locked --release -p kitrove-installer`) provides
`select-application-bundle` and `select-installer-bundle` for their respective archive
families. Both take only `--archive`, `--bundle`, `--tag`, `--commit`, and `--sha256`.
Here `--bundle` is the JSONL collection produced by
[`gh attestation download`](https://cli.github.com/manual/gh_attestation_download),
not a JSON array or `gh attestation verify --format=json` output. The archive must
have the exact published basename for this installer's compiled platform.

The commands read and revalidate both files, authenticate the exact release identity,
and print one selected bundle to stdout. No files, state roots or executable placement
are changed. Destination, prior-release, history and state-root options are rejected.
Failures print an error, not a partial bundle.

Selection accepts at most 32 records, 256 KiB per record and 8 MiB overall, with LF
or CRLF framing and an optional final newline. Blank/malformed/unsupported records
reject the entire collection. Cryptographically invalid or nonmatching candidates
are never selected. Exactly one match is required; even two identical matching
records are ambiguous. Resolve ambiguity by explicitly reviewing the attestations,
not blindly taking the first line. Preserve inputs on failure.

Save successful stdout as a new UTF-8 file in a private directory, without overwriting
an existing file. In older Windows PowerShell, default redirection may use an encoding
other than UTF-8; explicitly preserve UTF-8 without a BOM. Use that file as `--bundle`
for preflight/install or replacement. Those commands freshly verify it; selected JSON
or a past successful command is not reusable installation authority.

The reviewed-source-built consumer sequence is: acquire the exact application archive
and JSONL with an independently trusted download tool; run `select-application-bundle`
with independently selected tag/commit/digest; save successful stdout; then run
`preflight-install` and `install` with that single bundle, the same pins, the destination,
and every configured state root (or `--no-state-roots` only for a machine with no state).
The public repository currently has no release artifacts, so this is a development
contract, not a completed public release rehearsal. Do not run a downloaded installer
merely to ask it whether it is trustworthy.

## Commands

- `preflight-install` authenticates the release and checks selected state, absent
  destination and idle installer state without creating files. It holds state guards
  only during inspection; it is not a reservation or proof of future install success.
- `install` performs a state-guarded first installation. An existing executable is
  never overwritten. Success reports the operation ID after the contained version probe.
- `recover-install` reopens the retained first-install transaction using the same
  authenticated release inputs and original root selection. It does not imply a fresh
  installation. A failed probe can restore the absent-install state while retaining evidence.
- `retire-install` moves a verified terminal first-install operation into private history,
  preserving all evidence. Use current configured state roots for this operation.
- `history-status --operation ID` inspects one archived first installation without
  changing it. Its historical outcome does not identify the currently installed version.
- `history-sync --operation ID` explicitly retries synchronization of an already archived
  first installation, with current configured state roots. It does not complete pending
  journal entries or alter the installed executable.

All commands above take the exact release options. All except `history-status` also
require `--state-root PATH` repeated for **every** configured Kitrove state root, or
`--no-state-roots` only when no application state exists. These alternatives are exclusive.
Omitting state selection is an error. The installer cannot discover omitted roots for you.
`history-status` rejects state selection because stored root paths are historical data,
not permission to access them. Paths with spaces should be quoted in either shell.

If an operation fails, preserve `.kitrove-installer` and `.kitrove-installer-history`.
Do not delete files or change permissions to force a retry. Reuse the exact independently
selected release inputs for guarded recovery; unknown or changed evidence deliberately
requires manual investigation. Successful history inspection alone is not proof of a
durably synchronized archive; use `history-sync` when retrying an interrupted archival.

## Existing-binary upgrade and rollback

Use `preflight-upgrade` followed by `upgrade`, or `preflight-rollback` followed by
`rollback`. Both require the exact candidate inputs above and five additional options:
`--prior-archive`, `--prior-bundle`, `--prior-tag`, `--prior-commit`, and `--prior-sha256`.
The prior is always the version currently installed, including when the candidate is
older. Independently select both releases; neither a local version string nor saved
history supplies the expected release identity. Compatibility must be explicitly declared
by the newer release. Preflight performs no replacement and is not reusable authority.

Replacement retains a verified offline kit for the prior release before changing the
executable, holds all selected state roots, and checks the newly installed digest and
contained version probe before reporting success. A failed probe restores the exact
prior while preserving both executables and recovery evidence. Binary rollback does not
roll application data backward; incompatible state migrations are not supported.

Windows uses guarded journaled two-step moves, **not atomic exchange**. The CLI path can
be absent between moves or after interruption. Keep the separate verified installer,
candidate inputs and independently selected prior pins available for recovery.

- `recover-upgrade` or `recover-rollback` takes the candidate inputs, current state-root
  selection and `--prior-tag`, `--prior-commit`, `--prior-sha256`. It freshly authenticates
  the retained prior archive and bundle; prior file paths are rejected. Recovery requires
  the original operation's state evidence to match the selected roots. Untouched complete
  preparation may proceed; an interrupted Windows gap restores the prior. Restoration
  intent and completed restoration never restart a forward replacement.
- `retire-upgrade` or `retire-rollback` uses those same inputs with current configured
  state roots to retain a verified terminal operation in history, without deletion.
- `upgrade-history-status` or `rollback-history-status` additionally requires
  `--operation ID` and rejects state-root selection. It inspects only the selected
  archive, not the currently installed executable, and grants no rollback authority.
- `upgrade-history-sync` or `rollback-history-sync` takes `--operation ID` and current
  configured state roots to retry archival durability without completing journal entries
  or changing executable placement.

Direction always refers to the original operation. Restoring a failed upgrade does not
turn it into an explicit rollback operation. Retire terminal installer state before
starting another installation or replacement; do not manually clear it.

Full release-matrix acceptance and the authenticated public bootstrap procedure remain
release gates. The replacement command checkpoint passed canonical host validation and
focused native Windows acceptance; production-signed two-release bootstrap evidence is
not yet available.
Run `kitrove-installer --help` for its current syntax.
