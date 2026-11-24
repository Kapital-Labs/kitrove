# Diagnose local storage with Kitrove doctor

`kitrove doctor` checks local collection and application-storage conditions without
changing files. It gives a short report and a redacted JSON report for support.
Doctor was introduced in RC5.19; RC5.18 does not include it. RC5.20 adds the
specific retained-cleanup findings described below. RC5.19 keeps its original
generic cleanup messages and JSON schema 1.

RC5.21 identifies which part of a retained item's Unix filesystem identity
differs and reports it in JSON schema 3.

```sh
kitrove doctor --help
kitrove doctor
kitrove doctor --environment /absolute/path/to/collection
kitrove doctor --environment /absolute/path/to/collection --json
```

The default collection is `~/Kitrove`. An explicit `--environment` selects another
collection. The command uses the same private-state location as other Kitrove
commands, including an absolute `KITROVE_STATE_HOME` override. It does not print
that location or the override's value.

## What the report checks

- Portable manifest, derived lock and referenced-object integrity, using existing
  validators and their normal limits.
- Private-state protection, including the native ACL check where supported, and
  existing machine-local state-file metadata. Its contents are not parsed.
- Existing application-control directories, mutation-lock metadata and fixed
  recovery-marker presence.
- Retained quarantine structure and recorded identities, using the same bounded
  read-only inspector as transaction cleanup.

The first command covers user-scope application storage. It does not inspect a
project destination or establish which skill a tool loads. A present recovery
marker is an observation, not a statement that its contents are valid or that
recovery should run.

An ordinary permission listing can look correct while native private-directory
protection or retained recovery files fail validation. Follow the reported check
and code. Keep retained recovery files in place for review.

## Specific retained cleanup findings

Doctor reports the first failed cleanup invariant in each storage root directly
in its ordinary output. RC5.21 also distinguishes the mismatching Unix identity component.

```text
Kitrove doctor: needs attention
  Collection (retained files): the recorded device ID differs; the file ID matches.
    Retained item 3 in this inspection.
Next: leave retained files in place and share this report for recovery review.
No changes made. Write access and lock availability were not tested.
```

Findings distinguish recorded identity mismatches, entries that changed while
being inspected, links or redirected entries, wrong file types, hard-linked
retained files, unrecognized name formats, pending folders not verified empty,
multiple cleanup batches, directory protection failures, unreadable metadata or
listings, refused opens and inspection limits. These describe observed checks,
not an inferred cause of an earlier apply failure. A normal-looking `0700`
directory listing does not verify its retained entries.

On Unix, the identity finding states whether the recorded filesystem device ID, file
ID, or both differ from the current entry. It uses the metadata from the
original failed comparison, without another scan or disclosure of identifiers.
Other failures and Windows' complete native identity checks do not claim a Unix
component comparison. A disk-only mismatch does not by itself prove a restart,
remount or restore caused it; a file mismatch does not prove corruption.

The item number is a one-based position in this inspection's bounded, sorted
**top-level** cleanup listing. A descendant finding identifies a problem inside
that item's directory. The number can change on the next inspection and is not a
filename, a stable item ID or authority to delete anything. Boundary failures and
limits reached before selecting an item have no item number. Doctor stops at the
first failed invariant per root; it does not claim to find every cleanup issue.
Do not rename, remove or repair retained files based only on this report.

## What a result means

**Observed checks passed** means the reported read-only checks passed. It grants
no trust or ownership and does not replace an apply preview or confirmation.

**Needs attention** identifies an observed failed or incomplete check. Some
permission differences can be normalized by an approved mutation; a read-only
inspection does not try that operation or predict its outcome.

The report is an unlocked observation. It does not acquire locks, test write
access, normalize permissions, clean up files, recover transactions, initialize a
collection, synchronize, run collected content, launch tools or contact a provider.
A later filesystem change or operating-system refusal can still stop an apply.

## Sharing a report

Share the ordinary report first; it includes the cleanup identity component.
Use `--json` when support needs the full structured observations. The versioned report
contains the public CLI version, fixed roles/checks/statuses/codes and bounded
counts. RC5.19 emitted schema 1 and RC5.20 emits schema 2.
RC5.21 uses `schema_version: 3`. Version 2 retains the existing fields
and adds an optional `detail` object to
failed retained-cleanup checks: closed `location` (`boundary`, `entry` or
`descendant`) and `reason` labels, with an optional bounded `entry` number.
Version 3 adds optional `detail.identity_component` with closed values `device`,
`file` or `device_and_file` only for observed Unix recorded-identity mismatches.
The existing `reason: identity_mismatch` and coarse mutation errors remain.
It excludes paths, user/group identities, ACL principals, environment
values, skill names, trust decisions, file bodies and raw operating-system errors.
It does not upload or save a report automatically.

Normal findings use exit status `3`; successful reported observations use `0`.
Optional missing control or lock files are not created. Invalid arguments use `2`;
unexpected internal command failures retain the usual error handling.

The JSON labels the snapshot `inspection: unlocked` and
`mutation_access: not_tested`. A clean report cannot establish what caused a past
failure or prove that the next write will succeed.

See [adding items to tools](ADD-TO-TOOLS.md) for selection and approval, and
[quarantine recovery](QUARANTINE-RECOVERY.md) for retained-state boundaries.
