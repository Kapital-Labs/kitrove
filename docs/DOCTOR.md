# Diagnose local storage with Kitrove doctor

`kitrove doctor` checks local collection and application-storage conditions without
changing files. It gives a short report and a redacted JSON report for support.
This command is included in RC5.19; RC5.18 does not include it.

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

Use `--json` and copy its output into a support conversation. The versioned report
contains the public CLI version, fixed roles/checks/statuses/codes and bounded
counts. It excludes paths, user/group identities, ACL principals, environment
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
