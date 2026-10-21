# ADR-0057: Opt-in versioned machine-readable errors

Status: Accepted

## Context

Agent workflows already expose JSON plans/results and exact-digest approval.
Operational errors use human stderr; agents must otherwise parse prose. Changing
existing stderr unconditionally would break consumers and obscure compatibility.

## Decision

An optional leading `--json-errors` selects a version1 JSON stderr envelope for
argument and operational failures handled by the CLI entry point. Success stdout
is unchanged: use the command's existing `--json` flag for JSON plans/results.
The envelope contains only `schema_version`, `error.code`, and `exit_code`.
Do not copy diagnostic messages, input values, paths, source content or credentials.
Existing human stderr remains the default. The selector is recognized only as the
first argument, so flag-like values in other positions are never reinterpreted.

Exit1 means an operational refusal/failure; exit2 means invalid command usage.
Successful command reports can still return nonzero attention/conflict statuses;
their existing structured stdout is authoritative, not an error envelope. Process
termination, panic, and unavailable output streams are outside this contract.
Error codes are an extensible vocabulary; unknown codes require stopping and
operator review, never automatic retries, reapproval or privilege escalation.

This is an output-only increment. It does not make legacy interactive commands
noninteractive, perform recovery, grant trust, or authorize mutations. Agents use
documented preview/exact-confirm forms with closed stdin. Broader success-contract
standardization and capability acceptance remain separate roadmap gates.
Legacy interactive prompts may still precede errors; those flows are not a
JSON-only stderr stream.

## Validation and North Star

NS-01, NS-05, NS-06, NS-10: machine-readable bounded failures without widening
authority or exposing source material. Tests cover usage/operational failures,
default compatibility, unchanged success JSON, closed stdin and canary exclusion.
