# ADR-0036: Explicit local version probes bind executable policy

- **Status:** Accepted on Unix and Windows
- **Date:** 2026-08-31
- **Deciders:** Kitrove maintainers
- **North Star invariants:** NS-02, NS-04, NS-05, NS-07, NS-09, NS-10

## Context

Pi extension materialization is security-sensitive and its project-trust contract changed over time.
Read-only inventory deliberately does not launch harnesses, so its unknown version observation cannot
authorize executable projection. A caller-supplied version string would not prove which local
executable produced it, while automatic PATH probing would add surprising process execution to
ordinary planning.

## Decision

Kitrove provides an explicit diagnostic probe and an explicit materialization option for one absolute
harness executable. The reviewed policies support Pi and OpenCode V2 on Unix and Windows. Windows
user- and project-scoped Pi extension materialization use the same portable object, compiled policy,
plan, confirmation, and apply transactions as Unix; ADR-0039 supplies the additional handle-bound
saved-project trust authority on Windows. The probe invokes the selected executable
directly with `--version`, never through a shell; places the child in a dedicated process group on
Unix or an atomically assigned kill-on-close Job Object on Windows, terminates the whole group or Job
on completion or failure, and imposes a five-second timeout and bounded output;
rejects diagnostic, malformed, unsupported, or ambiguous output; sets Pi's offline/version-check
suppression flags; and disables OpenCode automatic updates and project-config loading. The child
receives only a minimal process-launch environment, not ambient API keys or harness credentials. On
Unix, `PATH` is reduced to directories that pass the same ownership and write-authority checks, and a
shebang interpreter—including one selected through `/usr/bin/env`—must resolve to a separately
validated executable. Windows omits `PATH` and every ambient environment variable.

On Unix, the probe canonicalizes the explicit executable path to support ordinary package-manager
shims, then requires the resolved target and every ancestor directory to have trusted ownership and
no group/world write authority. Windows accepts only a canonical local-DOS executable path and
retains a handle-validated owner/DACL authority chain for the executable, its ancestors, and the
System32 working directory. Both paths retain the opened file identity, check the selected path
against it immediately before and after execution, and hash the same opened file before and after. This closes
replacement by another account; a malicious concurrent process under the same operating-system
account remains outside Kitrove's isolation boundary. Accepted Pi versions are `>=0.79.0, <1.0.0`,
the reviewed line in which saved project trust is available and the earlier project-trust bypass is
fixed. OpenCode V2 is selected by its separately published `opencode2` executable identity and exact
`opencode2 v<semver>` output, not by guessing a numeric cutover from V1's `opencode` releases.

Verified evidence binds the harness, exact observed semantic version, selected compiled policy line,
and exact executable BLAKE3 hash. A dedicated, narrowly governed probe crate owns process launch and
returns an opaque authority value that production callers cannot construct from claimed evidence.
Core extension authorization requires that value and compares its exact evidence to adapter policy,
so version-range and evidence validation have one implementation. Both the individual extension plan
and the enclosing atomic batch digest include the evidence, so a different supported binary or
version invalidates confirmation. Apply rebuilds and reprobes after confirmation before mutation.

Ordinary scan remains process-free and reports unknown version evidence. A missing explicit probe,
unsupported harness or version, changed executable, timeout, or unsafe output fails executable
materialization closed. Probe evidence is local and ephemeral; it is not synchronized or treated as a
publisher signature.

## Alternatives considered

### Accept a version string from the command line

Rejected because it is not bound to a local executable.

### Probe PATH automatically during scan or every plan

Rejected because inspection would unexpectedly execute code and PATH selection would be ambiguous.

### Persist probe results

Rejected because executable replacement could make cached authority stale.

## Consequences

### Positive

- Pi executable materialization and explicit OpenCode V2 diagnostics can select reviewed policy
  evidence without weakening read-only scan.
- Confirmation binds the exact local executable evidence that selected the policy.
- Probe execution is direct, credential-minimized, explicit, and bounded to one terminated Unix
  process group or Windows Job Object.

### Negative

- Users must supply the exact harness executable path when a gated target requires version evidence.
- Executable hashing does not attest dynamically imported modules and is not a software signature.
- Each confirmed apply probes twice to detect authority changes around confirmation.
- Windows saved-project trust rejects unsupported namespaces, unsafe DACLs, and reparse-based
  profile or project layouts that Unix may represent differently.

### Follow-up

- Revisit the accepted Pi range when an incompatible 1.x policy is documented.
- Reassess Windows saved-project trust namespace and owner policy only with new native evidence and
  threat review.

## Validation

- Parser tests accept only one reviewed semantic-version token and reject unsupported ranges.
- Process tests prove absolute-path selection, timeout/output bounds, descendant termination, no
  shell, ambient-secret exclusion, unsafe interpreter-path refusal, and executable-hash binding.
- Materialization tests prove unknown evidence refuses and differing version evidence changes the
  confirmation digest.
- End-to-end tests prove saved-trust project application, and commit tests prove post-plan trust
  revocation refuses before mutation.
- OpenCode end-to-end tests prove project command and user instruction apply/removal, exact binary
  evidence changes confirmation digests, and receipt-backed removal does not re-execute the harness.
- Focused native Windows run `33594103934` proves exact executable/DACL authority, atomic Job Object
  containment, minimal environment and handle inheritance, Pi/OpenCode parsing, exact Unicode
  `argv[0]`, real user-scoped CLI plan/apply, Windows project refusal, confirmation-time re-probing,
  and the Rust 1.85 boundary for the three focused platform crates.
- ADR-0039 final implementation/evidence head `46b6e3f1e5847446936fd27c41136d1daaa069bf`
  and focused native Windows run `33653086327` additionally prove least-privilege structural
  traversal, exact trust-key and parent-inheritance semantics, saved-trust project plan/apply with
  project-scoped receipts, post-confirmation trust and ACL refusal, and complete CLI compilation on
  Rust 1.85.0.

## Supersession

This extends ADR-0012's no-active-probe rule for ordinary observation and amends ADR-0027's initial
user-only executable target. It should be superseded if Kitrove adopts signed harness attestations or
a stronger platform-native executable identity.
