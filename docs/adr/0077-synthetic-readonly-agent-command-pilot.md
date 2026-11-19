# ADR-0077: Synthetic read-only agent command pilot

- **Status:** Accepted for local prototype by maintainer request, 2026-11-18; live connection and public distribution not approved
- **North Star:** NS-01, NS-03, NS-04, NS-05, NS-07, NS-08, NS-09, NS-10
- **Related:** ADR-0003, ADR-0008, ADR-0057; Grok pilot tool contract

## Decision

Provide a source-only MCP stdio pilot for a private synthetic collection. Expose
only pack listing, authored-pack inspection and user-scope ordinary-skill plans
through the existing CLI. No mutation, arbitrary command, resource-body export,
trust, recovery, remote URL, binding resolution or agent execution tool exists.
No application command, dependency, release asset or channel is changed.

Operator configuration fixes a canonical private root, its role directories and
an independently verified CLI SHA256. A synthetic-data marker is mandatory.
Validate ownership, protected ancestors, regular files, no symlinks/hardlinks,
bounded inventory and the executable before and after each operation. The pilot
recognizes only the clean RC5.18 control layout. Recovery or unknown control
entries stop it without repair or evidence deletion.

Requests and CLI responses use closed schemas and bounded JSON. Tool arguments
are fixed arrays, never shell text. Return only validated IDs, member/action
counts, target, scope and known refusal codes. Discard private destinations,
skill bodies, source metadata, raw errors and all digests from Bot-facing output.
Preview results are advisory, not write authority or proof of tool loading.

The prototype supports POSIX systems with `waitid` and `WNOWAIT`. Windows
refuses before launch until a reviewed Job Object lifetime exists. A new session
owns each CLI child. Bound combined output and runtime, close its stdin and scrub
inherited environment. Keep the leader unreaped through the final group signal;
never signal a numeric group after reaping its leader. Cleanup must be confirmed
before returning any operation result. EOF, cancellation and handled shutdown
stop active work. Cleanup uncertainty or an unknown result terminates the session.

## Limits and consequences

This is not containment of hostile same-user code, a detached daemon, a malicious
operator or an uncatchable outer termination. The configured CLI and reviewed
server source remain trusted executable inputs. Filesystem operations themselves
are subject to the host filesystem; a ten-second child budget is not a promise
that arbitrary blocked filesystem access finishes in ten seconds.

Authored packs, ordinary skills, fixed user scope and short sessions keep the
first acceptance bounded. Unsupported content and future schemas refuse rather
than silently broadening the pilot. MCP annotations are hints, not authorization.
The server neither contains other applications on its computer nor establishes
separate isolation between Bots sharing a provider account.

A live Grok command connector runs on the provider's computer, not automatically
on the user's Mac. Uploading data/source there or connecting a local computer is
a separate scope decision after the reviewed prototype is concrete. No account,
credential, provider transfer, permission expansion, live connector installation,
new version, signing, tag, release or announcement follows from this decision.
