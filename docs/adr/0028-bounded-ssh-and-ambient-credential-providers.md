# ADR-0028: SSH and ambient credentials are bounded local transport capabilities

- **Status:** Accepted for Phase 2 implementation
- **Date:** 2026-08-29
- **Deciders:** Kitrove maintainers
- **North Star invariants:** NS-03, NS-05, NS-06, NS-07, NS-08, NS-09, NS-10

## Context

ADR-0025 deliberately limited Git synchronization to HTTPS with an operation-local Basic credential.
Phase 2 also calls for SSH Git transport and safe use of ambient credential providers without storing
credential values in Kitrove. Both features cross machine-local trust boundaries: SSH introduces host
identity, agent signing, and a remote command channel, while credential providers may execute code or
return secrets selected by local configuration.

Invoking the ambient `ssh` or `git` executable would import user configuration, aliases, proxies,
hooks, credential helpers, shell fragments, prompts, and version-dependent behavior into the trusted
path. Reimplementing SSH cryptography and protocol handling would create a larger and less reviewable
security surface. The existing bounded Git advertisement, packet-line, pack, object, history, and
exact-old compare-and-swap state machines should remain the only Git protocol implementation.

## Decision

### One Git protocol, two byte transports

Kitrove will extract the already-reviewed smart-Git client state machine from its HTTPS request wiring
behind a private bounded byte-transport contract. HTTPS and SSH will share canonical ref validation,
packet-line parsing, pack construction and decoding, object/history budgets, exact-old publication,
status validation, redaction, and recovery. The SSH adapter may translate channel events into that
contract; it may not duplicate Git parsing or relax any shared meter.

SSH support uses an exact Cargo.lock-pinned release of `russh` with default features disabled and only
the reviewed algorithms and runtime features enabled. The selected release must support Rust 1.85 and
all three tier-one operating systems. Kitrove does not invoke `ssh`, `git`, a shell, or an askpass
program for SSH transport. Dependency selection remains provisional until the exact feature graph,
licenses, advisories, and native builds pass the implementation gate.

The reviewed implementation uses `russh` 0.62.0 with only `ring`, plus `tokio` 1.53.1 with only the
runtime, I/O, network, synchronization, and time features required by that client. Russh's locked SSH
key implementation requires `zeroize` 1.9.0, which supersedes ADR-0025's 1.8.1 pin for both the
existing HTTPS credential and this SSH boundary. Compression, AWS-LC, RSA, DSA, DES, serialization,
legacy key-file parsing, process, signal, filesystem, and full-runtime feature bundles remain disabled
unless a later exact-graph review authorizes them. RSA is specifically excluded because the candidate
graph otherwise triggers RUSTSEC-2023-0071 with no fixed release; RSA-only host or agent keys fail
closed instead of receiving an advisory waiver. Because the selected library parses the returned
identity list as one bounded frame, an agent response containing an unsupported RSA identity also
fails closed rather than partially trusting the remaining list.

Russh 0.62.0 is an advisory-fixed release whose declared minimum Rust version matches KitRove's
Rust 1.85 floor. Its Windows-only dependency graph includes Pageant support, but KitRove never calls
that API: the composition root accepts only the fixed Windows OpenSSH named-pipe endpoint described
below. The target-specific package remains covered by the exact lockfile, license, and advisory gates.
The lockfile also holds `aes` at 0.9.2 because the next semver-compatible release raises its Rust
floor to 1.89; governance names that transitive pin explicitly in addition to binding the whole
lockfile digest.

### Canonical SSH repository identity

The only accepted SSH form is `ssh://[<user>@]<lowercase-ascii-host>[:<port>]/<repository-path>`.
The parser rejects passwords, query strings, fragments, empty or default-spelled ports, IP ambiguity,
Unicode/IDNA input, control or whitespace bytes, encoded delimiters, dot segments, repeated
separators, backslashes, quotes, tildes, and SCP-like syntax. The normalized URL and backend kind
derive `RemoteKey`; the raw URL, username, path, and host never enter portable state or output.

The SSH adapter opens one session channel and requests exactly one compiled service command:
`git-upload-pack '<path>'` for reads or `git-receive-pack '<path>'` for conditional writes. The narrow
path grammar makes the quoted operand unambiguous. No user-authored command bytes are accepted.
PTYs, interactive shells, environment requests, subsystems, X11, TCP forwarding, Unix-socket
forwarding, proxy/jump hosts, SSH config, agent forwarding, and server-initiated channels are refused.

### Host identity is explicit and read-only

Kitrove checks the server key against a machine-local OpenSSH `known_hosts` file. The path is supplied
by the composition root from the local user context and is never portable. Inspection is read-only:
Kitrove never creates, repairs, appends to, or changes permissions on the file or its parent.

The parser has fixed file, line, entry, host-list, key, and aggregate-work limits. It supports exact
canonical hosts, exact bracketed non-default ports, comma-separated exact entries, and OpenSSH hashed
host entries. Wildcards cannot grant authority. Target-matching revoked keys, certificate-authority
entries, malformed or unsupported records, ambiguous duplicate algorithms, unknown hosts, changed
keys, missing files, unsafe file types, symlinks, and concurrent replacement all fail closed with
structural redacted errors. Unrelated host records are charged to the aggregate budget but do not
control the selected host. The unbounded `russh` convenience parser is not used. Kitrove provides no
trust-on-first-use mode and does not learn host keys.

### Authentication is signing, not secret import

The first SSH authentication capability is a machine-local SSH agent. On Unix, Kitrove may connect to
the exact `SSH_AUTH_SOCK` Unix-domain socket after validating its local shape. On Windows, Kitrove uses
only the compiled OpenSSH named-pipe endpoint `\\.\pipe\openssh-ssh-agent`. Pageant is excluded from
this candidate because it would add a second Windows-specific IPC and identity boundary. Kitrove
requests a bounded list of
public identities, attempts at most a fixed number in deterministic agent order, and asks the agent to
sign only the SSH authentication challenge for the exact active session. Private keys and passphrases
never enter Kitrove. Agent forwarding, adding/removing keys, locking/unlocking the agent, and arbitrary
agent extensions are not exposed.

If the canonical URL omits a username, the compiled Git-hosting username `git` is used; Kitrove never
reads SSH configuration or an ambient login name to choose it.

Password and keyboard-interactive SSH authentication, private-key file loading, PKCS#11 providers,
FIDO middleware discovery, Pageant, and automatic SSH-agent startup are outside this decision. A
missing,
unavailable, malformed, oversized, or unsuccessful agent fails closed without falling back to another
credential source.

### HTTPS credential providers require explicit local authorization

Kitrove will not automatically run `git credential fill` or discover `credential.helper` entries.
Those interfaces may execute arbitrary shell fragments, inherit broad Git configuration, or prompt.
Direct operating-system keychain integration is deferred until a cross-platform read-only mapping can
be specified without making Kitrove the credential store.

The separately reviewed Phase 2 provider reads only `KITROVE_GIT_USERNAME` and `KITROVE_GIT_TOKEN`
after explicit `--git-env-credentials` selection. It accepts only the canonical HTTPS origin, returns
one operation-local zeroizing credential, has one challenge-gated attempt, and uses the existing fixed
transport deadlines, input/output limits, and structural redacted errors. It cannot enumerate,
create, update, approve, reject, or delete credentials. No provider name, path, account, or secret is
portable. Existing interactive Basic credential entry remains available and is never silently mixed
with the environment source. Operating-system keychain integration remains deferred.

### Budgets, lifecycle, and errors

Connection, key exchange, host verification, identity enumeration, each authentication attempt,
channel open, service start, reads, writes, shutdown, and task completion have fixed deadlines. SSH
stdout is charged to the existing request-global Git budget before parsing. Stderr, banners, debug
messages, disconnect descriptions, exit messages, library errors, and agent comments are untrusted;
they are bounded, discarded, and translated to compiled structural errors.

One synchronization operation owns one runtime, connection, agent handle, channel, and credential.
Nothing is cached across operations. Cancellation and every terminal parse, limit, authentication, or
transport result close the channel and session without another network, agent, or provider attempt.
No transport or credential bytes are written to disk.

## Alternatives considered

### Invoke ambient `ssh` and `git`

This offers maximum compatibility but imports unbounded local configuration, process and shell
behavior, prompts, proxies, helpers, and version variance. It is rejected for the synchronization
authority path.

### Implement SSH in Kitrove

This avoids a dependency but requires maintaining cryptography, key exchange, framing, and protocol
state. It is rejected in favor of a maintained Rust SSH implementation with a narrow adapter and an
explicit review of unsafe code in the locked transitive graph.

### Trust the first host key automatically

This makes first use convenient but cannot distinguish the intended host from an active attacker. It
is rejected; users establish host trust outside Kitrove.

### Load private-key files directly

This broadens secret parsing, passphrase handling, filesystem authority, and zeroization obligations.
It is deferred; agent-backed signing provides useful coverage without importing private material.

### Automatically use Git credential helpers

This is familiar but helper configuration can be a shell snippet and may prompt or invoke arbitrary
programs. Automatic discovery is rejected. A later explicit provider must receive its own reviewed
implementation record.

## Consequences

### Positive

- SSH reuses the accepted Git CAS semantics instead of creating a second synchronization protocol.
- Host trust and authentication remain machine-local and credential values never become Kitrove
  state.
- Common SSH injection, forwarding, configuration, and trust-on-first-use surfaces are absent.
- The maintained library owns SSH protocol and cryptography while Kitrove owns bounded policy.

### Negative

- Users must establish a matching `known_hosts` entry and have a usable agent before SSH sync.
- Some valid OpenSSH configurations, host patterns, certificates, proxy routes, hardware-provider
  flows, and private-key-only environments are unsupported.
- The async SSH implementation adds a runtime and a meaningful dependency graph that requires native
  and advisory evidence.
- Operating-system keychain and Git-helper credentials remain unavailable.

### Follow-up

1. Extract and test the shared bounded smart-Git session before adding the SSH adapter.
2. Review and exact-pin the `russh` feature graph, licenses, advisories, Rust 1.85 build, and native
   agent availability.
3. Implement the canonical SSH parser and bounded read-only host-key verifier with hostile fixtures.
4. Implement agent-only authentication and fixed-service channels with a synthetic SSH server.
5. Add native Unix and Windows OpenSSH-pipe evidence where the hosted environment permits; retain
   Pageant as an explicitly unsupported boundary unless a later ADR authorizes it.
6. Write a separate implementation record before enabling any HTTPS credential provider.

## Validation

- Parser-differential tests reject alternate URL interpretations, command delimiters, path aliases,
  credentials, and unsupported schemes before network access.
- Host-key fixtures cover exact, port-qualified, comma-separated, hashed, changed, unknown, missing,
  malformed, oversized, symlink, unsafe-type, and replacement cases without filesystem mutation.
- Synthetic agent fixtures cover bounded identity lists, rejected identities, malformed frames,
  signing refusal, timeouts, and the fixed attempt limit; no test exposes private key material to the
  Kitrove API.
- Synthetic SSH servers prove host verification precedes authentication, only one fixed exec request
  occurs, forbidden channels are rejected, stderr is discarded, and all stages respect deadlines and
  aggregate byte limits.
- Existing hostile Git protocol, pack, CAS race, recovery, redaction, and no-disk fixtures run through
  the shared session and both transports.
- Governance rejects ambient SSH/Git process launch, shell invocation, SSH config parsing, secret
  fields, private-key loading, trust-on-first-use, agent forwarding, and unreviewed credential-provider
  implementations in production.
- Stable, Rust 1.85, license, advisory, exact-feature, and native Ubuntu/macOS/Windows checks pass at
  the Phase 2 candidate boundary.

## Supersession

This extends ADR-0025 without weakening its HTTPS rules. Reconsider if the selected SSH library no
longer supports the Rust floor or tier-one platforms, if its security model changes, if a reviewed
cross-platform credential-provider standard becomes available, or if native evidence cannot prove
the stated boundaries.
