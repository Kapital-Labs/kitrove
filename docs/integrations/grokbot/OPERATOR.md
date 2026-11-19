# Read-only command-server prototype

This source-only prototype implements the three tools in the
[contract](TOOL-CONTRACT.md). It is not included in RC5.18, installed in Grok,
or connected to an account. Its acceptance uses disposable synthetic content.
Do not point it at a personal collection, installed executable or real sync root.

## Platform and invocation

Use Python 3.11+ on a reviewed POSIX host with `waitid`/`WNOWAIT`. The current
native proof is on this existing Apple Silicon Mac; Linux requires its own native
acceptance. Windows refuses before launch and needs a reviewed Job Object runner.
No new dependency is required.

Run the reviewed source with isolated Python environment/user-site settings:

```sh
python3 -E -s -B /path/to/reviewed-source/scripts/grokbot_readonly.py \
  --config /path/to/private-pilot/config.json
```

The server uses newline-delimited MCP JSON-RPC on stdin/stdout. It supports
protocol `2025-11-25` and `2025-06-18`, initialization/initialized, ping, tools/list
and tools/call. It has no network listener, HTTP authentication, resources,
prompts, background tasks or write endpoint. A client must use a supported
protocol after negotiation. Read-only annotations do not grant permissions.
[MCP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
[tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

## Operator-owned fixture

Prepare a canonical absolute private root with this layout; the server does not
initialize or repair it:

```text
private-pilot/                  owner-only directory (0700)
  config.json                  owner-only regular file (0600)
  .kitrove-grokbot-pilot        exact text below
  .git/                        empty project-boundary marker
  bin/kitrove                  independently verified executable, no hardlink
  home/                        disposable native-tool root
  collection/                  initialized synthetic collection
  state/                       its separate machine-local state
```

The marker is exactly `kitrove-grokbot-synthetic-only/v1` followed by one newline.
Create `bin`, `home` and `.git` first. Let the existing CLI `init` create the
absent `collection` and `state` directories with explicit disposable paths;
precreating those two directories makes initialization refuse. Configure the
server after seeding finishes.
The config accepts exactly:

```json
{
  "schema_version": 1,
  "root": "/path/to/private-pilot",
  "cli_sha256": "REPLACE_WITH_THE_64_LOWERCASE_HEX_DIGITS_YOU_VERIFIED",
  "data_policy": "synthetic-only"
}
```

The illustrative hash is deliberately invalid. Do not copy an installed Homebrew
binary or assign trust based on this example. Independently verify a public
artifact and its provenance, then copy only the verified executable into the
private fixture. Seed the public inert sample using existing CLI previews and
separate confirmations with explicit HOME/state/collection paths. Close the
seed operation before taking the read-only snapshot. The [prior CLI demo](DEMO.md)
describes these seed operations; they are fixture writes, not server tools.

The root, its role directories and protected ancestors must have trusted ownership.
Before seeding, check the complete canonical ancestor chain for the CLI's private
state path: every ancestor must be owned by the current user or root and must not
be group/world writable. A sticky temporary directory such as `/tmp` still fails
this CLI requirement, even when the fixture itself is mode0700. The Python
wrapper's allowance for sticky ancestors does not override the CLI's stricter
check. Choose a fresh private descendant of a verified home-directory chain;
do not loosen ancestor permissions or delete an earlier failed fixture to retry.
The inventory refuses symlinks, hardlinks, special files, group/world writable
entries, more than 4096 nodes or any file larger than 64 MiB. The CLI is hash
checked for every operation. Same-user/operator filesystem attacks and arbitrary
host filesystem stalls are outside this boundary; use a reviewed private fixture.

Only the known clean control layout is admitted: local `lifecycle.lock`, portable
`environment.lock` (empty regular lock files) and retained portable
`removal-quarantine`. Other control entries, including journal/pending evidence,
produce `pilot.recovery_or_unknown_state`. Do not delete evidence to get past it.
Inspect and handle recovery outside the server through the reviewed CLI, then
reassess the fixture and start a fresh session.

## Bounds and refusal behavior

- Input frames: at most 16 KiB; 32 JSON levels and 8192 nodes; no duplicate keys,
  nonfinite numbers or invalid UTF-8. Partial frames have a two-second bound.
- At most eight queued frames and 128 request IDs per session. IDs cannot repeat.
- CLI child: ten-second execution budget, 256 KiB combined stdout/stderr,
  closed stdin, scrubbed environment and bounded whole-group cleanup.
- Output delivery: at most 64 KiB per frame with a two-second delivery bound.
- Cancellation of the active request, stdin EOF and handled interrupt/termination
  stop its group. The leader stays unreaped through all group signals; no group
  is signaled after reaping. Cleanup uncertainty is terminal.

Pack IDs have the pilot's bounded lowercase identifier syntax (at most96 characters,
no `..`). Results admit at most128 packs or expanded components. Only authored
packs and ordinary skill components are supported; active profiles are outside
this first prototype. Unknown
CLI schemas, unexpected output, unknown error codes and inconsistent pack revisions
stop the session; do not automatically retry. Known CLI refusals return their
allowlisted code and require review. Attention/conflict output from an unsupported
operation is refused, never relabeled as success. The server offers no way to
invoke that operation, run a helper, fetch a remote, approve trust or recover state.

Responses contain IDs, counts, target, user scope and recognized refusal codes.
They omit destinations, bodies, digests, source metadata and raw stderr. A complete
plan can still be reviewed locally through the existing CLI. A returned summary
is advisory and cannot be used as a future write grant.

## Before a live Grok trial

Grok's Command connector starts a server on its shared account computer. It does
not grant this local Mac's filesystem. Use a separately approved disposable
provider collection or an explicitly approved isolated local connection; don't
paste credentials, private paths, tokens or a personal collection into chat.
[Provider connector documentation](https://docs.x.ai/grok-bot/computer-and-apps).

The reviewed source, runtime/platform, executable identity, synthetic data scope
and account sharing policy must be concrete before connecting. No upload,
provider invocation, account purchase, template publication or local-computer
permission is authorized by this guide. Never bypass team connector policy.
