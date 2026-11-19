# Read-only tool contract

Implemented as a source-only local MCP prototype in `scripts/grokbot_readonly.py`,
with closed projection and owned-process modules. It is not included in RC5.18
or accepted through a live Grok account. The [operator guide](OPERATOR.md) names
its synthetic-only POSIX scope, fixed limits and remaining connection gate.

## Initial tools

| Prototype tool | Inputs from the Bot | Existing CLI operation |
| --- | --- | --- |
| `list_packs` | No path or command | `kitrove --json-errors pack list --environment <configured collection> --json` |
| `inspect_pack` | One pack ID | `kitrove --json-errors pack inspect --pack <id> --environment <configured collection> --json` |
| `preview_pack` | Pack ID and one allowed target | `kitrove --json-errors plan --pack <id> --target <target> --scope user --environment <configured collection> --json` |

The pilot supports authored packs, ordinary text skills and the four existing targets. An advanced
member that needs version evidence or trust can refuse; the wrapper must preserve
that refusal. Do not run a probe or obtain trust to make a preview succeed.

The operator chooses the collection, machine-local state and executable outside
model input. Pin the executable identity and declare whether it runs on the Bot
computer or an approved local machine. The model cannot choose executable paths,
filesystem roots, environment variables, remote URLs or arbitrary arguments.

Validate closed schemas, reject duplicate or unknown fields, and constrain IDs
and target enums before constructing argument arrays. Use no shell. The prototype
bounds input, output, child runtime and its complete trusted POSIX process group.
Windows refuses until a reviewed Job Object implementation exists. The source
requires terminal cleanup tests; a local pass does not imply provider acceptance.

## Results and privacy

Return pack IDs/member counts, explicit target/scope, planned action counts and
structured refusal codes. Show a relative destination when it helps review.
Do not return raw skill bodies, credentials, machine-private paths, complete
manifests, environment dumps or raw provider stderr. The user must consent before
private collection identifiers leave their machine; a cloud conversation is a
data transfer even when a tool reads rather than writes.

Keep the complete plan review available to its local owner through the CLI. A friendly summary
cannot become authority for a different batch or hide a blocked member. Preserve
CLI stdout and code-only stderr errors as distinct cases. This pilot's selected
operations support known successful schemas and allowlisted operational refusals;
unknown attention/conflict envelopes, fields, versions and nonzero outcomes stop
it rather than being interpreted as approval. No raw unknown code is forwarded.

## No write endpoint in this stage

Do not expose apply, adopt, remove, sync, trust, recovery or an arbitrary command
endpoint. Do not make approval rules broader to improve a demo.

A later write design must bind authenticated authorization to the exact complete
operation, collection, target scope and current plan. It needs expiry/replay rules
and a trust boundary that the model cannot satisfy by copying a digest. Use the
existing transaction coordinator; never build a second direct file writer.

Acceptance includes changed content between preview and apply, unmanaged and
modified destinations, pending recovery, denied script trust, partial fidelity,
oversized/invalid output, terminated children and prompt injection in skill text.
The source prototype tests the applicable read-only boundaries; the prior offline
CLI demo alone does not certify them. Write/replay approval remains future work.
