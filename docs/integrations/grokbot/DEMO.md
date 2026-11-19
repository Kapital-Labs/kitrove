# Offline Grok Bot workflow demonstration

Validated November 18, 2026 (America/Chicago), using the verified public RC5.18
Apple Silicon CLI. This is a CLI flow proof on this existing Mac, not a live
Grok Bot run or an implemented connector. No provider account or computer access
was used. The real installed copy, collections and sync were untouched.

## Fixture and operation

The harness copied the public inert `review-notes` sample into a synthetic source
folder, initialized a new collection and adopted the sample after an exact preview.
It created an authored `starter-review` pack with that one member. Those five seed
commands changed only the disposable fixture; they are not read-only operations.
The harness retained the native source away from the proposed destination.

It then ran status, pack list and pack inspect, followed by a preview and a repeat
preview for each existing tool. All 11 read commands completed with closed stdin.
The complete fixture's paths, modes, bytes and modification times matched before
and after that inspection phase. No tool placement, trust grant or sync ran.

| Target | Asset | Planned action | Scope | Repeat plan identical |
| --- | --- | --- | --- | --- |
| claude | review-notes | install | user | yes |
| codex | review-notes | install | user | yes |
| pi | review-notes | install | user | yes |
| opencode | review-notes | install | user | yes |

## Proposed conversation

User: Show my saved packs.

Bot: `starter-review` contains one skill, `review-notes`. Which tool should I
preview it for?

User: OpenCode.

Bot: The preview would add one ordinary skill to OpenCode's user skills folder.
Nothing has changed. This pilot can inspect or preview another target; applying
the plan is outside its read-only tool set.

The text above illustrates a proposed presentation of actual CLI results. No model
or Grok account produced it. A Bot's claim of approval would not grant write access.

## Reproduction surface

With a separately initialized disposable collection containing the sample pack:

```sh
kitrove --json-errors pack list --environment /path/to/isolated-collection --json
kitrove --json-errors pack inspect --pack starter-review --environment /path/to/isolated-collection --json
kitrove --json-errors plan --pack starter-review --target opencode --scope user --environment /path/to/isolated-collection --json
```

Use the actual JSON fields from the [agent guide](../../AGENT-WORKFLOW.md).
The preview returns `batch_digest`; knowing that value is not human authorization.
Do not turn this example into an automatic apply or point the fixture at a real
collection. Future connector input/output limits, child cleanup and authorization
need their own tests; this demonstration does not certify those components.
