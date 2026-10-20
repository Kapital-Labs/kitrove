# Agent-facing plan and approval workflows

Agents can inspect and invoke Kitrove through its CLI. No MCP server is required.
The agent must still obtain the user's authorization for the selected operation;
a digest is a stale-plan safeguard, not a substitute for that authorization.

Use the field returned by the matching command; these existing JSON contracts
do not all use the same field name:

| Preview command | Field to pass to the matching `--confirm` |
| --- | --- |
| `plan` (for `apply`) | `batch_digest` |
| `remove --plan` or `pack remove --plan` | `batch_digest` |
| `pack create --plan` or `pack update --plan` | `digest` |
| `pack adopt --plan` or `pack rollback --plan` | `digest` |
| `adopt --plan`, including `adopt --update … --plan` | `plan_digest` |

## Preview, approve, apply

Run the read-only plan with explicit collection, assets and destinations:

```sh
kitrove plan --environment /absolute/path/to/collection \
  --asset review --target codex --json
```

Review the complete result, including destinations, fidelity/blocked results and
pack ownership when applicable. Keep the returned **`batch_digest`**.
Single-item plans also contain `plan_digest`, which is not whole-batch approval.

After approval, repeat the same selection:

```sh
kitrove apply --environment /absolute/path/to/collection \
  --asset review --target codex --confirm 'blake3:APPROVED_BATCH_DIGEST' --json
```

Replace the placeholder with the exact returned value. This form does not prompt
or read stdin. It recomputes the plan, rejects changed authority, revalidates, and
uses the existing receipt-backed atomic transaction. It does not install tools,
move credentials, grant executable trust, or overwrite unmanaged destinations.
Do not automatically approve a newly generated digest after a stale-plan error.

A pending or invalid batch journal stops this unattended path. Handle recovery
explicitly through the existing operator workflow, review its outcome, then
generate and approve a new plan. Do not delete journals or local state to force
the command through. The ordinary interactive `apply` workflow is unchanged.

## Pack authoring

Preview grouping existing members without changing the collection:

```sh
kitrove pack create --pack suite --member tooling --plan --json
```

After reviewing and approving the full plan, repeat the selection with
`--confirm <digest>` instead of `--plan`. Use the returned `digest`, not a pack
revision. `pack update` supports the same flags and still requires
`--expected-prior <pack-revision>`. These modes do not read stdin; the flags are
mutually exclusive. Existing interactive behavior is unchanged.

The approved commit refuses pending portable recovery under the environment lock.
It changes only portable pack authority, never installed projections or trust.
A fresh plan is required after changing members, collection authority, or
handling recovery. Do not automatically approve a replacement digest.

## Adoption and exact-prior updates

`adopt --plan` previews a selected current scan observation without writing or
reading stdin. After operator authorization, repeat the identical selection with
`--confirm <digest>` instead of `--plan`, using the returned `plan_digest`.
The flags are mutually exclusive. This applies to skills, instructions, prompt
commands, agents, MCP entries and native extensions within their existing
capability policies.

`adopt --update <asset-id> --expected-prior <content-hash>` accepts the same
approval flags. Existing source eligibility and receipt requirements remain:
approval does not turn an unmanaged standard-root file into a managed update.
Skill/instruction approved updates require an initialized local-state directory;
they do not silently initialize one. Native extensions remain executable and
require separate machine-local trust before application.

Neither mode performs recovery. A pending adoption journal stops preview;
approved commits also refuse pending recovery under their mutation locks,
including the portable sync journal used by native extensions.
Even a valid pending journal from the same plan requires operator recovery and
fresh review. Stale approval never triggers automatic reapproval. Interactive
adoption and its explicit recovery behavior remain unchanged.

## Other operations and limits

Direct `remove` and `pack remove` also accept mutually exclusive `--plan` and
`--confirm <batch_digest>`. Preview does not recover earlier transactions or
change files. Approval covers the complete receipt-backed batch, including
retained pack co-owners. Pack removal still requires `--expected-prior` for the
historical application revision. Modified or unmanaged destinations are refused,
and portable assets remain in the collection. These flags do not add support
for new asset kinds: direct removal currently supports instructions, prompt
commands, agents and MCP entries; skill/extension removal uses existing pack
ownership where available.

`sync plan` / `sync apply --confirm` and `trust plan` / `trust apply --confirm`
already have explicit digest approval. Sync can publish as well as receive.
Each machine keeps its own credentials, bindings, trust and receipts.

Pack adopt/rollback also support `--plan` and `--confirm <digest>`, mutually
exclusive with each other and legacy `--yes`. Repeat the same remote and pack
selection; rollback still requires `--expected-prior` and `--to`.
Preview performs verified remote history/object reads without committing
collection or native authority. Backends may perform temporary/cache writes
and network access. It refuses pending adoption recovery; approved commits
also refuse other pending portable recovery under lock, before cleanup.
Exact objects, history selection and local authority are still validated.
Legacy interactive/`--yes` behavior is unchanged; `--yes` is not approval of
a previously inspected digest. None of these operations grants executable trust.

Guided `init` and `configure` require a terminal; explicit initialization is
available for scripts.

The native Mac/Ubuntu RC4.2 acceptance covered a synthetic directory skill,
filesystem-backend transfer, reverse editing, exact native preservation, local
canary exclusion, conflicts, and unmanaged-target refusal. It does not establish
live harness execution, all capability types, all transport providers, or stable
production support.
