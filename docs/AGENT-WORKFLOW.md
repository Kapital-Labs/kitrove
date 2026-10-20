# Agent-facing materialization approval

Agents can inspect and invoke Kitrove through its CLI. No MCP server is required.
The agent must still obtain the user's authorization for the selected operation;
a digest is a stale-plan safeguard, not a substitute for that authorization.

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

## Other operations and limits

`sync plan` / `sync apply --confirm` and `trust plan` / `trust apply --confirm`
already have explicit digest approval. Sync can publish as well as receive.
Each machine keeps its own credentials, bindings, trust and receipts.

Ordinary adoption and removal still use their existing
confirmation interfaces. Pack adopt/rollback retain their existing `--yes`
option; it is not equivalent to externally approving a previously inspected
digest. Those operations are not covered by this materialization increment.
Guided `init` and `configure` require a terminal; explicit initialization is
available for scripts.

The native Mac/Ubuntu RC4.2 acceptance covered a synthetic directory skill,
filesystem-backend transfer, reverse editing, exact native preservation, local
canary exclusion, conflicts, and unmanaged-target refusal. It does not establish
live harness execution, all capability types, all transport providers, or stable
production support.
