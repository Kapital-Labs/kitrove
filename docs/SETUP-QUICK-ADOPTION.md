# Quick skill collection (RC5.7)

These instructions assume RC5.7. Quick collection was introduced in RC5.6;
RC5.5 has the older per-item prompts. Check
`kitrove --version` before following these shortcuts. This guide does not itself
establish publication or update an installed binary. Use the current download
and installation guidance, with verification before executing a new artifact.

In `kitrove init` or `kitrove configure`, choose **Add skills from this computer**.
Setup shows counts and the first 20 numbered observations. Enter previews recommendations;
it does not write them yet. `v` shows the full inventory and numbered list.

At the selection prompt:

| Input | Selection |
| --- | --- |
| Enter | Preview the recommended eligible set |
| `1,4,7` | Only observations 1, 4 and 7 |
| `all` | Consider every numbered observation |
| `all,-3,-8` | Everything except observations 3 and 8 |
| `-3,-8` | The same exclusion shorthand |
| `n` | Skip collection |
| `q` | Stop setup |

Numbers refer to this scan's displayed entries, not names or a later scan.
Excluding one occurrence of a name does not exclude other sources with that name.
Do not mix positive and negative numbers: use `all,-3,-8`, not `1,-3`.
Invalid or out-of-range input reprompts without changing anything.

The preview shows included items, excluded items, and selected-but-omitted items.
Every included item has its source tool, suggested collection name, four-tool
fidelity and any loss reasons. Invalid names, names already in the collection,
same-name ambiguities and blocked plans are not bulk-adopted. No source wins
silently and no existing item is overwritten. Choose a single numbered source,
or use individual review to rename it explicitly.

After preview:

- `y` or `yes` approves just the displayed ready set. Enter does not approve it.
- `r` walks through the original selection. Enter or `y` accepts the current
  single plan, `n` skips it, and `r` changes its collection name before a new
  preview. Invalid or occupied names must be renamed or skipped.
- `n` skips collection; `q` or end of input stops setup.

Bulk approval is not an all-or-nothing transaction. Each item uses the existing
exact-plan approval and fresh source/state checks. A stale source, changed
collection, pending recovery or failed commit stops later items. Previously
completed adoptions remain; setup reports the completed count. No approval is
saved for future scans or future setup sessions.

Adoption preserves original/native source bytes and copies into the collection;
it does not install into another tool, execute a skill, grant trust, or sync.
Apply and sync still show separate plans and require separate confirmations.
Those confirmations accept `y`/`yes`, while Enter still skips them. Credentials,
machine identity, trust and deployment receipts remain local.
