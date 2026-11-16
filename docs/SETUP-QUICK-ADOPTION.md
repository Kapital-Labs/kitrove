# Quick skill collection (RC5.9)

These instructions assume RC5.9. Quick collection was introduced in RC5.6;
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
| `from codex` | Choose only that displayed tool's observations |
| `from codex,-13,-20` | Choose that tool except those original inventory numbers |
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

- Enter or `y` approves just the displayed ready set after a nonempty preview.
- `s` chooses again using the same scan. An empty preview offers no adoption approval
  or zero-item success; Enter chooses again instead.
- `d` shows complete skipped-item details. Ready plans always retain full
  source/fidelity/loss details; the unreleased summary improvements below separate
  occupied names and named blockers without listing every unselected copy.
- `r` walks through the original selection. Enter or `y` accepts the current
  single plan, `n` skips it, and `r` changes its collection name before a new
  preview. Invalid or occupied names must be renamed or skipped.
- `n` skips collection; `q` or end of input stops setup.

Closed menus accept a single displayed key without Enter. Selection expressions,
paths, names and URLs remain text prompts: type the value and press Enter.
An Enter left over from an earlier prompt cannot approve a later preview.

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

## Choose one tool's copies when names repeat

Repeated names can be copies in different tools or one location discovered by
several tools. A matching name does not prove identical content. Use
`from codex`, `from claude`, `from pi` or `from opencode` to select
one displayed tool's observations. For example, `from codex,-13,-20` excludes
observations 13 and 20 from that source selection, using the original inventory
numbers. This does not make that tool the permanent source of truth or merge
other copies. Same-name ambiguity within the chosen tool still needs a specific
numbered choice or individual review. Existing collection names are not overwritten.

Skipped items retain complete details under `d`; ready plans still show full
source/fidelity/loss details. The unreleased summary improvements below keep
unselected-copy counts out of the default summary.
An empty preview does not ask for adoption approval or report success. Enter or
`s` chooses again using the same scan, `r` reviews individually, and `n` skips.
For a nonempty preview, `s` also chooses again; Enter approves only its displayed ready set.
These source-selection and choose-again improvements were introduced in RC5.8.
RC5.7 and earlier binaries do not include them.

## Guided duplicate-source choice (RC5.10)

This behavior requires RC5.10 or later. When no selected copies can be
collected and the same names appear across tools, setup offers a numbered tool
menu instead of requiring `from TOOL` syntax. Pick a displayed tool to see a new
preview of only its selected copies. This does not collect anything, make that
tool canonical, or bring back excluded inventory numbers. Enter/s chooses
different skills; it never chooses a default tool. Remaining ambiguity within a
tool still needs a specific inventory number or individual review.

The updated preview shows counts instead of repeated skipped-item examples;
press d for all details. Names already used in the collection are reported
separately. A matching name is not proof that the source is already collected or
unchanged. Ready plans still show every source, fidelity result and loss reason,
and adoption still needs a separate confirmation of that exact new preview.

## Collect from the scan browser (unreleased)

This handoff requires a future release after RC5.14. In an interactive terminal,
run `kitrove scan --harness claude --scope user`. The browser's **Ready to preview**
count means readable source candidates, not a promise that all can be added to
an existing collection.

Press `a` for **Add to collection**, either from the main inventory menu or while
browsing that group. Choose the collection path, then use the normal skill
selection and preview. An existing setup is validated and confirmed; a new
collection requires its own machine name and initialization confirmation. Enter
at skill selection only previews; Enter or `y` at a nonempty adoption preview
approves its displayed ready set. You do not need to restart in configure.

The handoff keeps the original scan's tools, scope, project root and explicit
source roots. It does not add the other tools' copies to the selection. Numbers
in the collection selection refer to that handoff's displayed list.

The collection preview distinguishes:

- **Ready to add:** the selected items that passed the planner for this collection.
- **Names already in your collection:** skipped without comparing or overwriting
  their contents. Use `r` to review individually and explicitly rename a copy.
- **Blocked:** each skill's planner reason is shown directly, such as executable
  content requiring separate trust review. Adding from scan grants no trust.

For example, 13 candidates can become zero ready items when 11 names are already
in the collection and the other two have blocked plans. Those are different
checks, not missing skills. Unselected copies are omitted from the default
summary; `d` still shows all skipped details, including exclusions. Up to ten
named blocker explanations appear by default before the full-details option.

Browsing, JSON, verbose and non-terminal scan remain read-only. The explicit
handoff never applies skills to tools, executes them or synchronizes anything.
A changed source, changed collection or pending recovery still refuses adoption.
