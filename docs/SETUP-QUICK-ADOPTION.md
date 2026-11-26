# Quick skill collection (RC5.24)

These steps describe the RC5.24 preview.

Run `kitrove` and choose **Find or collect skills**, or use **Collect skills
from this computer** in `kitrove configure`. The scan summarizes eligible
source copies first. Enter previews the eligible set. Type `v` to browse
numbered copies, `/name` to filter by skill name and `next` to page.

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

- Type `y` and press Enter to save the displayed ready set. Enter alone skips saving.
- `s` chooses again using the same scan. An empty preview offers no adoption approval
  or zero-item success. Enter chooses again for an empty preview.
- `d` shows complete skipped-item details. Ready plans always retain full
  source/fidelity/loss details; the summary improvements below separate
  occupied names and named blockers without listing every unselected copy.
- `r` walks through the original selection. Type `y` and press Enter to save
  the current skill. Enter alone skips it. Type `r` and press Enter to rename it
  before a new preview. Invalid or occupied names must be renamed or skipped.
- `n` skips collection; `q` or end of input stops setup.

Displayed shortcuts select immediately in supported inline menus. Up/Down and
Enter let you select by highlight. Enter submits typed answers and write
confirmations. Queued input cannot approve a later preview.

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
source/fidelity/loss details. The summary improvements below keep
unselected-copy counts out of the default summary.
An empty preview does not ask for adoption approval or report success. Enter or
`s` chooses again using the same scan, `r` reviews individually, and `n` skips.
For a nonempty preview, `s` chooses again and Enter alone skips saving.
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

## Collect from the scan browser (RC5.17)

This handoff is included in RC5.17. In an interactive terminal,
run `kitrove scan --harness claude --scope user`. The browser's **Ready to preview**
count means readable source candidates, not a promise that all can be added to
an existing collection.

Press `a` for **Add skills to collection**, either from the main inventory menu or while
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
- **Names already in your collection:** skipped without overwriting. Verified
  native matches, different contents and unverified copies have distinct labels
  as described below. Use `r` to review individually and explicitly rename a copy.
- **Blocked:** each skill's planner reason is shown directly, such as unsupported
  compiled payloads or native lifecycle directives. Eligible text helpers can be collected
  as data; adding them to a tool requires a separate exact local approval. Adding from scan grants no trust.

For example, 13 candidates can become zero ready items when 11 names are already
in the collection and the other two have blocked plans. Those are different
checks, not missing skills. Unselected copies are omitted from the default
summary; `d` still shows all skipped details, including exclusions. Up to three
named blocker explanations appear by default before the full-details option.

Browsing, JSON, verbose and non-terminal scan remain read-only. The collection
handoff itself never applies skills, executes them or synchronizes anything.
The subsequent optional tool-first phase has its own selection and approval.
A changed source, changed collection or pending recovery still refuses adoption.

## Compact scan navigation (RC5.18)

The compact summary separates actual skill candidates from **Scan issues**.
An unreadable or unsafe folder is an issue, not a skill named `(missing)`.
The source tier and logical folder ID distinguish your own folder from an
administrator-managed one. An issue means the inventory may be incomplete.
It does not prove there are no skills or that your personal folder is broken.

Choose **View scan issues** (`i`) to see what needs checking and a scoped verbose
command. Keep any explicit `--root` and `--project-root` options when using that
command. Check the identified location without changing permissions or links on
Kitrove's behalf, then choose **Scan again** (`r`). A retry keeps the same scan
selection. You can quit without changing anything.

Recognized Mac/Linux terminals of sufficient size support Up/Down and Enter.
Displayed shortcuts work immediately too. Narrow, unrecognized and native Windows
terminals use the same short action list with shortcuts and a marked Enter
default. Browsing a group defaults to Back; an empty scan defaults to Quit.
Adding skills still opens collection selection and a fresh preview before any
approval. Scan-to-collection has been available since RC5.17.

## Content status and grouped copies (RC5.17)

RC5.17 groups same-name source copies under one heading.
The summary separates unique skill names, selected source copies and ready
additions. Original inventory numbers, explicit exclusions and native variants remain
separate; no tool wins automatically. Full inventory and skipped details remain
available on demand.

For an occupied collection name the preview distinguishes:

- **Already collected (exact native content matches):** the captured source's
  layout, document name, bytes and file modes match the validated stored native
  object for that tool. This is an observation at comparison time, not update or
  ownership permission.
- **Same name, different native content:** the validated native content differs.
  Review or rename explicitly; nothing existing is overwritten.
- **Same name; native content not compared:** there is no comparable tool-native
  variant or the object/evidence cannot be verified. It is not an equality claim.

These are skipped copies, not successful new adoptions. A source can match one
stored tool variant while another tool's same-name observation remains unverified.
No cross-tool variants are silently merged and matching portable content alone
is not an exact-native comparison.

After a successful collection, setup suggests adding those newly collected IDs
through option 2. The scan handoff offers the same next step directly. It reuses
this collection and makes a separate [tool-first preview](ADD-TO-TOOLS.md).
Collecting alone never applies to a tool or syncs anything.
