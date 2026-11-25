# Kitrove CLI usability review

Review baseline is RC5.21, source `4529533a6f00aa690f257cb110948c42426165dc`.
I used a source-built Apple Silicon binary from that release, an isolated home
and collection, and synthetic skills. The scenarios included overlapping names,
partial fidelity, a script, a pre-existing destination copy, and more skills
than fit on one page. I checked entry points and flags on every command group,
ran the common journeys in a terminal and through redirected input, and
compared the output with the getting-started, setup, apply, agent and storage
guides. Network credentials, provider authentication, Windows display behavior
and live harness loading were outside this run. The synced fixture used a
local folder and a plan only.

## Recommendation

Overhaul how Kitrove presents the CLI. Keep the existing commands, selectors,
machine output and explicit approvals. The guided paths already have the right
sequence: see local skills, pick what to keep, pick where to place them, review a
preview, then decide. The problem is that the CLI presents too much theory and
advanced syntax before the user can make that next decision.

## What I found

| Area | What I observed | What I would change |
| --- | --- | --- |
| Finding a command | The main help takes 158 lines. Of 33 command and subcommand help probes, only `doctor --help` returned command-specific help. A typo in a scan flag printed 118 lines to stderr. | Make the main index fit on one screen. Group it by tasks and link to command-specific examples. Keep a full reference under an explicit flag or in the docs. For syntax errors, show the error and one matching help command. |
| Onboarding and return visits | The inspect choice from bare `init` printed 90 lines in the test. The same setup menu carries first-computer, second-computer and read-only work. On a return visit, two actions start with “Add skills” even though one collects and the other places. The website documents `apply` and `configure`, but the CLI entry points assume the user already knows when to switch. | Give new and returning users distinct entry points in help. Use clear verbs consistently: **Collect skills**, **Add to a tool**, **Sync collection**, **Copy selected items**, **Check storage**. |
| Browse and scan | The interactive list uses a compact menu with paging. Redirected text returned 39 lines for 27 skills, and a missing tool version appeared in a findings group as a raw code. The same result used phrases including “ready to preview” while later checks can still block collection. | Keep fast scan browsing. Say whether a status describes discovery, collection or a destination. Show brief issue summaries by default, with raw codes and complete output available for support. Document the nonzero findings exit code for scripts. |
| Collect | The synthetic bulk preview produced 132 lines. It mixed ready names, source-copy counts, fidelity for four tools, review reasons and next actions. A user who only wants Codex must read a four-tool grid before choosing a tool. Numbered source selection, skip and review are valuable. | Lead with ready, already saved and needs review. Show a short list and one actionable reason per group. Put per-tool fidelity and per-item explanations behind **Details**. Keep original source numbers and exclusions stable. |
| Add to a tool | The destination-first sequence works. The ready run displayed 57 lines from entry through skip. `all` followed by the ready shortcut displayed 71. The shortcut is discoverable and separate from confirmation, but related commands and the explanation for “ready” live in several different prompts. Packs, script approval and duplicate detection add more language at the same level. | Keep tool, scope and destination order. Use the same vocabulary for **Ready**, **Already current**, **Needs review** and **Blocked**. Offer each next action beside its reason. Keep exclusions, filters and individual review under `help`, with paging visible when needed. |
| Trust and packs | Script-bearing skills get their own review and approval. Packs have a different lifecycle, but the full pack command catalog appears in general help while basic pack selection already exists in guided apply. | Lead with **Add a saved pack** when serving a person. Move pack authoring, trust audit, exact digests and target version evidence to command or automation help. Preserve every separate approval. |
| Sharing and copying | Both setup branches reach a similarly worded storage question. The sync branch is bidirectional, while choosing selected items is a one-time copy. The distinction is easiest to see in the guide and less evident once both users reach the storage menu. | State the expected direction above the backend picker. For sync previews, show the upstream location, upload/download counts and conflict status together. Name one-time copy in its own confirmation. |
| Errors and storage | Portable status printed per-object verification and journal state. Doctor printed two human-readable lines on healthy synthetic storage. The cleanup refusal during guided collection directed the user to status, which doesn't inspect the retained files causing the refusal. A blocked write and an ordinary skipped preview are different outcomes. | Give each error family one next action. Storage refusals should lead to doctor. Present the human explanation and action first, then the stable support code. Leave structured errors and exit codes intact. |
| Automation | JSON plans, approval digests and stored receipts support precise automation. Top-level human help interleaves those flags with the guided workflows. Some bare guided commands with redirected input fall through to a different explicit-command error. | Document guided and scripted usage side by side for each command. Keep structured contracts stable and use one short terminal-required error with the matching explicit form. |

## Sequence the work

1. **Help and errors.** Add an index, real subcommand help and one next step on
   syntax and storage errors. This changes presentation first and improves every
   workflow without replacing the underlying commands.
2. **Collect and place.** Use a shared status vocabulary and a common preview
   layout for collection and application. Show the summary, relevant blockers,
   and confirmation, then let the user open details. Preserve the existing
   decision gates for script approval and destination writes.
3. **Setup and share.** Make the first-run and returning-user journeys explicit.
   Make one-time copy and bidirectional sync distinguishable at the backend
   and approval screens. Then update docs and examples around the revised flow.

Test the redesign with a clean collection, a large mixed inventory, a blocked
`all` selection, a script, a duplicate, an inaccessible source, and a storage
refusal. Measure how quickly someone can find the right command, how many
prompts they need before a preview, and whether they can describe exactly what
the next approval will change. Include narrow terminals, redirected input and
native Windows. A useful first target is one screen for the help index and
ordinary preview summaries, with additional pages available on demand.
