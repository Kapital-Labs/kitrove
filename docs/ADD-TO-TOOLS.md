# Add saved skills or packs to your AI tools

This guided flow adds local files for a tool to discover. It does not install tools, start an agent session, connect accounts or share a collection. Script-containing skills require the separate local approval described below. Advanced items can require an explicit bounded
version check.

Run `kitrove configure --environment /absolute/path/to/collection` and choose
**Add skills or packs to a tool**. You can also go directly there with `kitrove apply` in an interactive terminal. Packs appear first: select a pack number to preview its members together. After collecting skills in setup,
option 2 suggests the skills just collected. You can select different items.
Adding from the scan browser offers **Choose a tool** after collection, without
asking for the collection path again. Skipping this next step keeps the collection.

1. Press a tool number for **Claude Code**, **Codex**, **Pi** or **OpenCode**
   without Enter. Choose `m` to select several tools.
2. Choose **All projects on this computer** or **This project only**. Project
   scope asks for an absolute project folder.
3. Choose saved items by their original numbers. Each row shows the current
   destination check and its next action. Use `why N` for the selected item's
   description and destination details. `ready` selects only skills the planner
   can add/update, excluding unmanaged conflicts and managed copies already current.
   The picker counts ready, current and blocked items for the current page.
   `ready` checks all matching pages when you select it.
   Each blocked skill offers a next action:

   - **Review scripts:** `review N` opens the exact local bundle review, then a
     separate placement preview. Selecting its number follows the same checks.
   - **Compare existing copy:** `compare N` compares the complete rendered bundle
     with the chosen destination, including supporting files and recorded modes.
     It reports matching, different or unverified contents and changes no files.
     Matching contents do not grant ownership. Keep an unmanaged copy and leave
     the item out, or return to setup to choose another destination.
   - **Explain incompatibility:** `why N` shows the stored target fidelity and
     reasons. Choose another tool or leave the item out. Script approval cannot
     resolve a fidelity refusal. `why N` also explains other destination checks.

   `all` selects every matching item across pages, including already-current and
   blocked items. It does not bypass checks; one blocked item can stop the
   complete selection before placement approval. An incompatible selection offers
   **Choose different items**, keeping the tool and destination choices. `ready`
   selects compatible additions and still requires the full preview and your
   placement approval. Readiness describes the plan; the result after approval
   reports completion or a separate apply failure. Incompatible members are never
   silently removed from a selected pack or batch. `ready` checks
   the destination folder, not whether the tool can already discover another copy
   elsewhere. Packs and version-gated kinds need an explicit selection.
   Twelve entries appear per page; `next` and `back` browse, `/word` filters names,
   and `/` clears the filter. `all,-3,-8` selects matching items except original
   numbers 3 and 8. A filter narrows bulk selection; it never renumbers entries.
   Enter selects just-collected suggestions if present, otherwise skips.
4. Review the destination check and the combined preview. **Add**, **Already
   current (managed)**, **Restore managed copy**, and **Update managed copy**
   are distinct actions. Bracket keys browse preview pages; `d` shows full plan
   details. Approval covers the whole selected batch, not only the visible page.
5. Press `y` to approve that exact plan. Enter or `n` skips tool changes. A changed
   destination or collection after approval still refuses a stale plan. An
   unmanaged conflict is refused by the core planner; existing files are not overwritten.
   Completed collection steps remain if apply fails. Readiness is advisory: an
   interrupted earlier apply may need recovery before a new plan. Select the
   intended items explicitly to enter the existing recovery/confirmation flow.

Collecting another skill does not make previously added, unchanged skills need
replacement. They remain **Already current (managed)**. Approving them can refresh
the local receipt for the current collection revision without rewriting their
files. A modified or unmanaged destination is still refused.

Ordinary skills do not need an executable path. Selected Pi extensions still
need an explicit trusted Pi version probe and existing trust. OpenCode
instructions, commands, agents and MCP entries still require the reviewed
OpenCode V2 probe (`opencode2`). Selecting an unrelated ordinary skill does not
probe an unselected instruction or pack. Required probes are explicit, bounded
local operations; setup does not discover or launch an executable on its own.

## If applying fails

Use [`kitrove doctor`](DOCTOR.md) for a read-only storage report. Select the same
collection with `--environment` if it differs from `~/Kitrove`. The report can
identify private-storage or retained-state checks that a portable status summary
does not cover. It makes no repairs and does not replace a fresh apply preview.

## Tool destinations and discovery

These are the existing reviewed skill destinations. The actual plan shows the
chosen destination; this table does not authorize writes to a different root.

| Tool | All projects | This project | Important difference |
| --- | --- | --- | --- |
| Claude Code | `~/.claude/skills` | `.claude/skills` | OpenCode may also discover these copies. Enterprise and personal skills can take precedence over project copies. |
| Codex | `~/.agents/skills` | `.agents/skills` | Shared Agent Skills folders; Pi and OpenCode may also discover them. Same-name Codex skills can coexist. |
| Pi | `~/.pi/agent/skills` | `.pi/skills` | Pi also searches shared `.agents/skills`; project trust may affect loading. |
| OpenCode | `~/.config/opencode/skills` | `.opencode/skills` | Also searches Claude/shared compatibility folders; another definition or explicit configuration can override a name. |

The preview warns about observed same-name copies in the selected tools' search
locations. A name match proves neither matching contents nor Kitrove ownership.
An OpenCode destination copy can override a copy discovered through Claude or
shared folders; it is an additional managed copy, not required merely for discovery.
Choosing a destination controls where files go, not which tools exclusively see
them. Observation is not proof that a tool loaded the skill: settings, permissions,
project context, precedence and trust can affect availability. Setup does not
change those settings or launch the tool to check. Start or refresh the tool and
inspect its skills after adding files.

Official discovery references reviewed November 17, 2026:
[Claude](https://code.claude.com/docs/en/skills),
[Codex](https://developers.openai.com/codex/skills),
[Pi](https://docs.pi.dev/latest/skills),
[OpenCode](https://opencode.ai/docs/skills/).


## Script-containing skills

Kitrove can collect eligible text helper scripts alongside SKILL.md as data. Before adding such a skill to any tool, it offers a separate local review of the exact complete bundle. Inspect stored files with `f`, page the file inventory with `v`, and explicitly approve with `y`; Enter skips the selection. Tool placement then has its own preview and approval. A blocked member stops the selected pack; it is not silently dropped.

The local approval covers the bundle revision, including supporting files and retained native variants. Changing the skill requires a new approval. Another computer must approve its own copy; trust is not synchronized. Kitrove neither runs helpers nor installs Python, shell runtimes or dependencies. The receiving tool's permissions and runtime requirements still apply. References specific to another tool are retained, not automatically translated.

Compiled payloads, native lifecycle/install directives, credentials and executable principal documents remain unsupported. Unix helper mode classes are preserved; a platform that cannot preserve a recorded executable mode refuses before writing. Denial blocks future placement but does not remove already placed files or revoke tool permissions; use receipt-backed removal for that. Executable pack rollback is outside this feature.

When packs share an already placed script, removing one pack retains the exact existing files and denied decision for the other owner. It grants no new approval or replacement; removing the last owner removes only its unchanged receipt-backed files.
