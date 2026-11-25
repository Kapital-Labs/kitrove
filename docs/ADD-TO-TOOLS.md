# Add saved skills or packs to your AI tools

This guided flow adds local files for a tool to discover. It does not install tools, start an agent session, connect accounts or share a collection. Script-containing skills require the separate local approval described below. Advanced items can require an explicit bounded
version check.

Run `kitrove apply` in a terminal. To go directly to a specific collection,
run `kitrove apply --environment /absolute/path/to/collection`. Kitrove also
offers **Choose a tool** after you collect skills.

1. Select **Claude Code**, **Codex**, **Pi** or **OpenCode**, then press Enter.
   Use `m` and Enter to select several tools.
2. Choose **All projects on this computer** or **This project only**. Project
   scope asks for an absolute folder.
3. Preview ready skills across your collection, or from the batch you just
   collected. This skips managed copies already up to date, items that need
   review, and packs. For any pack, filter or specific skill, open **Choose
   specific items or review a blocker**. Packs are listed first. Stable item
   numbers carry across pages. `why N` shows the item's description and details.

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

   Type `help` for every selection command. `all` checks every matching item
   across pages before showing a preview. If incompatibility, script approval
   or an existing copy blocks the selection, choose `r` and press Enter to **Preview ready
   items from this selection**. You can also choose different items.
   The ready preview keeps your filter and exclusions, leaves out blocked and
   already-current skills, and still needs your placement approval. Choose a
   pack by number to preview it as a whole.
   The destination check covers the folder Kitrove would write to. Your tool
   may also discover copies elsewhere.
   Use `next` and `back` to browse, `/word` to filter names or `/` to clear
   the filter. `all,-3,-8` selects matching items except numbers 3 and 8.
   Numbers stay the same across filters and pages.
4. Review the destination check and the combined preview. **Add**, **Already
   current (managed)**, **Restore managed copy**, and **Update managed copy**
   are distinct actions. Bracket keys browse preview pages; `d` shows full plan
   details. Approval covers the whole selected batch, not only the visible page.
5. Type `y` and press Enter to approve that exact plan. Enter alone skips tool changes. A changed
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
does not cover. Doctor is read-only. In the guided flow on macOS, a verified device-only
mismatch can open a separate preview for preserving retained directories.
If you approve preservation and storage checks pass, review a fresh apply
preview before placing the selected items.

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

Kitrove can collect eligible text helper scripts alongside SKILL.md as data. Before adding such a skill to any tool, it offers a separate local review of the exact complete bundle. Inspect stored files with `f`, page the file inventory with `v`, and explicitly approve with `y` then Enter. Enter alone skips the selection. Tool placement then has its own preview and approval. A blocked member stops the selected pack; it is not silently dropped.

The local approval covers the bundle revision, including supporting files and retained native variants. Changing the skill requires a new approval. Another computer must approve its own copy; trust is not synchronized. Kitrove neither runs helpers nor installs Python, shell runtimes or dependencies. The receiving tool's permissions and runtime requirements still apply. References specific to another tool are retained, not automatically translated.

Compiled payloads, native lifecycle/install directives, credentials and executable principal documents remain unsupported. Unix helper mode classes are preserved; a platform that cannot preserve a recorded executable mode refuses before writing. Denial blocks future placement but does not remove already placed files or revoke tool permissions; use receipt-backed removal for that. Executable pack rollback is outside this feature.

When packs share an already placed script, removing one pack retains the exact existing files and denied decision for the other owner. It grants no new approval or replacement; removing the last owner removes only its unchanged receipt-backed files.
