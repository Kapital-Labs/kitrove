# Add collected skills to your AI tools (unreleased)

This guided flow is in development after RC5.14. It is not yet in the released
Homebrew executable. It adds local files for a tool to discover; it does not
install tools, start an agent session, grant trust, connect accounts or share a
collection. Advanced items can require an explicit bounded version check.

Run `kitrove configure --environment /absolute/path/to/collection` and choose
**Choose skills to add to your AI tools**. After collecting skills in setup,
option 2 suggests the skills just collected. You can select different items.
Adding from the scan browser offers **Choose a tool** after collection, without
asking for the collection path again. Skipping this next step keeps the collection.

1. Press a tool number for **Claude Code**, **Codex**, **Pi** or **OpenCode**
   without Enter. Choose `m` to select several tools.
2. Choose **All projects on this computer** or **This project only**. Project
   scope asks for an absolute project folder.
3. Choose saved items by their original numbers. Descriptions and a current
   destination check appear under skills. `ready` selects only skills the planner
   can add/update, excluding unmanaged conflicts and managed copies already current.
   Packs and version-gated kinds need an explicit selection.
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

Ordinary skills do not need an executable path. Selected Pi extensions still
need an explicit trusted Pi version probe and existing trust. OpenCode
instructions, commands, agents and MCP entries still require the reviewed
OpenCode V2 probe (`opencode2`). Selecting an unrelated ordinary skill does not
probe an unselected instruction or pack. Required probes are explicit, bounded
local operations; setup does not discover or launch an executable on its own.

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
