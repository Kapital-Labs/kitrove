# Pi adapter research

**Status:** Implemented through saved-trust project extension materialization

**Evidence last reviewed:** 2026-08-31

## Official source

- https://pi.dev/docs/latest/skills
- https://pi.dev/docs/latest/usage
- https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/trust-manager.ts
- https://github.com/earendil-works/pi/security/advisories/GHSA-mqxh-6gq7-558m

## Version evidence

Production `kitrove scan` does not invoke `pi --version` or another Pi process. It reports
`VersionObservation::Unknown`. C2 uses the Latest read-only layout baseline with an informational
unknown-version finding. This supports inventory and makes no materialization claim.

`kitrove versions probe --harness pi --binary <absolute-path>` and materialization's explicit
`--version-binary` option provide the separate active boundary. The reviewed Pi range is
`>=0.79.0, <1.0.0`: 0.79.0 fixes the published project-trust bypass and contains the saved trust
contract used below. The probe directly invokes `--version`, passes only a minimal launch
environment plus offline flags, filters `PATH` through trusted directory ownership and validates
the resolved shebang interpreter, bounds time and output, and binds the observed version and exact
resolved executable hash into the materialization confirmation. It is local evidence, not a
publisher signature, and ordinary scan remains process-free. The first probe is Unix-only. ADR-0038
now closes the Windows filesystem identity and ACL prerequisite, but Windows probing remains fail
closed pending process containment, native execution evidence, and review.

## Filesystem, scope, tier, and layout

| Native source | Scope | Root tier | Directory rule | Standalone Markdown rule |
|---|---|---|---|---|
| `~/.pi/agent/skills` | User | User | directories containing `SKILL.md` at any depth | direct root `.md` with valid skill frontmatter and non-empty description |
| `~/.agents/skills` | User | Compatibility | directories containing `SKILL.md` at any depth | direct root `.md` ignored; nested grouping-folder `.md` accepted with skill frontmatter |
| project `.pi/skills` | Project | Project | directories containing `SKILL.md` at any depth | direct root `.md` with valid skill frontmatter and non-empty description |
| project `.agents/skills` from working directory through Git root, or filesystem root outside a repository | Project | Compatibility | directories containing `SKILL.md` at any depth | direct root `.md` ignored; nested grouping-folder `.md` accepted with skill frontmatter |
| package `skills/` or `pi.skills` | source-dependent | Explicit | supported by Pi | C2 accepts a caller-supplied local directory or standalone file; it does not resolve a package |
| settings `skills` array | source-dependent | Explicit | file or directory path | C2 accepts a caller-supplied local directory or standalone file |
| CLI `--skill <path>` | caller-selected | Explicit | file or directory path | C2 accepts a caller-supplied local directory or standalone file |

Root Markdown files other than `SKILL.md` that do not look like skills are ignored by Pi. C2 still reports a file that resembles a skill but fails parsing as `Unknown`; it does not drop authored failure evidence.

C2 defines "resembles a skill" for a supported Pi standalone position as a Markdown file whose first bytes are `---\n` or `---\r\n`. The prefix check is bounded and no-follow; generic capture then reopens and validates the complete file. Markdown in a position where standalone is disabled remains a visible unsupported-layout finding.

Project sources require Pi project trust before Pi loads them. Scan does not read or change Pi trust
state. A typed transient observation is keyed by Pi plus the validated repository boundary, or the
working directory outside a repository. Without caller-supplied trust evidence, project candidates
carry `pi.project_trust_unknown`. A declined trust observation adds `pi.project_trust_declined` and
records native unavailability but does not authorize Kitrove to erase or stop ownership-classifying
the candidate.

For project extension materialization only, Kitrove reads Pi's saved `~/.pi/agent/trust.json`
decision without following links or changing permissions/content. The documented store maps
canonical absolute paths to `true`, `false`, or `null`; the nearest current path or ancestor decision
wins. Kitrove bounds file size and entries, rejects malformed/duplicate/unsafe stores, and binds the
exact store hash plus selected ancestor into the confirmed plan. Only effective saved `true` grants
authority. Global/default trust and one-run approval do not. The trust file must be
current-user-owned. On Unix, its ancestor directories must be current-user- or root-owned and not
group/world writable, except for a root-owned sticky directory such as `/tmp`. On Windows, the file
and every ancestor are opened without following reparses, retained during the bounded read, and
checked for accepted ownership and absence of untrusted mutation authority. The exact decision and
path authority are revalidated at commit on both platforms.

## Skill identity and naming

- Layouts: `Directory` and `Standalone` under the root-specific rules above.
- Directory principal document: `SKILL.md`.
- Standalone principal document: the authored Markdown file.
- Supporting files: captured for Directory; Standalone reads no siblings.
- Native skill name: frontmatter `name`.
- Container/name mismatch: Pi permits it. C2 accepts the candidate, retains the container and declared name, and records `skill.native_name_differs` for portable loss.
- Frontmatter issues: Pi warns for many standard violations, ignores unknown fields, and rejects a declared skill without a description.

The generic exact source identity retains layout, original file name, mode, and raw bytes. Portable projection maps the principal document to `SKILL.md`. Equal directory and standalone content can share portable identity while native evidence differs.

## Duplicate policy

Pi warns on a name collision and keeps the first skill found. The page lists source families but does not define a total enumeration order across all sources. C2 preserves every candidate and the documented first-found rule as evidence.

When official or verified fixture evidence does not establish the first source, classified scan returns `ConflictingDuplicate` for the group. Inventory mode leaves valid candidates `Unmanaged` and attaches `scan.duplicate_ambiguous`. C2 does not substitute its sorted traversal order for Pi runtime behavior.

## Capability inventory

### Agent Skills

C2 supports the documented directory and standalone forms. It preserves helper scripts, references, native fields, exact layout, file names, modes, and bytes. Known executable content remains `Executable`; scan runs none of it.

### Skill commands

Pi registers skills as `/skill:name` commands. This is invocation behavior of an Agent Skill, not a separate command source layout.

### Prompt templates, extensions, packages, and settings

Pi exposes these related native systems. C2 does not execute packages, load extensions, parse prompt templates as skills, or mutate settings. A verified local directory or standalone file can enter skill scan through `RootTier::Explicit`.

Gate F selects Pi extensions as the representative native-only executable capability. Current official documentation defines `~/.pi/agent/extensions/*.ts` and `~/.pi/agent/extensions/*/index.ts` as global auto-discovery forms, with corresponding project-local `.pi/extensions` forms. Extensions run with full system permissions, project-local extensions load only after project trust, and `/reload` reloads auto-discovered extensions. A directory extension may include helper modules beside `index.ts`; package dependencies require a separately installed package environment.

Gate F permits read-only bounded capture of the documented standalone and directory auto-discovery
forms and always classifies them as executable. Later gates add machine-local exact-content trust and
receipt-backed exact materialization. User materialization requires explicit supported Pi version
evidence; project materialization additionally requires effective saved project trust. Kitrove never
imports TypeScript, runs an extension, changes Pi trust, installs a package, or resolves dependencies.
Other harnesses remain unsupported for native Pi extensions. Package, settings-array, CLI `-e`, npm,
Git, and HTTP extension sources remain outside the adoption boundary.

### Instructions, agents, hooks, and MCP

C2 makes no support claim for these capability kinds.

Phase 3 research found agent Markdown only in Pi's optional subagent example extension. Installing
that example adds executable TypeScript which spawns separate Pi processes; project agents are
repo-controlled prompts enabled by extension parameters and trust. The directories therefore do not
form an independent built-in target contract. ADR-0031 keeps Pi agent adoption and materialization
unsupported until executable extension authority can be proven explicitly.

Phase 3 MCP research found no built-in MCP field or registry in Pi's official settings contract.
Extensions can add tools and integrations, but that is executable extension authority rather than a
portable MCP destination. ADR-0032 therefore keeps Pi MCP adoption and materialization unsupported.

## C2 policy contract

- Default roots use the scope, tier, and layout table above.
- No-repository `.agents/skills` traversal may reach filesystem root under the shared root limit.
- `Unknown` version selects Latest read-only layout rules and adds an informational finding.
- Project trust remains local evidence and scan never changes it.
- Container/name mismatch is accepted with portable-loss evidence.
- Ambiguous first-found order yields a duplicate conflict in classified mode.
- Unsupported standalone positions stay visible as `scan.layout_unsupported`.
- Inspection performs no write, process spawn, network request, package load, or symlink follow.

## Phase 3 agent evidence

| Date | Policy line | Observation | Source |
|---|---|---|---|
| 2026-08-30 | Optional example extension | The subagent feature requires installing executable TypeScript and spawns a separate Pi process. | https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent/examples/extensions/subagent |
| 2026-08-30 | Optional example extension | User and project agent Markdown directories are discovered by the extension, with project loading gated by explicit scope and trust. | https://github.com/badlogic/pi-mono/tree/main/packages/coding-agent/examples/extensions/subagent |
| 2026-08-30 | Latest settings | The built-in user/project settings contract lists tools and extension resources but no MCP registry. | https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/settings.md |

## Fixture contract

- native user and compatibility roots;
- project roots inside and outside a Git repository;
- direct native standalone, host-ignored but C2-visible direct compatibility Markdown, and accepted nested grouping standalone;
- directory discovery at nested depths;
- matching portable projection across layouts with different exact identities;
- accepted container/name mismatch;
- trusted, declined, and unknown project trust evidence;
- first-found ambiguity with every candidate retained;
- package, settings, and CLI local explicit directory or standalone sources;
- unsupported layout and malformed standalone candidates;
- executable content, symlink refusal, process sentinel, and filesystem equality.

## Evidence log

| Date | Policy line | Observation | Source |
|---|---|---|---|
| 2026-08-23 | Latest docs | Native and compatibility roots have distinct direct and nested standalone rules. | https://pi.dev/docs/latest/skills |
| 2026-08-23 | Latest docs | Directory packages with `SKILL.md` are discovered at any depth in skill locations. | https://pi.dev/docs/latest/skills |
| 2026-08-23 | Latest docs | Project sources require trust. | https://pi.dev/docs/latest/skills |
| 2026-08-23 | Latest docs | Pi permits container/name mismatch, warns on collisions, and keeps the first found. | https://pi.dev/docs/latest/skills |
| 2026-08-23 | Latest docs | The page lists package, settings, and CLI skill sources without a total duplicate enumeration order. | https://pi.dev/docs/latest/skills |
| 2026-08-23 | C2 decision | Scan uses the Latest read-only baseline without launching Pi. | docs/adr/0012-versioned-read-only-adapter-observation.md |
| 2026-08-28 | Latest extension docs | User and project auto-discovery accept direct `.ts` files and one-level directories rooted at `index.ts`; extensions run with full system permissions and project-local loading follows project trust. | https://pi.dev/docs/latest/extensions |
| 2026-08-28 | Gate F decision | Preserve exact Pi extension bytes and identity without import, execution, dependency installation, trust mutation, or materialization. | docs/adr/0026-native-only-executable-variant-preservation.md |
| 2026-08-31 | Saved project trust | Pi stores canonical path decisions and applies the nearest path/ancestor decision. | https://github.com/earendil-works/pi/blob/main/packages/coding-agent/src/core/trust-manager.ts |
| 2026-08-31 | Project-trust security boundary | Pi versions before 0.79.0 are affected by the published project-trust bypass; 0.79.0 contains the fix. | https://github.com/earendil-works/pi/security/advisories/GHSA-mqxh-6gq7-558m |
| 2026-08-31 | Phase 4/5 decision | Explicit executable-bound probing plus saved read-only project trust authorize exact Pi project extension materialization. | docs/adr/0036-explicit-local-version-probes-bind-executable-policy.md |
