# ADR-0030: Prompt commands use a narrow versioned portable core

- **Status:** Accepted for Phase 3 implementation
- **Date:** 2026-08-30
- **North Star:** NS-01, NS-02, NS-03, NS-04, NS-05, NS-07, NS-09, NS-10

## Context

Claude, Codex, Pi, and OpenCode no longer share one stable custom-command abstraction. Claude retains
a legacy Markdown command format but recommends skills. Codex removed custom prompts and recommends
skills. Pi and OpenCode retain first-class Markdown prompt templates, but their namespacing, argument
parsers, frontmatter, precedence, and interpolation behavior differ. Some authored templates execute
shell commands before the model sees the prompt.

Treating all Markdown as interchangeable would silently change invocation behavior, drop active
metadata, or turn imported text into code execution. Treating commands as skills would also erase the
user's chosen capability kind and make round trips ambiguous.

## Decision

Kitrove represents prompt commands as `AssetKind::Command` with a versioned portable envelope. Version
1 contains a validated single-segment logical name, optional description, Markdown body, and only the
portable argument forms `none` and `all_arguments`. Kitrove uses its own placeholder in portable objects and
renders the documented native placeholder at each supported target.

Pi Latest and OpenCode command Markdown are primary portable targets. Claude's legacy Markdown
commands are eligible only where the exact command can be represented without unreported loss;
deprecation and namespace limitations are fidelity evidence. Codex current is unsupported. Kitrove
does not automatically materialize a command as a skill.

Nested command names, native positional/default/range arguments, implicit argument appending, shell
interpolation, file inclusion, agent/model/tool selection, configuration-defined commands, and
additional/package/plugin sources do not enter the v1 portable core. Exact native bytes remain
preservable. A recognized shell
interpolation classifies the native component as executable and blocks this first materialization
slice. Unknown execution-affecting metadata fails closed.

Standard user/project Markdown targets use whole-file receipts and the existing atomic transaction
and recovery contracts. Discovery and planning do not run harnesses, templates, interpolations, or
version commands.

## Consequences

- Kitrove reports real portability instead of manufacturing four-target symmetry.
- Safe Pi/OpenCode prompt templates can round-trip without carrying target syntax in portable data.
- Claude legacy sources remain visible and preservable while their deprecation is explicit.
- Removed Codex prompts cannot be accidentally deployed as inert, ignored files.
- Rich native commands remain native or blocked until a later schema proves their semantics.
- Future positional argument support requires a new portable format version and cross-harness parser
  fixtures; it cannot reinterpret v1 content.
