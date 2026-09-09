# ADR-0014: Reusable skill source layouts and identity

- **Status:** Accepted
- **Date:** 2026-08-23
- **North Star invariants:** NS-01, NS-02, NS-03, NS-05, NS-10

## Context

Gate C1 accepts one Agent Skill directory containing `SKILL.md`. Current harness documentation shows a second native source form. Pi Latest discovers qualifying Markdown files in documented skill roots, and OpenCode V2 discovers root-level Markdown files. Claude Code and current OpenCode also expose Markdown files in adjacent capability systems, but those files do not all represent Agent Skills. Codex documents a directory package.

Treating every Markdown file as a skill would misclassify Claude commands and unsupported layouts. Treating every skill as a directory would hide valid Pi and OpenCode V2 sources. Reusing one content hash for both native forms would also discard the authored layout, file name, mode, and bytes.

Kitrove needs one capture model that can preserve both native forms while allowing equal portable semantics to converge.

## Decision

Kitrove defines a generic `SkillSourceLayout` with two variants:

```rust
enum SkillSourceLayout {
    Directory,
    Standalone,
}
```

`Directory` identifies a source tree whose principal document is `SKILL.md`. `Standalone` identifies one Markdown file whose authored file name remains part of the source.

The shared capture engine accepts a typed source:

```rust
enum SkillSource {
    Directory { path: PathBuf },
    Standalone { path: PathBuf },
}
```

The exact source identity uses a versioned frame containing the layout tag, every authored source-relative file name, each file-mode classification, each raw byte length, and the raw bytes. Directory sources retain `SKILL.md` and every supporting path. Standalone sources retain the original Markdown file name. The adapter-native identity, such as a containing directory name or path-derived ID, remains separate input to the observation identity.

The portable projection maps the principal document to the canonical portable path `SKILL.md`. Two sources may therefore have the same portable projection while their exact identities differ. A standalone `review.md` and a directory `review/SKILL.md` with equal projected content demonstrate this rule.

Adoption retains the exact source, source layout, original document name, and adapter-native identity as origin-native evidence. A later target may consume the portable projection through a different layout. Kitrove reports the resulting fidelity and does not rewrite the origin evidence.

The shared engine parses content and records optional declared name and description fields. Each compiled adapter owns the policy that relates a container, path-derived ID, file name, and declared name. A mismatch or missing field may be valid native behavior, a host rejection, or a portable-loss finding. The adapter returns the decision and a stable reason. A valid native candidate may have no portable projection when required standard fields cannot be derived without invention. The shared engine does not impose one harness's naming rule.

The existing `capture_skill(directory, limits)` function remains as a compatibility wrapper over `SkillSource::Directory`. Its Gate C1 behavior, including the standard directory-name check, remains stable for existing callers. New inspection code uses the generic source API and applies adapter policy after capture.

Adapters enable layouts by harness policy and evidence profile. C2 supports:

| Harness policy | Directory | Standalone Markdown |
|---|---|---|
| Claude Code current skills | yes | no; `.claude/commands/*.md` is a related `Command` capability |
| Codex current skills | yes | no |
| Pi Latest | yes | yes, under the root-specific rules in the Pi research record |
| OpenCode current | yes | no |
| OpenCode V2 | yes | yes at a source root |
| Unknown OpenCode line | yes at documented common directory roots | no; report the file as an unsupported layout |

An adapter reports a source that resembles a skill but uses a disabled layout. It returns `scan.layout_unsupported` instead of dropping the source. A related capability such as a Claude command uses its native capability kind and never enters the Agent Skill candidate set.

## Consequences

- Exact identity preserves native layout distinctions, file names, modes, and bytes.
- Portable identity can converge across layouts when projected semantics match.
- C3 must retain original layout evidence during adoption.
- C4 must select a target layout through adapter policy and include that layout in rendered-output identity.
- The shared capture crate gains a generic API without changing the accepted C1 wrapper.
- Adapter research must state layout support and the evidence profile that enables it.
- Unsupported or misclassified files remain visible through structured findings.

The model adds no community adapter ABI. ADR-0010 still governs adapter distribution.

## Security impact

Standalone capture reads one regular Markdown file with no-follow semantics, bounded bytes, credential checks, and the existing YAML limits. It does not infer supporting siblings from the parent directory. Directory capture keeps the C1 traversal and collision defenses.

Including the layout tag and original file name in exact identity prevents a file-to-directory conversion from appearing unchanged. The portable projection cannot prove native equality and cannot establish receipt ownership.

## Validation

- Exact hashes differ between `review.md` and `review/SKILL.md` even when their bytes match.
- Portable hashes match across those layouts when their projected content and supporting tree match.
- Standalone exact identity changes when the file name, mode, or bytes change.
- Directory exact identity retains the C1 path, mode, and byte behavior.
- The compatibility wrapper produces the same accepted output and errors as Gate C1.
- Pi and OpenCode V2 fixtures accept their documented standalone forms.
- Claude, Codex, current OpenCode, and unknown OpenCode fixtures report standalone files without accepting them as Agent Skills.
- A Claude command fixture appears as a related `Command`, not a `Skill`.
- Missing-name, missing-description, and container/name mismatch fixtures exercise each adapter policy and require a structured projection, loss, or rejection reason.

## Relationship to prior decisions

This decision extends ADR-0001, ADR-0002, ADR-0004, ADR-0012, and ADR-0013. It does not change ADR-0013's portable-path collision key. That key still governs every path admitted to an exact or portable tree.
