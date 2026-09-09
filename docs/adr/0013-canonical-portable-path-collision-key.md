# ADR-0013: Canonical Portable Path Collision Key

- **Status:** Accepted
- **Date:** 2026-08-23
- **North Star invariants:** NS-01, NS-03, NS-05, NS-10

## Context

Kitrove captures one portable tree for macOS, Linux, and Windows. Those platforms do not agree on case or Unicode normalization. A tree that contains two distinct names on one filesystem can address one destination on another. Examples include canonically equivalent NFC and NFD names, such as `Résumé.md` and `Re\u{301}sume\u{301}.md`, and full-fold equivalents, such as `Straße.md` and `STRASSE.md`.

This ambiguity threatens portable-state integrity and stable asset identity (NS-01 and NS-05). Accepting both names could overwrite one sibling during materialization or make descendants reachable through equivalent directory ancestors. Either outcome would violate the requirement to preserve native distinctions or report incompatibility (NS-03 and NS-10). It also extends the path-traversal and symlink-escape threat-model boundary: path validation must prevent two captured identities from resolving to one supported-platform destination.

## Decision

After validating each portable path, Kitrove derives this collision key from the complete `/`-separated path:

```text
NFC(full Unicode case fold(NFC(path)))
```

The fold is the Unicode default full case fold, without locale-specific or Turkic casing. The second NFC pass composes decomposed output introduced by folding. U+002F `/` remains the separator through every step. The algorithm does not use compatibility normalization such as NFKC, because compatibility-equivalent characters do not necessarily identify the same filesystem name.

The collision key is a validation key, not a stored path. A successful capture preserves the authored portable path and continues to hash that exact path under the existing tree-hash framing. This decision therefore changes capture eligibility, not the representation or hash of accepted trees.

Kitrove registers both files and directory ancestors in one bounded collision registry before returning a captured tree. If two distinct portable paths produce the same key, capture fails with the redacted `capture.path_collision` error. Equivalent siblings are rejected because a target filesystem could materialize them at one location. Equivalent ancestors are rejected because their descendants could otherwise acquire ambiguous or target-dependent identities.

The Unicode normalization and case-fold data are part of this compatibility rule. Their dependency versions remain pinned. An upgrade that changes the accepted path set requires compatibility review, fixture updates, and an amendment or superseding ADR.

## Alternatives considered

### Host-native comparison

Using only the capture host's filesystem rules would make acceptance depend on the machine performing capture and would miss collisions on another supported platform.

### ASCII lowercase or simple Unicode lowercase

Lowercasing covers common ASCII names but misses canonical equivalents and multi-code-point full folds such as `ß` to `ss`.

### Compatibility normalization or stored-path rewriting

NFKC would collapse characters beyond the filesystem ambiguity this rule addresses. Rewriting stored paths would also discard authored identity and change exact-tree hashes.

## Consequences

### Positive

- Portable capture has one deterministic collision rule across macOS, Linux, and Windows.
- Ambiguous siblings and directory ancestors fail before portable state can be accepted.
- Exact path spelling, file bytes, and existing hash framing remain unchanged for accepted trees.
- Collision failures remain explicit and redacted instead of producing silent loss.

### Negative

- The rule is conservative. Kitrove can reject a tree that the current host, or even a particular target filesystem, could store distinctly.
- Unicode table updates can change capture eligibility and must be handled as compatibility changes.
- The rule prevents known case and canonical aliases but does not claim to emulate every filesystem's complete name-equivalence behavior.

### Follow-up

- Execute the host-gated collision fixtures in native Linux, macOS, and Windows CI when runner capacity is restored.
- Review the key when supported platforms, filesystem guarantees, or pinned Unicode data change.

## Validation

Pure key tests cover ASCII and Unicode case pairs, NFC/NFD equivalence, full folds, and separator preservation. Filesystem fixtures cover sibling and ancestor collisions when the host can represent both names. Cross-platform jobs must compile the platform-specific capture code and, when native runners are available, execute the corresponding fixtures. Error tests verify stable codes and prevent captured bytes from appearing in diagnostics.

## Supersession

This decision extends ADR-0004's canonical hashing contract by defining which path sets are eligible for hashing; it does not supersede ADR-0004. Reconsider it if Kitrove changes its supported platforms, portable path model, or Unicode compatibility data.
