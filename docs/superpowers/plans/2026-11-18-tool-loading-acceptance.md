# Tool Loading Acceptance Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Separate "Kitrove placed the files" from evidence that each supported receiving tool discovers the intended skill.

**Architecture:** One closed acceptance-record schema serves all four tools. Tool-specific procedures pin official evidence, exact runtime identity and isolated roots. The harness records file placement and discovery separately; provider/model execution is not inferred from either.

**Tech Stack:** Existing signed CLI, synthetic testkit filesystem snapshots, Python standard library record validator; no installed-tool modification or new runtime dependency.

**Spec:** `docs/PRODUCT-PRIORITIES.md`, `docs/ADAPTER_GUIDE.md` and the existing per-tool research/fixture provenance.

## Global Constraints

- NS-03/04/07/09/10; no tool launch, download, account use, paid call or VM start is authorized by planning.
- Begin with OpenCode, then Claude, Codex and Pi using the same result definitions.
- Use a disposable profile or an approved test VM. Never use the maintainer's real HOME, tools' state, sign-in or startup extensions.
- No helper execution or arbitrary plugin installation; use the public inert `review-notes` sample.
- Record `unverified` if the pinned tool has no safe supported discovery surface. Never substitute a model's assertion for native evidence.

### Task 1: Closed result record and validator

**Files:** Create `scripts/tool_loading_record.py`, `scripts/test_tool_loading_record.py`, `docs/acceptance/tool-loading.md`.

**Interfaces:** `validate_record(value: dict) -> dict` accepts exactly `schema_version`, `tool`, `tool_version`, `tool_sha256`, `platform`, `observed_at`, `cli_tag`, `cli_sha256`, `scope`, `fixture_sha256`, `procedure_sha256`, `placement`, `discovery`, `runtime`, `source_reference`. Enums: placement `verified|failed|unverified`; discovery `observed|not_observed|unverified`; runtime `unverified` in the first increment. Hashes are lowercase SHA256; tool is one of the four compiled IDs; scope is `user`. Unknown runtime identity must be null and discovery must stay unverified, rather than inventing a version or hash. `observed` requires exact tool identity, UTC observation time, platform and reviewed procedure hash.

- [ ] Begin with failing tests for these invariants:

```python
def test_presence_does_not_become_loading(self):
    record = minimal_record(placement='verified', discovery='unverified')
    assert validate_record(record)['discovery'] == 'unverified'

def test_loading_requires_placement_and_exact_runtime_identity(self):
    with self.assertRaises(ValueError):
        validate_record(minimal_record(placement='unverified', discovery='observed'))

def test_records_cannot_smuggle_raw_provider_output(self):
    record = minimal_record(); record['stderr'] = '/private/not-for-publication'
    with self.assertRaises(ValueError): validate_record(record)
```

- [ ] Put those methods on a `unittest.TestCase` and use this complete fixture helper. Validator construction must not default a missing field to success:

```python
def minimal_record(*, placement='unverified', discovery='unverified'):
    return dict(schema_version=1, tool='opencode', tool_version=None,
        tool_sha256=None, platform='macos-arm64', observed_at='2026-11-18T00:00:00Z',
        cli_tag='v0.1.0-rc.5.18', cli_sha256='a'*64, scope='user',
        fixture_sha256='b'*64, procedure_sha256='c'*64, placement=placement,
        discovery=discovery, runtime='unverified',
        source_reference='https://opencode.ai/docs/skills/')
```
- [ ] Implement closed-schema and enum/hash checks. Require both tool identity and a reviewed discovery procedure for `observed`; leave runtime execution unverified.
- [ ] Run `python3 -m unittest discover -s scripts -p test_tool_loading_record.py`.

### Task 2: OpenCode disposable procedure

**Files:** Create `docs/acceptance/opencode-loading.md`; reference `docs/research/opencode.md` and `crates/kitrove-testkit/fixtures/harnesses/opencode/current/PROVENANCE.md`.

- [ ] Refresh official documentation for the selected installed/test version. Record the exact supported discovery command or UI action and HOME/config overrides before requesting execution.
- [ ] Prepare a new empty profile with one distinctive inert skill, no credentials and no inherited startup settings. Independently verify the CLI/runtime hashes. Keep the original collection and tool state outside the procedure.
- [ ] Run the existing Kitrove preview and separate apply on that fixture, then verify exact bytes and destination ownership.
- [ ] If approved, use the recorded native discovery operation. Record native identity/source evidence, not just an answer mentioning the skill name. If authentication or execution is required, stop at that actual gate with the procedure ready.
- [ ] Test shared Claude/OpenCode discovery and precedence with distinct inert contents. Verify whether one physical copy is discovered twice and whether a target-native copy shadows it. Keep observation, placement receipt and tool loading separate.
- [ ] Produce the closed record with raw private runtime output retained only in approved local evidence, not a public test fixture.

### Task 3: Same procedure for the other targets

**Files:** Create `docs/acceptance/claude-loading.md`, `codex-loading.md`, `pi-loading.md`; use `docs/research/{claude,codex,pi}.md` and the corresponding versioned fixture `PROVENANCE.md` files.

- [ ] For each target, repeat Task2's identity, profile, placement, native discovery and shared-path checks with its reviewed supported controls. Do not copy OpenCode's invocation or expected precedence into another adapter.
- [ ] Add closed records for each executed case and explicit `unverified` records for gated cases. No generic green badge may collapse mixed results.
- [ ] Update the public support/claims matrix only for the exact accepted versions/platforms. Run canonical checks and review before committing the validator/procedure/records.

## Exit criterion

One verified first-placement journey and an honestly populated four-tool matrix
are useful preview evidence. Clean-machine/offline launch, model execution,
script helpers and every capability type remain separate acceptance programs.
