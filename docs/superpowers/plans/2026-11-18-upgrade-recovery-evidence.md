# Upgrade and Recovery Evidence Plan

> **For agentic workers:** Use superpowers:executing-plans task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare an evidence-backed decision about a named collection upgrade pair and recovery boundary before promising stable upgrades.

**Architecture:** Audit persistence first, then exercise independently verified artifacts on disposable collections. Keep executable replacement, forward reading, state mutation and data rollback as distinct results. Existing transaction/recovery code remains the only writer.

**Tech Stack:** Version-pinned Rust sources, signed public artifacts, existing synthetic snapshots and recovery tests, closed Python acceptance records.

**Spec:** `docs/PRODUCT-PRIORITIES.md`, `docs/INSTALLER.md`, `docs/RELEASES.md`, `release/application-compatibility.json`.

## Global Constraints

- NS-03/05/06/07/09/10; no real collection, package-managed install, trust or sync mutation.
- No RC4.2 collection or cross-opening RC4.2/RC5 state. Do not infer a supported predecessor from a Homebrew upgrade.
- Candidate research pair: RC5.17 → RC5.18, **for disposable evidence only**, subject to exact public artifact/source availability and schema audit. This is not a support declaration.
- Keep predecessor lists unchanged until the maintainer approves the exact support statement. No automatic migration command or release is authorized by this plan.
- Preserve failure evidence, journals and interrupted snapshots. Never delete state or recovery evidence to manufacture success.

### Task 1: Persistence and authority delta

**Files:** Create `docs/acceptance/upgrade-recovery-policy.md`; inspect both candidate refs of `crates/kitrove-model/src/{portable,local}.rs`, `crates/kitrove-state-lifecycle/src/lib.rs`, `crates/kitrove-core/src/{local_state_authority,portable_transaction,apply_batch_journal,apply_batch_recovery}.rs`, and the application compatibility catalog.

- [ ] Verify both immutable tag/source identities and public signed artifact inventories. Refuse a missing/mismatched artifact; do not rebuild or reuse partial output as release acceptance.
- [ ] Record changes to portable/local schemas, defaults, strict unknown-field handling, receipt identity, trust hashes, lock derivation, local-state permissions and journal versions. Distinguish unchanged format from a tested supported transition.
- [ ] Enumerate every writer the proposed trial invokes: init, one ordinary-skill collect, authored pack create, explicit destination apply. Omit sync, trust, scripts and newer capability kinds from the first trial.
- [ ] Review whether the older reader would reject or misread any newly written field. Mark rollback unsupported unless independently proved; do not test by opening an unverified collection with an older binary.
- [ ] Prepare the exact trial procedure and support decision for maintainer review before crossing a compatibility boundary. No migration implementation is part of this audit.

### Task 2: Closed evidence record

**Files:** Create `scripts/upgrade_evidence_record.py`, `scripts/test_upgrade_evidence_record.py`.

**Interfaces:** `validate_record(value: dict) -> dict` accepts `schema_version`, `from_tag`, `to_tag`, `from_source`, `to_source`, `from_artifact_sha256`, `to_artifact_sha256`, `fixture_before_sha256`, `backup_sha256`, `forward_read`, `forward_write`, `recovery`, `rollback`, `approved_support`. Observation enums are `passed|failed|unverified`; `approved_support` must be false in research records.

- [ ] Write failure cases before the validator:

```python
def test_binary_upgrade_does_not_imply_collection_acceptance(self):
    value = complete_research_record()
    assert validate_record(value)['forward_write'] == 'unverified'
    assert validate_record(value)['approved_support'] is False

def test_research_cannot_declare_support(self):
    value = complete_research_record(); value['approved_support'] = True
    with self.assertRaises(ValueError): validate_record(value)

def test_unproved_rollback_remains_unverified(self):
    value = complete_research_record()
    assert validate_record(value)['rollback'] == 'unverified'
```

- [ ] Put those methods on a `unittest.TestCase` and use this complete fixture with synthetic hashes. Implement required keys, hash/tag/source checks and refusal of any extra fields or implied success:

```python
def complete_research_record():
    return dict(schema_version=1, from_tag='v0.1.0-rc.5.17',
        to_tag='v0.1.0-rc.5.18', from_source='a'*40, to_source='b'*40,
        from_artifact_sha256='c'*64, to_artifact_sha256='d'*64,
        fixture_before_sha256='e'*64, backup_sha256='f'*64,
        forward_read='unverified', forward_write='unverified',
        recovery='unverified', rollback='unverified', approved_support=False)
```
- [ ] Run `python3 -m unittest discover -s scripts -p test_upgrade_evidence_record.py` and canonical validation before commit.

### Task 3: Approved artifact trial and bounded recovery

**Files:** Create `docs/acceptance/upgrade-rc517-rc518.md` only if Task1 supports that candidate; preserve actual evidence outside the repository. Reuse `kitrove-testkit::harness::FilesystemSnapshot` and existing phase tests in `apply_batch_transaction_tests.rs` and `portable_transaction` tests.

- [ ] Create the candidate producer's collection entirely under a new private fixture. Capture exact source files, objects, receipts, trust, permissions and modification times; archive a byte-verified backup before the new reader touches a copy.
- [ ] Run new-reader inspection first. If approved and supported by the audit, separately preview and confirm the named ordinary-skill operation on the copy. Record every resulting schema and authority change.
- [ ] Reuse exact source-level phase/recovery tests; do not write duplicate tests that mirror the implementation. Add an artifact-level interruption case only where a journal/phase can be observed deterministically under the fixture with bounded owned-process control.
- [ ] Reopen through the existing approved recovery path. Require complete old or new authority, retained human files and no false receipts. Unknown or mismatched evidence refuses, and its original logs/snapshot remain.
- [ ] Review the record and proposed support statement. Only then may a separately reviewed catalog/documentation change name a supported pair. A failed trial produces a diagnosis and repair plan, not a blind retry or silent fallback.

## Exit criterion

A reviewed policy and tested named pair establish a scoped upgrade claim. They
do not prove all capability kinds, every older preview, downgrade compatibility,
cloud sync, concurrent upgrades or stable support by themselves.
