# Mac test launches honor the existing cooperative gate

## Failure and evidence

Post-merge CI41165780166 failed one native Mac library test at an immediate
nonblocking EOF assertion, with OS35/WouldBlock. Its exact hosted writer holder
was not identified. Linux, Windows including standard-user installer/CLI1.88,
Rust1.88 and advisory audit passed. No RC5.4 tag or signing attempt had started.

Twenty unchanged-source parallel library repetitions passed. A public-API stress
with400 guarded and400 unguarded rounds did not reproduce pending EOF. Those
passes do not disprove the original failure. A forced native pipe-window test
confirmed that an ordinary Rust Command child inherits a non-CLOEXEC writer and
keeps EOF pending until reaped; the CLOEXEC control does not retain it.

Darwin transport creation documents its temporary original pipe descriptors and
requires cooperating launches to hold the shared launch gate. Production native
and version launches already participate. Several test-only helper spawns did
not, creating a confirmed contract gap; this is not proof that production cleanup
failed or identification of the original hosted holder.

## Bounded correction

- One private `cfg(test)` helper in the existing shared Unix source acquires the
  existing Mac launch gate only around spawn. It releases before returning the
  child; callers retain their original wait/reap and assertions. Non-Mac spawning
  is unchanged. The default acquisition budget is the existing five-second bound.
- Fixture writers, the environment-canary subprocess and three shared lifecycle
  fixture launches use that helper. Production launch/cleanup code is unchanged.
- A deterministic Mac regression holds the gate over a temporary non-CLOEXEC
  writer window. A short bounded attempted launch must refuse; after closing the
  writer and releasing the gate, ordinary launch succeeds with immediate EOF.
  The child-only negative case is isolated from unrelated parallel launches.
  Every spawned child is killed/reaped before final assertions; a separate test
  proves the gate is released before caller wait.
- Red-before-green reproduced the original OS35/WouldBlock class when the helper
  used the old ungated spawn. An initial test compile error compared a wait result
  whose success type lacks PartialEq; the corrected assertion checks the exact
  ECHILD error, without weakening ownership. Both original logs are retained.
- The original immediate EOF, exact reaping, timeout/cancellation, identity/hash,
  output bounds and environment-canary assertions remain unchanged. There is no
  retry, skip, global test serialization, production timeout increase, new process
  authority, dependency/lockfile or signing/workflow/permission change.

## Product and threat-model impact

NS-07 and NS-09 remain intact: this enforces an existing test launch contract,
not a new native consumer or trust boundary. No discovery/adoption, portable
representation, native-variant preservation, fidelity/loss result, provenance,
deployment receipt, synchronization/conflict or local-data boundary changes.
No model/schema/platform guarantee or ADR decision changes. Fixture execution is
fixed source-built test code and a system sleep process, not capability content.
No signing credentials, account lookup, Keychain, provider, VM or package channel
operation is needed for the repair. No production-artifact acceptance claim.

Manual full-diff/caller review, not independent-agent or exhaustive-repository
sign-off. Require full stable/Rust1.88 canonical validation, fresh audit, license/
notices/governance and exact public required checks. Additionally require actual
full hosted native Mac execution; the PR compile fastpath alone is insufficient.
Only the approved bounded remediation may merge while main is red. Exact repaired
main must be green before the already-approved RC5.4 publication or another
feature merge. Failed runs remain evidence, not candidates for blind retry.
