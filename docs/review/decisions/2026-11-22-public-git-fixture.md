# Public Git connector fixture

The live smart-HTTPS check at merged source b4b047c failed with
sync_backend.git_limit_exceeded in both hosted Linux CI and a local exact-source
reproduction. The public Hello-World advertisement contains 4,097 reference
records. The unchanged transport permits 4,096. Its 268,503 bytes and 4,100 packet
lines are within their separate limits. The same parser, limits and test code
are present in RC5.20; the observation does not date the remote ref growth.

Use the existing public Kapital-Labs/homebrew-tap repository for this one
credential-free live test. At review it advertises 44 references, no peeled refs
and no refs/heads/kitrove-sync-v1 branch. The test continues to call the production
connector with default bounds and pinned TLS roots and require the exact absent
snapshot/revision. A future unexpected advertisement or selected branch must
still fail rather than changing the expected result or falling back.

Only the test URL and this review record change. Keep production parsing, limits,
credentials, TLS, redirect/proxy rules, assertions and CI selection intact. Keep
the deterministic over-limit, malformed and hostile-response tests. Do not create
or modify a remote fixture repository, publish collection data, introduce retries
or ignore the failed main run. Full source/toolchain checks and normal exact PR
checks remain required before the reviewed CI repair merge; the subsequent exact
main must pass before metadata or doctor feature merges and deployment.

This is a test-input repair. It does not alter Git sync behavior or prove the
cause of the affected Mac's storage refusal. No application signing, new release,
installation or personal synchronization is included.
