# ADR-0075: Make pack application a visible guided command

- **Status:** Accepted for implementation by maintainer, 2026-11-17
- **North Star:** NS-01, NS-02, NS-03, NS-04, NS-05, NS-06, NS-07, NS-09, NS-10
- **Related:** ADR-0073, ADR-0074

## Decision

Setup says Add skills or packs to a tool. The numbered selector lists packs before individual assets, with member count and a bounded member preview. A bare interactive `kitrove apply` (optionally selecting a collection) directly opens the existing tool-first journey. Explicit selection, scope/probe flags, JSON, confirmed digests and nonterminal commands retain their existing paths.

Navigation grants no write authority. Fresh recovery, source/target observations, ownership, exact plan approval, pack claims and per-destination receipts remain under existing planners and transactions. Cancellation writes no selected destinations. Pack selection previews its full resolved membership; it does not silently omit a blocked member. No implicit scanning, synchronization, trust or tool execution.
