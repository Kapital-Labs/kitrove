# Repository Layout

```text
kitrove/
├── README.md
├── NORTH_STAR.md
├── DEVELOPMENT_RULES.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE.md / LICENSE-APACHE / LICENSE-MIT
├── THIRD_PARTY_NOTICES.md
├── Cargo.toml
├── crates/
│   ├── kitrove-model/
│   ├── kitrove-adapter-api/
│   ├── kitrove-core/
│   ├── kitrove-cli/
│   ├── kitrove-testkit/
│   ├── kitrove-agent-skills/
│   ├── kitrove-instructions/
│   ├── kitrove-prompt-commands/
│   ├── kitrove-agents/
│   ├── kitrove-mcp/
│   ├── kitrove-frontmatter/
│   ├── kitrove-risk/
│   └── adapters/
│       ├── kitrove-adapter-claude/
│       ├── kitrove-adapter-codex/
│       ├── kitrove-adapter-pi/
│       └── kitrove-adapter-opencode/
├── xtask/
├── third_party/          # Audited, provenance-recorded compatibility patches
├── docs/
│   ├── ADAPTER_GUIDE.md
│   ├── PUBLIC_SOURCE_MANIFEST.md
│   ├── ROADMAP.md
│   ├── architecture/
│   ├── adr/
│   └── research/
├── fixtures/
├── examples/
└── .github/
```

## Crate responsibilities

### `kitrove-model`

Pure domain types, validation, and invariant-preserving constructors. No filesystem or network access.

### `kitrove-adapter-api`

Observation policy, scope, root-tier, request/response, and capability-matrix contracts. Depends on the model, not on concrete adapters.

### `kitrove-core`

Shared observation engine, optional desired/observed comparison, planning, profile resolution, fidelity aggregation, and semantic reconciliation.

### `kitrove-cli`

Human and machine output plus command orchestration. Domain decisions must not live here.

### Adapter crates

Thin compiled policies for harness paths, layouts, native identity, precedence, version evidence, exclusions, rendering, and validation.

### `kitrove-testkit`

Synthetic fixture homes, directory and standalone sources, temporary environment builders, golden comparisons, process sentinels, and security canaries.

### Capability crates

`kitrove-agent-skills`, `kitrove-instructions`, `kitrove-prompt-commands`, `kitrove-agents`, and
`kitrove-mcp` own harness-neutral parsing, strict storage, and rendering primitives for one capability
kind. They do not own filesystem transactions or CLI policy.

### Shared parsing and risk crates

`kitrove-frontmatter` provides the bounded flat-frontmatter parser shared by Markdown capabilities.
`kitrove-risk` provides pure credential-shape detection shared by capture, adoption, rendering, and
materialization authority boundaries.

### `xtask`

Rust-native repository checks, fixture maintenance, schema generation later, and release preparation later.
