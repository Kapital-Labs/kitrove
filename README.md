# Kitrove

Kitrove is a CLI for moving agent capabilities between Claude Code, Codex, Pi,
OpenCode, and your other computers. It reads capabilities from your existing setup,
preserves their native files, and adapts them for supported destinations.

Credentials, authentication settings, and machine-specific trust stay local.

## What you can do

- **Discover** skills and other supported capabilities in your agent tools without
  changing their files.
- **Adopt and update** capabilities in a portable collection while preserving the
  original content.
- **Preview and apply** changes to supported tools. Kitrove reports what transfers,
  what would lose meaning, and what it cannot apply.
- **Group capabilities into packs** that you can apply, update, remove, or restore
  from verified pack history.
- **Synchronize between computers** through a filesystem location or an explicitly
  configured HTTPS or SSH Git remote.

For example, you can adopt a skill from Claude Code, preview how it maps to Codex,
and apply it there. If a feature has no equivalent at the destination, Kitrove
reports that limitation rather than silently dropping it.

## Try it from source

You need Rust 1.85 or newer. Build from a source revision you have reviewed:

```sh
cargo build --locked --release -p kitrove-cli
./target/release/kitrove help
```

On Windows, use `./target/release/kitrove.exe`.

Inspect your existing setup without initializing or changing it:

```sh
./target/release/kitrove scan --json
```

Then create an empty Kitrove environment:

```sh
./target/release/kitrove init --machine-id my-machine
```

Initialization does not adopt capabilities. Use `kitrove help` for the available
commands and their options. Workflows that change managed files separate planning
from confirmation; `kitrove lock` rebuilds derived lock data immediately.

## Supported tools and boundaries

Kitrove targets Claude Code, Codex, Pi, and OpenCode on macOS, Linux, and Windows.
WSL has its own Linux machine profile. Support varies by capability, tool layout,
and version; a shared format does not guarantee equivalent behavior everywhere.

Capabilities include skills, prompt commands, instructions, agents, remote HTTPS
MCP declarations, and native Pi extensions. Extensions require explicit local trust
and supported-version evidence. Kitrove does not execute them or change Pi's trust
settings.

Kitrove is not a package manager, credential synchronizer, agent runtime, or
chat-history synchronizer. It can report missing prerequisites but does not install
them. It does not automatically resolve conflicts or overwrite unmanaged files.

For installation and release-verification requirements, see the
[installer guide](docs/INSTALLER.md) and [release documentation](docs/RELEASES.md).

## Documentation and development

- [Product specification](docs/01-PRODUCT-SPEC.md)
- [Architecture](docs/02-ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Security policy](SECURITY.md) and [threat model](docs/04-THREAT-MODEL.md)
- [Contributing](CONTRIBUTING.md)

Before changing the code, read the [North Star](NORTH_STAR.md),
[development rules](DEVELOPMENT_RULES.md), and relevant
[architecture decisions](docs/adr/README.md). Harness-policy changes also follow
the [adapter guide](docs/ADAPTER_GUIDE.md).

Run the full local validation suite with:

```sh
cargo ci
```

## License

Kitrove is dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT),
at your option. See [third-party notices](THIRD_PARTY_NOTICES.md) for dependencies.
