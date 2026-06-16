# Daxie

**The Ethereum wallet for AI.** An agent-first Ethereum CLI wallet in Go, with a
built-in MCP server. Non-interactive flags/env/stdin, `--json` everywhere,
deterministic exit codes, spend-limit guardrails, and a one-core/two-frontends
architecture so the CLI and the MCP server traverse the exact same wallet logic.

> **Status: pre-release, under construction.** This repository is being built
> milestone by milestone against the canonical design in
> [`docs/design.md`](docs/design.md). The current milestone is **M0 — scaffold,
> CI, config & output core**. Most commands described in
> [`docs/cli-spec.md`](docs/cli-spec.md) are not yet implemented. Do not use this
> to hold real funds.

## What works today (M0)

```sh
daxie version [--json]                 # version, commit, build date
daxie completion bash|zsh|fish         # shell completion scripts
daxie convert 1.5eth wei               # eth/gwei/wei unit conversion (exact integer math)
daxie config get|set|list [--json]     # Viper-backed operator settings
```

## Building

Requires Go 1.26+. All builds are pure-Go (`CGO_ENABLED=0`).

```sh
CGO_ENABLED=0 go build -o daxie ./cmd/daxie
```

## Design

The single source of truth is [`docs/design.md`](docs/design.md). It is bound by
[`docs/requirements.md`](docs/requirements.md) and the CLI contract in
[`docs/cli-spec.md`](docs/cli-spec.md).

Architecture in one line: **one core (`internal/service`), two thin frontends
(`internal/cli`, and later `internal/mcpserver`), each over the same wire contract
(`internal/domain`).** Frontends never import providers; providers never import the
core; `domain` imports nothing internal. This is enforced by `internal/arch_test.go`,
not by convention.

## License

See [LICENSE](LICENSE).
