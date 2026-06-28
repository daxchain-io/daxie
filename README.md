# Daxie

**The Ethereum wallet for AI.** An agent-first Ethereum CLI wallet in Go, with a
built-in MCP server. Non-interactive flags/env/stdin, `--json` everywhere,
deterministic exit codes, sealed spend-limit guardrails, and a
one-core/two-frontends architecture so the CLI and the MCP server traverse the
*exact same* wallet logic — and the *exact same* guardrails.

[![CI](https://github.com/daxchain-io/daxie/actions/workflows/ci.yml/badge.svg)](https://github.com/daxchain-io/daxie/actions/workflows/ci.yml)
[![Release](https://github.com/daxchain-io/daxie/actions/workflows/release.yml/badge.svg)](https://github.com/daxchain-io/daxie/actions/workflows/release.yml)
[![Go 1.26](https://img.shields.io/badge/go-1.26-00ADD8.svg)](https://go.dev/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status: v1 — stable.** The CLI surface, JSON schemas, exit codes, MCP tool
> set, config schema, and on-disk state formats are frozen and semver-protected
> (see [Versioning](#versioning)). Custody in v1 is an
> **encrypted local keystore inside one OS trust domain** (same uid as the agent).
> That boundary is stated honestly — see [Security model](#security-model) and
> the v2 signer-daemon path. Use a testnet and a small mainnet float while you
> evaluate.

**Install** — Homebrew or `curl | sh` (both verify the download; the full set of
paths and verification recipes is under [Install](#install)):

```sh
brew install --cask daxchain-io/tap/daxie
# or:
curl -fsSL https://github.com/daxchain-io/daxie/releases/latest/download/install.sh | sh
```

---

## What is Daxie?

Most Ethereum tooling assumes a human at a terminal confirming each action. Daxie
inverts that: it is built for an **autonomous agent** to hold an account and move
funds *within operator-set limits it cannot raise*. Two design choices follow:

- **One core, two frontends.** A single `internal/service` package owns every use
  case (build tx, evaluate policy, sign, broadcast, wait). The **CLI**
  (`internal/cli`) and the **MCP server** (`internal/mcpserver`) are thin adapters
  over that core. There is no second signing path to audit: whatever the CLI can
  do, an agent can do over MCP — and *neither* can bypass the guardrails, because
  the guardrails live *below* both frontends, inside the one signing chokepoint.
- **Two passphrases, two privilege levels.** The **keystore passphrase** unlocks
  signing (the agent may hold it). The **admin passphrase** authorizes policy
  changes (the agent *never* holds it). A fully prompt-hijacked agent can spend up
  to the limits — it cannot change the limits, change the allowlist, change what an
  alias means, or read a key out.

Everything an agent needs is non-interactive: flags, `DAXIE_*` env vars, stdin for
secrets, `--json` output on every command, and a small stable set of exit codes to
branch on.

---

## Install

Four supported paths. **Verify before you run** (see [docs/install.md](docs/install.md)
for the download-verify-run recipe and cosign signature verification).

> The *floating* install channels — Homebrew, the `curl | sh` `/releases/latest`
> URL, the `:latest` and `:X.Y` Docker tags, and `go install` with `@latest` —
> track the **stable** channel: they resolve to the latest stable release and a
> prerelease never moves them. Pin an exact version or image digest in production.

### Homebrew (macOS / Linux)

```sh
brew install --cask daxchain-io/tap/daxie
```

The cask pins the release URL **and** its SHA256; a tampered tap is detectable by
a checksum mismatch (residual R9 covers users who skip verification).

### curl | sh (Linux / macOS)

```sh
curl -fsSL https://github.com/daxchain-io/daxie/releases/latest/download/install.sh | sh
```

`install.sh` **verifies the download by default**: it checks the SHA256 against the
signed `checksums.txt`, and when `cosign` is on PATH it *also* verifies the keyless
signature automatically — falling back to checksum-only with a warning when cosign is
absent. Pass `--verify-signature` to make the signature check mandatory (fail if
cosign is missing). It installs to `/usr/local/bin` if writable, otherwise falls back
to `~/.local/bin` (no sudo). Flags and `DAXIE_INSTALL_*` env vars are documented in
[docs/install.md](docs/install.md).

> Prefer not to pipe to a shell? Download `install.sh`, verify its signature, read
> it, then run it — the recipe is in [docs/install.md](docs/install.md).

### Container image (GHCR)

```sh
# :1.1 floats to the latest 1.1.x stable. Pin an exact :X.Y.Z or an @sha256 digest in production.
docker pull ghcr.io/daxchain-io/images/daxie:1.1
docker run --rm ghcr.io/daxchain-io/images/daxie:1.1 version
```

Multi-arch (amd64 + arm64), **distroless/static, non-root (uid 65532)**, no shell,
no secrets baked in, cosign-signed by digest. See [docs/deploy/](docs/deploy/) for
the four-mount deployment pattern.

### go install

```sh
go install github.com/daxchain-io/daxie/cmd/daxie@latest
```

Pure-Go, `CGO_ENABLED=0`. (Skips checksum/signature verification — use a release
artifact for production.)

### Windows

v1 ships a release **zip** (amd64 + arm64) on the
[releases page](https://github.com/daxchain-io/daxie/releases). `install.sh` does
**not** install on Windows (it exits 2 with a pointer to the zip); scoop/winget
manifests are a later add-on.

---

## Quickstart

Full walkthrough in [docs/quickstart.md](docs/quickstart.md). The 60-second version,
on Sepolia:

```sh
# 1. Create a wallet (shows the mnemonic ONCE; encrypts it under your keystore passphrase).
daxie wallet create treasury
daxie account use treasury/0            # make it the default account

# 2. Pick a network + endpoint.
daxie network use sepolia
daxie rpc add sepolia-default --network sepolia --url https://rpc.sepolia.org

# 3. Check a balance (read-only; works with no policy).
daxie balance --json

# 4. Set guardrails. THIS needs the admin passphrase, not the keystore passphrase.
daxie policy set --max-tx 0.1eth --max-day 0.5eth
daxie policy allow 0xRecipient...       # allowlist a destination (or a contact / pinned ENS)

# 5. Send — the policy is enforced in core, before signing.
daxie tx send --to 0xRecipient... --amount 0.05 --wait --json --yes

# 6. Serve the same wallet to an AI agent over MCP (stdio).
daxie mcp serve
```

Exit codes are stable and agent-branchable — the ones you'll branch on most: `0`
ok, `3` policy-denied, `5` insufficient funds, `6` network, `7` reverted, `8`
timeout-pending **or** seal violation, `9` nonce/replacement conflict. The full
`0`–`12` table is in the [command surface](#command-surface).

---

## The agent / MCP story

`daxie mcp serve` exposes the wallet to any MCP client (Claude, an autonomous
agent, a custom harness) over **stdio** (the v1 transport; streamable HTTP arrives
in v1.1 with no refactor). The handshake reports the wallet version, so an agent can
assert what it is talking to without shelling out.

- **31 tools**, one per *operation* (a single `send` covers ETH / ERC-20 / ERC-721 /
  ERC-1155; a single `contract_send` covers any non-standard ABI). The tool list and
  JSON schemas are in [docs/agents.md](docs/agents.md) and printable with
  `daxie mcp tools`.
- **Schemas are derived from the same Go structs the CLI binds**, so CLI and MCP can
  never drift. One JSON output contract, two transports.
- **The same guardrails bind both frontends.** `policy.Reserve` runs inside the one
  signing method either frontend can reach. Set the policy once with the CLI; every
  MCP `send` / `token_approve` / `contract_send` is checked against it.
- **The MCP surface is deliberately narrowed.** It can move funds *within policy* and
  read everything; it **cannot** export keys, create/import wallets, mutate policy,
  or add a registry alias (the alias-spoofing boundary). Those are operator-only,
  out-of-band acts. The full exclusion list is in [docs/agents.md](docs/agents.md).

```sh
# Example MCP client launcher (a TRUSTED harness pins env + paths):
DAXIE_PASSPHRASE_FILE=/run/secrets/daxie-pass \
  daxie mcp serve
```

> The "paths fixed at launch" property is only as strong as the launcher. Run
> `daxie mcp serve` from a trusted harness with pinned env and flags — a deployment
> precondition documented in [docs/deploy/](docs/deploy/).

---

## Command surface

The noun/verb tree. Every command ships a human form **and** `--json`, a
non-interactive path, and documented exit codes. The authoritative contract is
[docs/cli-spec.md](docs/cli-spec.md).

| Noun | Verbs |
|---|---|
| `wallet` | `create` · `import` · `list` · `show` · `rename` · `export` · `delete` |
| `account` | `derive` · `alias` · `unalias` · `import` · `use` · `list` · `show` · `export` · `delete` |
| `keystore` | `change-passphrase` · `info` |
| `balance` | (ETH / `--token` / `--all`; raw address or ENS arg) |
| `tx` | `send` · `status` · `wait` · `list` · `speedup` · `cancel` (RBF) · `abandon` |
| `gas` | (base fee + slow/normal/fast suggestions) |
| `token` | `info` · `add` · `rename` · `list` · `remove` · `approve` · `allowance` · `revoke` |
| `nft` | `add` · `alias` · `aliases` · `list` · `show` · `send` |
| `contract` | `add` · `list` · `show` · `remove` · `call` · `send` · `logs` · `encode` · `decode` |
| `sign` / `verify` | `sign message` · `sign typed` · `verify` (EIP-191 / EIP-712) |
| `ens` | `resolve` · `reverse` |
| `receive` | (block until inbound funds confirm; `--new` invoice address) |
| `contacts` | `add` · `list` · `show` · `remove` |
| `network` | `list` · `add` · `use` · `show` · `remove` |
| `rpc` | `add` · `list` · `show` · `use` · `test` · `rename` · `remove` |
| `policy` | `show` · `set` · `allow` · `deny` · `verify` · `check` · `counters` · `pin` · `reset` · `change-admin-passphrase` · `typed allow/remove` · `contract allow/remove` |
| `mcp` | `serve` · `tools` |
| utility | `version` · `completion` · `config get/set/list` · `convert` |

**Exit codes (stable):** `0` ok · `1` internal · `2` usage · `3` policy-denied ·
`4` auth (passphrase) · `5` insufficient funds · `6` network · `7` reverted ·
`8` timeout-pending / seal · `9` tx conflict (nonce/replacement) · `10`
not-found / read-only mount · `11` state-dir problem · `12` integrity tripwire.

---

## Security model

Daxie's security objective, in one sentence: *a fully prompt-hijacked agent holding
the keystore passphrase must not be able to (a) extract key material through Daxie,
(b) spend beyond operator-set policy, or (c) change that policy — while a thief with
the disk but no passphrase gets nothing at all.* The full threat model is
[docs/design.md §8](docs/design.md); the operator-facing summary is
[docs/security.md](docs/security.md).

The controls, in brief:

- **Two passphrases.** Keystore passphrase = signing (agent may hold it). Admin
  passphrase = policy mutation + the policy seal (operator only, never on an agent
  host). They are independent (distinct salts + scrypt params), so the keystore
  secret buys nothing toward forging policy.
- **Ed25519-sealed policy + a pinned anchor.** The policy file carries a detached
  Ed25519 seal. The agent host holds only the **public verify key** (in the config
  class, read directly, never through Viper/env/flag), so it can *verify* on every
  signing op but *never forge*. A tampered or deleted policy fails closed (exit 8).
- **Rolling-24h spend limits.** Per-tx and per-day caps, gas included, aggregated
  across accounts per network, on durable counters that survive restarts (a reset
  counter would re-widen the window, so it fails closed on corruption rather than
  zeroing).
- **Destination allowlist + ENS/contact pinning.** Sends go only to allowlisted
  destinations; an allowlisted ENS name stores name **and** resolved address, and a
  later re-point is refused (`pin_drift`) until re-allowed.
- **Calldata classifier.** `contract send` decodes the 4-byte selector *before*
  signing: recognized spend-equivalents (`approve`/`transfer`/`setApprovalForAll`/
  `permit`) hit the *same* allowlist + unlimited-ack ceremony as the typed commands;
  unrecognized selectors are deny-by-default once a policy is active. The generic
  noun cannot defeat the typed nouns.
- **Signed supply chain.** Releases carry SHA256 checksums + cosign **keyless OIDC**
  signatures (Rekor transparency log, no long-lived key), SBOMs, and SLSA provenance;
  the OCI image is distroless/static, non-root, cosign-signed by digest.

### Honest residuals (not hidden)

v1 makes a scoped claim. The two residuals that matter most:

- **R1 — host compromise (Critical).** Arbitrary code execution as the agent's uid
  can read the keystore file *and* the passphrase it co-resides with, then decrypt
  offline, outside Daxie. No in-process design stops that in one trust domain. This
  is the headline motivation for the **v2 signer daemon**, which moves keys behind a
  real privilege boundary (agents then hold only a revocable credential; key export
  is not an API).
- **R2 — same-domain counter/state tampering (High).** The agent-facing process
  writes the spend counters and holds no secret to seal them, so within the same
  trust domain they are tamper-*evident* (`policy verify` cross-audits the journal),
  not tamper-*proof*. On Kubernetes the policy *anchor* lives in a read-only
  ConfigMap, which closes the policy-file-swap variant structurally; counter
  *continuity* under a repointed state dir remains the named gap. **Closed by the v2
  daemon.**

The full ranked residual table (R1–R10, each mapped to whether the v2 daemon closes
it) is in [docs/security.md](docs/security.md) and [docs/design.md §8.6](docs/design.md).

---

## The four state classes

Daxie splits its on-disk data into four classes so a container deployment can mount
each with the right durability and writability. This is the backbone of the
[deploy manifests](docs/deploy/).

| Class | Override var | Contents | K8s mount |
|---|---|---|---|
| **config** | `DAXIE_CONFIG` | `config.toml` (networks, RPC endpoints, gas/tx defaults) + `policy-anchor.json` (the seal verify key — read directly, never via Viper) | **read-only ConfigMap** |
| **keystore** | `DAXIE_KEYSTORE` | `keystore.json`, `meta.json`, `wallets/<uuid>.json`, `accounts/UTC--...`, `index.lock` | Secret/external secret sync or PVC (read-only at runtime) |
| **state** | `DAXIE_STATE_DIR` (+ `DAXIE_REGISTRY_DIR`) | tx journal + nonces, sealed `policy.json` + **durable spend counters**, token/NFT/contact registries | **PVC (must persist)** |
| **cache** | `DAXIE_CACHE_DIR` | ENS / metadata / fee-history caches (reconstructible) | emptyDir / tmpfs |

The litmus test: *config* is operator-provisioned and never written by a signing op;
*keystore* travels with key material in a backup; *state* is written by the agent's
runtime job and **must survive restarts**; *cache* is disposable.

---

## Build from source

Requires **Go 1.26+**. All builds are pure-Go (`CGO_ENABLED=0`).

```sh
CGO_ENABLED=0 go build -o daxie ./cmd/daxie
```

The release pipeline (`goreleaser`) builds six targets (darwin/linux/windows ×
amd64/arm64), reproducibly (`-trimpath`, commit-pinned `mod_timestamp`, no
wall-clock input). To validate the full pipeline locally without publishing:

```sh
goreleaser release --snapshot --clean --skip=sbom,sign
```

---

## Documentation

| Doc | What |
|---|---|
| [docs/quickstart.md](docs/quickstart.md) | First wallet, policy bootstrap, a Sepolia send, the agent/MCP flow |
| [docs/install.md](docs/install.md) | Every install path in depth + verification recipes + `--uninstall` |
| [docs/configuration.md](docs/configuration.md) | `config.toml`, `DAXIE_*` env vars, the four state classes |
| [docs/agents.md](docs/agents.md) | Deploying Daxie behind an agent: MCP, the tool surface, unattended secrets |
| [docs/security.md](docs/security.md) | Operator-facing threat model + the ranked residuals |
| [docs/deploy/](docs/deploy/) | Docker Compose + Kubernetes manifests (Helm chart ships in v1.1) |
| [docs/cli-spec.md](docs/cli-spec.md) | The authoritative command/flag/exit-code contract |
| [docs/design.md](docs/design.md) | The canonical design (the law) |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

Architecture in one line: **one core (`internal/service`), two thin frontends
(`internal/cli`, `internal/mcpserver`), each over the same wire contract
(`internal/domain`).** Frontends never import providers; providers never import the
core; `domain` imports nothing internal. This is enforced by `internal/arch_test.go`
and the depguard linter, not by convention.

---

## Versioning

SemVer 2.0.0, flat `v*` tags, released from `main`. The **public API** semver
protects: the command tree and flags, JSON output schemas, documented exit codes,
MCP tool names/schemas, the config file schema, `DAXIE_*` env var names, and on-disk
state formats. Channels: `stable` = `vX.Y.Z`; `beta`/`rc` = `vX.Y.Z-beta.N` /
`-rc.N`. Homebrew, the `:latest` and `:X.Y` Docker tags, and `/releases/latest`
track **stable only** — a prerelease never moves a floating tag under a running
deployment. Pin exact versions or image digests in production.

## Contributing

Daxie is public source for transparency, and development is currently
maintainer-led. See [CONTRIBUTING.md](CONTRIBUTING.md) for the current
contribution policy.

Every agreed change must keep the gate green: unit tests on the 3-OS matrix, the
anvil integration suite, `goreleaser build --snapshot` for all six targets,
golangci-lint (incl. the depguard frontend/leaf matrix), the architecture guard
in `internal/arch_test.go`, and the checked-in `docs/demos/mNN.sh` walkthroughs
running unmodified. The design in [docs/design.md](docs/design.md) is the source
of truth.

## Security

Report suspected vulnerabilities through the process in
[SECURITY.md](SECURITY.md). Do not publish exploit details, wallet material, or
live-funds reproductions in public issues.

## Risk Notice

Daxie is provided under the Apache License 2.0 on an as-is basis, without
warranties or liability except where required by law. Daxie signs and broadcasts
blockchain transactions, which may be irreversible and may result in loss of
funds.

Users are responsible for reviewing configuration, policies, keys, RPC endpoints,
transaction details, and applicable laws before using Daxie with real assets. Use
testnets and small balances while evaluating.

## License

[Apache License 2.0](LICENSE).
