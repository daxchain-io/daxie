# Daxie — The Ethereum Wallet for AI — Design Prompt

> **Status:** ready for design. All 28 logged decisions are resolved (see
> the Open Questions Log at the bottom); sections marked `[DECIDED]` are
> settled requirements. Remaining implementation details (default timeout
> values, per-network confirmation counts, ETH-arrival detection
> mechanics, `--amount` matching semantics) are deliberately delegated to
> the design session — see cli-spec.md for where they're flagged.

---

## The Prompt

You are designing **Daxie — the Ethereum wallet for AI**: a CLI wallet with
a built-in MCP server. Produce a complete design covering architecture,
command surface, MCP tool surface, key management, security model,
configuration, extensibility, and release/distribution pipeline. The design
must satisfy every requirement below and explicitly call out trade-offs
where you make a judgment call.

### 1. Vision & Audience

Daxie is **agent-first**. Its audiences, in priority order:

1. **AI agents** (primary) — autonomous agents that hold an identity and
   transact on Ethereum. Agents drive Daxie two ways: via the CLI
   (non-interactive flags/env/stdin, structured JSON output, deterministic
   exit codes, nothing that requires a TTY unless explicitly interactive)
   and via the **built-in MCP server** (`daxie mcp serve`, see §1a).
   Everything distinctive about Daxie — unattended signing, spend-limit
   guardrails, destination allowlists, JSON-everything, MCP built in —
   exists for this audience. When a design tension arises between human
   convenience and agent safety/scriptability, resolve it in the agent's
   favor.
2. **CLI-native humans** (secondary) — people who prefer the terminal to a
   browser extension or GUI wallet. An agent-grade wallet is automatically
   a great scriptable human wallet; human-readable output remains the
   default at an interactive TTY.

### 1a. MCP Server (in-repo, same binary)

- **[DECIDED]** The MCP server is **not a separate wrapper or repo** — it
  is a subcommand of the same binary: `daxie mcp serve` (stdio transport at
  minimum). One install (`brew install daxie`) gives an agent operator both
  the CLI and the MCP server; one release pipeline, one version.
- **[DECIDED]** MCP tools call the **internal Go packages directly** — the
  same wallet/signer/chain core the Cobra commands use. No shelling out to
  the CLI, no stdout parsing.
- **[DECIDED]** This forces the load-bearing architectural rule: **one
  core, two thin frontends.** All wallet logic lives in internal packages
  with a clean API; Cobra command handlers and MCP tool handlers are both
  thin adapters over it. No business logic in either frontend.
- The design should propose the v1 MCP tool list (mirroring the command
  surface: balances, transfers, tx status, address/wallet info) and state
  how guardrails (§5) apply identically to MCP-initiated signing.

### 2. Chain Support

- **[DECIDED]** Daxie is an **Ethereum/EVM wallet**. v1 targets Ethereum
  mainnet + Sepolia; other EVM chains (L2s like Base/Arbitrum/Optimism) are
  the natural expansion path and mostly reduce to config presets.
- **[DECIDED]** The design may assume **EVM-only** throughout: one address
  format, one transaction model, ABI-based tokens. Keep the signer and
  chain-client interfaces clean (cheap insurance), but do **not** design
  abstractions for UTXO-family chains (Bitcoin, Litecoin, Dogecoin) — if
  those ever happen, they're a future major version's problem.
- **[DECIDED]** Networks beyond the built-in presets are user-addable via
  config (chain ID + RPC URL) without code changes.
- **[DECIDED]** Tokens, NFT collections, and individual NFTs
  (`collection#tokenId`) are referenced by **local, per-network registry
  aliases** (or raw addresses). Aliases are never resolved via on-chain
  symbols — symbol spoofing is free, so name→address mapping is always
  local and explicit. see cli-spec.md (`daxie token`, `daxie nft`).
- **[DECIDED]** v1 asset scope: **ETH, ERC-20, ERC-721, and ERC-1155** —
  balances, ownership, and transfers for all of them. Rich NFT metadata
  rendering (`tokenURI` resolution, IPFS fetching, image display) is a
  nice-to-have the design may stage after core operations.

### 3. Technology Stack

- **[DECIDED]** Language: **Go**.
- **[DECIDED]** CLI framework: **Cobra** (commands) + **Viper**
  (configuration: file + env vars + flags, with the standard precedence
  flags > env > config file > defaults).
- **[DECIDED]** Ethereum library: **`go-ethereum`** (geth) as a library —
  it's the canonical Go implementation and gives us keystore, ABI, RPC
  client, and signing primitives in one battle-tested dependency.
- **[DECIDED]** MCP server: the official **MCP Go SDK**
  (`modelcontextprotocol/go-sdk`), embedded in the same binary (§1a).

### 4. Command Surface

- The shape is `daxie <noun> <verb>` (e.g., `daxie wallet create`,
  `daxie tx send`). A draft of the full v1 command tree lives in
  [cli-spec.md](cli-spec.md) — the design session should treat it
  as the starting point and refine it, including `daxie mcp serve` (§1a).
- **[DECIDED]** Naming model: HD **wallets** are named; accounts within
  them are addressable by derivation index or by user-assigned **alias**
  (e.g., `treasury/3` ≡ `treasury/payroll`); standalone **imported
  accounts** (raw private keys) are supported and named. One uniform
  account-reference syntax across all commands.
- **[DECIDED]** Every command supports `--output json` (or a global
  `--json`) for machine consumption; human-readable output is the default.
- **[DECIDED]** Non-interactive operation must be possible for every
  command (flags/env/stdin for anything that would otherwise prompt).
- **[DECIDED]** Every broadcasting command (`tx send`, `nft send`)
  supports `--wait` / `--confirmations` / `--timeout`; confirmation-count
  defaults are **per network** (flag > config > built-in), and
  confirmed / reverted / timed-out-but-pending get **distinct exit codes**
  so agents can branch. `daxie tx wait <hash>` resumes a wait.
- **[DECIDED]** **Gas handling** follows the cast/Foundry model with two
  deliberate departures: estimation by default (`eth_estimateGas` ×
  safety multiplier; `eth_feeHistory`-derived EIP-1559 fees with
  `--speed slow|normal|fast` presets), explicit `--max-fee`/
  `--priority-fee` flags (no dual-purpose `--gas-price` except in
  `--legacy` mode), env + per-network config overrides, per-network
  `legacy = true` for pre-1559 chains. **Gas caps are policy**: an
  admin-protected `--max-gas-price` refusal cap, and gas spend counts
  toward daily spend limits. `daxie gas` queries current fees;
  `daxie tx speedup`/`tx cancel` handle stuck transactions (RBF).
  Blob txs out of scope for v1.
- **[DECIDED]** **Message signing/verification** (`daxie sign` /
  `daxie verify`): EIP-191 personal messages and EIP-712 typed data — the
  gasless agent-identity primitive (SIWE, off-chain orders). The design
  must decide how message signing interacts with policy: EIP-2612
  `Permit` (and similar spend-equivalent signatures) must be
  policy-checked like approvals.
- **[DECIDED]** **ENS resolution**: names accepted wherever destinations
  or read-only addresses are (`--to vitalik.eth`), plus
  `daxie ens resolve|reverse`. Resolved addresses are always echoed
  before signing. **Allowlist pinning**: ENS entries in the policy
  allowlist/contacts pin name + resolved address at allow-time; a changed
  resolution refuses the send until re-allowed (ENS records are mutable —
  an agent must not silently follow a re-pointed name).
- **[DECIDED]** **ERC-20 approvals**: `daxie token
  approve|allowance|revoke`. Approvals are spend-equivalents: they count
  against policy guardrails, spenders must pass the allowlist, and
  unlimited approvals require explicit `--unlimited --yes`. *(Amended at
  design time — v1 spend limits are ETH-denominated (native value + gas
  only; there is no price oracle in v1), so token/NFT amounts are not
  converted against them: "count against policy guardrails" is delivered
  via the spender/destination allowlist, gas accrual, the gas cap, and
  the `--unlimited --yes` ceremony. To keep that fail-closed, token
  transfers and approvals are refused when spend limits are configured
  but no allowlist is, unless the operator explicitly acknowledges the
  gap under the admin passphrase; per-asset limits are the deferred item
  that closes the gap. Supersession recorded in the Open Questions Log,
  #2.)*
- **[DECIDED]** **Ergonomics**: default account (`daxie account use` /
  `DAXIE_ACCOUNT`) making `--from`/`--account` optional; **positional
  name arguments** (`daxie wallet create treasury`, not `--name`);
  `--qr` terminal QR rendering on `account show` and `receive`;
  `daxie convert` for eth/gwei/wei unit math.
- **[DECIDED]** Testnet faucet integration: **deferred** —
  provider-dependent; document manual faucet URLs instead.
- **[DECIDED]** **`daxie receive`** — the inbound counterpart: blocks
  until an account receives ETH / a token amount / a specific NFT and the
  arrival reaches the confirmation target. `--new` derives a fresh
  receiving address (invoice-style) and prints it before blocking. With
  `--json` it emits a line-delimited event stream (listening → detected →
  confirming → confirmed *(per inbound transfer)* → complete *(terminal,
  carries exit code)*; agents wait on the terminal `complete` line, not a
  final `confirmed` — design-session refinement of the original
  listening→detected→confirmed sketch). Detection: `Transfer` logs for tokens/NFTs; balance/block
  polling for plain ETH (no logs exist), upgradable to WebSocket
  subscriptions. Completes the agent-to-agent payment loop.

### 5. Key Management & Security Model

This is the highest-stakes section of the design. The design must address:

- **[DECIDED]** v1 custody model: **encrypted local keystore on disk** —
  BIP-39 mnemonic generation/import, BIP-32/44 HD derivation,
  geth-compatible encrypted keystore JSON (scrypt). Hardware wallets, OS
  keychain integration, and remote signers (KMS / ERC-4337) are explicitly
  future layers; the design should define a signer interface they can plug
  into later.
- **[DECIDED]** v1 ships **basic agent guardrails**: per-transaction and
  per-day spend limits plus an optional destination allowlist, enforced
  locally by the wallet before signing and configured via the
  admin-authenticated `daxie policy` commands — the sealed policy file
  lives outside Viper resolution by design (no config key or `DAXIE_*`
  env var can set a limit; Viper's flags > env precedence would otherwise
  let a compromised agent outvote the admin passphrase from its own
  process environment). *(Amended at design time — this bullet originally
  said "configured via Viper"; supersession recorded in the Open
  Questions Log, #2.)* *(Further amended — limits are ETH-denominated,
  native value + gas only; token/NFT spend paths must pass the allowlist
  and fail closed when limits are set but no allowlist is configured: see
  §4's approvals amendment and the Open Questions Log, #2.)* A fuller
  policy engine (rate limits, time windows,
  per-asset rules, approval webhooks) is a future layer; the design
  should leave room for it.
- **[DECIDED]** **Passphrase rotation**: `daxie keystore
  change-passphrase` re-encrypts the keystore under a new passphrase.
- **[DECIDED]** Passphrase granularity: **one passphrase per keystore**
  (per-wallet isolation is a possible later option). The design must
  specify how an unattended agent supplies it (env var, file, stdin) and
  the trade-offs of each.
- **[DECIDED]** **Privilege separation via a second secret:** policy
  mutations require a separate **admin passphrase** that the agent is
  never given. The agent holds the keystore passphrase (to sign within
  policy); only the human operator holds the admin passphrase (to set
  policy). A compromised agent cannot raise its own limits.
- Encryption-at-rest for key material, memory hygiene (zeroing secrets),
  and what is/isn't logged.
- Threat model: what attacks are in scope (stolen laptop, malicious RPC,
  clipboard snooping, compromised agent prompt) and which mitigations v1
  ships.

### 6. Network / RPC

- **[DECIDED]** Daxie ships **sensible default public RPC endpoints** for
  built-in networks so it works out of the box, with **user-supplied RPC
  URLs** (Alchemy/Infura/self-hosted) as the expected path for serious
  use. No provider-specific API integrations in v1.
- **[DECIDED]** **Networks and endpoints are separate objects.** A network
  is a chain definition (name, chain ID); an **RPC endpoint** is a named
  connection bound to a network — many per network (e.g. `mainnet-alchemy`,
  `mainnet-infura`, `corp-node`), one default per network, per-invocation
  override via `--rpc <name>`. Managed by `daxie network` and `daxie rpc`
  (see [cli-spec.md](cli-spec.md)).
- **[DECIDED]** Endpoint auth in v1: API keys embedded in URLs, **custom
  headers** (bearer tokens, API-key headers), and **mTLS** (client
  cert/key + optional CA bundle). Secrets in URLs/headers are stored as
  `${env:VAR}` / `${file:path}` references, resolved in-memory at connect
  time — never persisted resolved.
- **[DECIDED]** Chain-ID verification: endpoints are checked via
  `eth_chainId` against their declared network on add/test, guarding
  against misconfigured or malicious endpoints.

### 7. Configuration

- Config file (location per XDG / `~/.config/daxie/`), env vars
  (`DAXIE_*` prefix), and flags via Viper.
- **[DECIDED]** v1 supports **multiple named wallets** in the keystore;
  commands take `--wallet` (and `--account` for HD-derived accounts).
  Distinct identities matter early for agents. Full profile bundles
  (wallet + network + RPC presets switchable via `--profile`) are a later
  convenience layer.

### 7a. Deployment Environments & State Durability

Daxie runs in three contexts, and the design must work in all of them:

1. **Local workstation** — installed via brew/curl, driven by a human or a
   local agent framework (e.g. OpenClaw, Hermes Agent) over CLI or MCP
   stdio.
2. **Docker / Docker Compose** — Daxie in the same container as (or
   alongside) an agent.
3. **Kubernetes** — containerized agents with config from ConfigMaps,
   secrets from Secret mounts, and persistent state on PVCs. Pods restart;
   nothing may depend on process lifetime.

Requirements:

- **[DECIDED]** **State is split into four classes with independently
  configurable paths** (XDG defaults locally; env/flag overrides:
  `DAXIE_CONFIG`, `DAXIE_KEYSTORE`, `DAXIE_STATE_DIR`, `DAXIE_CACHE_DIR`):
  - **config** — read-only at runtime (K8s: ConfigMap mount). No Daxie
    operation may *require* writing config; mutating commands
    (`network use`, `rpc add`, …) fail with a clear error on read-only
    config rather than breaking signing paths.
  - **keystore** — key material (K8s: Secret mount or PVC).
  - **state** — tx journal, nonce tracking, policy file, **daily-spend
    counters** (K8s: PVC). Must survive restarts: a pod restart that
    reset spend counters would let an attacker bypass daily limits by
    crashing the pod.
  - **cache** — disposable (emptyDir/tmpfs).
- **[DECIDED]** **Crash-safe journaling:** the journal records a pending
  entry *before* broadcast, so a process killed mid-send does not
  double-broadcast on restart. All state writes are atomic
  (write-temp + rename + fsync). `tx wait` / `receive` are stateless and
  resumable by design — restart and re-run.
- **[DECIDED]** **Concurrency:** file locking on journal/nonce/spend
  state so parallel `daxie` invocations on one host are safe. **Single
  writer per account** is the documented rule: two replicas signing with
  the same key will collide on nonces — scale agents by giving each its
  own account, not by replicating pods behind one key.
- **[DECIDED]** **Secrets in K8s:** keystore passphrase via
  `DAXIE_PASSPHRASE_FILE` (Secret mount) or env (secretKeyRef); the
  existing `${env:}`/`${file:}` reference scheme covers RPC keys and mTLS
  certs as Secret mounts. The **admin passphrase is never deployed to
  agent pods** — policy administration happens out-of-band (operator
  workstation, one-off Job).
- **[DECIDED]** **Policy file integrity:** the policy file is
  sealed under the admin passphrase, so editing it directly on the
  volume (bypassing the CLI) is detected and signing halts. *(Amended at
  design time — this bullet originally said "MAC-sealed with a key
  derived from the admin passphrase". A symmetric MAC cannot deliver the
  guarantee: any MAC key the agent-facing process can read to verify
  with is a key a compromised agent can re-seal a tampered policy with.
  The seal is an admin-passphrase-derived **Ed25519 signature**; agent
  hosts verify against a public key pinned in operator-owned read-only
  config (K8s ConfigMap; operator-owned file locally) — never in
  agent-writable state and never bound to the keystore passphrase, which
  the agent holds. Missing pin or missing/unverifiable policy file fails
  closed. Supersession recorded in the Open Questions Log, #22.)* The
  threat model must be explicit about the residual gap: spend
  *counters* are maintained by the agent-facing process and cannot be
  sealed the same way — true tamper-proof enforcement requires a
  privilege boundary (file ownership or a future signer daemon), which
  the design should note as the v2 hardening path.
- **[DECIDED]** **Container hygiene:** static binary (`CGO_ENABLED=0`),
  runs as non-root with a read-only root filesystem (writes only to the
  declared state/cache paths), graceful SIGTERM (flush journal, exit
  resumable), logs/progress to stderr, no TTY or OS-keychain assumptions.
- **[DECIDED]** MCP transport: **v1 is stdio only**; the network
  transport (`daxie mcp serve --transport http`, streamable HTTP) is the
  **first post-v1 milestone (v1.1)**, bringing the K8s sidecar/service
  pattern and the Helm chart with it. The v1 internal design must
  accommodate it from day one (transport-agnostic MCP layer; auth hooks
  reserved).
- **[DECIDED]** **Helm chart: yes, gated on the HTTP transport.** With
  stdio-only MCP there is no standalone service to deploy (Daxie lives in
  the agent's container — v1 ships example Compose/K8s manifests in
  `docs/deploy/` for that pattern instead). When
  `mcp serve --transport http` lands, an in-repo chart (`charts/daxie`,
  published to an OCI registry per release, mirroring witwave's
  `release-helm` pipeline) deploys Daxie as a **wallet/signing service**:
  keys in the Daxie pod, agents holding only an access credential —
  which is precisely the signer-daemon privilege boundary named as the
  v2 hardening path. Chart security defaults are non-negotiable:
  authn between agent and service (bearer token or mTLS), default-deny
  NetworkPolicy, no Ingress by default, non-root/read-only-rootfs pod
  security context, keystore + state on PVC/Secret per the §7a state
  classes.
- Example Compose and Kubernetes manifests ship in `docs/deploy/`.

### 8. Distribution & Release

Model the release pipeline on the **witwave `ww` client**
(`witwave-ai/witwave`, `clients/ww`):

- **[DECIDED]** **goreleaser v2** builds multi-platform archives —
  darwin/linux/windows, amd64 + arm64 — and publishes GitHub Releases with
  checksums. (Homebrew and install.sh cover macOS/Linux; Windows users get
  the release archive, with scoop/winget manifests as a later addition.
  The keystore design must handle Windows paths/permissions.)
- **[DECIDED]** **Homebrew** via `homebrew_casks:` (not the deprecated
  `brews:` block) pushing to a tap repo (`daxchain-io/homebrew-daxie`),
  using a fine-grained PAT (`HOMEBREW_TAP_GITHUB_TOKEN`) since the default
  `GITHUB_TOKEN` can't push across repos.
- **[DECIDED]** **Universal curl installer**: an `install.sh` published as
  a release asset, following witwave's `scripts/install.sh` pattern —
  `--version`/`--channel`/`--prefix`/`--dry-run`/`--uninstall` flags,
  SHA256 verification by default, optional cosign signature verification,
  sudo-less fallback to `~/.local/bin`.
- **[DECIDED]** **OCI image** published per release (GHCR), multi-arch
  (amd64/arm64), minimal base (distroless/scratch — the static binary
  allows it), tagged + `latest`, cosign-signed like the binaries. This is
  the unit of deployment for the Docker/Kubernetes contexts (§7a).
- **[DECIDED]** Signed releases (cosign), given this is a wallet — supply
  chain integrity is a feature, not a nice-to-have.
- Version embedding via ldflags; `daxie version` reports
  version/commit/date.

### 9. Quality Bar

- Unit tests for all wallet/crypto logic; integration tests against a local
  devnet (e.g., anvil) in CI.
- **[DECIDED]** CI: GitHub Actions, mirroring witwave's workflow layout.

### 10. Deliverables Expected from the Design Session

1. Architecture overview: package layout following the one-core/two-
   frontends rule (§1a), signer and chain-client interfaces.
2. v1 command tree with flags and example invocations (human + JSON modes).
3. v1 MCP tool surface (names, schemas, how guardrails apply).
4. Key management design + threat model (including MCP-initiated signing).
5. Config schema (file, env, flags).
6. Release pipeline plan (goreleaser config outline, tap repo, install.sh).
7. v1 milestone cut: what's in, what's deferred.

---

## Open Questions Log

| # | Question | Section | Status |
|---|----------|---------|--------|
| 1 | Custody model for v1 | §5 | **decided** — encrypted local keystore (BIP-39/44, geth-compatible) |
| 2 | Agent signing policy controls | §5 | **decided** — basic guardrails in v1 (spend limits + allowlist). **Amended at design time:** limits are configured via the admin-authenticated `daxie policy` commands, not via Viper config/env — the original "configured via Viper" wording is superseded by #13 (admin secret) + #22 (sealed policy file); `daxie config get|set|list` excludes policy keys. **Further amended:** v1 limit denomination is ETH-only (native value + gas — no price oracle), so token/NFT amounts are never converted against the limits; token spend paths must pass the allowlist and **fail closed** (refuse) when limits are configured but no allowlist is, absent an explicit admin-acknowledged override — per-asset limits are the deferred item that closes the gap |
| 3 | v1 networks | §2 | **decided** — mainnet + Sepolia presets, others via config |
| 4 | v1 asset scope | §2 | **decided** — ETH + ERC-20 + ERC-721 + ERC-1155 |
| 5 | RPC provider strategy | §6 | **decided** — public defaults + user-supplied RPC URLs |
| 6 | Ethereum library | §3 | **decided** — go-ethereum |
| 7 | Windows builds | §8 | **decided** — yes, all platforms via goreleaser |
| 8 | Profiles/multi-wallet in v1 | §7 | **decided** — multiple named wallets; full profiles later |
| 9 | MCP server: separate wrapper or in-repo | §1a | **decided** — same repo, same binary (`daxie mcp serve`) |
| 10 | Positioning | §1 | **decided** — agent-first: "the Ethereum wallet for AI"; UTXO chains out of scope |
| 11 | Token/NFT discovery | §2 | **decided** — local registry + bundled majors; indexer later (pluggable) |
| 12 | Tx history source | §4 | **decided** — local journal of Daxie-originated txs; indexer later |
| 13 | Policy mutation protection | §5 | **decided** — separate admin passphrase, withheld from agents |
| 14 | Passphrase granularity | §5 | **decided** — per keystore |
| 15 | Address book | §4 | **decided** — `daxie contacts` in v1; `--to` and allowlist take contact names |
| 16 | Name collisions | §4 | **decided** — wallets + standalone accounts share one namespace |
| 17 | RPC failover | §6 | **decided** — single default + `--rpc` override; no auto-failover in v1 |
| 18 | `--network` / `--rpc` separation | §6 | **decided** — strictly separate |
| 19 | Confirmation waiting | §4 | **decided** — `--wait`/`--confirmations`/`--timeout` on all broadcasting commands; per-network defaults; distinct exit codes for confirmed/reverted/timeout |
| 20 | Inbound receive command | §4 | **decided** — `daxie receive` blocks until funds/token/NFT arrive + confirm; `--new` derives a fresh invoice address; JSON event stream |
| 21 | Gas handling | §4 | **decided** — cast-style estimation defaults + speed presets; explicit 1559 flags; policy-level gas caps; `tx speedup`/`tx cancel`; no blobs in v1 |
| 22 | Container/K8s deployment | §7a | **decided** — four state classes with separate paths; crash-safe journal; durable spend counters; signature-sealed policy file (**amended at design time:** the original "MAC-sealed" wording is superseded — the seal is an admin-passphrase-derived Ed25519 signature verified against a verify-key pin in operator-owned read-only config; a MAC key readable by the agent host would be re-forgeable by a compromised agent, and so would any pubkey binding keyed by the keystore passphrase); OCI image; single-writer-per-account rule |
| 23 | MCP network transport for K8s | §7a | **decided** — v1 is stdio-only; HTTP transport is the v1.1 fast-follow (with the Helm chart) |
| 24 | Helm chart | §7a | **decided** — yes, but gated on HTTP transport (#23); v1 ships example manifests; chart deploys Daxie as a wallet/signing service with hardened defaults |
| 25 | Token/NFT aliasing | §2/§4 | **decided** — registry names are local per-network aliases (anti-spoofing: never resolved via on-chain symbols); NFT collections + individual NFTs (`collection#id`) aliasable |
| 26 | Competitive-gap features | §4/§5 | **decided** — v1 adds message sign/verify (EIP-191/712), ENS with allowlist pinning, token approve/allowance/revoke under policy, keystore passphrase rotation |
| 27 | Ergonomics | §4 | **decided** — default account, positional name args, `--qr`, `daxie convert` |
| 28 | Testnet faucet | §4 | **decided** — deferred; document manual faucet URLs |
