# Daxie — Canonical Design

> **What this is.** The single canonical engineering design for **Daxie — the
> Ethereum wallet for AI**: a Go CLI wallet with a built-in MCP server, agent-first
> by mandate. It is the authority for architecture, key management, the policy
> engine, the transaction pipeline, the MCP tool surface, configuration and local
> data, the threat model, the release/CI pipeline, and the v1 milestone cut.
>
> **Inputs.** This document is bound by two specifications it does **not** restate
> in full and never contradicts: [`docs/requirements.md`](requirements.md) (the
> 29 resolved `[DECIDED]` items + the Open Questions Log) and
> [`docs/cli-spec.md`](cli-spec.md) (the v1 command tree, the account-reference
> grammar, and the JSON/exit-code output contract). Where requirements delegated a
> detail to the design session (default timeouts, per-network confirmation counts,
> ETH-arrival detection, `--amount` semantics, secret-input precedence, KDF
> parameters, the seal construction), this document **decides it**, with the
> rationale, and records the call in §11.
>
> **Provenance.** Produced by a reviewed multi-agent design session: nine verified
> parts (architecture, key management, policy, transaction pipeline, MCP server,
> configuration, threat model, release pipeline, milestone plan) were synthesized
> and **reconciled to the Architecture section (§2)**. Every terminology, package,
> type, file-path, exit-code, and config-key conflict between parts was resolved in
> favor of §2 and rewritten in place; the load-bearing reconciliations and the two
> places the corpus *improved* on the original architecture are recorded in §11.
> No part contributes a contradicting second version of any fact.
>
> **Status:** ready to build. Nothing below is TBD.

---

## Table of contents

1. [Overview & design goals](#1-overview--design-goals)
2. [Architecture](#2-architecture)
3. [Key management & custody](#3-key-management--custody)
4. [Policy & guardrails engine](#4-policy--guardrails-engine)
5. [Transaction pipeline](#5-transaction-pipeline)
6. [MCP server](#6-mcp-server)
7. [Configuration & local data](#7-configuration--local-data)
8. [Threat model](#8-threat-model)
9. [Release & CI pipeline](#9-release--ci-pipeline)
10. [v1 milestones & build order](#10-v1-milestones--build-order)
11. [Design decision log](#11-design-decision-log)

---

## 1. Overview & design goals

Daxie is **agent-first**. Audiences in priority order (requirements §1):

1. **AI agents** (primary) — autonomous agents that hold an Ethereum identity and
   transact. They drive Daxie two ways: the CLI (non-interactive flags/env/stdin,
   `--json`, deterministic exit codes, no required TTY) and the **built-in MCP
   server** (`daxie mcp serve`). Unattended signing, spend-limit guardrails,
   destination allowlists, JSON-everything, and an in-binary MCP server all exist
   for this audience. When human convenience and agent safety/scriptability
   conflict, resolve in the agent's favor.
2. **CLI-native humans** (secondary) — an agent-grade wallet is automatically a
   good scriptable human wallet; human-readable output is the default at a TTY.

**Scope (requirements §2).** EVM-only, Ethereum mainnet + Sepolia in v1, other EVM
chains addable via config (chain ID + RPC URL). Assets: ETH, ERC-20, ERC-721,
ERC-1155 — balances, ownership, transfers. Custody is an encrypted local keystore
(BIP-39/32/44, geth-compatible scrypt JSON). The MCP server is the same binary,
calling internal Go packages directly.

**Design goals, in priority order.** These shape every decision in §§2–10:

- **One core, two thin frontends (requirements §1a).** All wallet logic lives in
  internal packages behind one service API; the Cobra and MCP frontends are thin
  adapters. Business logic cannot live in a frontend — it is *structurally*
  prevented (§2.2). Guardrails therefore apply identically to CLI- and
  MCP-initiated signing because both traverse one chokepoint.
- **Agent safety over convenience.** Spend limits, destination allowlists, an
  admin/agent privilege split (two distinct secrets), and a fail-closed posture
  on every integrity boundary.
- **Survive the deployment evolution with zero core changes.** v1 ships
  workstation + container + stdio-MCP; the design must accommodate the v1.1 HTTP
  transport and the v2 signer-daemon privilege boundary as *additions and provider
  swaps*, never refactors (requirements §7a).
- **Determinism, decimal-exactness, crash-safety.** No float near value math; all
  durable writes atomic; spend counters and the tx journal survive restarts.
- **Supply-chain integrity is a feature** (requirements §8): reproducible builds,
  cosign signatures from the first tag, SBOM + provenance.

The full command tree and the account-reference grammar live in
[`cli-spec.md`](cli-spec.md) and are not duplicated here; this document references
them and records the refinements the design session made to them (§5.6, §6.8, §11).

---

## 2. Architecture

**Design lens: the composed service core, governed by minimal-abstraction
discipline.** The core is a single *composed* `service.Service` object with an explicit
lifecycle (`Open` → use → `Close`). The CLI is a short-lived host for one instance;
`daxie mcp serve` is a long-lived host for the *same* instance; the v1.1 HTTP
signer-daemon is a third — the core never learns which host runs it. An interface earns
its place **only** if it has a named second implementation or is a security-critical test
seam; otherwise the struct stays concrete. Three commitments fall out, each justified by a
§7a-named milestone (and each paid for in §2.9's trade-offs, not speculatively):

1. **The core API is wire-able from day one** — every request/result struct is
   JSON-serializable, every user value crosses as a *string*, every error carries a
   stable machine code. The CLI, MCP, and v1.1 HTTP frontends are all ~30-line binders
   over the *identical* structs. Refactoring a wallet API after agents depend on it is how
   you ship a breaking change to people holding keys.
2. **The core is concurrency-safe in v1** — the dangerous code (nonce + spend counters +
   journal) is made safe for concurrent use *now* (per-account serialization of the sign
   path; everything else stateless or read-mostly), so the MCP server and the HTTP daemon
   need no hardening pass.
3. **The privilege kernel is concrete code behind the service boundary, not a named
   interface** — policy-check → reserve-spend → reserve-nonce → journal-pending → sign is
   orchestrated by one private method, `service.authorize`, running policy *in core, ahead
   of* `domain.Signer`. The v1.1+ relocation into a separate process lands on the
   `domain.Signer` line (already an interface) + a remote-policy adapter — not on a
   standalone `Authorizer` abstraction (§2.7, §2.10).

### 2.1 Package tree

```text
github.com/daxchain-io/daxie

cmd/
  daxie/              main() ONLY: install SIGTERM/SIGINT handler, inject
                      ldflags version, call cli.Execute(ctx). ~25 lines.

internal/
  ── frontends (thin hosts; binding code only, zero business logic) ──
  cli/                Frontend 1 — Cobra tree, one file per noun (tx.go,
                      wallet.go, account.go, …). Parses flags/env/stdin into
                      service request structs, opens the service, renders the
                      result. Owns TTY passphrase prompting and the SINGLE
                      typed-error → exit-code table (render.go, §5.7).
    render/           Human tables, --json marshaling, terminal QR, stderr
                      progress rendering of domain.Event, NDJSON for receive.
  mcpserver/          Frontend 2 — MCP server assembly over the SAME service
                      instance. Transport-agnostic: a Server built once, served
                      over whatever transport the host hands it. Maps the SAME
                      typed errors to MCP tool-error payloads.
    tools/            One typed handler per tool; binds tool args → service
                      request struct → service call → tool result. Input schemas
                      are *inferred from the service request structs*.

  ── the core (composition root + every use case + cross-cutting types) ──
  service/            THE core. The `Service` struct (composition root); one
                      method per use case (SendTx, Balance, Receive, SignMessage,
                      Approve, …); the concrete privileged sequence (authorize →
                      broadcast → settle/abort); the gas-fee strategy;
                      reservation↔journal reconciliation. Takes time only via the
                      injected clock; all real I/O is in providers — determinism
                      is structural (the AST guard, §2.3).
  domain/             Cross-cutting value types shared by service + both
                      frontends: AccountRef, Asset, Dest, TxRequest, TxResult,
                      WaitOpts, Amount, Duration, Principal, Event, Error + codes,
                      the Signer + Unlocker interfaces. Pure types + parsers; no
                      I/O; no geth *client* deps. This is the wire contract; the
                      ONE package a future SDK or the HTTP frontend imports. NO
                      float-typed field appears in any request/result/value type.

  ── providers (the leaves the core composes; each owns its own state) ──
  keys/               Keystore: BIP-39/32/44, geth-compatible scrypt v3 JSON,
                      wallet/account metadata index (meta.json), the shared alias
                      namespace, passphrase acquisition, rotation. Concrete struct;
                      satisfies domain.Signer via a thin adapter.
  chain/              chain.Client INTERFACE + JSON-RPC/WS implementation: Dial()
                      with custom headers / mTLS / chain-ID verification; nonce,
                      balance, estimate, SuggestFees (feeHistory + speed percentile
                      in ONE method, §5.4), call, send, receipt, log-filter,
                      subscribe. The single load-bearing test seam (§2.9).
  erc/                ERC-20/721/1155 mechanics: calldata builders (transfer,
                      approve, safeTransferFrom), Transfer-log parsers, metadata
                      reads (decimals/symbol/ownerOf/balanceOf). Stateless; takes a
                      chain.Client per call (§2.8). Concrete.
  ens/                Namehash + registry/resolver/reverse lookups; takes a
                      chain.Client per call; resolve-with-pin helper for the
                      allowlist. Concrete struct (the pin-refusal seam is the
                      chain.Client fake one layer down, §2.10).
  policy/             Guardrail engine: pure Evaluate(); EIP-2612/DAI/Permit2
                      typed-data recognizers; durable rolling-24h counters
                      (Reserve/Commit/Release/SettleActual). Concrete struct.
  policyseal/         scrypt admin-key derivation + HKDF + Ed25519 sign/verify of
                      the policy file (anti-rollback nonce); verify-key pin loaded
                      from operator-owned read-only config. Concrete.
  journal/            Crash-safe tx journal (append-only JSONL), nonce derivation,
                      durable daily-spend reservation linkage, per-account file
                      locks (via internal/fsx → gofrs/flock), source attribution
                      (cli|mcp|http). Concrete struct.
  registry/           Token / NFT-collection / individual-NFT / contact stores
                      (per-network JSON in STATE) + compiled-in bundled majors
                      (USDC/USDT/WETH/DAI). Concrete.
  config/             Viper wiring (config.toml + DAXIE_* + flags); the four
                      state-class paths; network + RPC-endpoint definitions;
                      ${env:}/${file:} secret-reference resolution. ALSO reads the
                      policy-anchor file directly (no Viper key — §2.7, §7.6).
                      Concrete.
  fsx/                The single durable-write + locking + permission helper:
                      WriteAtomic (temp+fsync+rename+dir-fsync; Windows
                      MoveFileEx path), sidecar-.lock flock convention (Lock/RLock),
                      CheckPerms (POSIX bits + fsGroup carve-out; Windows DACL).
                      No other package hand-rolls durable writes. Concrete.
  secret/             secret.Bytes — zeroing buffer, redaction on String/Marshal,
                      best-effort mlock/VirtualLock; plus the secret-acquisition
                      resolver (stdin/file/*_FILE-env/env/prompt precedence, §3.6).
                      Concrete.
  ethunit/            Pure unit math: parse/format eth/gwei/wei, decimal-aware token
                      amounts. No I/O, no floats. Concrete.
  abi/                ABI parse/encode/decode + positional-string arg coercion +
                      the calldata SELECTOR RECOGNIZERS. Wraps go-ethereum
                      accounts/abi (pure Go: keccak via golang.org/x/crypto/sha3,
                      math/big, reflect — touches NO secp256k1, so CGO_ENABLED=0
                      holds, J8/§9.4). Stateless concrete struct (abi.Codec); no
                      I/O, no chain dep — the contract-verb analogue of erc/ (§2.8).
                      Functions: ParseJSON, ParseSig, CoerceArgs, ParseLiteral,
                      PackCall, UnpackReturns/UnpackCalldata, PackEvent, UnpackLog,
                      ClassifySelector (the §4.2 raw-calldata recognizer source).
  version/            ldflags vars (Version, Commit, Date).

docs/deploy/          Example Compose + K8s manifests (Helm chart arrives with the
                      HTTP transport, v1.1).
.goreleaser.yml, scripts/install.sh, Dockerfile.release, .github/workflows/
```

> **Reconciliation note (the two factored-out helpers).** The original
> architecture sketch put atomic-write/lock primitives inside `journal` and named a
> `secret.Bytes` type without a host package; the configuration, keys, and policy
> parts independently converged on a shared **`internal/fsx`** for all
> durable-write/lock/permission mechanics and a shared **`internal/secret`** for the
> secret buffer + acquisition resolver. The canonical tree adopts both as named
> leaf packages — every other package does its file I/O through `fsx` and holds
> secrets in `secret.Bytes`, so the platform divergence (Windows) and the redaction
> discipline each live in exactly one place. Earlier drafts' `internal/atomicfile`,
> `keys.Buffer`, and `secret.Buffer` names are superseded by `fsx` + `secret.Bytes`
> (§11, D2).

**Interface count is deliberately small: two exported provider interfaces —
`domain.Signer` and `chain.Client` — plus one wire-contract package (`domain`).**
Everything else is a concrete struct. The two interfaces are the only ones with a
*named, committed* second implementation (Signer → HW/KMS/4337/remote-daemon,
requirements §5; chain.Client → WebSocket subscriptions and later indexer-backed
reads, requirements §4/§2) or that serve as the *universal test seam*
(chain.Client, §2.9).

#### 2.1.1 Interfaces deliberately rejected (and why)

An interface exists *only* for a named second implementation or a security test
seam. A more abstraction-happy design would add each of these; each is a concrete
struct instead.

| Tempting interface | Why it is a concrete struct |
|---|---|
| `service.Authorizer` (the privileged sequence as a named interface) | The privileged sequence already sits *behind the service API boundary* — only the broadcasting use cases call it and frontends can't reach providers. Running policy in core ahead of `domain.Signer` puts the whole kernel behind the boundary for free. The v1.1 daemon relocation falls on the `domain.Signer` line (already an interface) plus a remote-policy adapter, so no `Authorizer` interface is needed (§2.10). It would be indirection with exactly one implementation forever. |
| `keys.KeystoreBackend` | The second key *backend* is HW/KMS/4337, which lives behind `domain.Signer`, not behind the keystore. The keystore has exactly one impl forever. |
| `policy.Engine` (as an exported interface) | The "fuller engine" (requirements §5 future layer) extends this via an internal `[]Rule` slice, not a runtime-swapped impl. The extension seam is internal, not exported. |
| `journal.Store` | No second journal backend on any roadmap. Crash-safety is a property of the concrete struct. The indexer is a *read* path (future `Discovery`), not a journal swap. |
| `registry.Store` | One local registry. The indexer answers a *different* question ("what does this address hold on-chain?") and lands as a new `Discovery` interface when its second impl is built. |
| `ens.Resolver` | The ENS-pin-refusal test (a re-pointed name must refuse the send) is faked one layer down at `chain.Client` — the universal seam. An `ens.Resolver` interface would be a second mock for behaviour the `chain.Client` fake already exercises. |
| `abi.Codec` (the ABI codec + selector recognizers as an interface) | One concrete codec wrapping go-ethereum `accounts/abi`. No second impl on any roadmap; its determinism is a property of pure functions over bytes + types, table-tested against golden cast-encoded bytes (§2.9). The selector recognizers it exposes (`ClassifySelector`) are consumed by `policy` and `contract decode` — a shared concrete source, not a swappable seam. |
| Per-frontend `Renderer` interface | Output is two concrete functions (human, JSON) selected by a bool in `cli/render.go`; MCP always emits structured content. A bool beats an interface; there is no third renderer. |

One concession kept on purpose: the thin `domain` package. The v1.1 HTTP frontend
and any future Go SDK must import the wire types *without* importing `service`
(which transitively pulls in keys, chain, every provider). `domain` is the
import-light contract; `service` is the implementation that depends on it. Cost: one
extra package + a discipline rule (domain imports nothing internal). Benefit: the
API is a shippable library boundary the day the daemon lands.

### 2.2 Dependency rules — enforcing one core, two frontends

```text
            cmd/daxie
                │
                ▼
   cli ──────► service ◄────── mcpserver
    │   (frontends import only │  (cli imports mcpserver for the single
    │    service + domain)     │   `daxie mcp serve` wiring line)
    └────────────┐            │
                 ▼            ▼
              domain   ◄── everyone (the wire contract; imports nothing internal)
                              │
   ┌────┬────┬────┬───────┬───┼──┬────────┬───────┬──────┬──────┬──────┐
   ▼    ▼    ▼    ▼       ▼   ▼  ▼        ▼       ▼      ▼      ▼      ▼
 keys chain policy journal registry config secret fsx ethunit  erc   ens
        ▲ ▲    │
   ens ─┘ └─ erc          policy ──► policyseal       (config,keys,journal,policy ──► fsx/secret)
```

| Layer | Packages | May import |
|---|---|---|
| host/main | `cmd/daxie` | `cli`, `version` only |
| frontends | `cli`, `mcpserver` | `service`, `domain`, `version`, `ethunit` (output formatting) (and `cli`→`mcpserver` for one line) |
| core | `service` | `domain` + every provider |
| contract | `domain` | stdlib + go-ethereum *value* types ONLY (no internal pkg, no geth behavioral pkg) |
| providers | `keys` `chain` `erc` `ens` `policy` `policyseal` `journal` `registry` `config` `secret` `fsx` `ethunit` `abi` | `domain`, stdlib, geth; sanctioned edges: `ens→chain`, `erc→chain`, `policy→policyseal`, `policy→abi` (the calldata classifier delegates selector matching to `abi.ClassifySelector`), and `{config,keys,journal,policy,registry}→fsx`/`→secret`. `abi` is a pure leaf (imports `domain`, stdlib, geth `accounts/abi` only). |

**Rules (each machine-enforced):**

1. **Frontends import only `service` + `domain` (+ `version`, `ethunit`).** They
   cannot import any provider. Consequence: business logic *physically cannot* live
   in a frontend. The one-core/two-frontends law (requirements §1a) is structural,
   not aspirational.
2. **No provider imports `service` or any frontend.** Because `policy` cannot see
   `journal`, the reservation↔journal reconciliation (§5.1) is necessarily
   orchestrated by `service`, which sees both — the dependency rule *forces* the
   coordination into the one place that should own it.
3. **`domain` imports nothing internal**, and no geth *behavioral* package
   (`ethclient`, `keystore`, `accounts`, `rpc`) — only geth *value* types
   (`common`, `big`, `apitypes`, `types`).
4. **Providers don't import each other**, except the sanctioned edges above.
5. **Viper appears only inside `config`.** `cli` binds pflags and hands a plain
   `config.Options` to `service.Open`. No config singleton, no `viper.Get` outside
   `config`. (Directly serves the requirement that the policy trust root live
   *outside* Viper resolution, §2.7.)
6. **The JSON contract is the core's request *and* result structs.** `cli --json`
   marshals results; `mcpserver` marshals the same results into tool results *and
   infers tool input schemas from the same request structs* (§6.2). Two machine
   surfaces, one definition — they cannot drift.

### 2.3 Enforcement is CI, not convention

A documented lattice, enforced by two CI gates:

**(a) The components/deps lattice** states the intent — the canonical statement of
the import rules, enforced by (b) and (c) below. (`go-arch-lint` once checked this
lattice directly, but it duplicated (c) and its `@latest` schema drifted, so it was
retired from CI; the lattice is kept here as the law it expresses.)

```yaml
# architecture lattice (intent) — enforced by depguard (b) + arch_test.go (c):
components:
  frontends: { in: internal/{cli,mcpserver}/... }
  core:      { in: internal/service/... }
  contract:  { in: internal/domain/... }
  providers: { in: internal/{keys,chain,erc,ens,policy,policyseal,journal,registry,config,secret,fsx,ethunit,abi}/... }
deps:
  frontends: { mayDependOn: [core, contract, version] }   # cannot reach providers
  core:      { mayDependOn: [contract, providers] }        # the only orchestrator
  contract:  { mayDependOn: [] }                           # imports nothing internal
  providers: { mayNotDependOn: [core, frontends] }         # leaves only
```

**(b) `depguard` in `.golangci.yml`** is the precise deny-list (a fast lint-time
belt to the authoritative matrix in (c)): the frontend rule denies every provider
import; the
`contract` rule denies all `internal/*` and geth behavioral packages; the providers
rule denies `service`/`cli`/`mcpserver` and `github.com/spf13/viper` (allow-listed
only in `config`).

**(c) Behavioral + AST gates.** `internal/arch_test.go` runs `go list -deps -json
./...` and asserts the same matrix, so the law holds even without the linters. A
second AST test scans `internal/service` and `internal/domain` and enforces
determinism by banning **wall-clock reads and non-deterministic I/O**, not the
`time` package itself:

- it fails if either package imports `os`, `net`, or `crypto/rand`;
- it walks call expressions and fails on `time.Now`, `time.Since`, `time.Until`,
  `time.After`, `time.Tick`, `time.NewTimer`, `time.NewTicker`, or `time.Sleep`; and
- it **permits** `time.Time` / `time.Duration` *type* references, because the core
  takes time only through the injected `clock func() time.Time` (§2.4) and
  `domain.Duration` wraps `time.Duration` as a value type.

The determinism ban targets `internal/service` and `internal/domain` only. **`internal/abi` is a provider, not core** — the keccak hashing it does for 4-byte selectors / 32-byte topics is allowed (it is pure computation over bytes, like every other provider's crypto), and it is therefore *not* subject to the `service`/`domain` no-`os`/no-`crypto/rand`/no-`time.Now` ban. Keeping the hashing in `abi` (a provider) rather than `service` is exactly why `service.EncodeCalldata`/`DecodeCalldata` can be pure use cases without tripping the guard.

Determinism is *structural and checkable* — a call-expression check, not reviewer
vigilance. The third gate is the frontend *parity* suite (§2.9): identical inputs
through both frontends must produce identical core call traces.

### 2.4 The Service façade (composition root + every use case)

There is one object that *is* the wallet. It is composed of injected providers (so
tests inject fakes and the daemon injects an HTTP-backed signer + remote policy), and
it has a lifecycle.

```go
package service

// Service is the composed daxie core. ONE per process for the CLI and the stdio
// MCP server; ONE per daemon for the v1.1 HTTP server. Safe for concurrent use (the
// sign path serializes per account; everything else is read-mostly or stateless).
type Service struct {
    signer   domain.Signer       // keys/ (or remotesigner/ in the daemon)
    chains   ChainProvider       // resolves req.Network+req.RPC -> chain.Client,
                                 // PER REQUEST (requirements §6: per-invocation override)
    policy   *policy.Engine      // CONCRETE; runs in core ahead of signer
    journal  *journal.Journal    // CONCRETE
    tokens   *registry.Tokens    // CONCRETE
    nfts     *registry.NFTs
    contacts *registry.Contacts
    ens      *ens.Resolver       // CONCRETE; takes chain.Client per call (§2.8)
    erc      erc.Ops             // concrete pure-fn namespace; chain.Client per call
    cfg      config.Resolved
    fees     FeeStrategy
    clock    func() time.Time    // the ONE injected time source (§2.3 AST guard)
}

// Open composes the service from resolved options. The ONLY thing that changes
// between CLI, stdio-MCP, and the v1.1 daemon is which providers Open wires in (a
// local vs. remote domain.Signer; a local vs. remote-proxy policy engine).
func Open(ctx context.Context, opts config.Options) (*Service, error)

// Close flushes the journal and releases file locks. Wired to SIGTERM so a killed
// container exits resumable (requirements §7a graceful shutdown).
func (s *Service) Close() error

// Every use case is shaped (ctx, Principal, Request, EventSink) -> (Result, error).
func (s *Service) SendTx(ctx, p domain.Principal, req domain.TxRequest, sink domain.EventSink) (domain.TxResult, error)
func (s *Service) WaitTx(ctx, p domain.Principal, req domain.WaitRequest, sink domain.EventSink) (domain.TxResult, error)
func (s *Service) Speedup(ctx, p domain.Principal, req domain.RBFRequest, sink domain.EventSink) (domain.TxResult, error)
func (s *Service) Cancel(ctx, p domain.Principal, req domain.RBFRequest, sink domain.EventSink) (domain.TxResult, error)
func (s *Service) Balance(ctx, req domain.BalanceRequest) (domain.BalanceResult, error)
func (s *Service) Receive(ctx, p domain.Principal, req domain.ReceiveRequest, sink domain.EventSink) (domain.ReceiveResult, error)
func (s *Service) SendNFT(ctx, p domain.Principal, req domain.NFTSendRequest, sink domain.EventSink) (domain.TxResult, error)
func (s *Service) Approve(ctx, p domain.Principal, req domain.ApproveRequest, sink domain.EventSink) (domain.TxResult, error)
func (s *Service) SignMessage(ctx, p domain.Principal, req domain.SignRequest) (domain.SignResult, error)
func (s *Service) SignTyped(ctx, p domain.Principal, req domain.SignTypedRequest) (domain.SignResult, error)
func (s *Service) Verify(ctx, req domain.VerifyRequest) (domain.VerifyResult, error)
func (s *Service) ResolveENS(ctx, req domain.ENSRequest) (domain.ENSResult, error)
func (s *Service) Gas(ctx, req domain.GasRequest) (domain.GasResult, error)
func (s *Service) AbandonTx(ctx, p domain.Principal, req domain.AbandonRequest) (domain.AbandonResult, error)  // daxie tx abandon
// + daxie contract — five use cases (only ContractSend is privileged):
func (s *Service) ContractCall(ctx, req domain.ContractCallRequest) (domain.ContractCallResult, error)            // READ; eth_call; never signs
func (s *Service) ContractSend(ctx, p domain.Principal, req domain.ContractSendRequest, sink domain.EventSink) (domain.TxResult, error) // SIGNS; reuses SendTx's authorize→broadcast→settle path
func (s *Service) ContractLogs(ctx, req domain.ContractLogsRequest) (domain.ContractLogsResult, error)            // READ; eth_getLogs; never signs
func (s *Service) EncodeCalldata(ctx, req domain.EncodeRequest) (domain.EncodeResult, error)                      // PURE; no chain, no signing
func (s *Service) DecodeCalldata(ctx, req domain.DecodeRequest) (domain.DecodeResult, error)                      // PURE; no chain, no signing
// + contract-registry admin (AddContract/ListContracts/ShowContract/RemoveContract) — same shape + state-class
//   read-only handling as the §7.8 token/nft/contact registry methods.
// + wallet/account/token/nft/contact/network/rpc/policy admin methods, same shape.
```

`Principal` (§2.5) is the *who*; the same parameter the HTTP daemon will fill from a
bearer token. In v1 it is always the local process. Passing it from day one means
the daemon does not add a parameter to every method — it just stops hard-coding it.

**`daxie contract` adds no new pipeline.** `ContractSend` resolves the ABI, coerces the positional args into raw calldata, builds a `domain.TxRequest` carrying that calldata + `--value`, and routes through the *identical* `authorize → broadcast → settle/abort` sequence (§2.7, §5.1) `SendTx` uses — so it inherits the policy chokepoint structurally and cannot route around it (§2.2 rule 2). The four read/pure verbs do not sign and so take neither `Principal` nor `EventSink`; `EncodeCalldata`/`DecodeCalldata` touch no provider that does I/O (the keccak hashing happens in the `abi` provider, satisfying the §2.3 guard on `service`). All five exist on the one façade so both frontends reach them through a single API.

> **Reconciliation note (package name).** Several parts referred to this composition
> root as `internal/core` / `core.Daxie` / `core.Signer`. The canonical name is
> `internal/service` / `service.Service` per the Architecture; the consumer-defined
> signer interface lives in `domain` as `domain.Signer` (§2.6). Every `core.*`
> reference in the provider parts maps as: `core.Daxie`→`service.Service`,
> `core.Open`→`service.Open`, `core.Signer`→`domain.Signer`, `core.Event`/
> `core.EventSink`→`domain.Event`/`domain.EventSink`, `core.Err`→`domain.Error`,
> `core.Options`→`config.Options`, `core.Principal`→`domain.Principal` (§11, D1).

### 2.5 Domain types (`internal/domain`)

The core accepts **user-level strings** and does all parsing/resolution itself. Both
frontends hand it strings anyway (flags; MCP JSON args), so parsing in core means it
happens once, identically. Request structs carry `json` + `jsonschema` tags because
they are **triple-duty**: the CLI flag-binding target, the MCP tool input-schema
source (§6.2), and the v1.1 HTTP request body.

**The drift hazard, and the rule that closes it.** MCP schema inference keys off Go
field *types*, not runtime JSON marshaling — so a field whose custom
`MarshalJSON`/`UnmarshalJSON` diverges from its declared type produces a *wrong*
schema. The rule: **every wire-facing field with a custom (Un)Marshaler carries an
explicit `jsonschema:"..."` override matching what it marshals to** (`Duration` →
`type=string,format=duration`), and a contract test (§2.9) round-trips each request
struct through both `MarshalJSON` *and* the inferred schema's validator to PROVE they
agree.

**Decimal-exactness is a compile-time property: no float-typed field exists in any
request, result, or value type.** ETH/gas amounts cross the boundary as strings and
are resolved to `*big.Int` wei in core; token amounts are decimal-aware integers
(base units + decimals). `float64` appears nowhere near value math.

```go
package domain

// ── account references (cli-spec §1) ──────────────────────────────────────────
type RefKind int
const (
    RefHDIndex RefKind = iota + 1 // treasury/3
    RefHDAlias                    // treasury/payroll
    RefNamed                      // ops-key (standalone; shares wallet namespace)
    RefAddress                    // 0x52ae…  (read-only ops only)
    RefENS                        // vitalik.eth (destinations + read-only)
)
type AccountRef struct {
    Raw    string
    Kind   RefKind
    Wallet string         // RefHDIndex/RefHDAlias
    Index  uint32         // RefHDIndex
    Name   string         // alias / standalone name / ENS label
    Addr   common.Address // RefAddress, or filled after resolution
}
func ParseAccountRef(s string) (AccountRef, error)

// Dest — a resolved destination with provenance, so policy can enforce ENS pins and
// output can echo what was resolved (requirements §4: always echo before signing).
type Dest struct {
    Input    string         `json:"input"`               // "vitalik.eth" / "exchange" / "0x.."
    Addr     common.Address `json:"address"`
    Via      string         `json:"via,omitempty"`       // "ens" | "contact" | "literal"
    ENSName  string         `json:"ens_name,omitempty"`
    PinValid *bool          `json:"pin_valid,omitempty"` // ENS allowlist pin check result
}

// Amount — user value as a STRING on the wire; resolved to wei (ETH/gas) or base
// units (tokens) inside core. NEVER a float; NEVER bare *big.Int on the boundary.
type Amount struct {
    Display string   `json:"display"`        // "0.5", "100"
    Unit    string   `json:"unit,omitempty"` // "eth"|"gwei"|"wei"; tokens use decimals
    Wei     *big.Int `json:"-"`              // resolved in core, never serialized raw
}

// Asset — resolution is ALWAYS through the local registry or a raw address
// (requirements §2: never via on-chain symbol — symbol spoofing is free).
type AssetKind int
const ( AssetETH AssetKind = iota; AssetERC20; AssetERC721; AssetERC1155 )
type Asset struct {
    Kind     AssetKind      `json:"kind"`
    Ref      string         `json:"ref,omitempty"`      // "USDC" | "punks#42" | "0x.."
    Contract common.Address `json:"contract,omitempty"`
    TokenID  *big.Int       `json:"-"`                  // 721/1155
    Decimals uint8          `json:"decimals,omitempty"`
    Symbol   string         `json:"symbol,omitempty"`   // local alias, NOT on-chain
}

// Duration — string JSON form ("5m"), because time.Duration marshals as int64
// nanoseconds. Every wire-facing use carries jsonschema:"type=string,format=duration"
// matching the marshaler, verified by the round-trip contract test (§2.9).
type Duration struct{ D time.Duration }
func (d Duration) MarshalJSON() ([]byte, error)   // emits "5m"
func (d *Duration) UnmarshalJSON(b []byte) error  // accepts "5m"
```

The full `TxRequest`/`TxResult`/`WaitOpts`/event structs and the error taxonomy are
in §5.2, §5.3, and §5.7 (they belong with the transaction pipeline they serve).

**`daxie contract` request/result types (§2.5 conventions — no float field; every user value a string, J4).** Args cross as `[]string` — positional, coerced **once** in core by the ABI (§2.3 "parse once"). Return/decoded values come back as **labeled string-typed** entries (a `uint256` exceeds int64; it is a decimal string, never a number — same rule as §6.2 amounts).

```go
package domain

// ABISource — resolution input; precedence enforced in core (registered alias's
// stored ABI > --abi/--abi-stdin JSON > inline --sig). Exactly one source must be
// resolvable for the named method/event; disagreement is usage.* (exit 2).
type ABISource struct {
    Alias   string `json:"alias,omitempty"`     // registry alias → stored ABI
    ABIJSON string `json:"abi_json,omitempty"`  // --abi file contents OR --abi-stdin (read by the frontend)
    Sig     string `json:"sig,omitempty"`       // inline "earned(address)(uint256)"
}

// DecodedValue — one labeled output/arg; Value ALWAYS a string (uint256 > int64;
// arrays/tuples → JSON-encoded string).
type DecodedValue struct {
    Name  string `json:"name,omitempty"` // ABI output name when present
    Type  string `json:"type"`           // solidity type, e.g. "uint256","bytes32[]"
    Value string `json:"value"`
}

// ── contract call (READ; eth_call; never signs) ──────────────────────────────
type ContractCallRequest struct {
    Contract string    `json:"contract" jsonschema:"alias, 0x address, or ENS of the contract"`
    Method   string    `json:"method,omitempty" jsonschema:"function name; omit when --sig carries it"`
    Args     []string  `json:"args,omitempty" jsonschema:"positional args as strings, coerced by the ABI"`
    ABI      ABISource `json:"abi,omitempty"`
    From     string    `json:"from,omitempty" jsonschema:"optional msg.sender (address/ENS/account ref); NOT a signer"`
    Block    string    `json:"block,omitempty" jsonschema:"block number or tag; empty = latest"`
    Network  string    `json:"network,omitempty"`
    RPC      string    `json:"rpc,omitempty"`
}
type ContractCallResult struct {
    Contract Dest           `json:"contract"`           // resolved + echoed (Dest, §2.5)
    Method   string         `json:"method"`
    Returns  []DecodedValue `json:"returns"`            // one per ABI output, labeled
    Block    *uint64        `json:"block,omitempty"`
    Network  string         `json:"network"`
}

// ── contract send (SIGNS; routes through §5.1 exactly like tx send) ───────────
type ContractSendRequest struct {
    Contract string    `json:"contract" jsonschema:"alias, 0x address, or ENS — the tx DESTINATION"`
    Method   string    `json:"method,omitempty"`
    Args     []string  `json:"args,omitempty"`
    ABI      ABISource `json:"abi,omitempty"`
    Value    string    `json:"value,omitempty" jsonschema:"msg.value, e.g. 0.5 (ETH); counts vs spend limits"`
    From     string    `json:"from,omitempty"`
    // gas/nonce/wait/dry-run/confirm — IDENTICAL to TxRequest so there is ONE gas+wait surface.
    GasLimit    string   `json:"gas_limit,omitempty"`
    MaxFee      string   `json:"max_fee,omitempty"`
    PriorityFee string   `json:"priority_fee,omitempty"`
    GasPrice    string   `json:"gas_price,omitempty"`
    Speed       string   `json:"speed,omitempty"`
    Legacy      bool     `json:"legacy,omitempty"`
    Nonce       *uint64  `json:"nonce,omitempty" jsonschema:"type=integer,minimum=0"`
    Network     string   `json:"network,omitempty"`
    RPC         string   `json:"rpc,omitempty"`
    DryRun      bool     `json:"dry_run,omitempty"`
    Confirm     bool     `json:"confirm" jsonschema:"default=false"` // the --yes gate; MCP default false
    Yes         bool     `json:"-"`                                  // CLI-only TTY skip; excluded from MCP schema
    Wait        WaitOpts `json:"wait,omitempty"`
}
// ContractSend returns the SAME domain.TxResult as SendTx (§5.2) — one result type
// for every broadcasting op.

// ── contract logs (READ; eth_getLogs; never signs) ───────────────────────────
type LogFilter struct {
    Name  string `json:"name"`
    Value string `json:"value"` // coerced to a 32-byte topic by the ABI (address args ref/ENS-resolved)
}
type DecodedLog struct {
    TxHash    string         `json:"tx_hash"`
    LogIndex  uint           `json:"log_index"`
    Block     uint64         `json:"block"`
    BlockHash string         `json:"block_hash"`
    Event     string         `json:"event"`
    Args      []DecodedValue `json:"args"` // indexed (topics) + non-indexed (data), labeled
}
type ContractLogsRequest struct {
    Contract  string      `json:"contract" jsonschema:"alias, 0x address, or ENS"`
    Event     string      `json:"event,omitempty" jsonschema:"event name; omit when --sig carries it"`
    ABI       ABISource   `json:"abi,omitempty"`
    Args      []LogFilter `json:"args,omitempty" jsonschema:"indexed-arg filters (name=value)"`
    FromBlock string      `json:"from_block,omitempty"`
    ToBlock   string      `json:"to_block,omitempty"` // empty = latest
    Network   string      `json:"network,omitempty"`
    RPC       string      `json:"rpc,omitempty"`
}
type ContractLogsResult struct {
    Contract Dest         `json:"contract"`
    Event    string       `json:"event"`
    Logs     []DecodedLog `json:"logs"`
    Network  string       `json:"network"`
}

// ── encode / decode (PURE; no chain, no signing) ─────────────────────────────
type EncodeRequest struct {
    Method string    `json:"method,omitempty"`
    Args   []string  `json:"args,omitempty"`
    ABI    ABISource `json:"abi,omitempty"`
}
type EncodeResult struct { Calldata string `json:"calldata"` } // "0x…"
type DecodeRequest struct {
    Calldata string    `json:"calldata" jsonschema:"0x… raw calldata"`
    ABI      ABISource `json:"abi,omitempty"` // --sig "stake(uint256)" or a registered/--abi ABI
}
type DecodeResult struct {
    Method   string         `json:"method"`
    Selector string         `json:"selector"` // "0x…" 4-byte
    Args     []DecodedValue `json:"args"`
}
```

**ABI resolution + arg coercion (plugs into §2.3 "parse once").** Core coerces `Args []string` **once**, in `service.Contract*`, via `abi.CoerceArgs`. The ABI *is the parser*: each positional string is coerced to the declared solidity type. `address`-typed params additionally accept **account refs / contacts / ENS** — resolved through the same `domain.ParseAccountRef` + `Dest` resolution as any `--to` and **echoed before signing** (§4 always-echo rule). Scalars: `uintN`/`intN` are decimal **or** `0x`-hex base-unit integers (**no implicit decimal scaling** — `daxie convert` does the 10^n math); `bool` = `true`/`false`; `bytes`/`bytesN` = `0x` hex (length-checked); `string` verbatim. Compound literals (one cast-compatible grammar in `abi.ParseLiteral`, type-directed recursive descent, pure, golden-tested against `cast calldata`): arrays `[a,b,c]`, tuples `(a,b,c)`, nesting allowed; a delimiter-containing element is double-quoted (`"a,b"`, with `\"`/`\\` escapes); `[]`/`()` are empty. A malformed literal is `usage.*` (exit 2) naming the offending arg index + expected type. **`call` requires return types** (`--sig` carries `(outputs)`, or the JSON ABI declares `outputs`); `send`/`encode` need only inputs; `decode` needs only the input shape.

### 2.6 Provider interfaces (the two that earn their keep)

```go
// ── domain.Signer — the future-proofed key boundary (requirements §5) ─────────
package domain

type Signer interface {
    // Resolve a parsed ref to an address WITHOUT unlocking (read-only ops).
    Address(ctx context.Context, ref AccountRef) (common.Address, error)
    // SignTx returns the RLP-encoded signed tx. Unlock material flows via Unlocker,
    // kept off this signature so a KMS/daemon signer implements the same interface
    // without a passphrase concept.
    SignTx(ctx context.Context, ref AccountRef, tx *types.Transaction, chainID *big.Int, u Unlocker) ([]byte, common.Hash, error)
    SignHash(ctx context.Context, ref AccountRef, hash common.Hash, u Unlocker) ([]byte, error) // EIP-191/712
}
// Unlocker is how a passphrase reaches the signer. The local keystore reads it; a
// KMS/daemon signer ignores it. This is why the daemon is a SWAP not a refactor.
type Unlocker interface{ Passphrase(ctx context.Context) (secret.Bytes, error) }
```

> **Reconciliation note (signer shape).** The keys part defined a 3-method
> `core.Signer` taking a plain `from common.Address` and no unlock method. The
> canonical signer is `domain.Signer` above: it takes a parsed `AccountRef` (so the
> keystore resolves wallet/index/alias/standalone, not a bare address) and threads
> unlock material through a separate `Unlocker`. Policy is **not** behind this
> interface and there is **no** `GuardedSigner` decorator — policy runs in `service`
> ahead of `Signer` (§2.7), which makes the v1.1 daemon a swap and gives identical
> CLI/MCP/daemon enforcement for free (§11, D1). Both shapes share the load-bearing
> property the keys part insisted on: no `Unlock` *method on the interface* and no
> passphrase concept a KMS backend can't satisfy — that lives in `Unlocker`.

```go
// ── chain.Client — RPC/chain ops (requirements §6); THE universal test seam ───
package chain

type Client interface {
    ChainID(ctx context.Context) (*big.Int, error)        // also the rpc-add/test guard
    Nonce(ctx context.Context, a common.Address, pending bool) (uint64, error)
    Balance(ctx context.Context, a common.Address, block *big.Int) (*big.Int, error)
    EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
    // SuggestFees folds eth_feeHistory + the --speed percentile math into ONE method,
    // so the gas/speed policy lives in exactly one place. Returns 1559 fees.
    SuggestFees(ctx context.Context, speed domain.Speed) (maxFee, priorityFee, baseFee *big.Int, err error)
    SuggestGasPrice(ctx context.Context) (*big.Int, error) // legacy chains
    CallContract(ctx context.Context, msg ethereum.CallMsg, block *big.Int) ([]byte, error) // backs `contract call`: --from→msg.From (Signer.Address, no unlock), --block→block (nil=latest)
    SendRawTransaction(ctx context.Context, raw []byte) (common.Hash, error)
    Receipt(ctx context.Context, h common.Hash) (*types.Receipt, error)
    BlockNumber(ctx context.Context) (uint64, error)
    BlockByNumber(ctx context.Context, n *big.Int, fullTx bool) (*types.Block, error) // receive ETH scan
    FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) // backs `contract logs` (abi.PackEvent builds Topics) and the §5.8 receive engine — no signature change
    SubscribeLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error)  // WS, v1.1
    SubscribeNewHead(ctx context.Context, ch chan<- uint64) (ethereum.Subscription, error)                          // WS; ErrNotSupported on HTTP
    Close()
}
// Dial applies chain-ID verification, custom headers, and mTLS from the resolved
// endpoint. Secret refs are resolved in-memory by service before dial, never
// persisted resolved. Subscribe* return a typed "unsupported" error on HTTP, which
// the receive loop falls back from to polling — no second interface.
func Dial(ctx context.Context, ep chain.Options) (Client, error)
```

### 2.7 The privileged sequence — policy in core, ahead of the signer

This is the most important orchestration in the codebase: **the privileged sequence
is concrete code in `service`, not a named interface.** Policy runs *in core, ahead
of* `domain.Signer`, behind the service boundary that frontends cannot cross.
Everything the v2 hardening path wants to relocate behind a process boundary — policy
check, spend reservation, nonce reservation, journal-before-broadcast, sign, counter
commit — is sequenced inside the tx-shaped use cases (`SendTx`/`Approve`/`SendNFT`/
`Speedup`/`Cancel`) via one private helper, `authorize`. The one gasless
spend-equivalent (`SignTyped` on a recognized permit) takes a sibling non-tx gate,
`authorizeSignature`.

```go
package service

// authorize is the privileged kernel as concrete orchestration (NOT an exported
// interface). It evaluates policy, reserves spend + nonce, writes the PENDING journal
// entry, and signs — returning everything the caller needs to broadcast. The caller
// broadcasts (broadcast is NOT privileged: a signed tx is already authorized) and
// then calls settle or abort.
func (s *Service) authorize(ctx, p domain.Principal, intent Intent) (authorized, error)
func (s *Service) settle(ctx, a authorized, h common.Hash, st domain.TxStatus, gasWei *big.Int) error
func (s *Service) abort(ctx, a authorized, reason error) error

type authorized struct {
    raw         []byte        // signed RLP, ready to broadcast
    hash        common.Hash   // deterministic from raw; recorded BEFORE broadcast so
                             //   restart re-broadcasts the SAME tx instead of freeing the nonce
    nonce       uint64
    journalID   string
    reservation policy.Reservation
}
```

**EvalContext-prefetch-before-spend-lock.** Inside `authorize`, all network-derived
inputs — the resolved `To` address and the current base fee — are fetched *before*
taking the per-account spend flock, so a hung RPC never stalls other `daxie`
processes holding the lock. Ordering: resolve `To` + fetch base fee → **then** acquire
flock → evaluate policy → reserve. RPC latency is never serialized under the lock.

**Commit/Abort lifecycle.** Inside `SendTx` the spend reservation is released on *any*
build/sign/broadcast failure via a deferred abort, paired with §5.1 restart
reconciliation for the crash case:

```go
func (s *Service) SendTx(ctx, p domain.Principal, req domain.TxRequest, sink domain.EventSink) (domain.TxResult, error) {
    // … resolve, gas, build intent …
    a, err := s.authorize(ctx, p, intent) // policy → reserve → nonce → journal-pending → sign
    if err != nil { return domain.TxResult{}, err }
    committed := false
    defer func() { if !committed { _ = s.abort(ctx, a, errIncomplete) } }() // releases the reservation
    h, err := s.broadcast(ctx, a.raw)
    if err != nil { return domain.TxResult{}, err }
    // … wait (optional) …
    if err := s.settle(ctx, a, h, status, actualGasWei); err != nil { return … }
    committed = true
    return res, nil
}
```

The `defer`-abort makes "exactly one of settle/abort runs" a structural guarantee for
the *live* process; the §5.1 reconciliation handles the *crashed* process.

**The gasless policy path — `authorizeSignature`.** A gasless EIP-712 signature has
no nonce, no broadcast, no journal entry, so it cannot traverse the tx-shaped kernel.
But EIP-2612 `Permit` and similar spend-equivalents must be "policy-checked like
approvals" (requirements §4), so `SignTyped` runs a slimmed, non-tx
policy-evaluation path that mirrors the approvals check WITHOUT the tx machinery:

```go
func (s *Service) authorizeSignature(ctx, p domain.Principal, t *apitypes.TypedData, from common.Address) error {
    check, isSpend := s.policy.ClassifyTypedData(t)  // recognizes Permit/Permit2/DAI
    if !isSpend { return nil }                       // ordinary off-chain msg (SIWE, order) — not gated in v1
    check.Account = from                             // check.Dest is the PERMIT SPENDER
    d, err := s.policy.Evaluate(ctx, check)          // allowlist + fail-closed + unlimited gate
    if err != nil { return err }
    if !d.Allowed { return &domain.Error{Code: d.Code, Msg: d.Reason} }
    return nil
}
// SignTyped: parse → authorizeSignature (REFUSE here) → signer.SignHash.
```

This reuses `policy.ClassifyTypedData` + `policy.Evaluate` and refuses *before*
`signer.SignHash`. It lives in `service` ahead of `domain.Signer` exactly like
`authorize`, so the v1.1 daemon relocation covers it on the same two seams. Because
EIP-2612 amounts are not ETH-denominated and v1 has no price oracle, the
spend-equivalent guarantee is delivered (as for token approvals) via the **spender
allowlist** + the fail-closed rule (§4); per-asset limits are deferred.

**The sealed policy file (requirements §7a, OQ #22).** The policy file is sealed
with an **admin-passphrase-derived Ed25519 signature** (scrypt KDF in `policyseal`)
over canonical policy bytes that include a monotonic `Nonce`. The verify key + KDF
salt + nonce high-watermark are pinned together in a machine-only anchor file
(`$DAXIE_CONFIG_DIR/policy-anchor.json`) in the **config** state class — read
*directly* by `config`, with **no Viper key, no `DAXIE_*` env var, no flag** able to
reach it. Load refuses `nonce < watermark` (`policy.rollback`) exactly like a bad
signature. A symmetric MAC is rejected on purpose: any MAC key the agent host can read
to *verify* is a key a compromised agent can re-seal a tampered policy with — the
asymmetry of Ed25519 is the point. Full mechanics in §4.5–§4.6.

**Residual gap, stated plainly (requirements §7a demands this).** Spend *counters*
are maintained by the agent-facing process, so they cannot be sealed the way the
policy *rules* are. A compromised agent that gains write access to the STATE volume
could reset its own day counter. The Ed25519 seal protects the *limits and
allowlist*; it does not protect the *counter*. True tamper-proofing requires the
privilege boundary — file-ownership separation in v1 where the platform allows, or the
v1.1+ signer daemon. **This is precisely why the privileged sequence is one concrete
kernel behind the service boundary: the v2 fix is "move this code and its providers
across a process boundary," wired at `service.Open`, not a refactor.**

### 2.8 Per-request endpoint binding (`ens`, `erc`)

`ens.Resolver` and `erc.Ops` are stateless concrete structs that take a
`chain.Client` **per call**, not at construction. Requirements §6 lets every
invocation (and every MCP/HTTP request) choose its network + RPC endpoint, so
`service` resolves the request's `chain.Client` from `ChainProvider` (from
`req.Network`/`req.RPC`) and passes it in. One composed resolver/ops serves all
networks; the per-request endpoint is a parameter, not constructor state.

```go
package ens
type Resolver struct{}
func (r *Resolver) Resolve(ctx, cc chain.Client, name string) (common.Address, error)
func (r *Resolver) Reverse(ctx, cc chain.Client, a common.Address) (string, error)
// ResolvePinned returns ErrPinChanged if the name now resolves differently from the
// allow-time pin (requirements §4). The pin-refusal TEST SEAM is the chain.Client fake.
func (r *Resolver) ResolvePinned(ctx, cc chain.Client, name string, pinned common.Address) (common.Address, error)

package erc
type Ops struct{}
func (Ops) TransferCalldata(to common.Address, amount *big.Int) []byte           // pure, no network
func (Ops) ApproveCalldata(spender common.Address, amount *big.Int) []byte
func (Ops) SafeTransferFromCalldata(from, to common.Address, tokenID, amount *big.Int) []byte
func (Ops) Decimals(ctx, cc chain.Client, token common.Address) (uint8, error)   // client per call
func (Ops) Symbol(ctx, cc chain.Client, token common.Address) (string, error)
func (Ops) BalanceOf(ctx, cc chain.Client, token, owner common.Address) (*big.Int, error)
func (Ops) OwnerOf(ctx, cc chain.Client, nft common.Address, tokenID *big.Int) (common.Address, error)
func (Ops) ParseTransfers(logs []types.Log) ([]Transfer, error)
```

### 2.9 Testing seams

**The architecture's payoff is its testability.** Because the two provider interfaces
are injected into `service.Open` and the rest are concrete structs driven against temp
dirs, the entire pipeline is unit-testable, and only the providers that *touch the
chain* need integration tests. The principle is **concentrate the fakes**:
`chain.Client` is the single load-bearing test seam, so the bulk of pipeline tests
need exactly one hand-written fake. The entire fake surface of the codebase is a
handful of small hand-written files (chiefly `chain/fake`, plus a deterministic test
signer) — no mock framework.

Per-seam inventory (each unit under test maps to a single faked dependency):

| Under test | Single faked dependency | What it proves |
|---|---|---|
| `service.*` use cases (full pipeline) | `chain/fake` + deterministic test signer; concrete policy/journal/registry against temp dirs | gas resolution order, ENS-pin refusal, fail-closed token rule, authorize→broadcast→settle, defer-abort releases the reservation on failure, wait/reverted/timeout status mapping, restart reconciliation, prefetch-before-lock ordering. No network. |
| **Frontend parity** | recording `Service` mock; drive the same request through `cli` (cobra `ExecuteC`) and `mcpserver` (in-memory pipe) | the one-core/two-frontends law is *behavioral*: identical core method + identical request struct. Catches logic that sneaks into a frontend. |
| `domain` parsers | none (table-driven) | `ParseAccountRef`, Amount/Duration (un)marshal, asset-ref parsing, the error-code↔exit-code table. |
| **render stream routing** | none (capture stdout+stderr) | `send`/`wait` progress → **stderr** never stdout; `receive` NDJSON → **stdout** with the address up front and the terminal `complete`/`timeout` line carrying `Exit`; `confirmed` lines per-transfer and non-terminal. |
| **schema↔marshaling contract** | none (per request struct) | each request struct round-trips through both `MarshalJSON` AND the inferred MCP schema's validator, asserting they AGREE. |
| `policy` engine | none (pure) + temp dir for counters | per-tx/per-day limits, gas-cap refusal, allowlist, fail-closed when limits set & no allowlist, EIP-2612/Permit2 classification + permit-spender gate, RBF gas accrual, seal round-trip, anti-rollback (nonce < watermark refused). |
| **spend-counter window rollover** | injected `clock func() time.Time` | the rolling-24h window boundary tested WITHOUT sleeping — set the clock, reserve, advance, assert debits age out. |
| `journal` crash-safety | temp dir + injected fault points | the explicit state machine: kill-while-RESERVED → safe abort + nonce freed; kill-while-SIGNED/BROADCAST → re-broadcast SAME bytes (idempotent), nonce stays consumed until mined or definitively replaced; atomic temp+rename+fsync (POSIX) / `MoveFileEx(REPLACE_EXISTING\|WRITE_THROUGH)` (Windows); file-lock contention; counter durability survives "restart". Runs on Windows CI. |
| `keys` | real crypto, known vectors | BIP-39/32/44 (Trezor vectors); geth keystore round-trip both directions; namespace-collision rejection; passphrase rotation crash matrix; Windows DACL perm check. |
| ENS allowlist pinning refusal | `chain/fake` returning X at allow-time, Y at send-time | re-pointed name → distinct `policy.denied.pin_drift` until re-allowed. |
| gas estimation/fees | `chain/fake.SuggestFees`/`EstimateGas` | speed presets, ×multiplier, max-fee headroom, `--max-gas-price` refusal at a spiked base fee. |
| `secret.Bytes` | none | zeroing, redaction in Marshal/String, no secret in logs. |
| `ethunit` | table tests | eth/gwei/wei + token-decimal parse/format exactness (no float drift). |
| `erc` calldata | golden ABI-encoded bytes | transfer/approve/safeTransferFrom match cast/foundry output byte-for-byte. |
| `registry` aliasing | temp dir | case-fold rules, per-network isolation, collision-requires-`--name`, never on-chain symbol resolution. |
| `policyseal` | generated keypair | Ed25519 sign/verify; tampered policy → fail-closed; wrong/missing pin fails closed. |
| `config` secret-refs | env + temp files | `${env:}`/`${file:}` resolved in-memory, never persisted; literal-secret heuristic warns; read-only-config enforcement. |
| `fsx` | temp dir, 3-OS CI | `WriteAtomic` yields old-or-new never torn (incl. under an open reader on Windows); sidecar-lock contention; `CheckPerms` fsGroup carve-out. |

**Shared port contract-test suites.** For `chain.Client` and `journal` a shared
contract-test suite runs against BOTH the real adapter and the fake, so the fakes used
in core unit tests cannot drift from real behavior. The same pattern covers `keys`
(real geth v3 round-trip vs. the deterministic test signer).

**anvil integration tests (CI, real EVM).** The real `chain` impl against a local
anvil devnet covers what fakes can't: `tx send --wait` confirmed/reverted/nonce
sequencing; `tx speedup`/`tx cancel` (real mempool replacement); ERC-20/721/1155
transfer + approve against deployed fixtures; `receive` ETH (balance/block poll) and
token/NFT (Transfer log filter); `sign typed` Permit + on-chain `permit()`; ENS
resolve/pinning against a deployed mock registry; `rpc test` chain-id verification;
gas `--speed` presets and `--max-gas-price` refusal *at a spiked base fee*; and an
**MCP smoke test** that drives the SAME anvil scenario through the OTHER frontend
(`daxie mcp serve` over stdio) and asserts identical on-chain effects — the executable
proof of one-core/two-frontends.

### 2.10 Where the v1.1 evolution plugs in — no refactor

Each step of the §7a evolution is an *addition* or a *provider swap*, never a core
change:

| v1.1+ capability | What changes | What does NOT change |
|---|---|---|
| **HTTP MCP transport** | `mcpserver` gets a transport switch: `mcp.NewStreamableHTTPHandler` instead of `StdioTransport`. The `Server` is built once and transport-agnostic. | The tool set, every handler, every `service` method, `domain`, every provider. |
| **Auth on the HTTP transport** | A `PrincipalFunc(r *http.Request) (domain.Principal, error)` wired as middleware (empty chain in v1). It fills the `Principal` already threaded through every method. | Every `service` signature already takes `Principal`. Zero new params. |
| **Signer daemon / privilege boundary** (v2) | New `internal/remotesigner` implements `domain.Signer` over HTTPS; a remote-policy adapter stands in for `policy.Engine`'s call sites; `service.Open` wires both when `opts.AuthorizerURL != ""`. | The concrete `authorize` sequence and its call sites; counters, journal-before-broadcast, sign — all already behind the boundary. |
| **KMS / hardware signer** | New `domain.Signer` impl with a no-op `Unlocker`; `service.Open` selects by config. | `SignTx`/`SignHash` callers; the keystore stays a peer impl. |
| **Helm chart as wallet/signing service** | Ships with the HTTP transport; pod runs `daxie mcp serve --transport http`; chart bakes the non-negotiable defaults (authn, default-deny NetworkPolicy, no Ingress, non-root/read-only-rootfs, PVC/Secret per state class). | The binary, the four-state-class model, the SIGTERM-resumable lifecycle. |
| **RPC failover / priority ordering** | `ChainProvider` gains ordered endpoints; `Dial` is already per-endpoint. | `chain.Client`; every caller. |
| **Indexer-backed history / discovery** | New `Discovery` interface behind registry reads; `journal.List` stays the local-tx source. | The concrete registry; the interfaces designed as seams now. |

The single mechanism that makes all of this work is the uniform method shape —
`(ctx, Principal, Request, EventSink) → (Result, error)` with JSON-serializable
Request/Result — plus the privileged kernel behind the service boundary on the two
relocation seams (`domain.Signer` + the policy call sites).

### 2.11 State placement (the four classes, requirements §7a)

The core knows nothing of paths; it gets constructed providers from `service.Open`,
which reads resolved `config.Options` (paths in §7.3).

| Class | Providers | Path source | Read-only-tolerant? |
|---|---|---|---|
| config | `config` (+ the policy-anchor file, read directly, no Viper key) | `DAXIE_CONFIG` (XDG) | yes — mutating cmds (`network use`, `rpc add`) fail clean with `config.read_only` |
| keystore | `keys` | `DAXIE_KEYSTORE` | reads only at runtime; metadata mutations (`account use/derive/alias`, `receive --new`) fail `keystore.read_only` on a Secret mount |
| state | `journal` (tx journal + nonce + durable spend reservations), sealed `policy.json` + counters, `registry` (tokens/NFTs/contacts) | `DAXIE_STATE_DIR` (+ `DAXIE_REGISTRY_DIR`) | must be writable (durable — a reset counter would bypass daily limits) |
| cache | ENS/metadata/feeHistory caches | `DAXIE_CACHE_DIR` | disposable (emptyDir/tmpfs) |

The policy verify-key **pin** is read from operator-owned *config* (ConfigMap), never
from agent-writable *state*, and is reachable by *no* Viper key, env var, or flag
(§2.7, §4.6).

---

## 3. Key management & custody

This section owns the on-disk keystore (geth-compatible v3 JSON + a Daxie metadata
sidecar), BIP-39 generation/import, BIP-44 derivation, the wallet vs standalone-account
data model, where aliases and the default account live, keystore-passphrase
acquisition (interactive and unattended), the KDFs and their parameters (key material
**and** admin), atomic re-encryption (`keystore change-passphrase`), export guards,
memory hygiene, and Windows path/permission handling. It does **not** own the policy
engine, the sealed-policy file, or the spend counters (§4); the one seam it shares with
policy is the **admin passphrase KDF**, named here so the parameter choice exists in
exactly one place. All packages, types, file paths, and error codes are the canonical
ones from §2; where the keys part used `core.Signer`, `secret.Buffer`, `internal/signer`,
or `ERR_*` codes, those are superseded (§11, D1/D2).

### 3.1 Data model: wallet vs standalone account (cli-spec §1)

```go
package keys

// WalletID / standalone account ID are random UUIDv4, assigned at creation, never
// reused. Names are mutable metadata; the UUID is the stable identity, so a rename
// never rewrites a secret file.
type Wallet struct {
    ID         string               // uuid; also the secret-blob filename stem
    Name       string               // user-visible; shares ONE namespace with StandaloneAccount.Name
    CreatedAt  time.Time
    PathPrefix string               // "m/44'/60'/0'/0" — fixed in v1, stored for fwd-compat
    NextIndex  uint32               // monotonic allocator; never decremented, never reused
    Accounts   map[uint32]HDAccount // only *materialized* indexes (derived or aliased)
}
type HDAccount struct {
    Index     uint32
    Address   common.Address // cached plaintext (public) — list/balance need NO unlock
    Alias     string         // optional; unique within the wallet
    CreatedAt time.Time
}
type StandaloneAccount struct {
    ID        string
    Name      string         // shares the one namespace with wallet names
    Address   common.Address // cached plaintext
    KeyFile   string         // relative path: "accounts/UTC--…--<addr>"
    CreatedAt time.Time
}
```

Decisions baked in:

1. **HD accounts are metadata, not key files.** Deriving `treasury/3` writes only
   `meta.json`; the private key is re-derived from the encrypted mnemonic at signing
   time. Consequences: `account delete` on an HD account is a pure *forget* (the
   mnemonic still holds it); rotation re-encrypts a small bounded file set; there is
   exactly **one secret source of truth per wallet**. Trade-off accepted: HD accounts
   aren't individually visible to external geth/clef tooling — `account export` bridges
   the gap when a specific HD key must leave Daxie.
2. **Standalone accounts are stock geth v3 key files**, byte-for-byte
   (`UTC--<ts>--<addr>` naming, scrypt envelope). Point geth/clef at
   `<keystore>/accounts/` and it works.
3. **One namespace** for wallet names and standalone-account names (cli-spec §1,
   resolved Q5/Q16), enforced at create/import/rename time. Name grammar:
   `[a-z0-9][a-z0-9_-]{0,63}`. Stored case-sensitively, **collisions checked
   case-insensitively** (default macOS/Windows filesystems are case-insensitive).
   `/`, `#`, and `.` are **reserved** (they are the reference-syntax separators).
   Reserving `.` keeps "bare names are always unambiguous" true — `ops.key` would
   otherwise be captured by the ENS branch of `ParseAccountRef`. Creation also rejects
   any name matching the `0x`+40-hex address shape. Aliases follow the same grammar and
   additionally must **not be purely numeric** (would collide with an index).

### 3.2 Reference resolution — `domain.ParseAccountRef` + `keys` lookup

Parsing lives in `domain` (§2.5, `ParseAccountRef` → `AccountRef` with a `RefKind`).
`keys` provides the *lookup* that turns a parsed ref into a signer or an address. The
split that matters for correctness — **source/signing positions** (`--from`,
`--account`, exports) vs **destination/read-only positions** (`--to`, `policy allow`,
`--spender`, balances) — is an explicit context parameter so it cannot be skipped:

```go
func (s *Store) LookupSigning(ref domain.AccountRef) (Signable, error) // wallet/idx, wallet/alias, or standalone
func (s *Store) AddressOf(ref domain.AccountRef) (common.Address, error) // no unlock; read-only/destination
```

Resolution rules (canonical error codes `ref.not_found`, `ref.ambiguous`, §5.7):

1. `RefAddress` → raw address. **Read-only only**; a signing position rejects it.
2. `RefHDIndex`/`RefHDAlias` (`wallet/…`) → split once: left is a wallet name; right is
   all-digits (index) or an alias. Unknown wallet/index/alias each give a distinct
   `ref.not_found` message.
3. `RefENS` (contains `.`) → ENS — **destination/read-only only**; resolution is the
   `ens` package's job. Deterministic by construction: `.` is reserved out of local
   names, so a dotted ref is never a local object.
4. `RefNamed` (bare name) → **context-dependent**:
   - **Signing context:** exactly the keystore namespace. A bare *wallet* name is
     **not** a signing identity (a wallet has many addresses) — reject with a hint
     (`did you mean treasury/0?`). Contacts never resolve here.
   - **Destination context:** look up in **both** the keystore namespace (standalone
     accounts) **and** the contacts book (requirements §4 OQ #15 binds `--to` and the
     allowlist to contact names). Exactly one match → resolve; a match in **both** →
     hard `ref.ambiguous` naming both objects (never guess in a fund-routing position);
     no match → `ref.not_found`.

**Cross-namespace collision guard — best-effort at create, authoritative at resolve.**
`contacts add` rejects a name already held by a wallet/standalone; `wallet
create|rename`/`account import` reject a name already held by a contact. Because
contacts (state class) and the keystore (its own class) share no lock and no lifetime,
creation-time rejection cannot be airtight; the **authoritative** guard is the runtime
`ref.ambiguous` rule, which makes a collision unexploitable.

> **cli-spec amendment.** cli-spec §1's account-reference table omits a `<contact>` row
> even though `daxie contacts` promises contact names for `--to` and the allowlist. The
> destination-context rule above adds it (destination contexts only) plus the
> ambiguity/collision rules (§11, D11).

### 3.3 On-disk keystore layout

`$DAXIE_KEYSTORE` is a **self-contained directory for key material**: `tar czf
backup.tgz $DAXIE_KEYSTORE` under the lock is a complete key backup.

```text
keystore/
├── keystore.json          # manifest: format version, KDF defaults, passphrase verifier
├── meta.json              # sidecar: names, aliases, HD index map, default account
├── index.lock             # advisory sibling .lock (fsx flock convention); empty
├── wallets/
│   ├── 6f1c2e58-….json    # encrypted mnemonic blob (v3 envelope, daxie superset)
│   └── a3b9d0c1-….json
└── accounts/
    └── UTC--2026-06-12T09-21-33.000000000Z--52ae…   # stock geth v3 key files
```

**The policy verify-key pin and anti-rollback watermark do NOT live here** — they live
in the dedicated `policy-anchor.json` in operator-owned read-only **config** (§2.7,
§4.6, §7.6). An earlier draft put a `policy_pin` inside `keystore.json`; binding policy
freshness to the keystore would couple it to a secret the **agent holds**, defeating
the privilege separation. The keystore is self-contained for **key material**, with no
policy coupling (§11, D9).

**Locking and atomicity (via `fsx`, §7.9; requirements §7a).**

- All mutations (create/import/derive/alias/rename/rotate/delete/`account use`) take
  the exclusive sibling `index.lock`. **Reads are lock-free on POSIX** (every write
  goes through `fsx.WriteAtomic`, and POSIX rename is atomic against open readers); on
  Windows readers take a shared `fsx.RLock` (§7.9). The single exception is when
  rotation artifacts are present (§3.8 recovery protocol).
- **Windows divergence is owned by `fsx`, not by `keys`.** Directory fsync is skipped;
  rename-replace uses `MoveFileEx(MOVEFILE_REPLACE_EXISTING)` /
  `FILE_RENAME_FLAG_POSIX_SEMANTICS` with bounded retry on sharing-violation; lock-free
  readers retry transient `ERROR_ACCESS_DENIED` (a name in pending-delete during a
  concurrent rename). `keys` calls `fsx` and stays portable.
- **Secrets and metadata are separate files on purpose.** `meta.json` is read/written
  (for `account use`, derive, alias) without touching ciphertext; this also lets the
  two files carry different K8s mount permissions.
- Keystore dir `0700`; secret files `0600`; `meta.json`/`keystore.json` `0600` (the
  address list maps *your* identity to addresses — privacy-sensitive). Windows:
  owner-only DACL (§3.11).

**`keystore.json` (manifest).**

```json
{
  "daxie_keystore": 1,
  "created_at": "2026-06-12T09:21:33Z",
  "kdf_defaults": { "kdf": "scrypt", "n": 262144, "r": 8, "p": 1, "dklen": 32 },
  "verifier": { "crypto": { /* standard Web3 Secret Storage v3 `crypto` object */ } }
}
```

The **verifier** is 32 random bytes encrypted under the keystore passphrase in a
standard v3 envelope, written at keystore initialization. Two purposes: (1)
**fail-fast passphrase check** — a successful decrypt proves the passphrase without
touching any wallet (the canonical wrong-passphrase code is `keystore.bad_passphrase`,
§5.7); (2) **enforces one-passphrase-per-keystore** (requirements §5, OQ #14) — every
operation that *adds* encrypted material verifies first, so you cannot fork the
keystore onto a typo'd passphrase.

**First-init typo protection.** On the very first use (when the verifier is being
written) there is nothing to check against, so a typo'd passphrase would silently
*become* the keystore passphrase — and since `wallet create` emits the mnemonic once,
the operator could be unable to unlock the only copy. Both init paths therefore require
**confirmation before the verifier is written**: interactive double-entry, or
non-interactively a `--passphrase-confirm-stdin|file` / `DAXIE_PASSPHRASE_CONFIRM[_FILE]`
channel that must match (absent on first init → distinct `keystore.confirm_required`,
never a prompt hang). After the keystore exists the confirm channel is ignored. The
first `wallet create --json` echoes a non-secret **passphrase fingerprint** (a salted
hash, not the verifier salt or any KDF input) so an orchestrator can assert it matches a
re-derivation from its secret source.

**Wallet secret blob (`wallets/<uuid>.json`).** Reuses the geth v3 `crypto` envelope
**verbatim** via `keystore.EncryptDataV3`/`DecryptDataV3` (which roundtrip arbitrary
bytes, not a 32-byte key — deliberately not `EncryptKey`/`DecryptKey`, which validate
the plaintext as a curve key). The outer object is a marked superset (geth tools skip
it: it lives outside `accounts/` and has no `address` field). The decrypted plaintext is
a tiny JSON document parsed by a string-free decoder and zeroed after use:

```json
{ "v": 1, "mnemonic": "abandon abandon … about", "bip39_passphrase": "" }
```

- **Store the mnemonic *sentence* (NFKD-normalized), not the seed** — `wallet export`
  must print the words; the 64-byte seed is derived on demand. v1 generates and
  validates English-wordlist mnemonics only; import rejects bad checksums hard.
- **The BIP-39 "25th word" lives inside the encrypted payload** (`bip39_passphrase`):
  re-supplying it per signing op is unusable unattended. Its deniability value (against
  someone holding only the *paper* mnemonic) survives because on disk it sits under the
  keystore encryption like everything else. `wallet export` prints it under an explicit
  label alongside the words.

**`meta.json` (sidecar — names, aliases, default account).**

```json
{
  "daxie_meta": 1,
  "default_account": "bot/0",
  "wallets": {
    "6f1c2e58-…": {
      "name": "treasury", "created_at": "…", "path_prefix": "m/44'/60'/0'/0",
      "next_index": 4,
      "accounts": {
        "0": { "address": "0x52ae…", "created_at": "…" },
        "3": { "address": "0x9bd1…", "alias": "payroll", "created_at": "…" }
      }
    }
  },
  "accounts": {
    "0d4f…": { "name": "ops-key", "address": "0x77aa…", "file": "accounts/UTC--…--77aa…", "created_at": "…" }
  }
}
```

**The default account lives in `meta.json`, not config.** It references keystore objects
and must stay consistent under rename/delete (one lock, one transaction), and config is
read-only at runtime (requirements §7a) — `account use` writing config would break in
K8s by design. Resolution precedence for the active account: `--from`/`--account` flag >
`DAXIE_ACCOUNT` env > `meta.json` `default_account` (the `config.Options.Account` slot,
§7.7). **Aliases live here too** — they are keystore-object metadata and must travel
with a keystore backup (contacts and the token/NFT registry are *not* keystore metadata;
they live in `internal/registry` over the state class, §7.8).

**Read-only keystore consequences.** On a read-only keystore (K8s Secret mount), every
`meta.json` mutation fails `keystore.read_only`: `account use` (workaround:
`DAXIE_ACCOUNT`), `account derive`, `account alias`, and **`receive --new`** (which
allocates an index through the same `DeriveNext` path) — the last three with **no
workaround**. A Secret-mounted keystore is therefore a **static account set**: derive
and alias every account at provisioning time. Invoice-style deployments
(`receive --new`) must put the keystore on a **PVC**. `docs/deploy/` shows both shapes.

**Why `next_index`/aliases stay keystore-class even though that costs `receive --new` on
Secret mounts (a deliberate departure from §7a's state-class taxonomy).** §7a places
monotonic counters like nonce tracking in the *state* class, and `next_index` is
functionally a monotonic counter. But unlike a nonce, address freshness is a
**key-derivation invariant**: a wrong index derives a wrong, possibly already-used
address from the *same* mnemonic, so it must share the mnemonic's durability/backup unit.
A keystore restored *without* its paired state dir would silently reuse derivation
indexes — minting an "invoice" address already handed to a counterparty. A read-only
keystore failing closed with `keystore.read_only` is loud and recoverable (use a PVC);
silent index reuse is neither. The override is named, not silent (§11, D10).
**Restore-coupling is fail-closed:** the whole keystore dir (including `meta.json`) is
the backup unit, and on open `keys.Open` rejects a `meta.json` whose `next_index` is
*below* any materialized index (`keystore.derivation_watermark`).

### 3.4 Cryptography and KDF parameters

Two secrets, two independent scrypt derivations — one audited primitive, distinct
parameters and per-secret salts.

| | Keystore passphrase | Admin passphrase |
|---|---|---|
| Protects | key material at rest (mnemonics, raw keys) | policy mutations + policy-file integrity (requirements §5, §7a) |
| KDF | **scrypt** N = 262144 (2¹⁸), r = 8, p = 1, dkLen = 32; 32-byte random salt **per file** | **scrypt** N = 131072 (2¹⁷), r = 8, p = 1, dkLen = 32; 32-byte salt in `policy-anchor.json` |
| Why these | geth v3 compatibility is `[DECIDED]` — these are geth's `StandardScryptN`/`StandardScryptP` (~1 s, ~256 MiB peak) | one audited CGO-free KDF primitive across both secrets; the seal is operator-side and **rare** (~128 MiB, sub-second), and agents never derive it (they only verify the Ed25519 signature) |
| Cipher / auth | AES-128-CTR + Keccak-256 MAC (v3 spec) | Ed25519 signature over the sealed policy body bytes (mechanism in `policyseal`, §4.5) |
| Output use | derive 32-byte key; `[0:16]` = AES key, `[16:32]` MAC'd with ciphertext | scrypt root → HKDF-SHA256 domain-separated Ed25519 seed (§4.5) |

> **Reconciliation note (admin KDF).** An earlier keys draft proposed Argon2id for the
> admin seal. The canonical choice is **scrypt N=2¹⁷** (matching the policy section and
> the threat model), so both secrets run through one audited, CGO-free primitive;
> independence is preserved by distinct salts and params, not a distinct algorithm
> (§11, D4).

KDF parameters are **self-describing and per-file**: each v3 envelope carries its own
`kdfparams`; the admin scrypt salt+params live in the anchor. So a future parameter bump
is a per-file change `change-passphrase` upgrades — no format break. `keystore.json
.kdf_defaults` is the *template for new files only*. **Test escape hatch:**
`DAXIE_KDF_LIGHT=1` (scrypt N=4096) is honored **only when the keystore manifest was
created light**, so a production keystore can never be silently downgraded.

### 3.5 BIP-39 / BIP-44 flows

Derivation path: `m/44'/60'/0'/0/{index}` (cli-spec §1); `path_prefix` is stored per
wallet so a future `--path` flag is a metadata change, not a format change.
Dependencies are all pure Go (`CGO_ENABLED=0` is `[DECIDED]`): `go-ethereum`
(crypto/keystore/apitypes), `tyler-smith/go-bip39` (mnemonic generate/validate),
`btcsuite/btcd/btcutil/hdkeychain` + `chaincfg` (BIP-32/44; `chaincfg.MainNetParams`
supplies only the HD version bytes, which never reach the chain), `x/crypto/scrypt` and
`x/crypto/hkdf` (admin seal KDF, in `policyseal`), and `gofrs/flock` (via `fsx`).
go-ethereum's `crypto/secp256k1` is forced onto its pure-Go (`btcec`) path so
`CGO_ENABLED=0` links cleanly.

- **`wallet create <name>` `[--words 12|24]`:** verify (or initialize) the passphrase
  against the verifier (first-init confirmation, §3.3); 128/256 bits from `crypto/rand`
  → BIP-39 mnemonic; **display-once + recorded-it proof** (TTY: show once, clear-screen,
  require re-entry of two random word positions; non-interactive `--json --yes`: the
  mnemonic appears **once** in the JSON result with `"sensitive": true` and never again
  — not in logs, the journal, or any later command; the MCP surface has **no**
  `wallet create` tool, §6.1); encrypt the blob → `wallets/<uuid>.json`; update
  `meta.json`; **index 0 derived automatically** so a fresh wallet is usable as
  `<name>/0`.
- **`wallet import <name>`:** mnemonic via prompt/stdin/file (never a flag value),
  NFKD-normalize, checksum-validate, optional `--bip39-passphrase-*`. A gap-limit
  discovery scan is deferred; v1 imports derive indexes explicitly.
- **`account derive <wallet> [--index N] [--name alias]`:** allocates `next_index` (or
  validates an explicit `--index`), derives the address (one unlock), writes metadata
  only. `next_index` is monotonic and never reused after `account delete` (forget).
- **`receive --new`** calls the same allocator (`DeriveNext`), inheriting the
  read-only-keystore rule (§3.3).
- **`account import <name>`:** raw 32-byte hex key (prompt/stdin/file), validate it is in
  `[1, n-1]`, reject an address already present, encrypt to a stock geth v3 file under
  `accounts/`, register in `meta.json`.
- **Unlock-for-signing** (the `domain.Signer` impl, §3.10). HD: scrypt-decrypt the
  wallet blob → BIP-39 seed (string-free via `x/crypto/pbkdf2`) → hdkeychain master →
  derive `path_prefix/index` → btcec key → geth `*ecdsa.PrivateKey` → sign → zero the
  key + seed + plaintext. Standalone: geth `keystore.DecryptKey` on the v3 file → sign →
  zero. Caching for the long-lived MCP server is in §3.6.

### 3.6 Keystore-passphrase acquisition (interactive + unattended)

Requirements §5 (OQ #14) delegate the env/file/stdin precedence — decided here. One
resolver in `secret` serves the keystore passphrase; the same shape serves the admin
passphrase (§3.7) and the mnemonic/raw-key inputs, with per-secret flag names.

**Precedence — first present wins:**

| # | Source | Notes |
|---|---|---|
| 1 | `--passphrase-stdin` | explicit flag beats everything (Viper convention: flags > env) |
| 2 | `--passphrase-file <path>` | perms-checked (§7.9) |
| 3 | `DAXIE_PASSPHRASE_FILE` | **the recommended unattended channel** (K8s Secret mount, requirements §7a) |
| 4 | `DAXIE_PASSPHRASE` | supported, documented **least-safe** |
| 5 | interactive prompt | only if stdin is a TTY; hidden input |
| — | none + no TTY | a distinct **passphrase-required** error, distinct exit code, **never a prompt hang** |

> **cli-spec amendment (already folded into cli-spec).** cli-spec §1 originally listed
> "interactive prompt (default at TTY)" first; the design session inverted it — any
> explicit or ambient source beats the prompt, even at a TTY. **User-facing
> consequence, documented loudly:** if `DAXIE_PASSPHRASE`/`DAXIE_PASSPHRASE_FILE` is
> exported, you are **not** prompted, even at an interactive TTY (and a wrong one fails
> fast against the verifier). Rationale: env-beats-prompt is the established convention
> (`PGPASSWORD`, `sudo -A`); identical TTY/non-TTY behavior; deterministic error, never
> a hang (§11, D5).

**Trade-offs (verbatim in user docs):** *stdin* never touches disk or environment
(ideal for piping a secret manager) but composes badly with payload-on-stdin commands —
Daxie **errors rather than guessing** on a stdin conflict. *file* survives restarts,
fits Secret mounts, has auditable perms — the **recommended unattended channel**. *env*
is easiest but visible in `/proc/<pid>/environ`, inherited by children, and captured by
crash reporters — the last choice.

**File hygiene:** exactly one trailing `\n`/`\r\n` is stripped (K8s Secrets and `echo`
append one). Permission checks use the one unified `fsx.CheckPerms` rule (§7.9).

**Caching:** CLI one-shots read → use → `Zero()`, nothing cached. `daxie mcp serve`
(long-running) verifies the passphrase against the verifier **at startup** (fail fast at
boot, not on the first signing call) and holds it in an mlock'd `secret.Bytes` for the
process lifetime; decrypted HD seeds are cached after first use so each signing tool call
does not pay ~1 s of scrypt. Starting with **no** source
is allowed: read-only tools work; signing tools return the structured
passphrase-required error. A concurrent `keystore change-passphrase` invalidates the
cache mid-flight with a distinct **passphrase-stale** error (§3.8).

### 3.7 Admin passphrase — what keys owns, what policy owns

The admin passphrase (`[DECIDED]`, OQ #13) **never encrypts keys**. It authorizes
policy mutations and seals the policy file. Owned here: the **admin KDF and parameters**
(§3.4) and the **admin-passphrase acquisition** path (the same resolver shape as §3.6,
with flags `--admin-passphrase-stdin|file` and env `DAXIE_ADMIN_PASSPHRASE[_FILE]`,
never set in an agent environment). Owned by `internal/policy`/`policyseal` (§4.5):
the Ed25519 seal derivation, the sealed file, the nonce/watermark anti-rollback, and the
`policy-anchor.json` trust root. **The one cross-section invariant:** the admin secret
and the keystore secret are **independent** — distinct params and per-secret salts, so a
compromised agent holding the keystore passphrase gains *nothing* toward forging a seal
or raising a limit. This is the structural realization of the privilege separation
(requirements §5), and why the prior draft's "policy pin in `keystore.json`" was moved
out (§11, D9).

### 3.8 `keystore change-passphrase` — atomic re-encryption

Files under the keystore passphrase: the verifier + every wallet blob + every standalone
key file (bounded — typically under a dozen). A crash must **never** leave a
mixed-passphrase keystore. Two-phase, marker-committed; all writes via
`fsx.WriteAtomic`:

1. Take the exclusive `index.lock`.
2. Resolve + verify the old passphrase against the verifier; resolve the new
   (`--new-passphrase-stdin|file`, `DAXIE_NEW_PASSPHRASE[_FILE]`, or double-entry).
3. **Stage:** decrypt each secret file with the old passphrase, write its re-encryption
   (fresh salts/IVs) as `<file>.new`. Any decrypt failure aborts with nothing changed.
4. **Commit point:** atomic-write `ROTATE-COMMIT` listing every staged file. Before this
   the rotation has not happened; after, it is irrevocable.
5. **Swap:** rename each `X.new` → `X`, delete `ROTATE-COMMIT`, zero all plaintext.

**Crash recovery — run by `keys.Open` on every start, mutating only under the exclusive
lock** (no passphrase needed): scan for artifacts; if a marker is present roll
**forward** (finish renames), else if `.new` files exist roll **back** (delete them); if
the lock is held elsewhere, a rotation is in progress — touch nothing, readers proceed
lock-free against a consistent view. Reader races (ENOENT fallback from `X.new`→`X`;
a mixed-generation MAC failure that re-runs the artifact scan and retries once before
surfacing `keystore.bad_passphrase`) are part of the read protocol. A concurrent
`change-passphrase` under a running `mcp serve` invalidates the cached passphrase: a MAC
failure surviving the retry re-verifies the cached passphrase against the rotated
verifier and, if rejected, returns a distinct **passphrase-stale** error ("rotated under
a running server; restart with the new source"). **Documented rule: rotating the
keystore passphrase requires restarting `mcp serve`** — hot-reload would need a fresh
secret channel into a running process. The same machinery serves future KDF-parameter
upgrades (one tested code path).

### 3.9 Export guards

`wallet export` (mnemonic + 25th word) and `account export` (hex key):

| Guard | Decision |
|---|---|
| Passphrase | always freshly resolved — never satisfied by `mcp serve`'s cached unlock |
| Interactive confirm | TTY: red warning + type the wallet/account *name*; non-TTY: `--yes` required, else a distinct confirmation-required error |
| Output | **stdout only**; never written to a file path; JSON `{"mnemonic":"…","bip39_passphrase":"…","sensitive":true}`, never journaled, never logged |
| MCP | **no export/import tools exist in the MCP surface, period** (§6.1) — a prompt-injected agent must not exfiltrate key material through its tool channel; same for `keystore change-passphrase` and `policy *` mutations: administration is CLI-only |

**Honest trade-off (for the threat model).** Export guards stop *accidents and casual
prompt-injection*, not a principal that legitimately holds the keystore passphrase
**and** shell access — such an agent can copy the keystore files and decrypt offline
(threat model R1). Gating export behind the admin passphrase would be security theater
(the agent already has the keystore secret). The real fix is the v1.1/v2 signer-service
boundary, which `domain.Signer` is already shaped for. *(The threat model, §8.3 item 4,
additionally requires the admin passphrase on the CLI export ceremony as defense in
depth against the casual-injection case; that is an additive guard on the CLI path and
does not change the honest-limit analysis.)*

### 3.10 Memory hygiene, logging, errors

- **`secret.Bytes`** is the only container for secrets in Daxie-controlled code: heap
  `[]byte`, `Zero()` via a `crypto/subtle`-style loop + `runtime.KeepAlive`,
  `defer buf.Zero()` at every acquisition site. It implements `fmt.Stringer`,
  `fmt.GoStringer`, `slog.LogValuer`, and `json.Marshaler`, all returning
  `"[REDACTED]"` — an accidental `%v`/log/JSON of a secret is structurally harmless.
  `secret.Bytes.Reveal() []byte` is the single greppable escape hatch for the two
  commands that must emit real secret material (`wallet create --json`, the exports).
- **Honest scope of the no-`string` rule.** The *encrypt* side is `[]byte`-clean both
  paths (`EncryptDataV3`/`EncryptKey`); the only residual `string` surface is the
  *decrypt/validate* side (geth `DecryptDataV3`/`DecryptKey` take `auth string`;
  go-bip39 is string-only). Where the boundary is ours we remove it: the decrypted
  wallet plaintext is parsed by a custom string-free decoder, and the BIP-39 seed is
  derived string-free via `x/crypto/pbkdf2`.
- **Locked memory, best-effort:** long-lived buffers in `mcp serve` are mlock'd
  (`x/sys/unix`) / `VirtualLock`'d (`x/sys/windows`); a lock failure logs one warning.
- **Core dumps disabled** at process start on Unix (`Setrlimit(RLIMIT_CORE, 0)`);
  documented residuals (swap, kernel crash dumps, Windows WER) are not oversold.
- **geth key structs:** geth's zeroing helper is unexported, so Daxie zeroes
  `*ecdsa.PrivateKey` itself (`zeroECDSA`) immediately after the sign call returns.
- **Errors never carry secrets**; **logging** is structured slog to **stderr**;
  key-management code logs operation names and object names/addresses only.

### 3.11 Paths, permissions, Windows (requirements §7a, §8)

Default locations are per §7.3 (XDG on Linux/macOS; `%APPDATA%` for config, `%LOCALAPPDATA%`
for keystore/state/cache on Windows — **keys must never roam**). Permission enforcement
is the one unified `fsx.CheckPerms` rule (§7.9): any **world** bit or **group-write** is
a hard error; **group-read** is accepted silently iff the file's group is the process's
effective GID or a supplementary group (the K8s `fsGroup` case), else warned; Windows
inspects the **DACL** and refuses `Everyone`/`BUILTIN\Users`/`Authenticated Users` read.
Secret files and dirs are created with an explicit owner-only DACL via `x/sys/windows`;
lock files use `LockFileEx` on a sibling `.lock` (never the data file). Key-file names use
**lowercase** hex addresses (safe on case-insensitive filesystems).

### 3.12 The Signer seam (the §2.6 interface, satisfied)

`keys.Store` is wrapped by a thin adapter that implements `domain.Signer` (§2.6). Two
consequences honored here: (1) the signer is **stateless re: identity** — the parsed
`AccountRef` is the parameter, and there is **no `Unlock` method on the interface**;
unlock material flows through `domain.Unlocker`, so a future KMS/4337 backend has no
passphrase concept. (2) **Policy is not behind this interface** — it runs in `service`
ahead of `Signer` (§2.7), so every backend (local, hardware, remote daemon) is guarded
identically and "guardrails apply identically to MCP-initiated signing" is structural.
The v2 remote signer is a new `internal/remotesigner` package implementing the same
interface over HTTPS — keys never leave the signing pod, and policy already runs ahead of
`Signer`, so the daemon gets policy enforcement behind the privilege boundary for free.

---

## 4. Policy & guardrails engine

`internal/policy` is the **normative owner** of the guardrail engine, the policy-file
format and its seal (`internal/policyseal`), spend accounting, and the policy-denied
error model. It is the single chokepoint below both frontends: it is called by
`service.authorize`/`authorizeSignature` (§2.7), inside the only code that can reach
`domain.Signer`. There is no exported path that produces a signature without passing
through `policy` — that is how "guardrails apply identically to MCP-initiated signing"
(requirements §1a) is delivered **structurally**.

The package is a **pure** evaluation function plus an **impure** engine shell:

```go
package policy

// Evaluate is PURE: no I/O, no clock reads, no lock, no network. The entire rule set
// in one deterministic, table-testable function. The caller supplies the already-summed
// window total and the clock instant, so the window POLICY (rolling-24h, §4.1) lives in
// how the caller computes spentWindowWei — Evaluate compares numbers it is handed.
func Evaluate(p Policy, req Check, spentWindowWei *big.Int, now time.Time) Decision

// ClassifyTypedData is the pure EIP-712 recognizer set (§4.2). ok=false means "not
// spend-shaped" → the caller applies the typed-data gate (§4.3 stage 5).
func ClassifyTypedData(td *apitypes.TypedData) (checks []Check, ok bool)

type Engine struct { /* stateDir, anchor, counter store; flock sidecars */ }
func Open(stateDir string, a Anchor) (*Engine, error)

// Reserve: verify seal + anti-rollback nonce, load the account's window counter, run
// Evaluate, and — atomically under the per-account sidecar flock — append
// SpendWei+MaxGasWei as a persisted reservation {id, wei, state:"reserved"}. Two
// parallel sends cannot each pass a limit they jointly exceed. Deny ⇒ a typed
// *domain.Error (machine code, §5.7). Permit checks never reach Reserve (§4.4).
func (e *Engine) Reserve(req Check) (*Reservation, error)
func (r *Reservation) Commit(txHash common.Hash) error // broadcast ok: reserved → committed, bind hash
func (r *Reservation) Release() error                   // pre-signature local failure only (§4.4)
func (r *Reservation) ID() string                       // persisted; recorded in the journal entry

// SettleActual adjusts a committed reservation's gas component down from the pessimistic
// gasLimit×maxFee to gasUsed×effectiveGasPrice once a receipt is observed; if the receipt
// reverted, the value component is released too. Idempotent.
func (e *Engine) SettleActual(network string, from common.Address, txHash common.Hash, gasUsedWei *big.Int, reverted bool) error

// Orphan reconciliation — driven by service at Open (policy may not import journal).
func (e *Engine) Orphans(network string, from common.Address) ([]OrphanReservation, error)
func (e *Engine) ReleaseOrphan(id string) error
func (e *Engine) CommitOrphan(id string, txHash common.Hash) error

// Admin surface — separate secret, never held by the agent (requirements §5, §4.7).
func (e *Engine) Show() (Policy, error)                            // unauthenticated
func (e *Engine) Set(adminPass secret.Bytes, c Change) error       // verify → mutate → Nonce++ → re-seal → bump watermark
func (e *Engine) Allow(adminPass secret.Bytes, entry AllowEntry) error // pins ENS/contact addr at allow time (§4.8)
func (e *Engine) Deny(adminPass secret.Bytes, entry DenyEntry) error
func (e *Engine) InitSeal(adminPass secret.Bytes) (Anchor, error)  // first `policy set` bootstraps: salt + verify key + watermark 0
```

`adminPass` arrives as `secret.Bytes` (§3.10), never `string`. **Failure direction is
fail-closed:** if the policy file exists but its seal cannot be verified, or the anchor
is missing while a policy file exists, or the counter file cannot be locked/read/written,
signing is refused (`policy.seal_violation` / `policy.rollback` / `policy.state_error`).
If *no* policy has ever been initialized (no `policy.json` **and** no anchor), the engine
is a no-op allow — guardrails are opt-in (requirements §5). The asymmetric rule that
closes the "delete the policy to escape it" hole: **once an anchor exists, absence or
unverifiability of the policy file is itself a violation** — there is no "policy present
but no anchor" tolerated mode.

> **Reconciliation note (types).** The policy part used `policy.Request`/`signer.Signer`/
> `secret.Buffer`/`internal/core`. Canonically the engine's request type is `Check`
> (above; `policy.Request` → `policy.Check`), the signer is `domain.Signer`, the secret
> type is `secret.Bytes`, and the orchestrator that drives orphan reconciliation is
> `service` (§11, D1/D2).

### 4.1 Day-window semantics — rolling 24-hour window

`max_day_wei` means: **the sum of debits in any trailing 24-hour window never exceeds the
limit**, evaluated at authorization time as `sum(entries where ts > now − 24h) +
thisDebit ≤ max_day_wei`. A UTC calendar day is **rejected**: its midnight-burst hole —
spend `max_day` at 23:59 and again at 00:01 — hands an attacker **2× the limit in two
minutes on a schedule they choose**, the whole game against an unattended agent. The only
added cost is keeping timestamped debit entries (which RBF supersession, gas
reconciliation, and orphan reconciliation already require). This needs no architecture
change because `Evaluate(p, req, spentWindowWei, now)` is window-agnostic — the window
policy lives entirely in how the impure shell computes `spentWindowWei` (filter
`ts > now−24h`). When a daily-limit denial occurs, the engine computes the earliest
instant enough debits age out and returns it as `retry_after` (§4.9) — agents schedule
instead of poll.

> **Reconciliation note (one stray phrase fixed).** The transaction-pipeline part
> originally called this a "per-account UTC-day counter" (and spoke of "UTC rollover").
> The canonical semantic is **rolling-24h** (this section, the threat model §8, and the
> architecture all agree); the txpipeline phrasing is reconciled to rolling-24h here
> (§5, §11, D6). Clock source is the local wall clock; clock rollback is in the same
> residual trust domain as counter tampering (§8 R-clock) and is fixed by the same v2
> boundary.

**Limit scope.** Limits are **per network** (counters key on `chain_id`; Sepolia spends
never consume mainnet headroom; an explicit `"max_day_wei": null` per-network override
means "no limit on this network") and **aggregate across all accounts in the keystore on
a network**, not per account. The unit of compromise is the keystore passphrase — a
compromised agent signs with *every* account it can unlock — so per-account limits would
silently multiply the cap by the account count, exactly wrong for the multi-account
keystores requirements §7 promotes. *(Concurrency note: the aggregate-across-accounts
cap requires a per-`(network)` day lock held across read-sum-of-all-accounts + reserve,
or one network-scoped counter file under one lock; the single-account path is sound under
the per-account flock, and the multi-account aggregate is journal-detectable via
`policy verify` — tracked as residual R2a in §8.)* Per-account sub-limits, if ever added,
sit *under* the aggregate cap.

### 4.2 Request model and spend-equivalent recognizers

Every signing operation is decoded into a `policy.Check` before evaluation:

```go
type Kind int
const (
    KindTransfer Kind = iota + 1 // ETH / ERC-20 / ERC-721 / ERC-1155 send
    KindApprove                  // ERC-20 approve / revoke (spend-equivalent, requirements §4)
    KindPermit                   // EIP-2612 / DAI-style / Permit2 signature (spend-equivalent)
    // NO opaque KindContractCall is added: a Kind policy treats as "contents unknown"
    // would carry no spender/recipient/unlimited for the gates to read and would BE the
    // bypass. daxie contract send's calldata is classified into the three Kinds above or
    // denied (the §4.3 stage-5b unknown-calldata gate). See the reversed paragraph below.
)
type Check struct {
    Kind     Kind
    Network  string
    From     common.Address
    To       common.Address // recipient, or SPENDER for approvals/permits
    ToSource ToSource       // SourceRawAddress | SourceENS | SourceContact | SourceSelf
    ToInput  string         // exactly what the user typed: "vitalik.eth", "exchange", "0x…"
    ENSName  string         // non-empty when To came from an ENS name → stage-4 pin check
    // SpendWei is the ETH-denominated spend in WEI, and ONLY that: the native value of
    // an ETH transfer. nil for token/NFT amounts, approvals, permits. Token base units
    // are NEVER written here — no price oracle in v1, so a token amount must never be
    // compared against an ETH-denominated limit.
    SpendWei  *big.Int
    MaxGasWei *big.Int // gasLimit × maxFeePerGas — counts toward limits; nil for gasless permits
    GasPrice  *big.Int // effective max fee per gas, checked against --max-gas-price
    Asset     string   // "eth" | lowercase token/NFT contract address (display + future per-asset layer)
    TokenAmt  *big.Int // raw token base units (display only in v1)
    Unlimited bool     // unbounded approval/permit amount OR deadline
    Acked     bool     // explicit unlimited acknowledgment — CLI --unlimited --yes; MCP acknowledge_unlimited:true
    AccountNonce *uint64 // RBF supersession (§4.4): set on tx speedup / tx cancel
}
```

Decoding rules: the policy-relevant destination for ERC-20/NFT ops is the
**recipient/spender decoded from the calldata, never the token contract** (the contract
is identity-checked through the registry; the human-meaningful flow of value goes to the
recipient/spender). `tx cancel`/`tx speedup` build a `KindTransfer` carrying the
replacement's fields plus `AccountNonce`; they are re-evaluated against the *current*
policy and their spend accounting **supersedes**, not adds (§4.4).

**`daxie contract send` admits arbitrary user calldata, so the v1 surface no longer
builds *all* calldata itself.** Raw calldata can encode an ERC-20 `approve`, an ERC-721
`setApprovalForAll`, an EIP-2612 `permit` — the exact operations the typed paths wrap in
the spender-allowlist + unlimited-ack ceremony. Daxie therefore **classifies the calldata
before signing** rather than introducing an opaque kind. Before policy runs,
`ClassifyCalldata` (the raw-calldata sibling of `ClassifyTypedData`, below) inspects the
4-byte selector and, on a match to a known ERC-20/721/1155/Permit spend-equivalent,
**emits the same `KindApprove`/`KindTransfer` `Check` the typed path emits** — so it
traverses the **identical** stage-3 spender-allowlist, stage-3c fail-closed, and stage-6
unlimited-ack gates as `daxie token approve` / `tx send`. An **unrecognized** selector
(or short/undecodable calldata) is **not** given a new Kind; it falls to the new
deny-by-default **stage-5b unknown-calldata gate** (`contract_call.unknown`, §4.3), the
calldata analogue of `typed_data.unknown` — "I can't classify it" is never "harmless".
`--value` is ordinary `SpendWei` either way, and the contract address is the policy
destination (§5.11). **The conclusion "there is no `KindContractCall`" is kept — but for
the opposite reason:** not because no arbitrary calldata exists, but because all of it is
classified into the existing kinds or denied (the prior "no unclassifiable path"
assertion is withdrawn; §11 D12).

**Message signing × policy (requirements §4 demands this).**

| Signature request | Policy treatment |
|---|---|
| **EIP-191 `personal_sign`** (incl. SIWE) | **Allowed by default**; governed by the single `messages: "allow"\|"deny"` kill switch. The `\x19Ethereum Signed Message:\n` prefix makes the output unusable as a transaction or typed-data forgery; blocking it breaks SIWE for zero gain. Residual: a legacy protocol honoring personal-sign-prefixed payloads as fund-moving authorization is not value-checked → R5. |
| **Raw-hash signing** (`eth_sign`-style, no prefix) | **Not offered in v1 at all.** No command emits it; if ever added it is admin-gated blind-signing. |
| **EIP-712 recognized as spend-equivalent** | `KindPermit` — evaluated **exactly like an on-chain approval** (spender allowlist, unlimited gate, fail-closed no-allowlist rule). Permits carry no ETH, so no per-tx/per-day wei debit and they **do not reserve** (§4.4). Checked at *signature time*. |
| **EIP-712 not recognized** | The typed-data gate (§4.3 stage 5): `typed_data.unknown` (`deny` by default once a policy is active) plus an explicit per-domain allowlist. Unknown typed data is how Seaport listings, exchange withdrawals, and meta-tx relays move assets — "I can't parse it" is never treated as "harmless". |

**Spend-equivalent recognizers (the v1 set).** `ClassifyTypedData` matches on
`(primaryType, type-field shape, domain)` — **never** on the domain `name` string:

| Recognizer | Match | Extracted → `Check` |
|---|---|---|
| **EIP-2612 `Permit`** | `primaryType=="Permit"`, fields `owner,spender,value,nonce,deadline`; token = `domain.verifyingContract` | `To = spender`; `Unlimited` if `value == 2^256−1` or deadline is the max sentinel |
| **DAI-style `Permit`** | `primaryType=="Permit"`, fields `holder,spender,nonce,expiry,allowed` | `To = spender`; `allowed == true` ⇒ `Unlimited` |
| **Permit2** | `domain.verifyingContract == 0x000000000022D473030F116dDEE9F6B43aC78BA3` and `primaryType ∈ {PermitSingle,PermitBatch,PermitTransferFrom,PermitBatchTransferFrom}` | one `Check` per token/amount entry; service signs only if **all** pass |

Permit2 extraction is a fixed switch on `primaryType` (four shapes, four extractors); a
`PermitSingle.details.amount == 2^160−1` is unlimited (uint160 max), the
`PermitTransferFrom.permitted.amount == 2^256−1`, etc. Any shape mismatch returns
`ok=false` (falls to the deny-by-default typed-data gate), never a partial extraction. A
recognizer shape on a **different `chainId`** than the active network is denied
(`policy.denied.typed_data`, reason `chain_mismatch`) — a permit for chain 1 signed
"while on Sepolia" is a classic exfiltration trick.

**The raw-calldata classifier — `ClassifyCalldata` (the calldata twin of `ClassifyTypedData`).** Pure, in `internal/policy`, delegating selector matching to `abi.ClassifySelector` so the known-selector set is defined **once** and shared with `contract decode`/display. It decodes the leading 4-byte selector and, for recognized spend-equivalents, the minimum args needed to fill a `Check`:

```go
// `to` is the resolved CONTRACT address; `data` is selector||abi-encoded-args; `value`
// is msg.value (nil = 0).  ok==true → spend-equivalent Checks evaluated EXACTLY like the
// typed path (Permit2-batch calldata yields >1; service signs only if ALL pass).  ok==false
// → unrecognized: caller applies the §4.3 stage-5b contract_call.unknown gate (NOT harmless).
// A short selector (len(data)<4) or a recognized selector whose args fail to decode to the
// expected shape returns ok=false WITHOUT a partial Check — same fail-direction as
// ClassifyTypedData's shape-mismatch rule.
func (e *Engine) ClassifyCalldata(to common.Address, data []byte, value *big.Int) (checks []Check, ok bool)
```

| Recognizer | Selector (sig) | Extracted → `Check` |
|---|---|---|
| **ERC-20 `approve`** | `0x095ea7b3` `approve(address,uint256)` | `Kind=KindApprove`; `To=spender` (arg0); `Unlimited` if amount ∈ the §4.2 unlimited sentinels (`2²⁵⁶−1`, uint96/uint160 max); `Asset=to`; `TokenAmt=arg1` |
| **ERC-20 `increaseAllowance`** | `0x39509351` `increaseAllowance(address,uint256)` | `Kind=KindApprove`; `To=spender` (arg0); `Asset=to` |
| **ERC-20 `transfer`** | `0xa9059cbb` `transfer(address,uint256)` | `Kind=KindTransfer`; `To=recipient` (arg0); `SpendWei=nil` (token value, not ETH); `Asset=to`; `TokenAmt=arg1` |
| **ERC-20 `transferFrom`** | `0x23b872dd` `transferFrom(address,address,uint256)` | `Kind=KindTransfer`; `To=recipient` (arg1, destination of value); `Asset=to`; `TokenAmt=arg2` |
| **ERC-721/1155 `setApprovalForAll`** | `0xa22cb465` `setApprovalForAll(address,bool)` | `Kind=KindApprove`; `To=operator` (arg0); `Unlimited = (approved==true)` (operator-for-all is unbounded → takes the unlimited-ack ceremony); `Asset=to` |
| **ERC-721 `approve`** | `0x095ea7b3` (selector-collides with ERC-20 `approve`) | disambiguated by registry/ABI `kind` when known, else `KindApprove` `To=spender`, `Unlimited=false` — the conservative reading still routes through the spender allowlist |
| **ERC-721/1155 `safeTransferFrom`** | `0x42842e0e`, `0xb88d4fde` (721), `0xf242432a`, `0x2eb2c2d6` (1155 batch) | `Kind=KindTransfer`; `To=recipient` (arg1); `Asset=to`; value not ETH-denominated |
| **EIP-2612 on-chain `permit`** | `0xd505accf` `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` | `Kind=KindApprove`; `To=spender` (arg1); `Unlimited` if value(arg2) ∈ sentinels or deadline is max; `Asset=to` (a broadcast permit is an approval someone else's signature authorized → closes the "relay a permit via contract send" hole) |
| **DAI-style on-chain `permit`** | `0x8fcbaf0c` `permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)` | `Kind=KindApprove`; `To=spender` (arg1); `allowed(arg4)==true ⇒ Unlimited`; `Asset=to` |
| **Permit2** | `0x2b67b570`/`0x30f28b7a`/… on `0x000000000022D473030F116dDEE9F6B43aC78BA3` | `Kind=KindApprove`; `To=spender`; `Unlimited` per uint160/uint256 sentinel; multi-spend yields >1 Check |

Decode discipline mirrors `ClassifyTypedData`: match on the **4-byte selector + a successful ABI-decode of the argument shape**, never on a name string (the selector is a property of the *signed bytes*; a user-supplied ABI may lie). `To` is the **decoded spender/recipient**, never the contract. `Unlimited` uses the **same sentinels** as the typed path, so the `--unlimited --yes` / `acknowledge_unlimited` ceremony fires on an unlimited approval encoded as raw calldata exactly as on the typed path. Both the **contract address** (the tx `To`, for the destination allowlist, §5.11) and the **decoded spender** (the rewritten `Check.To`) are checked.

### 4.3 The evaluation pipeline

The service fetches every network-derived input **before** the spend-state lock (fresh
ENS resolution, current base fee), bounded by `rpc.timeout`, so the locked critical
section is local file I/O + pure computation only (§2.7 prefetch). Stages run in order;
1–2 abort immediately; 3–8 **all run and accumulate violations** so an agent gets the
complete fix list in one denial. The exit code/string is taken from the
highest-precedence violation (§4.9).

| # | Stage | Applies to | Denial code |
|---|---|---|---|
| 1 | **Seal & freshness** — load `policy.json`, verify the detached Ed25519 seal over the canonical body bytes against the anchor-pinned key; refuse if `body.Nonce < anchor.NonceWatermark`; anchor present + policy missing/unparseable ⇒ deny; policy present + anchor missing ⇒ deny; unknown body fields ⇒ deny | every signing op | `policy.seal_violation` / `policy.rollback` / `policy.version` |
| 2 | **Classification** — build `Check`(s); decode calldata / typed data. For `contract send`, run `ClassifyCalldata(to, data, value)` (§4.2): recognized selectors emit the same `KindApprove`/`KindTransfer` Checks the typed path emits and run stages 3–8 unchanged; `ok=false` (unrecognized/short/undecodable) routes to stage 5b. `--value` folds into `Check.SpendWei` here for **every** `contract send`, recognition-independent, so stages 6–8 see the ETH debit even on an unrecognized call. Undecodable calldata on a *typed* token/NFT path remains a hard deny | every signing op | `policy.unclassified` |
| 3 | **Denylist → allowlist → fail-closed no-allowlist** — (a) denylist match (pinned address, or contact/ens deny entry by name) ⇒ deny unconditionally (beats allowlist, beats `include_self`); (b) when `allowlist_enabled`, the resolved `To` (recipient or spender) must match a pinned address — one gate, uniformly across transfers/NFT sends/approvals/permits; own accounts pass when `include_self` against the **sealed `self_addresses` snapshot**, never the live keystore; (c) for token/NFT transfers and approvals/permits, if limits are set but `allowlist_enabled` is false ⇒ deny `policy.denied.no_allowlist` unless `tokens_no_allowlist_ok` is set under the admin passphrase. ETH transfers are exempt (the ETH limit caps them directly) | transfers, NFT sends, approvals, permits | `policy.denied.allowlist` / `policy.denied.no_allowlist` |
| 4 | **Pin drift** — if `ToInput` was an ENS name or contact, compare the fresh resolution (carried in pre-lock) to the allow-time pin | same as 3 | `policy.denied.pin_drift` |
| 5 | **Typed-data gate** — only for `sign typed` not matched by §4.2: unknown ⇒ `typed_data.unknown` (per-network override) + per-domain allow entries; chain mismatch ⇒ deny | sign typed | `policy.denied.typed_data` |
| 5b | **Unknown-calldata gate** — only for `contract send` whose selector `ClassifyCalldata` returned `ok=false`: once a policy is active, **deny by default** (`contract_call.unknown`), with a per-`(network, contract, selector)` allow registry (`contracts_allowed[]`) the operator opts triples into **under the admin passphrase** — the structural twin of the §4.5 `typed_data.allowed[]` registry. A recognized spend-equivalent never reaches 5b (it ran 3–8 as a typed op). The ETH gates (3a denylist, 3b/3c allowlist on the **contract address as destination**, 6 per-tx, 7 daily, 8 gas cap) on `--value` + gas still apply here a fortiori. There is **no `tokens_no_allowlist_ok`-style blanket override for arbitrary calldata** — the ack is per-triple, because one wrong arbitrary call's blast radius is unbounded | contract send | `policy.denied.contract_call` |
| 6 | **Per-tx limit** — ETH, for every broadcasting Kind: `SpendWei(0 if nil) + MaxGasWei(0 if nil) ≤ max_tx_wei`. Unlimited approvals/permits: denied unless `Acked` and the policy does not set `allow_unlimited:false` for that token | tx, approvals | `policy.denied.tx_limit` / `policy.denied.unlimited_unacked` |
| 7 | **Daily limit** — rolling-24h window sum + this request's ETH debit ≤ `max_day_wei`. The window accumulates native value **plus worst-case gas of every signed tx** | tx, approvals | `policy.denied.day_limit` |
| 8 | **Gas cap** — `GasPrice` ≤ `max_gas_price_wei`. **No silent clamping** (clamping under the market base fee produces stuck txs); the payload carries the current base fee so the caller distinguishes "fee spike, retry" from "my flags are wrong" | everything that broadcasts | `policy.denied.gas_cap` |

`--dry-run` and `daxie policy check` run stages 1–8 with no reservation and emit the
full violation list in JSON — agents pre-flight without burning a signing attempt. RBF
deadlock is documented behavior: if a stuck tx needs a ≥ +12.5% bump that exceeds the
gas cap, `tx speedup` is denied (the remediation is the operator raising the cap).

**`contract send` and the fail-closed-no-allowlist rule (a fortiori).** The stage-3c rule already refuses token/NFT/approval paths when limits are configured but `allowlist_enabled` is false. `contract send` is strictly broader — its calldata can move value the ETH limits cannot see — so the refusal binds *harder*: recognized spend-equivalent calldata inherits stage-3c verbatim (`policy.denied.no_allowlist`); unrecognized calldata to a non-allowlisted contract with limits set is refused unless the contract address is allowlisted **or** the `(network, contract, selector)` triple is in `contracts_allowed[]`. `daxie contract send --dry-run` runs stages 1–8 + 5b with no reservation and emits the **classification result** in the JSON verdict (`"classified_as":"approve","spender":"0x…","unlimited":true`), so an agent pre-flights whether its raw calldata is treated as a spend-equivalent before burning a signing attempt — the recommended relayer/meta-tx pattern. `ClassifyCalldata` runs at stage 2 inside `authorize` (§2.7), the same insertion point `ClassifyTypedData` uses for `SignTyped`: one classification step, two sources (typed data + raw calldata), one downstream gate set.

> **Reconciliation note (denied sub-code strings).** Two spellings exist across the
> corpus for the same denials: the policy part used `policy.denied.tx_limit` /
> `policy.denied.day_limit` / `policy.denied.pin_drift`; the architecture, MCP, and
> threat parts used `policy.denied.spend_limit` / (the day variant of `spend_limit`) /
> `policy.denied.ens_pin`. The exit code is the same (3) in every case. **Canonical
> spelling adopted here:** `policy.denied.tx_limit`, `policy.denied.day_limit`,
> `policy.denied.pin_drift` (the policy part owns this taxonomy), with
> `policy.denied.spend_limit` / `policy.denied.ens_pin` recorded as **withdrawn
> aliases** — agents branch on the canonical strings (§11, D7). The full code table is
> §4.9 and the CLI-wide exit registry is §5.7.

### 4.4 Spend accounting & reservation lifecycle

Counters live at `$DAXIE_STATE_DIR/spend/<network>/<from>.json` — one file per
`(network, account)`. Mutual exclusion is two-layered (cross-platform via `fsx`,
§7.9): a per-account sidecar flock across processes
(`$DAXIE_STATE_DIR/locks/policy-<net>-<addr>.lock`) and an `Engine`-level per-account
mutex within the process, taken **before** the file lock (so N concurrent MCP tool calls
don't each park in a blocking `flock` syscall). Acquisition ordering, fixed: mutex →
open fd → flock → read → evaluate/mutate → write → funlock → close fd → release mutex.
**All readers take a shared lock too** (`policy show/counters/verify`) — a
Daxie-internal consistency measure, *not* the Windows rename-safety mechanism (that is
`fsx.WriteAtomic`'s `MoveFileEx`+retry, §7.9). All atomic writes and permission setting
go through `fsx`; `internal/policy` owns **no** platform-specific code.

Counter file shape (timestamped reservation entries the rolling-24h window and lifecycle
require):

```json
{
  "version": 1, "policy_nonce": 12, "network": "mainnet", "from": "0x52ae…",
  "entries": [
    { "id": "01HZX5K8…", "ts": "2026-06-12T14:03:11Z", "account_nonce": 42,
      "kind": "transfer", "asset": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "candidates": [
        { "tx_hash": "0x9f1c…", "value_wei": "0", "gas_max_wei": "1890000000000000",
          "gas_actual_wei": null, "state": "committed" }
      ] }
  ]
}
```

- One logical entry per spend, keyed by `(from, account_nonce)`; `candidates[]` holds
  every RBF candidate for that nonce. The wei counted is the **max across candidates**
  (`value_wei` and `gas_max_wei` independently). `asset` is `"eth"` or the lowercase
  contract address — for display/future per-asset layer only; the counted wei is
  `value_wei + gas_max_wei`, ETH-denominated regardless of asset.
- `policy_nonce` records the policy generation (the rollback tripwire, §4.6).
- **Pruning:** at each locked write, entries with `ts < now − 24h` whose every candidate
  is terminal are dropped. The tx journal is the permanent audit record; counters are a
  working set.

**Reservation lifecycle (debit-before-sign).** Ordering: `Reserve` (fsynced before any
signature exists) → sign (outside the lock) → journal entry (carrying the reservation
ID) → broadcast → `Commit(hash)` → `SettleActual` (down-only on receipt; on revert,
value released). **`Release()` is valid only while no signature bytes exist** — local
failures strictly *before* signing. **Once a transaction is signed, nothing observed at
broadcast releases the reservation** — not transport failures, not synchronous
rejections, not timeouts/5xx/"already known": the signed bytes are durable in the journal
and remain broadcastable by anyone who has seen them, so released allowance could always
correspond to live, spendable bytes. The concrete hole this closes: `rpc add` is
unauthenticated, so an agent could otherwise add a dead endpoint, sign, "fail"
transport, get the reservation released, and re-send later — spending outside the
counted window. **Over-counting is the stated safe direction.**

**Crash reconciliation at `service.Open`** (driven by `service` because `policy` may not
import `journal`). For each reservation still in `reserved`, under that account's flock:
no broadcast recorded in the journal ⇒ `ReleaseOrphan` (crash *between Reserve and
broadcast* — sound because the journal proves no signed bytes were broadcast); broadcast
recorded ⇒ `CommitOrphan(hash)` (crash *between broadcast and Commit*). When `tx wait`
re-broadcasts a journaled `signed` record whose reservation was reconciled away, service
**re-reserves before re-broadcasting**. Crashes therefore only ever *under*-spend.
**Permits do not reserve**: a `KindPermit` is gasless and never broadcast, so it has no
txHash for `Commit` and no wei to count — service calls pure `Evaluate` directly (spender
allowlist, ENS pin, unlimited gate, no-allowlist rule) and skips Reserve/Commit/Settle
entirely (this also keeps orphan reconciliation sound — a permit "reservation" could
never acquire a broadcast record).

**Gas reconciliation.** Daily debits are taken at worst case (`gasLimit × maxFeePerGas`,
~2–3× actual with the 2× base-fee headroom); `SettleActual` adjusts **downward only** on
the first observed receipt (monotonic — no sequence of reconciliations can retroactively
create headroom). A fire-and-forget agent that never waits lives under a tighter daily
gas budget — acceptable, and `--wait` is the recommended pattern anyway.

**RBF supersession.** A `tx speedup`/`tx cancel` appends a candidate to the existing
`(network, from, account_nonce)` entry rather than creating a new one; the counted
envelope is the **max across candidates** until a receipt finalizes one (either tx might
mine). `SettleActual` matches the receipt's hash against **any** candidate, collapses to
its actuals, and marks siblings `replaced`. A `tx cancel` does not immediately release
the original value's headroom — only the cancel receipt does. (Spend-accounting
specifics for RBF, including the gas-delta-only rule and the cancel exemption, are in
§5.5.)

**Approvals/permits (no value debit in v1).** Per the no-oracle rule, token amounts are
never converted into ETH-denominated limits. Enforcement: the spender must pass the
per-network allowlist gate, the fail-closed no-allowlist rule applies, unlimited requires
the `--unlimited --yes` / `acknowledge_unlimited` ceremony, and `allow_unlimited:false`
(per token) is an operator hard-deny. On-chain approvals additionally debit only their
**gas** to the ETH counters. **Deliberately not in v1:** per-token value limits — the
"per-asset rules" requirements §5 names as a future layer; `tokens[]` reserves the field
shape so the future layer is additive. This is the deferred item that closes residual R6.

**`contract send --value` (msg.value).** ETH attached to a payable call is ETH-denominated native value, written to `Check.SpendWei` for *every* `contract send`, recognized selector or not. It is the **one** part of arbitrary calldata v1's ETH limits can fully see, so it is debited and reserved identically to a `tx send` amount: it counts toward the **per-tx** limit (stage 6) and the **rolling-24h daily** limit (stage 7), reserves before signing under the per-account flock, and `SettleActual` releases it on a reverted receipt; gas counts toward the daily limit + gas cap (stage 8) exactly as `tx send`. **What the ETH limits cannot see** is value moved *inside* the calldata — that is why the contract-as-destination allowlist + the fail-closed-no-allowlist rule + the selector classifier (§4.2) are load-bearing for `contract send`, not the ETH limits alone. `--value` (named for `msg.value`) and `tx send --amount`/token amounts never co-mingle in `SpendWei`: a `contract send` carries *either* a display-only `TokenAmt` (recognized token op) *or* an ETH `SpendWei` from `--value`, and only `SpendWei` is ever compared to a limit. No new reservation state, no counter-file shape change: the reservation is an ordinary `(network, from, account_nonce)` entry whose `value_wei` is `--value` and whose `asset` is the recognized token contract (or `"eth"` when none).

### 4.5 Policy file format and sealing

`$DAXIE_STATE_DIR/policy.json` — **state class**. The stored file is a two-member
envelope so a mutation is a single-file atomic write and no torn body/seal pair is
possible:

```json
{
  "version": 1,
  "body_b64": "eyJ2ZXJzaW9uIjoxLCJub25jZSI6MTIsIC4uLn0=",
  "seal": { "alg": "scrypt/ed25519", "sig": "base64(64B)" }
}
```

- **The seal covers the exact stored body bytes — never a re-marshaled projection.**
  `sig = ed25519.Sign(sk, "daxie/policy/v1\n" || base64decode(body_b64))`. Verification
  never round-trips through Go structs, so a binary of *any* version verifies a file
  written by any other — unknown fields cannot produce a false seal failure (the mode
  that would brick a fleet whose agent pods run an older image than the operator's
  one-off `policy set` Job). The salt and verify key are **not** in the seal block (they
  live in the anchor, §4.6) — the file alone is not self-verifying, which is the point.
- **Version skew is a fail-closed refusal via a two-pass decode.** A field this binary
  doesn't know may be a *restriction* it would silently drop, so it is a hard
  `policy.version` refusal: pass 1 (permissive, after the seal verified) reads
  `{Version, WrittenBy}`; pass 2 (strict, `DisallowUnknownFields`) — any unknown-field
  failure is the refusal, naming pass-1's `written_by` and the remediation "upgrade agent
  images to ≥ the version that wrote the policy".
- **Nullable limits are tri-state on read and write.** `"max_day_wei": null` (no limit on
  this network) is distinct from an *absent* field (inherit the default block). Body bytes
  are produced by hand-built ordered writers (absent → omit; null → literal `null`;
  value → marshaled; fixed key order; decimal-string amounts), not by marshaling structs —
  two writers at the same version produce byte-identical bodies (a reproducibility/diff
  convention, never a security property, since the seal covers stored bytes).

**Decoded body schema:**

```json
{
  "version": 1, "nonce": 12, "updated_at": "…", "written_by": "1.4.2",
  "messages": "allow", "tokens_no_allowlist_ok": false,
  "rules": {
    "default": { "max_tx_wei": "100000000000000000", "max_day_wei": "500000000000000000",
      "max_gas_price_wei": "100000000000", "allowlist_enabled": true, "include_self": true },
    "networks": [
      { "network": "sepolia", "max_tx_wei": null, "max_day_wei": null,
        "max_gas_price_wei": null, "allowlist_enabled": false, "typed_data_unknown": "allow" }
    ]
  },
  "tokens": [
    { "network": "mainnet", "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "alias_at_set": "USDC", "allow_unlimited": false }
  ],
  "allowlist": [
    { "source": "address", "address": "0xabc…", "label": "", "added_at": "…" },
    { "source": "contact", "name": "exchange", "address": "0xabc…", "added_at": "…" },
    { "source": "ens", "name": "vitalik.eth",
      "address": "0xd8da6bf26964af9d7eed9e03e53415d37aa96045", "resolved_at": "…" }
  ],
  "denylist": [ { "source": "address", "address": "0xbad…", "label": "drainer", "added_at": "…" } ],
  "self_addresses": ["0x52ae…", "0x9b1c…"],
  "typed_data": {
    "unknown": "deny",
    "allowed": [ { "chain_id": 1, "verifying_contract": "0x…adc0",
      "primary_type": "OrderComponents", "label": "seaport-1.6" } ]
  },
  "contracts_allowed": [
    { "network": "mainnet", "contract": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
      "selector": "0x12345678", "label": "vault-withdrawTo", "added_at": "…" }
  ]
}
```

- **`nonce`** is the monotonic anti-rollback counter, +1 on every admin mutation, covered
  by the seal, compared against the anchor's watermark (§4.6).
- **Every default-block field overrides per network.** `typed_data.unknown` participates
  via an optional per-network `typed_data_unknown` field. Every gate is CLI-switchable
  under the admin passphrase (§4.7); none is reachable only by editing the file.
- **`tokens[].allow_unlimited` is tri-state** (`Optional[bool]`): absent → governed by
  the ceremony alone; `false` → hard deny regardless of ceremony; `true` → documents the
  permissive default. No `max_tx`/`max_day` on token rules in v1 (the deferred per-asset
  layer).
- **`denylist[]` — `policy deny` is a real denylist, not allow-removal.** `deny` *adds* a
  pinned entry (same shape and allow-time pinning as `allowlist[]`); precedence
  **denylist > allowlist > include_self**. Sign-time matching is by pinned address **or**,
  for `contact`/`ens` entries, by typed name (so drift never weakens a deny). Removal is
  explicit: `policy allow --remove X` / `policy deny --remove X`.
- **`self_addresses` is the sealed snapshot of keystore addresses** that `include_self`
  resolves against — *not* the live keystore. `account import` needs only the keystore
  passphrase, so without the snapshot a prompt-compromised agent could import an attacker
  key and mint itself an allowlisted destination. Refreshed at every admin mutation;
  `policy show` lists keystore addresses missing from the snapshot.
- **`contracts_allowed[]` is the §4.3 stage-5b unknown-calldata allow registry** — the
  structural twin of `typed_data.allowed[]`, but keyed on a `(network, contract, selector)`
  triple instead of `(chain_id, verifying_contract, primary_type)`. Each entry is
  `{network, contract, selector, label, added_at}` (`selector` is the 4-byte function
  selector as `0x` hex; `label` is an operator note like `"vault-withdrawTo"`). An
  unrecognized selector on `contract send` is **deny-by-default once a policy is active**
  unless either the contract address is allowlisted **or** its exact triple appears here —
  there is no `tokens_no_allowlist_ok`-style blanket override (the ack is per-triple
  because one wrong arbitrary call's blast radius is unbounded, §4.3 stage 5b). It is
  **per-network keyed** like the rest of the body and **covered by the seal/nonce** like
  every other field — editing it directly on the volume fails seal verification and halts
  signing. Written only by the admin-gated `policy contract allow|remove` command (§4.7).

**Seal construction (`policyseal`):**

```text
salt        = 32 random bytes, generated at first `policy set` (rotated by change-admin-passphrase)
K_master    = scrypt(adminPassphrase, salt, N=2^17, r=8, p=1, dkLen=32)
K_seed      = HKDF-SHA256(K_master, info="daxie/policy/sig-seed/v1", L=32)
(sk, pk)    = ed25519.NewKeyFromSeed(K_seed)
sig         = ed25519.Sign(sk, "daxie/policy/v1\n" || body)   -> seal.sig
pk          -> the anchor's VerifyKey (NOT stored in the policy file, §4.6)
```

Pure-Go throughout (`x/crypto/scrypt`, `x/crypto/hkdf`, `crypto/ed25519`). **One
signature, deliberately no MAC** (requirements OQ #22): a symmetric MAC cannot split
"verify" (which the agent process must do on every signing op) from "forge" (which only
the operator may do) — any MAC key the agent host can read to verify with is a key a
compromised agent can re-seal with. A MAC layered alongside the signature adds zero
security, so there is exactly one primitive over the bytes. **Wrong-passphrase vs
tampered-file discrimination, without a separate verifier blob:** on an admin mutation
the engine derives `(sk, pk)` and compares `pk` to the anchor's pinned `VerifyKey` —
mismatch ⇒ `policy.admin_auth`; `pk` match but bad `sig` ⇒ `policy.seal_violation`. The
pinned key *is* the verifier (the earlier draft's `seal.verifier` field is withdrawn).

### 4.6 The anchor — signing-time soundness (the trust root)

The verify key, scrypt salt, and nonce high-watermark live **together** in a dedicated
machine-managed file in the **config** state class, `$DAXIE_CONFIG_DIR/policy-anchor.json`,
read **directly** by `internal/config` — **not** in `config.toml`, **not** under any
Viper key:

```json
{ "verify_key": "ed25519:base64…", "verify_key_next": null,
  "salt": "base64(32B)", "scrypt": { "n": 131072, "r": 8, "p": 1 },
  "nonce_watermark": 12 }
```

- **Carved out of Viper precedence, exactly like the sealed file** (requirements §5,
  OQ #2). No flag, no `DAXIE_*` env var; `daxie config get|set|list` rejects the
  `policy.*` subtree outright, and a regression test pins that `DAXIE_POLICY_*` env vars
  and flags have no effect. Reason (requirements §5's own words): *"Viper's flags > env
  precedence would otherwise let a compromised agent outvote the admin passphrase from
  its own process environment."* An env-settable verify key would let any agent pair a
  self-forged `policy.json` with a key it generated, "verify" it, and sign anything.
- **Why a dedicated config-class file:** (a) outside `config.toml` so no machine write
  path touches the human-owned config; (b) config-class because that is the one mount the
  agent process genuinely cannot write in K8s (read-only ConfigMap). The ConfigMap
  protects the *file*; the Viper carve-out protects against the env/flag bypass no file
  permission can stop. Both are required; neither alone suffices.
- **Load path, every signing op:** load `policy.json` → verify `sig` against
  `anchor.VerifyKey` (or `VerifyKeyNext`) → **refuse if `body.nonce <
  anchor.NonceWatermark`**. The watermark makes rollback **prevention-grade**: a bare
  signature verifies any historically-sealed policy forever, so a state-volume writer
  could snapshot the policy before the operator tightens limits and restore it later as a
  valid seal carrying yesterday's looser limits. The watermark refusal halts signing on
  exactly that move.
- **`daxie policy set` is the only watermark writer.** A mutation bumps `body.nonce`,
  re-seals, and rewrites `policy-anchor.json` via `config`'s direct writer
  (`fsx.WriteAtomic` under the `policy-anchor.lock` sidecar). At runtime, a loaded nonce
  *above* the watermark advances it opportunistically when the config class is writable
  (workstation), and is accepted as-is when it isn't (K8s) — self-healing without ever
  *requiring* a config write (§7a).
- **Anchor lifecycle (read-only config, the K8s case).** There is **no separate `policy
  init` command** — the **first** `policy set` against a config dir with no anchor
  *bootstraps* it (generates the verify keypair, salt, watermark 0); subsequent
  `policy set` updates it. On a writable config it writes the anchor directly; on a
  read-only config it **emits the anchor JSON to stdout (or `--anchor-out <staging
  path>`)** and the operator/CI lands it into the ConfigMap (the documented out-of-band
  step; `daxie policy pin --print` re-emits it any time). `policy set` refuses to replace
  an existing trust root.
- **Fail-closed on absence.** Anchor present + policy missing/unverifiable ⇒
  `policy.seal_violation`; policy present + anchor missing ⇒ `policy.seal_violation`
  (reason `anchor_missing`) — there is **no unpinned verification mode**.
- **Pin-test canary, passphrase-free.** `daxie policy pin --verify <key>` reports whether
  the on-disk `policy.json` verifies under a *supplied* key (exit 0/8) — run as a one-off
  K8s Job against the candidate ConfigMap value **before** cutover, so a fat-finger
  becomes a canary, not a fleet-wide refusal.
- **Staged, zero-outage rotation** (`change-admin-passphrase`). The loader accepts
  `verify_key` (current) + optional `verify_key_next`; signing verifies against either.
  Flow: `--stage` (authenticate current, prompt new, print the new key, record a
  `staged_salt`) → operator rolls `verify_key_next` into the ConfigMap, canaries with
  `pin --verify` → `--commit` (re-derive from the staged salt, check the derived key
  equals `verify_key_next`, reseal under the new key family; on read-only config
  `--commit` **blocks until the new anchor is observed** on the mount before retiring the
  old key) → operator promotes `verify_key_next` to `verify_key` at leisure.

> **Reconciliation note (config-key sketches withdrawn).** Three drafts sketched the
> anchor differently (a `policy.verify_key` config key; a `policy_pin` in
> `keystore.json`; the dedicated `policy-anchor.json`). The canonical, normative anchor is
> **`policy-anchor.json`** in the config class; the config-key and keystore-pin sketches
> are withdrawn (§11, D9).

### 4.7 Admin-auth flow for mutations

Two secrets, never interchangeable: the keystore passphrase signs *within* policy; the
admin passphrase *defines* policy. The admin passphrase is accepted through the standard
secret channels only (prompt at TTY, `--admin-passphrase-stdin|file`,
`DAXIE_ADMIN_PASSPHRASE[_FILE]`) — never as a flag value, never present in agent pods.
Every mutating command (`policy set/allow/deny/typed allow|remove/contract
allow|remove/counters release/change-admin-passphrase`) executes: read policy + anchor;
derive `(sk, pk)` from the supplied passphrase +
`anchor.salt`; `pk != anchor.VerifyKey (and != VerifyKeyNext)` ⇒ `policy.admin_auth`,
stop; verify the seal over the decoded body (`policy.seal_violation` on mismatch); decode
strict; apply the mutation; `nonce++`; refresh `self_addresses`; re-sign over the exact
new bytes; write the envelope atomically; bump `anchor.NonceWatermark`; emit a JSON diff.

**The one carve-out: `daxie policy reset --force`** — exempt from the *file* checks (it
recovers exactly the files this pipeline refuses), **never** from authentication. It
authenticates against the **anchor** (derive `(sk, pk)`; `pk` must equal
`anchor.VerifyKey`/`VerifyKeyNext`) — real proof that survives body tampering — then
reseals fresh **default** body (nonce restarts at watermark+1; `self_addresses`
re-snapshotted) under the *same* key family (no rotation, no ConfigMap update, no fleet
outage). There is **no `--yes` bypass**: a prompt-compromised agent that trashes
`policy.json` cannot follow up with a reset under a passphrase of *its own* choosing,
because its passphrase never derives the pinned key. When authentication is impossible
(anchor missing/destroyed) reset refuses; recovery moves out-of-band (operator removes
the anchor and re-runs the bootstrap `policy set`). **No lockout/rate-limit on admin
attempts** — the file is local so an attacker brute-forces offline regardless; scrypt's
cost *is* the defense, and a lockout would only add an agent-triggerable DoS.

**Command surface (extends cli-spec's `daxie policy`):** `policy show` (unauthenticated;
rules + seal status + 24h usage + headroom), `policy set` (limits/gas-cap/`--allowlist
on|off`/`--include-self`/`--typed-unknown`/`--messages`/`--allow-tokens-without-allowlist`/
per-token `--allow-unlimited true|false|inherit`/per-network overrides; `none`/`inherit`
literals give nullable limits a full CLI representation; **the first `policy set`
bootstraps the anchor**), `policy allow`/`policy deny` (with `--remove`; ENS pinning,
§4.8), `policy verify` (exit 0/8, anchor-based, no passphrase — CI-friendly),
`policy check` (what-if `Evaluate`), `policy counters [release <id>]`, `policy pin
--print|--verify <key>`, `policy change-admin-passphrase` (`--stage`/`--commit` for
fleets), `policy typed allow|remove` (the per-domain typed-data allow registry),
`policy contract allow <contract> --selector 0x… [--network …] [--label …]` /
`policy contract remove <contract> --selector 0x… [--network …]` (the
per-`(network, contract, selector)` unknown-calldata allow registry that writes the §4.5
`contracts_allowed[]` field — the §4.3 stage-5b twin of `policy typed allow|remove`;
admin-passphrase-gated, running the same seal/nonce/`self_addresses`-refresh flow as every
other mutation above), `policy reset --force`. **K8s two-domain ordering (a required `docs/deploy/` runbook):**
each mutation produces the sealed `policy.json` (state PVC) and the anchor (config
ConfigMap); write the **policy file first, then the anchor** (a failure between leaves
`file.nonce > anchor.watermark`, which the runtime accepts; anchor-first would
self-inflict a `policy.rollback` halt). Provisioning seeds both before the first agent pod
starts.

### 4.8 ENS and contact pinning; the drift-refusal flow

**Invariant: the sealed allowlist/denylist store resolved `0x` addresses, never bare
names.** Names are mutable indirection (ENS by their owner; contacts by anyone who can run
`daxie contacts` — contacts are *not* admin-protected). Pinning at allow-time makes later
mutations powerless. Allow-time behavior: `0x…` → pinned as-is; contact name → the
contact's current address snapshotted (resolve ENS-backed contacts now); ENS name →
resolved **now**, echoed (cli-spec: always echoed before signing), pinned with
`resolved_at`. `policy deny X` pins identically into `denylist[]` but its sign-time
matching is deliberately *broader* — a deny entry matches on pinned address **or** typed
name, so a re-pointed denied ENS name stays blocked under both.

Sign-time check (stage 4), after stage 3 matched the resolved address. The fresh
resolution is performed by `service` **before** the spend-state lock and handed to the
engine — the engine only compares; it never does network I/O inside the locked section:

| Input form | Check | On mismatch |
|---|---|---|
| raw `0x…` | address ∈ pins | `policy.denied.allowlist` |
| contact name | contact's current address must equal the pinned address | `policy.denied.pin_drift` (reason `contact_drift`; payload `pinned`+`current`) |
| ENS name | fresh on-chain resolution must equal the pinned address; **resolution failure also refuses** (`ens_unresolved`) | `policy.denied.pin_drift` (reason `ens_drift`; payload `name`,`pinned`,`current`,`resolved_at`) |

The drift refusal is a **distinct code** from a plain allowlist miss (requirements §4:
"a changed resolution refuses the send until re-allowed"); the remediation is a human
judging the re-point and re-running `daxie policy allow vitalik.eth`. Homograph defense
(ENSIP-15 normalization + non-ASCII warning with codepoint escape) is owned by the
resolution layer (§8 T5).

### 4.9 The policy-denied error model

String codes are canonical (they survive every transport); the numeric CLI exit code is
the CLI's mapping. Policy codes land in exactly two rows of the CLI-wide registry (§5.7):
**exit 3** (the agent-branchable *denied* class) and **exit 8** (the
seal/auth/state/rollback class). Neither collides with the tx-lifecycle codes.

| Exit | Canonical code | Meaning | Key `details` |
|---|---|---|---|
| 8 | `policy.seal_violation` | seal failed / pinned-but-absent / anchor missing / unknown fields (`policy.version`) — **all signing halts** | `seal_status`, `anchor_source`, `written_by` |
| 8 | `policy.rollback` | `body.nonce < anchor.NonceWatermark` (older validly-sealed file replayed) | `body_nonce`, `watermark` |
| 8 | `policy.admin_auth` | wrong admin passphrase on a mutation (derived key ≠ anchor) | — |
| 8 | `policy.state_error` | counters unreadable/unlockable/unwritable — fail closed | `path`, `cause` |
| 3 | `policy.denied` | a guardrail refused; the specific sub-code is in `code` and every violation in `details.violations[]` | `violations[]` |
| 3 | `policy.denied.tx_limit` | per-tx ETH limit exceeded | `limit`, `attempted`, `network` |
| 3 | `policy.denied.day_limit` | rolling-24h ETH limit exceeded | `limit`, `used_24h`, `attempted`, `retry_after` |
| 3 | `policy.denied.allowlist` | destination/spender denylisted or not allowlisted | `address`, `role`, `reason` (`denylisted`\|`not_allowlisted`) |
| 3 | `policy.denied.no_allowlist` | limits set, no allowlist, token/NFT/approval, no admin override | `network` |
| 3 | `policy.denied.gas_cap` | maxFeePerGas above cap (incl. `gas_cap_below_bump_floor` during a fee spike, §5.5) | `cap`, `attempted`, `current_base_fee` |
| 3 | `policy.denied.pin_drift` | ENS/contact resolution ≠ allow-time pin | `reason`, `name`, `pinned`, `current` |
| 3 | `policy.denied.typed_data` | unknown typed data with deny / chain mismatch / unlisted domain | `reason`, `primary_type`, `verifying_contract`, `chain_id` |
| 3 | `policy.denied.unlimited_unacked` | unlimited approval/permit without the ceremony, or `allow_unlimited:false` | `token`, `spender` |
| 3 | `policy.denied.contract_call` | `contract send` with an **unrecognized selector** to a non-allowlisted contract while a policy is active, and the `(network, contract, selector)` triple is not in `contracts_allowed[]` (the §4.3 stage-5b unknown-calldata gate) | `network`, `contract`, `selector`, `reason` (`unknown_selector` \| `not_allowed`) |
| 3 | `policy.denied.contract_value` | reserved alias — `contract send --value` over the per-tx/day ETH limit surfaces as the existing `policy.denied.tx_limit`/`day_limit` (msg.value is ordinary `SpendWei`); this row documents that **no new value code is minted** | — |

**Precedence when multiple violations accumulate:** `seal_violation` > `state_error` >
`allowlist`/`no_allowlist` > `pin_drift` > `typed_data` ≈ `contract_call` > `tx_limit` >
`day_limit` > `gas_cap` (`contract_call` sits in the same "can't classify; deny-by-default"
band as `typed_data`, one for calldata, one for typed data; `retryable: false` for both —
retrying without operator action is pointless). The process exits with the highest-precedence code; **all** violations ride in
`details.violations`. `retryable` per code: `day_limit` true (+`retry_after`), `gas_cap`
true (the fee market moves), everything else false (retrying without operator action is
pointless). The wire shape is the global error envelope (§5.7) on **stderr**.

**MCP mapping.** MCP has no exit codes; tool handlers return `isError: true` carrying the
**same envelope** as the CLI's stderr `error` object — identical `code` strings,
identical `details` — because both come from the same `internal/policy` engine below the
two thin frontends. The unlimited ceremony crosses the same way: the CLI's
`--unlimited --yes` and the MCP tool's `acknowledge_unlimited: true` both set
`Check.Acked`, which `Evaluate` reads — neither frontend implements the gate.

### 4.10 What v1 deliberately defers (forward room, requirements §5)

The fuller engine (rate limits, time windows, per-asset *value* rules, approval
webhooks) is a future layer; the schema leaves room without committing. The seal covers
exact stored bytes, so schema growth can never break *verification*; cross-version reads
hit the explicit fail-closed `policy.version` rule. `Check` already carries everything a
rate-limiter, per-asset rule, or webhook would inspect; `Reserve`'s lifecycle is exactly
the hook an async-approval flow would suspend in; `tokens[]` already carries token
identity so the deferred **per-asset value limit** (the item that closes R6) is an
additive field + clause + a token-base-unit counter. None is built; none is precluded.

### 4.11 Residual tamper gap and exactly what v2 fixes

v1's enforcement runs **inside the agent's trust domain** (the agent, the Daxie process,
the keystore, and the state dir share one uid). Two tiers: (1) a prompt-compromised,
**interface-confined** agent (tools = only `daxie` invocations; sandbox excludes the
config path) → **policy holds**: it cannot mutate policy (admin passphrase), forge the
seal (Ed25519 + mandatory anchor outside Viper), reset its way to fresh limits (reset
authenticates against the anchor), rollback (the watermark), or mint itself an
allowlisted destination (sealed `self_addresses`). (2) a **code-executing** compromise of
the agent process → policy is advisory, because this adversary holds the keystore
passphrase and can sign with twenty lines of its own code, never touching daxie (R1).
Every local check shares that ceiling.

The named residual gap (requirements §7a) sits between these tiers and is **exactly the
spend counters**: a code-executing same-uid attacker can rewrite `counters.json` to bypass
*daily* limits only (per-tx, allowlist, gas cap, typed-data, unlimited gate are stateless
against the *sealed* file and unaffected). The counters **cannot** be sealed — the sealing
key must stay with the operator while the agent process must write a debit on *every*
send, but here the *writer* is untrusted, so no key arrangement works. v1 mitigation:
journal cross-audit (`policy verify` recomputes the 24h window from the append-only
fsynced journal and flags divergence), fail-closed on corruption, and file-ownership
separation where the platform allows. **The v2 signer-daemon boundary closes it** — the
daemon owns the keystore, policy, anchor, **and counters** on volumes the agent cannot
mount; the agent keeps only a revocable access credential and submits requests. The v1
engine is written so this is a transplant, not a rewrite: `Evaluate` is already pure and
the `Engine` reaches storage through a narrow surface (`Open(stateDir, anchor)` + the
reserve/commit/settle/orphan methods) that v2 re-binds inside the daemon.

---

## 5. Transaction pipeline

One pipeline — `service.SendTx` — serves **every** broadcasting operation: `tx send`,
`nft send`, `token approve`/`revoke` (via `service.Approve`, which builds the calldata
then routes into the same path), `tx speedup`, `tx cancel`. Both frontends call it
identically; the Cobra command and the MCP `send` tool are each thin adapters that build
a `domain.TxRequest` and render the `domain.TxResult` / event stream. The orchestrator
lives in `internal/service` (gas in `service/gas.go`, receive in `service/receive.go`);
the journal + nonce manager are `internal/journal`; the policy contract is §4's
`Reserve`/`Commit`/`Release`/`SettleActual`.

**Decisions requirements delegated to this section (decided here):**

| Delegated item | Decision |
|---|---|
| Default `--wait` timeout | **10m** for every pipeline-routed broadcasting command (`tx send/nft send/token approve/revoke/tx speedup/cancel --wait`) and for `tx wait` (config `tx.wait-timeout`, env `DAXIE_WAIT_TIMEOUT`). **`daxie receive` defaults to no timeout** (`receive.timeout = "0"` = forever) — "block until paid" is its contract; bounded callers pass `--timeout`. |
| Built-in per-network confirmation counts | **mainnet 2, Sepolia 1, user-added 1** (resolution `--confirmations` flag > `networks.<n>.confirmations` config > built-in). `safe`/`finalized` keywords are reserved, **not in v1** (numeric only). |
| `--amount` matching | **Cumulative-minimum is the default** (Σ of confirmed inbound ≥ amount since listen start). **`--exact` ships in v1** (completes on a single transfer whose value equals the amount; non-matching transfers reported `"match":false` but don't complete). Per-tx-minimum mode is deferred. |
| ETH-arrival detection | **Block-scan primary (attributable) + balance-delta safety net (unattributed)** over HTTP polling (default `receive.poll-interval = 4s`); WebSocket subscriptions are a v1.1 drop-in upgrade. Full mechanics §5.8. |
| Journal format | **JSONL + cross-platform flock** (not pure-Go sqlite — §5.6). |
| CLI-wide exit-code table | §5.7. |

> **Deliberate refinement — `--wait`/`--confirmations`/`--timeout` extended to `token
> approve`/`revoke`.** requirements §4 enumerates the wait flags for `tx send` and `nft
> send`; cli-spec's `daxie token` examples show approve/revoke without them. Because they
> **broadcast** (routing through this pipeline via `service.Approve`), requirements
> decision #19 ("all broadcasting commands") binds them too — cli-spec's `daxie token`
> examples are updated to show the wait flags (§11, D8).

### 5.1 Stage order (the critical section) and crash-safety

```text
resolve intent ─► preview build (gas quote, ENS echo) ─► confirm (TTY) / --yes skip
   ─► acquire account lock ─► reconcile journal + derive nonce
   ─► build (gas engine: limit + fees)
   │      [TTY-confirmed sends only] worst-case cost drift > gas.drift-tolerance?
   │      ─► release lock (lease never committed) ─► re-confirm with new quote ─► loop
   ─► policy.Reserve (durable spend reservation) ─► Signer.SignTx
   ─► journal.Append(status=signed, raw_tx, reservation_id)
   ─► broadcast ─► outcome:
        ├─ accepted / already known / ours-mined race
        │      ─► journal SetState(broadcast) ─► reservation.Commit(hash) ─► nonce lease commit
        ├─ transport exhausted (may have reached mempool)
        │      ─► record stays `signed` (NO recorded broadcast, NO Commit) ─► nonce lease commit
        └─ permanently rejected
               ─► nonce lease abort (file untouched) ─► journal SetState(failed) ─► reservation.Release()
   ─► release lock ─► [optional] wait state machine (§5.3)
```

Each arrow is load-bearing:

- **Policy reservation is durable *before* sign** (requirements §5: enforced before
  signing; §7a: counters survive restarts). `policy.Reserve` sees the fully built tx —
  recipient, native value, decoded calldata classification, and **worst-case gas =
  `gasLimit × maxFeePerGas`** — and atomically adds `SpendWei + MaxGasWei` to the
  per-account rolling-24h counter as a `{id, wei, state:reserved}` entry. A compromised
  agent that deterministically SIGKILLs its own process to dodge the counter gains
  nothing — the counter was bumped before the bytes could reach the chain (the §7a
  "crash to reset counters" attack, defeated by ordering). Pre-sign failures call
  `Release()`.
- **The two journal statuses `signed` (before broadcast) and `broadcast` (after broadcast
  succeeds) are the reconciliation discriminator.** A reservation still `reserved` whose
  journal record shows a recorded broadcast MUST be committed; one whose record has *no*
  recorded broadcast (status still `signed`) is *released*. "No broadcast recorded ⇒
  release; broadcast recorded ⇒ commit" is the safe-direction proof: a crash between
  `Append(signed)` and the broadcast/`Commit` pair releases the reservation, and the
  re-broadcast path **re-reserves before rebroadcasting** the `signed` record, so crashes
  only ever *under*-spend. Because `policy` may not import `journal`, **`service` drives
  this reconciliation at `Open`** — it reads each reservation's journal record
  (`journal.ByReservation`, chain-scoped) and feeds the verdict to policy's orphan
  surface (`Orphans`/`CommitOrphan`/`ReleaseOrphan`).
- **Journal before broadcast** (requirements §7a). The `signed` record carries the full
  signed RLP in `raw_tx` written **before** broadcast; broadcast success flips it to
  `broadcast`. A crash after `Append` can never produce a *different* second tx: recovery
  re-reserves and rebroadcasts the *same bytes* (same hash, idempotent) — it never re-runs
  send logic.
- **Nonce lease committed only after the broadcast outcome is known.** The journal is the
  source of truth for consumed nonces; the nonce file is a cache. **Commit** the lease on
  accepted / `already known` / ours-mined-race / transport-exhausted; **abort** (lock
  released, nonce file untouched) on permanent rejection. A refused broadcast never burns
  the nonce.
- **Confirmation happens *before* the lock; the locked window is non-interactive and
  bounded — unconditionally.** At a TTY the user confirms the previewed
  recipient/value/fees first (the `Confirm` callback, invoked after the *preview* build);
  only then does the pipeline take the lock and rebuild with fresh quotes. The **drift
  check applies only when a TTY confirmation actually occurred**: if the rebuilt
  worst-case cost exceeds the confirmed quote by more than `gas.drift-tolerance` (default
  **10%**), the lock is released first, then the user is re-prompted. Non-interactive
  sends (`--yes`, or non-TTY) skip confirmation, so no drift check runs: the locked
  rebuild is authoritative, bounded by `policy.max-gas-price` (exit 3) and any explicit
  `--max-fee`. Routine fee drift never fails an agent send. The locked window is all
  RPCs-with-deadlines + local writes, so parallel `daxie` invocations on one host
  serialize cleanly; `tx.lock-timeout` (default 30s) → exit 11 (`state.lock_timeout`).
- **`--dry-run` runs through the policy verdict inclusive** — via the check-only
  `policy.Evaluate` path that writes **no** reservation — prints the built tx + verdict,
  stops before sign/broadcast. A dry-run that would be denied exits 3.

**Flag → request mapping (no new types).** The pipeline consumes `domain.TxRequest` /
emits `domain.TxResult` (§5.2). `--from`/`DAXIE_ACCOUNT` → `From` (""⇒default account);
`--to` → `To` (ENS resolved + echoed via `EvResolved` before sign); `--amount`/`--token`/
`--nft` → `Asset`,`Amount` (registry-only name resolution); the gas flags → `Gas`;
`--nonce` → `Nonce`; `--dry-run` → `DryRun`; `--yes` → `Confirm` const-true (confirmation
skip only, **not** a safety ack); `--wait`/`--confirmations`/`--timeout` → `Wait` (nil ⇒
return after broadcast). `speedup`/`cancel` take a hash + gas opts and reconstruct the
intent from the journal record (§5.5).

**`contract send` maps onto the same `TxRequest` with no new pipeline input but the data field.** `service.ContractSend` resolves `Contract` → the tx **`To`** (alias/0x/ENS, resolved + echoed via `EvResolved` before sign — the contract address is the policy destination), maps `abi.PackCall(method, coercedArgs)` → the tx **data** (the one field empty for plain ETH), `--value` → native value (`Amount`, counting vs spend limits exactly like `tx send --amount`), and gas/nonce/wait/dry-run/confirm/yes → identical fields with identical treatment (the 21000 EOA-transfer gas exception does **not** apply — a contract call is never 21000). RBF (`tx speedup`/`tx cancel`) works on a `contract send` hash with no special-casing (`speedup` rebuilds the identical calldata+value, bumped fees). The entire signing-side surface of `contract send` is: (1) resolve ABI, (2) coerce args, (3) classify the calldata (§4.2), (4) hand a `TxRequest` to the existing pipeline — no new gas, wait, journal, or exit code. The pure read/encode/decode paths deliberately bypass this pipeline (§5.11).

**Broadcast error taxonomy.** `eth_sendRawTransaction` errors are normalized
(string-matched against geth/erigon/nethermind variants) into the canonical codes (§5.7):
`already known` → success (`broadcast`, exit 0); `nonce too low` → re-fetch *our* receipt
first (race with self), present → proceed; absent → another tx consumed the nonce
(`tx.replaced`, exit 9); `replacement transaction underpriced` → refuse
(`tx.replacement_underpriced`, exit 9); `insufficient funds…` → refuse
(`funds.insufficient`, exit 5); transport/5xx/timeout → rebroadcast same `raw_tx` with
backoff (3 tries 1s/2s/4s), still failing → leave record **`signed`** (recovery
resurrects it; `rpc.unreachable`, exit 6). The transport-failure row deliberately leaves
the journal `signed` (**no** recorded broadcast) so the reconciliation discriminator
treats it as not-broadcast — `daxie tx wait <hash>` **re-reserves then rebroadcasts** the
stored bytes through the shared reservation-checked helper if the chain never saw it.

**Token-path fail-closed rule + admin override.** requirements §4/§5 (OQ #2) bind a
two-part rule for token transfers and approvals: refused when spend limits are configured
but no allowlist is, **unless** the operator set the sealed flag `tokens_no_allowlist_ok`
under the admin passphrase (`daxie policy set --allow-tokens-without-allowlist on`). The
verdict is `policy.Reserve`/`Evaluate`'s (§4.3 stage 3c); the pipeline renders it —
unacknowledged ⇒ `policy.denied.no_allowlist` (exit 3, nothing signed); acknowledged ⇒
the normal path (exit 0 on accepted broadcast). The override is a **persisted,
admin-sealed policy bit**, never a per-invocation flag — there is deliberately no
per-send `--ack` escape hatch.

### 5.2 Requests and results (the wire contract)

```go
package domain

type TxRequest struct {
    From    string `json:"from"   jsonschema:"account ref; defaults to the active account"`
    To      string `json:"to"     jsonschema:"address, ENS name, or contact"`
    Amount  string `json:"amount" jsonschema:"e.g. 0.5 (ETH) or 100 (token base units)"`
    Token   string `json:"token,omitempty" jsonschema:"registry alias or contract; omit for ETH"`
    GasLimit    string  `json:"gas_limit,omitempty"`
    MaxFee      string  `json:"max_fee,omitempty"`      // "30gwei"
    PriorityFee string  `json:"priority_fee,omitempty"`
    GasPrice    string  `json:"gas_price,omitempty"`    // --legacy only
    Speed       string  `json:"speed,omitempty"`        // slow|normal|fast
    Legacy      bool    `json:"legacy,omitempty"`
    Nonce       *uint64 `json:"nonce,omitempty" jsonschema:"type=integer,minimum=0"`
    Network     string  `json:"network,omitempty"`
    RPC         string  `json:"rpc,omitempty"`
    DryRun      bool    `json:"dry_run,omitempty"`
    Confirm     bool    `json:"confirm" jsonschema:"default=false"` // the --yes gate; MCP default false, declared not inferred
    Yes         bool    `json:"-"`                                  // CLI-only TTY skip; excluded from the MCP schema
    Wait        WaitOpts `json:"wait,omitempty"`
}
type WaitOpts struct {
    Enabled       bool     `json:"enabled,omitempty"`
    Confirmations *uint64  `json:"confirmations,omitempty" jsonschema:"type=integer,minimum=0"` // nil → per-network default
    Timeout       Duration `json:"timeout,omitempty" jsonschema:"type=string,format=duration"`  // "5m"; zero → default 10m
}

type TxResult struct {
    Hash          string         `json:"hash"`
    Network       string         `json:"network"`
    From          common.Address `json:"from"`
    To            Dest           `json:"to"`
    Asset         Asset          `json:"asset"`
    AmountWei     string         `json:"amount_wei"`        // canonical big-int as string
    Nonce         uint64         `json:"nonce"`
    Gas           GasResult      `json:"gas"`
    Status        TxStatus       `json:"status"`            // pending|confirmed|reverted|timeout
    Confirmations uint64         `json:"confirmations"`
    BlockNumber   *uint64        `json:"block_number,omitempty"`
    JournalID     string         `json:"journal_id"`
}
type TxStatus string
const (
    StatusPending   TxStatus = "pending"
    StatusConfirmed TxStatus = "confirmed"
    StatusReverted  TxStatus = "reverted"
    StatusTimeout   TxStatus = "timeout"  // NOT failure; resumable
)
```

**Built-in confirmation/timeout defaults:** mainnet `confirmations = 2`, Sepolia = 1,
user networks = 1; `--wait` default timeout = 10m (`tx.wait-timeout`); `receive` defaults
to no timeout. Resolution order: `--confirmations` flag > `networks.<n>.confirmations`
config > built-in.

### 5.3 Wait state machine (`--wait` and `tx wait`)

Applies to `--wait` on **every** pipeline-routed broadcasting command and to `daxie tx
wait`; all inherit the 10m default timeout.

```text
                     ┌───────────────────────────────────────────────┐
                     ▼                                               │
 signed ─► broadcast ─► pending ──► mined ──► confirmed (exit 0)     │
   │           │           │          │                             │
   │           │           │          └──► reverted (exit 7)        │
   │           │           ├──► replaced (exit 9)  [nonce consumed  │
   │           │           │                        by a diff hash] │
   │           │           └──► dropped ─► re-reserve + rebroadcast ─┘
   └───────────┴──► failed (broadcast rejected permanently)
 any non-terminal state at deadline ─► timeout (exit 8, resumable)
```

Loop every `tx.poll-interval` (default 4s). Each new confirmation emits an
`EvConfirmation` event — `cli` renders it to **stderr** (progress); `--json` stdout
carries exactly **one final JSON object** (the cli-spec single-object rule); MCP forwards
each event as a progress notification. The loop queries `eth_getTransactionReceipt`
first: receipt present `status 0x0` → **reverted** (exit 7); `0x1` → **mined**
(confirmations = `head − blk + 1`); at target re-fetch the receipt and compare
`blockHash` (same → **confirmed**, exit 0, and `service` calls `policy.SettleActual`;
different but mined → restart counting; gone → back to `pending`, reorged). No receipt →
`eth_getTransactionByHash`: known → still `pending`; unknown with a journal record → the
nonce/receipt re-check disambiguates **replaced** (exit 9, never fires while our own
payment mined) from **dropped** (re-reserve + rebroadcast through the shared helper);
unknown and not in the journal (a foreign hash) → poll to the deadline → exit 8. Deadline
in any non-terminal state → **timeout** (exit 8, not failed; `--json` stdout carries
`{"status":"pending","resume":"daxie tx wait 0x…"}`).

**Rebroadcast rule (binding).** Every rebroadcast of stored `raw_tx` — the reconcile
resurrect, the `dropped` transition, and `tx wait`'s exit-6 recovery — goes through **one
shared helper** that (a) gates on *no canonical receipt for this hash or any same-nonce
sibling* and *no live `replaced_by` link* (the double-spend guard), and (b) resolves the
reservation by record status: `signed` (no recorded broadcast) → re-reserve before
rebroadcasting; `broadcast` → ride the already-committed reservation. If a `broadcast`
record's reservation id resolves to **no** durable reservation (impossible absent
counter-file tampering) → never rebroadcast; mark `failed` with
`tx.integrity.reservation_missing` (exit 12). So a counted transaction is never lost and
an *uncounted* one is never resurrected. `tx wait` is stateless and resumable; SIGTERM
during `--wait` flushes via `service.Close` and exits resumable.

### 5.4 Gas engine (`service/gas.go`)

**EIP-1559 fees (default path).** One RPC call:
`eth_feeHistory(20, "latest", [25, 50, 90])` (`chain.SuggestFees` folds the call + the
percentile math into one method, §2.6). The `reward` array has 20 entries (one per
block); `baseFeePerGas` has 21 (the last *is* the next block's base fee). The percentile
triple **25/50/90** is the shared contract with config (`slow|normal|fast → p25/p50/p90`)
and the test fixture.

| `--speed` | percentile | Intent |
|---|---|---|
| `slow` | 25th | lands within several blocks; cheapest sane tip |
| `normal` (default) | 50th | typical next-few-blocks inclusion |
| `fast` | 90th | next-block inclusion with high probability |

Aggregation: **median across the 20 sampled blocks** of each block's chosen percentile
(not the mean — a single MEV-bribe block would poison `fast`). Priority-fee floor
`gas.min-priority-fee` (default 0.01 gwei, per-network overridable). Max fee =
`gas.base-fee-multiplier` × nextBaseFee + priorityFee (default multiplier 2.0; base fee
grows ≤ 12.5%/block and 1.125⁶ ≈ 2.03, so the tx survives ~6 full blocks; the surplus is
never paid). Partial overrides: `--priority-fee` alone → maxFee recomputed; `--max-fee`
alone → tip = min(speed estimate, maxFee); both → verbatim (tip ≤ maxFee else exit 2).
**Precedence: flag > env (`DAXIE_MAX_FEE`/`DAXIE_PRIORITY_FEE`/`DAXIE_GAS_LIMIT`) > config
(`networks.<n>.gas.*` > `gas.*`) > estimated.** Fallback ladder when an RPC is limited:
`eth_feeHistory` → (`eth_maxPriorityFeePerGas` + latest-header base fee) → legacy; the
`Quote.Source` field records which rung was used.

**Gas limit:** `eth_estimateGas` × `gas.limit-multiplier` (default 1.2, rounded up);
exception: an estimate of exactly **21000** (plain EOA transfer) is used as-is (the
intrinsic cost is exact). Estimation failures surface the revert reason
(`--dry-run`-friendly): revert-on-estimate exits 7, insufficient-funds exits 5, malformed
input exits 2.

**Legacy-chain mode** (`networks.<n>.legacy = true`, `--legacy`, or auto-detected on a
base-fee-less block with a warning): `eth_gasPrice` × speed multiplier (slow ×1.0, normal
×1.2, fast ×1.5). `--gas-price` exists **only** here; `--max-fee`/`--priority-fee` on a
legacy network → exit 2.

**Policy hooks.** The cap check is `maxFeePerGas` (1559) or `gasPrice` (legacy) vs
`policy.max-gas-price` → exit 3 (`policy.denied.gas_cap`), unconditional on every signed
tx including `tx speedup`/`tx cancel`. Daily-limit accounting uses worst-case
`gasLimit × maxFeePerGas`, durably reserved before signing, shrunk to actual on receipt,
released on `failed`. `daxie gas` prints all three speed quotes + next base fee from one
`eth_feeHistory(20,"latest",[25,50,90])` call.

### 5.5 Speedup / cancel (RBF)

Both are ordinary pipeline sends with a pinned nonce and a `Replaces` link, reusing §5.1
wholesale via `service.Speedup`/`service.Cancel`. **Bump rule:** `newTip =
max(quote(fast).PriorityFee, ceil(oldTip × 1.125))`, `newMaxFee = max(quote(fast).MaxFee,
ceil(oldMaxFee × 1.125))` (12.5% clears geth's 10% `pricebump` with margin; re-quoting at
`fast` handles a moved market). Explicit `--max-fee`/`--priority-fee` override the quote
but are validated against the +12.5% floor → exit 9 (`tx.replacement_underpriced`) if
below.

- **`tx speedup <hash>`** requires a journal record (Daxie-originated; foreign hashes →
  exit 10, `ref.not_found`). Precondition: no receipt yet (already mined → exit 9,
  `tx.already_mined`). Rebuilds the identical tx, bumped fees, re-runs policy. **Value is
  NOT re-counted** (at most one of the two can land); only the *positive delta* in
  worst-case gas counts, **enforced** against the daily limit (exit 3 on breach — else
  repeated speedups would be a spend-limit bypass). Old/new records cross-link
  (`replaced_by`/`replaces`); whichever mines flips the other to `replaced`.
- **`tx cancel <hash>`** replaces with a **0-value self-send** (`to = from`), gas 21000,
  same bump rule, journal `kind: "cancel"`. Allowlist satisfied trivially (self). Policy
  counts only the gas delta. The spend-limit exemption is **bounded, not blanket**: a
  cancel may proceed with the daily budget exhausted **only when its fees come from the
  bump formula** (gas delta *recorded*, never *denied* — `policy show` flags the overage,
  because the extra spend is capped at `21000 × formula maxFee`). **Explicit
  `--max-fee`/`--priority-fee` above the formula are ordinary gas spend**: the full delta
  is enforced (exit 3) — else "cancel" would be an unbounded fee-drain bypass.

| Operation | Worst-case-gas-delta daily-limit treatment | `max-gas-price` cap |
|---|---|---|
| `speedup` | **enforced** — exit 3 on breach | enforced |
| `cancel` at formula fees | **recorded, never denied** — counter may exceed cap; flagged in `policy show` | enforced |
| `cancel` with overrides above formula | **enforced** — exit 3 on breach | enforced |

**Corner case decided:** during a fee spike the mandatory +12.5% bump can exceed
`max-gas-price`, making *any* replacement un-signable. Daxie refuses with
`policy.denied.gas_cap` (sub-reason `gas_cap_below_bump_floor`, exit 3): the nonce queue
is wedged pending admin action, a market fall, or the original mining/evicting — agents
surface that sub-reason to the operator rather than retrying. Both accept
`--wait`/`--confirmations`/`--timeout` with §5.3 semantics.

### 5.6 The journal (`internal/journal`)

**Format decision: JSONL + flock, not pure-Go sqlite.** The journal holds
Daxie-originated txs only (thousands of records, three query shapes); a linear fold over
a few MB is microseconds. `modernc.org/sqlite` is ~9 MB of machine-translated C in a
*wallet's* trusted computing base for a key-value workload, brings a second crash model
(WAL), and disclaims network filesystems (K8s PVCs are often NFS/EFS). JSONL needs only
`gofrs/flock` (via `fsx`) and `oklog/ulid` (IDs), maps 1:1 onto the required
write-temp+rename+fsync discipline, and is `cat`/`jq`-debuggable on a wedged pod.
Trade-off accepted: no indexes, no multi-key transactions — microseconds at journal
scale; a future indexer add-on gets its own store behind `Discovery`.

**Layout & write discipline.** `$DAXIE_STATE_DIR/journal/<chainID>.jsonl` (one file per
chain, append-only) + `$DAXIE_STATE_DIR/locks/journal-<chainID>.lock` (sidecar). Every
append acquires the journal flock, **opens the file fresh by path** (`O_APPEND` — never a
long-lived fd, so an append after another process's compact-rename lands in the live
file, not the unlinked old inode), reads the current max `seq` and assigns `seq+1` under
the lock, writes one record = one line = one `write(2)`, fsyncs, closes, releases.
**Lock ordering (binding, everywhere): account lock → journal lock** — the
`tx status`/`tx list` reconcile path takes only the journal flock and never subsequently
acquires an account lock, so a status query can never deadlock against an in-flight send.
Torn/corrupt-line tolerance: a non-parsing line is skipped with a stderr warning (never
fatal); a non-parsing *final* line is truncated to the last newline; records are
last-wins-per-id, so a skipped mid-file line loses at most one transition reconciliation
re-derives from the chain. Compaction (under the same flock, when superseded lines > 5000
or the file > 8 MiB): rewrite latest-snapshot-per-id to a temp file, `fsx.WriteAtomic`.
Terminal records are **kept** — the journal *is* `tx list` history. IDs are **ULIDs**.

**Record schema** (uint256 quantities are decimal strings; `kind` ∈ `eth-transfer |
erc20-transfer | erc721-transfer | erc1155-transfer | approve | contract-call | cancel |
speedup` — a `contract send` whose calldata the §4.2 classifier recognizes as an
approve/transfer/permit is journaled under that **classified** kind (`approve` /
`erc20-transfer` / etc.), so `tx list` stays truthful; only an *unrecognized* call is
`contract-call`, with `asset:{ "kind": "contract" }` carrying the target contract address
and `amount: null` (`value_wei` always carries `msg.value`). `source:"mcp"` on an MCP
`contract_send` gives the operator an audit trail that an agent invoked the broadest-reach
signing tool. RBF/`replaces`/`replaced_by`, nonce, raw_tx, fees, reservation_id, receipt,
and the full status lifecycle are identical to any other tx;
`status` ∈ `signed | broadcast | pending | mined | confirmed | reverted | replaced |
dropped | failed`; `signed` = journaled before broadcast, `broadcast` = after broadcast
succeeds — the §5.1 reconciliation discriminator; `source` ∈ `cli | mcp | mcp:<principal>`):

```json
{
  "v": 1, "id": "01J9ZD3A6K2Q4XH8YQ0VBM5T2N", "seq": 3, "ts": "2026-06-15T17:04:05.123Z",
  "chain_id": 1, "network": "mainnet", "kind": "erc20-transfer", "status": "pending",
  "source": "cli", "from": "0x52ae...", "to": "0xdef1...", "nonce": 187,
  "tx_hash": "0x9c1f...", "raw_tx": "0x02f8b1...", "value_wei": "0",
  "asset": { "kind": "erc20", "contract": "0xa0b8...", "alias": "USDC",
    "decimals": 6, "amount": "25000000", "token_id": null },
  "fees": { "type": "eip1559", "gas_limit": 65000,
    "max_fee_per_gas": "30000000000", "max_priority_fee_per_gas": "1000000000",
    "gas_price": null, "speed": "normal" },
  "reservation_id": "01J9ZD...", "worst_case_gas_wei": "1950000000000000",
  "replaces": null, "replaced_by": null,
  "receipt": { "block_number": 19000123, "block_hash": "0x77aa...",
    "gas_used": 48211, "effective_gas_price": "12100000000", "status": 1 },
  "error": null, "rpc": "mainnet-alchemy"
}
```

**Nonce manager (same package).** Single-writer-per-account is the documented rule
(parallel hosts are out of contract). `AcquireNonce` takes the account lock, reconciles,
then `NextNonce(chainID, addr) = max(chainPending, localNext, journalNext)` where
`journalNext = max(nonce over ALL records that consumed an on-chain nonce — every status
EXCEPT failed) + 1`. Folding over terminal records too makes "the journal is the source
of truth for nonces" literally true: a consumed nonce can never be re-allocated even when
the cache is stale and the RPC lags. `--nonce N` bypasses derivation but still takes the
lock and journals. A `chainPending` exceeding the local view with no in-flight records
emits a single single-writer-violation warning and adopts the chain value. The `Lease`
API makes the §5.1 ordering explicit: `Commit()` writes `next = nonce+1` (only after the
broadcast outcome); `Release()`/abort frees the lock without committing.

**Restart reconciliation** runs inside every `AcquireNonce` and on `tx status`/`tx
list`/`service.Open` (`journal.Unresolved()`). For each non-terminal record it queries
the receipt/nonce **first**, then branches: (i) unknown/pending → re-broadcast the
persisted bytes (tolerating `already known`); (ii) receipt found → advance to
`seen-on-chain` + reconcile gas (the mined-while-down case, do **not** re-broadcast); (iii)
`nonce too low` with no receipt for this hash → mark **superseded** (`replaced`), never
auto-reclaim. Before any rebroadcast it runs the two same-nonce gates (§5.3 rebroadcast
rule). `service.AbandonTx(hash)` (exposed as `daxie tx abandon`) is the operator escape
hatch: it voids a signed-never-broadcast record (`failed` + `Release()` + the
next-nonce cache lowered to the journal next so the freed nonce is reused, not left a
gap). It refuses a record that already shows a recorded broadcast.

### 5.7 CLI-wide exit codes (stable, binding)

This is the single exit-code registry the whole CLI surface maps onto. Cobra runs with
`SilenceErrors` + central error mapping (in `cli/render.go`) so every command exits
through this table. The mapping key is the canonical dotted `domain.Error.Code` string;
the string namespaces finer causes *within* one exit number, so the numeric set stays
small and agent-branchable while the code preserves precision. With `--json`, errors emit
a structured envelope on **stderr** (stdout keeps the single-result contract):

```json
{"error":{"code":"policy.denied.day_limit","exit":3,"message":"…","retryable":true,"data":{…}}}
```

MCP tool errors carry the **same** `code`/`exit` fields (`isError:true`), so agents
branch identically on both frontends. Numbers 0–12 are assigned; 13–63 reserved; 64+
never used (avoids BSD `sysexits` collisions).

| Exit | Name | Meaning | Representative codes |
|---|---|---|---|
| 0 | `OK` | success; with `--wait`: **confirmed**; `receive`: target reached (a no-wait `tx send` exits 0 on accepted broadcast — 0 ≠ mined there, by design) | — |
| 1 | `INTERNAL` | Daxie bug / unexpected panic | `internal` |
| 2 | `USAGE` | bad input: unknown flag/alias/account, malformed address/amount, `--max-fee` on a legacy chain, confirmation needed but no TTY and no `--yes`, an out-of-range `config set` value, a `contract logs` range over the 100k-block cap | `usage.*`, `usage.bad_value`, `usage.log_range_too_wide`, `ref.ambiguous`, `usage.confirmation_required` |
| 3 | `POLICY_DENIED` | guardrail refusal *before signing*: per-tx/daily limit, allowlist miss, `max-gas-price` cap (incl. RBF bump floor > cap), ENS pin mismatch, unlimited-approve without ceremony, token/approval path with limits-but-no-allowlist and no admin override, `contract send` with an unrecognized selector to a non-allowlisted/un-opted-in contract (stage 5b) | `policy.denied.tx_limit`, `policy.denied.day_limit`, `policy.denied.allowlist`, `policy.denied.gas_cap`, `policy.denied.pin_drift`, `policy.denied.no_allowlist`, `policy.denied.typed_data`, `policy.denied.unlimited_unacked`, `policy.denied.contract_call` |
| 4 | `AUTH` | wrong/missing keystore passphrase; undecryptable keystore | `keystore.bad_passphrase`, `keystore.confirm_required` |
| 5 | `INSUFFICIENT_FUNDS` | balance < value + worst-case gas (build-time or node-reported) | `funds.insufficient` |
| 6 | `NETWORK` | RPC unreachable/timeout/5xx; broadcast transport failure (state journaled; resumable) | `rpc.unreachable` |
| 7 | `REVERTED` | tx mined with `status 0x0` (also: estimation revert with reason) | `tx.reverted` |
| 8 | `TIMEOUT_PENDING` / `SEAL` | deadline hit, tx still pending / `receive` still listening — **not a failure**; AND the policy seal/rollback/admin-auth/state class — **all signing halted** | `tx.wait_timeout`, `receive.timeout`, `policy.seal_violation`, `policy.rollback`, `policy.admin_auth`, `policy.state_error` |
| 9 | `TX_CONFLICT` | nonce/replacement family: replaced by another tx, replacement underpriced, speedup/cancel target already mined, `nonce too low` | `tx.replaced`, `tx.replacement_underpriced`, `tx.already_mined`, `tx.nonce_gap` |
| 10 | `NOT_FOUND` / `READONLY` | unknown journal/tx/network/rpc/contact/account reference; read-only **config** mutation attempted; read-only **keystore** mutation attempted | `ref.not_found`, `config.read_only`, `keystore.read_only` |
| 11 | `STATE` | state-dir problems: lock-acquisition timeout, corrupt journal beyond tolerance | `state.lock_timeout`, `state.corrupt` |
| 12 | `INTEGRITY` | tamper/misconfig tripwires: endpoint `eth_chainId` ≠ declared network; a **broadcast-recorded** journal record (a counted tx) whose policy reservation has vanished (impossible absent counter-file tampering) | `rpc.chain_id_mismatch`, `tx.integrity.reservation_missing` |

**Branching contract for agent authors:** **3 vs 5 vs 6 vs 7 vs 8 vs 9** are the codes a
send loop switches on — deny (escalate to operator), top up, retry later, investigate
revert, keep waiting, re-quote/replace.

> **Reconciliation note (the exit-code table).** The Architecture's §3.8 enum and this
> registry disagreed on several numbers (e.g. the Architecture used 5=policy, 8=network;
> this registry uses 3=policy, 6=network). The provider corpus (policy, MCP, threat,
> milestone) was written against **this** 0–12 registry and all four cite it as the
> single source of truth, so it is adopted canonically and the Architecture's §3.8
> numeric assignment is superseded (the dotted code *strings* from §3.8 are preserved as
> the wire codes; only the integer projection changes). Two consequences worth stating
> plainly: **policy-denied = exit 3** (not 5), and the seal/rollback/auth/state class +
> `tx_timeout`/`receive_timeout` share **exit 8** (the "wall is broken or still waiting"
> class). `config.read_only` and `keystore.read_only` are **exit 10** (conflict/not-found
> class), not a separate code (§11, D3).

### 5.8 `daxie receive` detection engine (`service/receive.go`)

`daxie receive` blocks until the account receives the expected asset and it reaches the
confirmation target — the inbound counterpart that completes the agent-to-agent payment
loop. The detection core consumes block heads and is transport-agnostic; **v1 ships
polling only** (`receive.poll-interval = 4s`), and the v1.1 WebSocket upgrade changes
*only* the head source (`chain.SubscribeNewHead` already exists and returns
`ErrNotSupported` on HTTP — the fallback signal). `--new` derives the wallet's next index
(a keystore `meta.json` write, so it **requires a writable keystore** —
`keystore.read_only` on a Secret mount; invoice deployments use a PVC).

**Token/NFT detection** (`eth_getLogs` via `chain.FilterLogs`): ERC-20 by `topic0 =
keccak("Transfer(address,address,uint256)")` with 3 topics (recipient `topic2`, amount
`data`); ERC-721 same `topic0` with 4 topics (tokenId `topic3`); ERC-1155 by
`TransferSingle`/`TransferBatch` topics (recipient `topic3`). Topic-count disambiguates
ERC-20 from ERC-721; the registry's declared kind is cross-checked. Each matching log
yields a `detected` event carrying the emitting `tx_hash`/`log_index`, tagged
`attribution:"log"` (**attributable** — the transfer is bound to a specific tx and log).

**ETH detection** (decided mechanics — no logs exist for plain value transfer), per new
block `N`: (1) **block scan (primary, attributable)** — `eth_getBlockByNumber(N, true)`,
every tx with `to == addr && value > 0` → a `detected` event with `tx_hash/from/value`,
`attribution:"tx"`; (2) **balance delta (safety net, unattributable)** —
`Δ = balance(N) − balance(N−1)`, with `unattributed = Δ − Σ(direct inbound in N) +
Σ(outbound value + actual fees of own txs in N)`, where own outbound txs are identified
from the same block-scan response and their **receipts fetched** so the fee term is
actual `gasUsed × effectiveGasPrice` (the journal's worst-case gas is **never** used here
— it would inflate `unattributed` into a phantom inbound detection). `unattributed > 0` →
a `detected` event with `tx_hash:null`, `attribution:"balance-delta"` (catches internal
transfers — a contract sending ETH via `CALL`, invisible to block scanning and to public
RPCs that lack `trace_*`); `unattributed < 0` → clamp to zero and warn (a negative residue
means ETH left through a path the scan can't see). All three attribution kinds count
toward the cumulative target, but only the two **attributable** kinds — `attribution:"tx"`
(ETH block-scan) and `attribution:"log"` (token/NFT logs) — can satisfy `--exact`; the
unattributable `attribution:"balance-delta"` cannot (it has no single transfer to equal `X`).

**Confirmation, reorg, archive-independence.** A detection at block `B` reaches
`confirmed` when `head − B + 1 ≥ target` (same per-network resolution as sends), at which
point the evidence is **re-verified** (logs → re-fetch + compare blockHash + receipt
status; direct txs → receipt block hash; balance deltas → re-read balances at `B−1/B`).
Reorged-out detections emit `reorged` and subtract from the cumulative counter. `receive`
keeps **no persistent state** (stateless & resumable): resume state lives on the chain
(token/NFT logs) or in the captured event stream (ETH). The ETH baseline is captured
**once** at listen start and **carried forward incrementally at the chain head, never
re-queried at a fixed historical block** — the shipped public RPCs are pruning full nodes
(state beyond ~128 blocks returns `missing trie node`), and the default is an *unbounded*
invoice wait, so a re-query of `listenStartBlock` would break after ~25 minutes. Crash
restart is resumable from the event stream alone: every post-`listening` event carries
`last_scanned`, `cumulative_confirmed`, and `remaining`, and a `heartbeat` fills quiet
periods, so a supervisor re-runs with `--from-block <last_scanned + 1> --amount
<remaining>` from the **last captured line**. **Completion:** no asset flags → any inbound
ETH; `--amount X` (with optional `--token`) → cumulative; `--exact` → one single transfer
equal to `X`; `--nft c#id` → that token arrives (1155 `--amount` = cumulative quantity).
ETH resume is explicitly weaker (balance-delta detections can't be reconstructed across a
gap) — docs tell agents to check `daxie balance` before resuming, and the `--new`
fresh-address path is immune by construction.

**The receive event stream (NDJSON on stdout).** The one sanctioned exception to the
single-object-on-stdout rule: line-delimited events on stdout (humans get the same events
rendered to the terminal). These map 1:1 onto `domain.Event` (§5.9). All amounts are
base-unit decimal strings; `"v":1` on every line.

```json
{"v":1,"event":"listening","address":"0x52ae...","network":"mainnet","chain_id":1,
 "asset":{"kind":"erc20","contract":"0xa0b8...","alias":"USDC","decimals":6},
 "target":{"mode":"cumulative","amount":"100000000","confirmations":2,"timeout":null},
 "from_block":19000200,"ts":"2026-06-15T17:00:00Z"}

{"v":1,"event":"detected","tx_hash":"0x9c1f...","log_index":7,"from":"0xbeef...",
 "value":"60000000","token_id":null,"block":19000208,"block_hash":"0x77aa...",
 "attribution":"log","match":true,"cumulative_detected":"60000000",
 "cumulative_confirmed":"0","remaining":"100000000","last_scanned":19000208,"ts":"..."}

{"v":1,"event":"confirming","tx_hash":"0x9c1f...","confirmations":1,"target":2,
 "cumulative_confirmed":"0","remaining":"100000000","last_scanned":19000209,"ts":"..."}

{"v":1,"event":"confirmed","tx_hash":"0x9c1f...","value":"60000000",
 "cumulative_confirmed":"60000000","remaining":"40000000","last_scanned":19000210,"ts":"..."}

{"v":1,"event":"reorged","tx_hash":"0x9c1f...","value":"60000000",
 "cumulative_confirmed":"0","remaining":"100000000","last_scanned":19000212,"ts":"..."}

{"v":1,"event":"heartbeat","cumulative_confirmed":"60000000","remaining":"40000000",
 "last_scanned":19000240,"ts":"..."}

{"v":1,"event":"complete","cumulative_confirmed":"100000000",
 "tx_hashes":["0x9c1f...","0x3d2b..."],"address":"0x52ae...",
 "last_scanned":19000260,"exit":0,"ts":"..."}

{"v":1,"event":"timeout","cumulative_confirmed":"60000000","remaining":"40000000",
 "last_scanned":19000275,
 "resume":"daxie receive --account treasury/payroll --token USDC --amount 40 --from-block 19000276",
 "exit":8,"ts":"..."}
```

The contract is exact: `confirmed` is the **per-transfer** event (one per confirmed
inbound transfer), **never terminal**; `complete` is the **single terminal** success line
carrying the process `exit`; on timeout the terminal line is `timeout` (exit 8,
resumable). **Agents wait on the terminal `complete` line, not a final `confirmed`.** The
`timeout.resume` string is executable as-is — `--amount` carries the **remaining** amount
at **full fixed-point precision** (every `decimals` digit, never rounded down — a
rounded-down resume amount would let an agent under-charge the counterparty; the raw
base-unit `…wei` form is an unambiguous alternative), and `--from-block` is
`last_scanned + 1` so gap arrivals are scanned while already-counted ones are not
re-counted. ETH listens append `"note":"verify balance before resuming"`.

> **Wire-contract supersession (both surfaces updated).** cli-spec and requirements §4
> originally fixed the stream as `listening → detected → confirmed`, with `confirmed` as
> the *terminal* success line. A cumulative/multi-transfer listen needs both a
> *per-transfer* confirmation signal **and** a single terminal line carrying the exit
> code, so the canonical stream is **`listening → detected → confirming → confirmed
> (per-transfer) → complete`** (OQ #20). cli-spec.md and requirements.md are updated to
> this same stream (§11, D8). The MCP `receive` tool maps the same events to progress
> notifications plus a final structured result (§6.5).

### 5.9 Events — the one streaming seam (`EventSink`)

Four distinct requirements demand a progress stream: `--wait` confirmation progress to
stderr; `receive`'s NDJSON; MCP progress notifications; and the v1.1 HTTP server's
SSE/chunked progress. The core emits to one function-typed sink — a single callback, the
lightest seam that still lets the daemon plug in. **One sink type does NOT mean one
stream destination:** the *frontend* routes per use case — `send`/`wait` progress to
**stderr** ("never stdout"), `receive`'s NDJSON to **stdout** (the address up front,
agents parse the terminal line). The `Event` carries enough — its `Kind`, a `Stream`
hint, and the terminal `Exit` code — for the frontend to pick the right renderer and
`io.Writer`.

```go
package domain
type EventKind string
const (
    EvResolved   EventKind = "resolved"     // ENS/contact resolved (echo before signing)
    EvEstimated  EventKind = "estimated"
    EvPolicyOK   EventKind = "policy_ok"
    EvSigned     EventKind = "signed"
    EvBroadcast  EventKind = "broadcast"
    EvConfirmation EventKind = "confirmation"
    EvListening  EventKind = "listening"    // receive — address emitted, now blocking
    EvDetected   EventKind = "detected"
    EvConfirming EventKind = "confirming"
    EvConfirmed  EventKind = "confirmed"    // receive — ONE PER confirmed inbound transfer (NOT terminal)
    EvComplete   EventKind = "complete"     // receive — the SINGLE terminal success line (carries Exit)
    EvTimeout    EventKind = "timeout"      // receive — the terminal line on timeout (carries Exit)
)
type Event struct {
    Kind    EventKind      `json:"event"`
    Hash    string         `json:"hash,omitempty"`
    Address common.Address `json:"address,omitempty"`
    Conf    uint64         `json:"confirmations,omitempty"`
    Target  uint64         `json:"target,omitempty"`
    Detail  string         `json:"detail,omitempty"`
    Exit    *int           `json:"exit,omitempty"`   // carried by the TERMINAL receive lines
    Stream  string         `json:"-"`                // "stdout" (receive) | "stderr" (send/wait)
}
type EventSink func(Event)  // nil sink = no progress (the common fire-and-return case)
```

### 5.10 End-to-end data flow (both frontends, identical core path)

`daxie tx send --to vitalik.eth --amount 0.5 --wait --json --yes`:

```text
cli/tx.go (~30 lines)
  • bind pflags/env/stdin → domain.TxRequest{From, To:"vitalik.eth", Amount:"0.5",
    Wait:{Enabled:true}, Confirm:true}
  • acquire passphrase via the §3.6 precedence; wrap as a domain.Unlocker
  • svc,_ := service.Open(ctx, opts); defer svc.Close()
  • sink := render.StderrProgress(jsonMode)        // SEND/WAIT progress → stderr
  • res,err := svc.SendTx(ctx, domain.LocalPrincipal(), req, sink)
  • render.Result(res) | render.JSON(res); os.Exit(render.ExitFor(err))
        │
        ▼
service.SendTx  (THE one pipeline — byte-identical for both frontends)
  1. Resolve From; resolve To: literal→contact→ens (ens.ResolvePinned if allowlisted ENS)
     → domain.Dest. emit EvResolved (the "echo resolved address before signing" rule).
  2. Resolve gas: flag>env>config>estimate. emit EvEstimated.
  3. PRE-FETCH (before any lock): resolved-To addr + base fee, rpc.timeout-bounded.
  4. authorize: flock → policy.Evaluate (limits/allowlist/fail-closed) → policy.Reserve
     (durable counter) → journal.NextNonce + Reserve(RESERVED) → signer.SignTx (emit
     EvSigned) → journal.MarkSigned(raw,hash) BEFORE broadcast. defer-abort unless committed.
  5. broadcast → SendRawTransaction. emit EvBroadcast{hash}. journal.MarkBroadcast.
  6. --wait: poll Receipt to target. emit EvConfirmation per block. reverted→settle+ErrReverted;
     timeout→settle(pending,gas=0)+ErrTimeout; confirmed→settle(commit ACTUAL gas). committed=true.
  7. return TxResult{Status, Confirmations, Hash, ...}.
```

The MCP `send` tool builds the *same* `domain.TxRequest`, calls the *same*
`service.SendTx`, serializes the *same* `domain.TxResult`. Guardrails are not
re-implemented per frontend — they live inside `authorize`, which both paths traverse
(§6.4). `receive` is the one command whose stream is the PRIMARY output on stdout: the
frontend selects `render.NDJSONStdout`, the core emits `listening → detected → confirming
→ confirmed (per inbound) → complete (terminal)`, and the exit code is also carried in the
terminal line's `Exit` so agents read it from the stream without inspecting `$?`.

### 5.11 `contract call` / `logs` / `encode` / `decode` — the pure read paths

These four `daxie contract` verbs deliberately **bypass** the §5.1 pipeline (no account lock, no nonce, no journal, no policy, no passphrase, no `Signer` unlock — they never reach `authorize`, §2.7), so they belong with the pipeline they sidestep:

- **`contract call`**: resolve ABI → coerce args → `chain.CallContract` (optional `--from` via `Signer.Address`, the explicitly unlock-free method §2.6; optional `--block`, nil=latest, numeric per cli-spec, `safe`/`finalized` tags reserved not in v1) → `abi.UnpackReturns` → labeled `DecodedValue[]`. Accepts raw `0x`/ENS contract refs and a raw `0x`/ENS `--from` freely.
- **`contract logs`**: resolve ABI → build `ethereum.FilterQuery` (`q.Addresses=[contract]`, `q.Topics[0]=keccak(eventSig)`, indexed-arg filters → positional `q.Topics[i]` via `abi.PackEvent`; a filter on a non-indexed arg is `usage.*` exit 2; the total `--from-block`..`--to-block` span is capped at 100,000 blocks — a wider range is `usage.log_range_too_wide` (exit 2), paged with successive windows — then chunked by the existing §5.8 `receive.max-log-range` 1000-block splitter, no new config key) → `chain.FilterLogs` → `abi.UnpackLog` per log → `DecodedLog[]`.
- **`contract encode`/`decode`**: **no chain client at all** — `abi.PackCall` / `abi.UnpackCalldata` over the resolved ABI. Pure functions for relayers/meta-tx/debugging.

All four return through the §5.7 taxonomy: ABI/arg errors → `usage.*` (exit 2); unknown contract alias → `ref.not_found` (exit 10); RPC failure → `rpc.unreachable` (exit 6); `eth_call` revert → `tx.reverted` (exit 7, with the decoded revert reason). **No exit 3 is reachable from a read path** — they never touch policy (the cli-spec invariant).

---

## 6. MCP server

`internal/mcpserver` is Frontend 2, grounded in the official MCP Go SDK
(`github.com/modelcontextprotocol/go-sdk/mcp`): `mcp.AddTool[In, Out]` with input and
output schemas **inferred from the `In`/`Out` Go types** (`jsonschema:"…"` struct tags
become property descriptions); `*mcp.StdioTransport` (v1) and
`mcp.NewStreamableHTTPHandler` (v1.1); progress via
`req.Session.NotifyProgress(ctx, *ProgressNotificationParams)` gated on the client's
progress token. Three rules drive every decision:

1. **The MCP server is a frontend, not a service.** It imports **only** `service`
   (+ `version`, `ethunit`) — never any provider (depguard fails CI otherwise). A handler
   therefore *cannot* contain business logic: the types it would need aren't importable.
   Each handler is `args → one service method → result`, ~20 lines.
2. **Schemas are derived, never hand-written.** The `In` type of every `AddTool` call
   **is a `domain` request struct**; the `Out` type **is a `domain` result struct**. The
   CLI binds its flags into the *same* structs, so CLI/MCP schema drift is impossible by
   construction; a golden-snapshot test on `daxie mcp tools` turns any struct change into
   a reviewed diff.
3. **Guardrails bind below the frontend.** `policy.Reserve` (and pure `Evaluate` for
   permits) runs *inside* `service.SendTx`/`Approve`/the signing methods, the only way
   either frontend can reach `domain.Signer`. There is no second signing path to audit.

A direct consequence: **policy mutation and key material never become tools** (§6.1).

> **Reconciliation note (types).** The MCP part referenced `core.Daxie`, `core.TxRequest`,
> `core.Err`, and `core.WithPrincipal`. Canonically these are `service.Service`,
> `domain.TxRequest`, `domain.Error`, and the service ctx helpers (§2.4). The
> unlimited-approval ack field is **`acknowledge_unlimited`** (mapping to `Check.Acked`).

### 6.1 Tool surface and deliberate omissions

**v1 ships 31 tools**, one per *operation* (not per asset — a single `send` covers
ETH/ERC-20/ERC-721/ERC-1155, disambiguated by the `asset` field; and
`contract_call`/`contract_send` cover every *non-standard* ABI behind a single read/sign
pair, disambiguated by the function name + ABI source):

| # | Tool | Mirrors | Service method | Input → Output |
|---|---|---|---|---|
| 1 | `balance` | `daxie balance` | `Balance` | `BalanceQuery` → `BalanceResult` |
| 2 | `token_list` | `daxie token list` | `ListTokens` | `RegistryQuery` → `TokenListResult` |
| 3 | `token_info` | `daxie token info` | `TokenInfo` | `TokenInfoQuery` → `TokenInfo` |
| 4 | `nft_list` | `daxie nft list` | `ListNFTs` | `NFTQuery` → `NFTListResult` |
| 5 | `send` | `tx send` / `nft send` | `SendTx` | `TxRequest` → `TxResult` |
| 6 | `tx_status` | `tx status` | `TxStatus` | `TxRef` → `TxResult` |
| 7 | `tx_wait` | `tx wait` | `WaitTx` | `TxWaitRequest` → `TxResult` |
| 8 | `tx_list` | `tx list` | `ListTxs` | `TxListQuery` → `TxListResult` |
| 9 | `tx_speedup` | `tx speedup` | `Speedup` | `TxRBFRequest` → `TxResult` |
| 10 | `tx_cancel` | `tx cancel` | `Cancel` | `TxRBFRequest` → `TxResult` |
| 11 | `receive` | `daxie receive` | `Receive` | `ReceiveRequest` → `ReceiveResult` |
| 12 | `token_approve` | `token approve` | `Approve` | `ApproveRequest` → `TxResult` |
| 13 | `token_revoke` | `token revoke` | `Approve` (amount 0) | `RevokeRequest` → `TxResult` |
| 14 | `token_allowance` | `token allowance` | `Allowance` | `AllowanceQuery` → `AllowanceResult` |
| 15 | `sign_message` | `sign message` | `SignMessage` | `SignMessageRequest` → `SigResult` |
| 16 | `sign_typed_data` | `sign typed` | `SignTyped` | `SignTypedRequest` → `SigResult` |
| 17 | `verify` | `daxie verify` | `Verify` | `VerifyRequest` → `VerifyResult` |
| 18 | `wallet_list` | `wallet list` | `ListWallets` | `WalletListQuery` → `WalletListResult` |
| 19 | `wallet_show` | `wallet show` | `ShowWallet` | `WalletRefQuery` → `WalletInfo` |
| 20 | `accounts_list` | `account list` | `ListAccounts` | `AccountListQuery` → `AccountListResult` |
| 21 | `account_show` | `account show` | `ShowAccount` | `AccountRefQuery` → `AccountInfo` |
| 22 | `gas` | `daxie gas` | `Gas` | `GasQuery` → `GasQuote` |
| 23 | `convert` | `daxie convert` | `Convert` (pure) | `ConvertRequest` → `ConvertResult` |
| 24 | `ens_resolve` | `ens resolve` | `ResolveENS` | `ENSQuery` → `ENSResult` |
| 25 | `ens_reverse` | `ens reverse` | `ReverseENS` | `AddressQuery` → `ENSResult` |
| 26 | `policy_show` | `policy show` | `PolicyShow` | `Empty` → `PolicyView` |
| 27 | `contract_call` | `contract call` | `ContractCall` | `ContractCallRequest` → `ContractCallResult` |
| 28 | `contract_logs` | `contract logs` | `ContractLogs` | `ContractLogsRequest` → `ContractLogsResult` |
| 29 | `contract_encode` | `contract encode` | `EncodeCalldata` (pure) | `EncodeRequest` → `EncodeResult` |
| 30 | `contract_decode` | `contract decode` | `DecodeCalldata` (pure) | `DecodeRequest` → `DecodeResult` |
| 31 | `contract_send` | `contract send` | `ContractSend` | `ContractSendRequest` → `TxResult` |

**Deliberately NOT tools** (a recorded, non-regressable security boundary):

| Excluded | Why it must never be an MCP tool in v1 |
|---|---|
| All `policy` mutations (`policy set/allow/deny`, the bootstrap `policy set`, `reset`, `change-admin-passphrase`, `typed allow/remove`, `contract allow/remove`) | Policy mutation requires the **admin passphrase the agent never holds** (requirements §5). Exposing it would defeat the privilege separation — a compromised agent could raise its own limits or opt its own unknown-calldata triple into `contracts_allowed[]`. CLI/operator-only, out-of-band. `policy_show` (read-only) **is** exposed. |
| Key export (`wallet/account export`) | A prompt-injected agent must not exfiltrate key material through its own tool channel (§3.9). No tool, ever, in v1. |
| Key/wallet import & create (`wallet create/import`, `account import`) | Creating a wallet emits a mnemonic once (a secret-emitting op); importing ingests a mnemonic/key over the tool channel (a path an injected prompt could abuse to plant an attacker key). Operator-only. |
| `account derive`/`alias`/`use` | Keystore-index/default-pointer mutations; over a read-only Secret-mounted keystore they fail `keystore.read_only` anyway. The fresh invoice address an agent legitimately needs is delivered by **`receive`'s `new:true`** — the one derivation path on the agent surface. |
| `keystore change-passphrase` | Administration is CLI-only; rotating the unlocking secret from inside the agent channel is a privilege the agent must not have. |
| `network`/`rpc` mutations | Config-class deploy-time topology that fails on a read-only ConfigMap by design; they write **secret references** — operator acts. (Read-only `rpc test` is not exposed either — a debugging affordance.) |
| `wallet/account delete`, `token/nft/contacts remove/rename` | Destruction is an operator act; clear blast-radius reduction. |
| `token_add` / `nft_add` / `contacts_add` **/ `contract_add`** | The registry is a *security boundary*: an alias resolves **only** through the local registry (never on-chain symbol, requirements §2). Letting a prompt-injected agent `token_add 0xFAKE --name usdc` (or `contract_add staking 0xFAKE --abi …`) would let it redefine what an alias means for every later `send`/`contract_send` — a spoofing primitive. `contract_add` is **strictly worse**: it also plants an attacker-chosen ABI that mis-decodes args for every later `contract_send staking …`, so the exclusion is even less negotiable. Deferred to v1.1 behind per-principal policy. The escape hatch costs nothing: any tool taking an asset/destination/contract accepts a **raw 0x address** (and `contract_call`/`contract_send` additionally accept an inline `abi`/`sig`), so withholding the add-tools blocks the *spoofing* path without blocking the *transacting* path. |
| `contract_remove`, `contract_list`/`contract_show` (registry mutations + introspection) | Mutations are an operator act (same blast-radius reduction as `token/nft/contacts remove/rename`; the contract registry has no `rename` verb — §2.4, §7.8, §10.2 expose only add/list/show/remove). The read introspection is omitted too: the agent transacts by raw address + inline ABI and never needs the operator-curated alias map (exposing it is a mild recon affordance, and there is no `token_list_aliases`-style read tool for the spoofable registries on the v1 agent surface). The matching reads land in v1.1 alongside `contract_add` behind per-principal policy — keeping the count delta clean at **+5**, not +7. |
| `mcp serve`/`mcp tools`/`version`/`completion`/`config` | Self-referential or shell-only. |

The shape of the exclusions is one sentence: **the MCP surface can move funds *within
policy* (including arbitrary `contract_send` calls the calldata classifier has bound to
the typed approval ceremonies) and read everything; it cannot change who holds the keys,
change what the keys are allowed to do, change what an alias means (token, NFT, contact,
*or contract+ABI*), or read a key out.**

> **Reconciliation note (registry-add tools).** The Architecture's §4.2 tool table
> listed `token_add`/`nft_add`/`contacts_add` as agent tools (registries are agent-mutable
> state-dir data). The MCP part **tightened** this in the agent-safety direction the
> requirements mandate (the alias-spoofing argument above) and deferred the three to v1.1
> behind a per-principal policy. The canonical surface is the tightened **31-tool** set
> (the original 26 + the five `contract` tools); the divergence is recorded as a deliberate
> security tightening, not a contradiction (§11, D8). It is the one place this section
> narrows the Architecture's larger list, and only ever toward less agent capability. The
> `daxie contract` noun (requirements #29) is a pure extension of this surface: its four
> read/pure verbs + `contract_send` become tools, while `contract_add` + the contract
> registry mutations/introspection join the deferred registry-add set under the **identical**
> alias-spoofing argument — no Architecture row narrowed, the same direction (less agent
> capability at the spoofing boundary, full capability at the transacting boundary).

### 6.2 Schema conventions

Every tool handler returns `(*mcp.CallToolResult, Out, error)`. The SDK marshals the
typed `Out` into the result's **structured content** (validated against the inferred
output schema), and Daxie additionally puts the same object pretty-printed into one
`TextContent` (so a text-only host sees it too) — the same bytes from the same struct.
The JSON output contract of cli-spec §3 is reused **verbatim**: the `Out` struct is the
result struct the CLI marshals for `--json`. One serialization, two transports.

Field conventions (properties of the `domain` request/result structs): addresses are
`^0x[0-9a-fA-F]{40}$` in output, inputs accept **address | contact | ENS** in
`to`/`spender`/`owner`/`account`; amounts (input) are **decimal strings in asset units**
(never a number — `10^18` is unrepresentable in IEEE-754; the `convert` tool exists so
agents never do `10^18` math); durations are Go duration strings (`"5m"`); `network`/`rpc`
selection is optional (empty = config defaults); `from` is **optional everywhere** (the
default account); enums (`status`, `asset.kind`, `speed`) reach the schema as `enum`s via
jsonschema tags. The only MCP-visible field the CLI expresses through interaction rather
than a struct field is **`acknowledge_unlimited`** — and the Architecture put it directly
on `ApproveRequest`/`SignTypedRequest`, so those structs are shared and **no MCP-only
wrapper exists in v1**. `TxRequest.Yes` carries `json:"-"`, so the SDK never infers it
into the schema (it is a CLI-interaction flag; `Confirm` is wired constant-true over MCP).

### 6.3 Representative tool schemas

The full schemas are inferred from the named structs; the agent-facing **descriptions**
(written for a model deciding which tool to call) are pinned by the §6.7 golden test. Two
representative tools:

**`send` — input (`domain.TxRequest`):**

```json
{
  "type": "object", "additionalProperties": false,
  "description": "Sign and broadcast a transfer. Policy-checked before signing (spend limits, destination allowlist, gas cap). Waits for confirmations by default over MCP.",
  "properties": {
    "from":   {"type": "string", "description": "Account ref. Omit to use the default account."},
    "to":     {"type": "string", "description": "0x address, contact name, or ENS name. ENS is resolved now and echoed in the result."},
    "asset":  {"type": "string", "description": "'eth' (default), a token alias or 0x address, or an NFT 'collection#tokenId'."},
    "amount": {"type": "string", "description": "Decimal amount in asset units (e.g. '0.5'). ERC-1155: quantity. Plain ERC-721: omit."},
    "gas":    {"$ref": "#/$defs/GasOpts"},
    "nonce":  {"type": "integer", "description": "Manual nonce (advanced). Omit to auto-derive."},
    "dryRun": {"type": "boolean", "description": "Build + estimate + policy-check, return the plan, do NOT sign or broadcast."},
    "wait":   {"$ref": "#/$defs/WaitOpts", "description": "Confirmation wait. Over MCP, waiting is the DEFAULT (an absent 'wait' = wait to the network default depth)."},
    "network":{"type": "string"}, "rpc": {"type": "string"}
  },
  "required": ["to"]
}
```

**`send` — output (`domain.TxResult`):** `status` is `enum:["broadcast","confirmed",
"reverted","pending"]` — the agent's branch point (the MCP projection of the CLI's
distinct exit codes). `reverted` is surfaced as a **tool error** (`isError:true`, code
`tx.reverted`) *and* the result carries `status:"reverted"` so an agent inspecting
structured content sees both — the dual-signal mechanism in §6.6.

**`token_approve` — input (`domain.ApproveRequest`):**

```json
{
  "type": "object", "additionalProperties": false,
  "description": "Approve an ERC-20 spender. APPROVALS ARE SPEND-EQUIVALENTS: policy-checked like a transfer (spender must pass the allowlist), and an unlimited approval grants the spender an unbounded allowance over every unit the account ever holds.",
  "properties": {
    "from":    {"type": "string"},
    "token":   {"type": "string", "description": "ERC-20 registry alias or 0x contract address."},
    "spender": {"type": "string", "description": "0x address, contact, or ENS. Must pass the policy allowlist when one is set."},
    "amount":  {"type": "string", "description": "Decimal allowance, e.g. '500'. Omit only with unlimited:true."},
    "unlimited": {"type": "boolean", "description": "Grant an unbounded (max-uint256) allowance. Requires acknowledge_unlimited:true."},
    "acknowledge_unlimited": {"type": "boolean", "description": "Required when the approval is UNLIMITED. Grants the spender an unbounded allowance over the token. Omit unless that is the explicit intent."},
    "gas": {"$ref": "#/$defs/GasOpts"}, "wait": {"$ref": "#/$defs/WaitOpts"},
    "network": {"type": "string"}, "rpc": {"type": "string"}
  },
  "required": ["token", "spender"]
}
```

**Shared `$defs`** (inferred once, referenced everywhere):

```json
{
  "GasOpts": {"type":"object","additionalProperties":false,"properties":{
    "limit":{"type":"integer"},"maxFee":{"type":"string"},"priorityFee":{"type":"string"},
    "gasPrice":{"type":"string","description":"Legacy mode only."},"legacy":{"type":"boolean"},
    "speed":{"type":"string","enum":["slow","normal","fast"]}}},
  "WaitOpts": {"type":"object","additionalProperties":false,"properties":{
    "confirmations":{"type":"integer","description":"Target depth; 0/omit = per-network default (mainnet 2, Sepolia 1)."},
    "timeout":{"type":"string","description":"Go duration, e.g. '5m'. Omit = default 10m."}}},
  "Dest": {"type":"object","properties":{"input":{"type":"string"},"address":{"type":"string"},
    "contact":{"type":"string"},"ens":{"type":"string"}},"required":["input","address"]},
  "Asset": {"type":"object","properties":{"kind":{"type":"string","enum":["eth","erc20","erc721","erc1155"]},
    "contract":{"type":"string"},"tokenId":{"type":"string"},"decimals":{"type":"integer"},
    "symbol":{"type":"string"},"alias":{"type":"string"}},"required":["kind"]},
  "ReceiptInfo": {"type":"object","properties":{"blockNumber":{"type":"integer"},"gasUsed":{"type":"integer"},
    "effectiveGasPrice":{"type":"string"},"status":{"type":"integer","description":"1 success, 0 reverted."}}}
}
```

**`contract_send` — input (`domain.ContractSendRequest`):** the one tool whose description must carry the **selector-classifier guarantee** so a model knows raw calldata does not dodge the approval ceremony:

```json
{
  "type": "object", "additionalProperties": false,
  "description": "Sign and broadcast a state-changing call to ANY contract (the escape hatch for non-standard ABIs). Policy-checked before signing EXACTLY like 'send': the contract is the destination (allowlist), --value + gas count toward spend limits and the gas cap, and it FAILS CLOSED when limits are set but no allowlist is. CRITICAL: if the calldata encodes a known approve/transfer/permit, it is classified and routed through the SAME checks as token_approve — including the unlimited ceremony; raw calldata is NOT a policy bypass. Provide the ABI by registry alias, or pass abi/sig inline with a raw 0x address. Waits for confirmations by default over MCP.",
  "properties": {
    "from":     {"type": "string", "description": "Account ref. Omit to use the default account."},
    "contract": {"type": "string", "description": "Contract registry alias OR a raw 0x address. The policy destination; must pass the allowlist when one is set."},
    "method":   {"type": "string", "description": "Function name (resolved against the ABI), e.g. 'stake'. Omit when 'sig' carries the name."},
    "args":     {"type": "array", "items": {"type": "string"}, "description": "Positional args as strings, coerced by the ABI. address-typed args accept 0x / contact / ENS (resolved + echoed). Arrays/tuples use the literal form, e.g. '[0xabc...,0xdef...]'. Large uints are base-unit decimal strings (use the convert tool — decimals are unknowable for an arbitrary param)."},
    "abi":      {"type": "string", "description": "Inline JSON ABI. Use with a raw 0x contract when no alias is registered."},
    "sig":      {"type": "string", "description": "Inline human-readable signature, e.g. 'stake(uint256)'. Alternative to abi for one function."},
    "value":    {"type": "string", "description": "msg.value (ETH attached to the call), decimal e.g. '0.5'. Counts toward spend limits exactly like a transfer. Named 'value' (not 'amount') to stay distinct from token amounts."},
    "acknowledge_unlimited": {"type": "boolean", "description": "Required when the calldata classifier detects an UNLIMITED approve/permit. Grants the spender an unbounded allowance. Omit unless that is the explicit intent."},
    "gas":  {"$ref": "#/$defs/GasOpts"},
    "nonce": {"type": "integer", "description": "Manual nonce (advanced). Omit to auto-derive."},
    "dryRun": {"type": "boolean", "description": "Build + estimate + policy-check (incl. the calldata classifier), return the plan, do NOT sign or broadcast."},
    "wait": {"$ref": "#/$defs/WaitOpts"},
    "network": {"type": "string"}, "rpc": {"type": "string"}
  },
  "required": ["contract"]
}
```

**`contract_send` — output:** reuses **`domain.TxResult`** verbatim — same `status` enum (`broadcast`/`confirmed`/`reverted`/`pending`), same dual-signal `tx.reverted` mechanism (§6.6), same `tx.*` / exit-3-policy codes; no new output type, no new exit code. `acknowledge_unlimited` maps to `Check.Acked` exactly as for `token_approve` (never frontend-set, §6.4). `contract_call`/`contract_logs` need no representative block (read-only); `contract_encode`/`contract_decode` are pure, like `convert`.

`wallet_list`/`wallet_show` are read-only and emit **non-secret wallet-grouping metadata
only** (names, counts, dates, the BIP-44 derivation path, per-index aliases, derived
addresses) — never a mnemonic, key, or seed. `convert`, `contract_encode`, and
`contract_decode` are the only **pure** tools (no network/keystore/policy); `convert` is
the cheapest live-server smoke test. `receive`'s
`ReceiveRequest` carries `new:true` as the one derivation path on the agent surface (fails
`keystore.read_only` on a Secret-mounted keystore); its `wait.timeout` defaults to *block
forever* (the schema description tells agents to set one).

### 6.4 How guardrails bind MCP (the central guarantee)

Every write tool's handler is the **same three lines around the same service call** the
CLI command runs:

```go
// internal/mcpserver/tools — registered in mcpserver.New(svc *service.Service)
mcp.AddTool(srv, &mcp.Tool{
    Name: "send", Description: sendDesc,
    Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(true)},
    // InputSchema/OutputSchema: nil → SDK infers from domain.TxRequest / domain.TxResult
}, func(ctx context.Context, req *mcp.CallToolRequest, in domain.TxRequest) (*mcp.CallToolResult, *domain.TxResult, error) {
    if in.Wait == nil { in.Wait = &domain.WaitOpts{} }    // MCP waits by default (agents want finality + settle-to-actuals)
    p := domain.Principal{Kind: "local", Label: "mcp"}    // → journal Source = "mcp"
    res, err := svc.SendTx(ctx, p, in, progressSink(ctx, req)) // *** byte-for-byte the same call as the CLI ***
    if dualSignal(err) { return dualResult(res), &res, nil }
    return resultContent(res), &res, toolError(err)
})
```

Three observations make the guarantee airtight: (1) `svc.SendTx` is the *only* path to
`domain.Signer`, and `policy.Reserve` + the seal/allowlist/ENS-pin/gas-cap/unlimited
checks execute *inside* it before `Signer.SignTx`; `mcpserver` cannot import `policy` or
`keys`, so it has no way to *skip* the check. (2) The handler adds nothing the CLI
doesn't — only `Wait` defaults true, the `Principal.Label` is `"mcp"`, and the
`EventSink` forwards to MCP progress; none touches policy, signing, or the journal's
*contents* (only its `Source`). The frontend parity suite (§2.9) enforces byte-equal
journal records and policy counters modulo timestamp and `Source`. (3) The unlimited gate
is the one safety ack and it is in the schema (`acknowledge_unlimited`, never frontend-set,
mapped to `Check.Acked`); a compromised agent prompt must *say the dangerous thing out
loud* in the audited tool call. `Confirm` is wired constant-true over MCP (the
interactive y/N is a TTY convenience that cannot exist over a tool call) — **that is the
full extent of "MCP is non-interactive," not a safety waiver.**

Mapping (requirements §5 guardrail → MCP behaviour), every row "none" except the two
deliberate absences and the one schema-shape change:

| Guardrail | Enforced in | MCP behaviour | Difference from CLI |
|---|---|---|---|
| Per-tx / per-day spend limit | `policy.Evaluate` inside `SendTx`/`Approve` | deny → `policy.denied.tx_limit`/`.day_limit` | none |
| Destination/spender allowlist (+ ENS pin) | `policy.Evaluate` | deny → `policy.denied.allowlist`/`.pin_drift` | none |
| Gas-price cap | `policy.Evaluate` | deny → `policy.denied.gas_cap`; a speedup bump is re-checked | none |
| Unlimited-approval/permit ceremony | `policy.Evaluate` (`Acked`) | `acknowledge_unlimited` field; absent ⇒ `policy.denied.unlimited_unacked` | ack is a **schema field**, not a flag |
| Fail-closed: tokens with limits but no allowlist | `policy.Evaluate` | deny → `policy.denied.no_allowlist` | none |
| Policy seal / anti-rollback | `policy.Engine` load path | load failure halts every signing tool → `policy.seal_violation`/`.rollback` | none |
| Spend counters durable across restart | `policy.Engine` (state-dir, fsync, flock) | a `mcp serve` crash mid-send reconciles at next `service.Open` | none |
| **Policy mutation** | admin passphrase, CLI-only | **no tool exists** | MCP cannot raise its own limits |
| Key export | CLI-only, guarded | **no tool exists** | MCP cannot exfiltrate keys |

### 6.5 Long-running operations: bounded long-poll + progress

`tx_wait`, `receive`, and any `send`/`token_approve`/`tx_speedup` with a wait **block and
stream progress** (not immediate-return-plus-poll). Justification: the SDK's progress
mechanism is purpose-built for this — the handler holds the call open and emits
`NotifyProgress` for each intermediate `domain.Event` (`resolved`, `estimated`, `broadcast`,
each `confirmation`, `listening`, `detected`) while the agent's `CallTool` future stays
pending; it maps the single `EventSink` 1:1 with zero new mechanism; it is bounded by
`wait.timeout` (10m for `tx_wait`/`send`; *block-forever* for `receive`, docs recommend
agents set one) so there is no unbounded hang; and `ctx` cancellation (client drop) is
honored by the core's wait loops. On timeout the tool returns `status:"pending"` (tx) / a
timeout result (receive) — a resumable, non-error-for-receive state. `tx_status` remains
the explicit poll primitive for hosts that prefer it.

The progress translation: `progressSink` wraps the call's ctx; if the client sent no
progress token it no-ops (the final result still carries the full picture). It translates
each `domain.Event` into a `ProgressNotificationParams` whose `Message` is the
`EventKind` string (the same vocabulary the CLI renders to stderr and `receive --json`
emits) and whose `Meta.data` carries the typed payload (resolved address, confirmation
depth). Progress is best-effort (dropped notifications never affect the outcome, which is
fully captured in the return value).

**The one exception — `receive`'s up-front address.** `receive` must emit the receiving
address **before** it blocks (the counterparty needs it). Over MCP this is the **first
progress notification** (`listening`, carrying the address) emitted immediately on entry,
before the watch loop — exactly as the CLI emits the `{"event":"listening","address":…}`
NDJSON line up front. The final `ReceiveResult` (on confirm or timeout) is the tool's
return value; a `receive` timeout is **not** a tool error (it is "still listening,"
resumable — re-call to resume).

### 6.6 Error model — one taxonomy, two renderings

The MCP error model is the **same `domain.Error` taxonomy as the CLI, projected onto
MCP's tool-error mechanism**. The SDK auto-packs a returned regular Go `error` into
`CallToolResult.Content` with `IsError:true` (only a `*jsonrpc2.WireError` becomes a
protocol fault). So a policy denial — a *tool outcome* the agent must reason about, not a
malformed-request fault — is delivered by returning the `*domain.Error` as a normal Go
error; `domain.Error.Error()` returns the JSON envelope (`{code,message,data}`)
byte-identical to the CLI's `--json` error, so the SDK puts that envelope into the
`TextContent` it packs. `toolError(err)` passes a `*domain.Error` straight through and
returns nil on success. Because the SDK fills `StructuredContent` from `Out` **only** on
the nil-error return path, the **dual-signal** cases (`tx.reverted`, `tx.wait_timeout`,
`tx.nonce_gap`) that need *both* `IsError:true` **and** the structured `*domain.TxResult`
return a **nil Go error** with a hand-built `*mcp.CallToolResult{IsError:true}` and the
populated `Out`, so the SDK still fills `StructuredContent` while the result is flagged as
an error. The taxonomy is one table, two projections — the `error.code` an agent reads is
the **same string** the CLI puts in its `--json` error and maps to an exit code (§5.7);
an agent branches on `error.code`, a shell on `$?`.

**Keystore-passphrase rotation while `mcp serve` is running.** A running server caches its
unlock (§3.6); a concurrent `keystore change-passphrase` makes it stale, and the next
signing tool surfaces a distinct passphrase-stale cause (`keystore.bad_passphrase` family,
§3.8). **Hot-reload is deliberately not supported** — restart is the honest contract. Read
tools keep working.

### 6.7 `daxie mcp tools`

The introspection + contract-verification command builds the same `*mcp.Server`
(`mcpserver.New(svc)` — wired lazily, touching no keystore/network), asks the SDK for
every registered tool's inferred schema, and prints it. Default human output: a compact
`TOOL / KIND / DESCRIPTION` table with a footer (`31 tools (23 read-only, 8 signing).
Transport: stdio (v1). Signing tools enforce policy in core; no policy-mutation or
key-export tools are exposed.`). `--json` emits the exact `tools/list` payload (every
tool's `name`, `description`, `inputSchema`, `outputSchema`, `annotations`) — the
byte-for-byte contract a client sees on connect. Three uses: (1) the **golden-snapshot
contract test** diffs `--json` against a checked-in fixture (any struct change altering an
agent-visible schema fails review); (2) operator/host onboarding; (3) debugging (confirms
excluded-by-design tools are genuinely absent). `daxie mcp tools <name>` prints one tool's
full schema. The command never dials RPC or unlocks the keystore.

### 6.8 Transport abstraction: stdio now, HTTP in v1.1 without refactor

`mcpserver.New(svc)` builds the `*mcp.Server` (registers all 31 tools) and is
**transport-free** — it never changes when transports are added. `ServeStdio(ctx, s)` is
the v1 wiring (`s.Run(ctx, &mcp.StdioTransport{})`). v1.1 lands `ServeHTTP` in a new file,
touching nothing above, with the signature **reserved now** so auth has a home:

```go
type HTTPOptions struct {
    Addr          string
    Authenticator func(r *http.Request) (domain.Principal, error) // bearer/mTLS; nil ⇒ refuse non-loopback
    TLS           *tls.Config
}
func ServeHTTP(ctx context.Context, s *mcp.Server, o HTTPOptions) error // mcp.NewStreamableHTTPHandler
```

The Cobra side ships `daxie mcp serve --transport stdio` in v1 with `stdio` the only
accepted value (`http` rejected with a forward-pointing error), so the CLI contract is
stable when `http` is added — flipping it on is a new file + a new enum value, not a
refactor. Four properties make HTTP a drop-in: (1) `service.Service` is already
concurrency-safe (stdio allows concurrent in-flight calls, file locks already hold under N
HTTP sessions); (2) handlers keep zero per-connection state (one `*mcp.Server` serves
every connection; the per-request principal rides in ctx); (3) the `Principal` seam is
already threaded — v1.1's `Authenticator` fills `Principal.ID` from the bearer/mTLS
identity (a value change, not a plumbing change); (4) the `EventSink`/`progressSink` and a
`Health(ctx)` readiness probe already exist (the SDK delivers `NotifyProgress` over HTTP
transparently). v1 builds none of HTTP, auth, the signer-daemon boundary, or per-principal
policy — it builds the seams that make them additive.

> **cli-spec refinements (called out, not silent).** cli-spec's `daxie mcp` block lists
> `daxie mcp serve` (no flags) and `daxie mcp tools` (no positional). The canonical surface
> adds `daxie mcp serve --transport stdio` (with `http` reserved/rejected in v1) and
> `daxie mcp tools [<name>]` — pure-additive refinements cli-spec invites as the design
> session's job (§11, D8).

---

## 7. Configuration & local data

`internal/config` owns: the config file format and schema, the `DAXIE_*` env mapping and
Viper precedence, the four state-class paths across platforms (incl. Windows), the
network/RPC-endpoint config objects, the token/NFT/contact registry file schemas, the
secret-reference resolver, and the read-only-config behavior. `internal/fsx` owns the
atomic-write/lock/permission mechanics it consumes. Field-level semantics owned by sibling
sections (keystore internals → §3; journal/nonce → §5; policy/spend → §4) are
cross-referenced, not re-litigated.

**Decisions at a glance.** Config file format **TOML** (`config.toml`, pure-Go
`pelletier/go-toml/v2`, kebab-case keys); one-format rule (config = TOML, comment-bearing
and human-first; keystore/state/cache = JSON/JSONL, machine-first); token/NFT/contact
registries in the **state class** (`DAXIE_REGISTRY_DIR` override); aliases + default
account in keystore `meta.json` (§3.3); default network/RPC are config keys (`network
use`/`rpc use` are config mutations); ENS pins live on the entry that authorized them (no
separate pin file); the policy anchor is never Viper-resolved (§4.6); `${env:}`/`${file:}`
secret references resolved in-memory at connect time; read-only config fails mutators with
`config.read_only` (exit 10) while signing/receiving never write config; no hot reload of
`config.toml`; every Daxie-owned file is version-stamped.

> **Reconciliation note (registries to state; types).** An earlier config draft placed
> registries in the *config* class and called the seal anchor `policy.pin` inside
> `config.toml`; both are **superseded** — registries are state-class (so `token add`
> works on a read-only-config pod), the anchor is the dedicated `policy-anchor.json`
> (§4.6). The atomic-write helper is `internal/fsx`; the composition root is `service`;
> the typed options are `config.Options` (§11, D1/D2/D9).

### 7.1 Config file format: TOML

Viper loads it with `SetConfigType("toml")`; the backend is `pelletier/go-toml/v2` (pure
Go — `CGO_ENABLED=0`). Over YAML: TOML has **no type-coercion footguns** (YAML 1.1's
implicit typing turns `legacy = no` into a string on one library version and a bool on
another — unacceptable for a signing tool); requirements §4/§7 already *write* config in
TOML syntax; TOML is comment-bearing and human-owned (the policy anchor and counters are
machine JSON, so the one file humans curate stays human-friendly). Trade-off: deeply
nested tables are wordier; the schema is deliberately shallow (≤ 3 levels) and uses keyed
tables (`[rpc.<name>]`), not array-of-tables, so every object has a stable name to address
from env/flags. **Keys are kebab-case**; the env replacer maps both `.` and `-` to `_` so
`gas.limit-multiplier` → `DAXIE_GAS_LIMIT_MULTIPLIER`.

### 7.2 The four state classes — assignment rule and contents

The litmus test that assigns every file:

> **config** — a human/operator provisions it; **no** signing/receiving operation may
> require writing it (K8s: read-only ConfigMap). **keystore** — it must travel with key
> material in a backup (K8s: Secret mount or PVC). **state** — the agent's *runtime job*
> (sign, send, receive, learn a token) writes it and it **must survive restarts** (K8s:
> PVC). **cache** — reconstructible from the chain; losing it costs only latency (K8s:
> emptyDir/tmpfs).

| Class | Override var | Contents |
|---|---|---|
| **config** | `DAXIE_CONFIG` (file *or* dir) | `config.toml` (defaults, networks, RPC endpoints, gas/tx defaults), `policy-anchor.json` (seal verify key + salt + nonce watermark — read directly, not via Viper, §4.6), `config.lock` + `policy-anchor.lock` sidecars |
| **keystore** | `DAXIE_KEYSTORE` | `keystore.json`, `meta.json` (names, aliases, `default_account`), `index.lock`, `wallets/<uuid>.json`, `accounts/UTC--…` — owned by §3; this section owns only path resolution + the §7.9 permission rule |
| **state** | `DAXIE_STATE_DIR` (+ `DAXIE_REGISTRY_DIR`) | `journal/<chainID>.jsonl` (§5), `policy.json` + `spend/<net>/<addr>.json` counters (§4), `registry/<network>.json` + `registry/contacts.json`, `locks/` sidecars |
| **cache** | `DAXIE_CACHE_DIR` | ENS resolution cache, `tokenURI`/metadata cache (staged NFT-metadata feature), feeHistory snapshots — all disposable, never a source of truth, never a secret |

**Registries are state, not config:** an agent encountering a new token mid-task runs
`token add`, which must succeed on a pod whose config is a read-only ConfigMap; parking
registries on the ConfigMap would block a routine agent op in exactly the deployment §7a
targets, and requirements §1 resolves human-convenience-vs-agent tensions in the agent's
favor. Networks and RPC endpoints stay **config** (deploy-time topology). **The default
account is keystore-class** (`meta.json`, §3.3) — it references keystore objects and
travels with a keystore backup; precedence `--from`/`--account` > `DAXIE_ACCOUNT` >
`meta.json` `default_account`.

### 7.3 Paths, platform resolution, override mechanism

`internal/config` computes the four roots once at `service.Open`. Each class honors its
`XDG_*` env var when set, otherwise an explicit `$HOME` join (no Go stdlib helper gives
these paths on macOS):

| Class | Linux/macOS (XDG env → else `$HOME` default) | Windows |
|---|---|---|
| config | `$XDG_CONFIG_HOME/daxie` → `~/.config/daxie` *(deliberate: CLI convention over `~/Library`)* | `%APPDATA%\daxie` |
| keystore | `$XDG_DATA_HOME/daxie/keystore` → `~/.local/share/daxie/keystore` | `%LOCALAPPDATA%\daxie\keystore` |
| state | `$XDG_STATE_HOME/daxie` → `~/.local/state/daxie` | `%LOCALAPPDATA%\daxie\state` |
| cache | `$XDG_CACHE_HOME/daxie` → `~/.cache/daxie` | `%LOCALAPPDATA%\daxie\cache` |

- **State uses `$XDG_STATE_HOME`** (not the data dir) — XDG's state class is exactly
  "current state that should persist but isn't portable user data," and it keeps mutable
  runtime state out of the keystore data dir so a `tar` of the keystore dir is a pure key
  backup (§3.3). *(This refines the keys part's §11, which wrote state under the data dir;
  the keystore path is independent, so the keystore section is unaffected.)*
- **Windows: config roams, keys do not.** `%APPDATA%` is replicated across domain
  machines by roaming profiles; silently copying key material to every machine is exactly
  wrong for a wallet — keystore/state/cache live under non-roaming `%LOCALAPPDATA%`.
  Config may roam (it holds no secret — RPC keys are `${env:}`/`${file:}` references).
- **macOS deliberately mirrors Linux XDG**, not `~/Library` (the audience is
  terminal-first); `internal/config` does **not** rely on `os.UserConfigDir`/`UserCacheDir`
  (which return `~/Library/…` on macOS).

**Override hierarchy (per class, first present wins):** the global flag
(`--config`/`--keystore`/`--state-dir`; no `--cache-dir` flag — cache is env-only) > the
dedicated env var (`DAXIE_CONFIG`/`DAXIE_KEYSTORE`/`DAXIE_STATE_DIR`/`DAXIE_CACHE_DIR` +
`DAXIE_REGISTRY_DIR`) > the platform default. These five path vars are resolved **outside**
Viper's config-key machinery (read with `os.LookupEnv` before Viper reads the file) and
are deliberately **not** bound as config keys, so they never appear in `config.toml` (a
self-relocating config is a footgun) and `config get` doesn't list them. `DAXIE_CONFIG`/
`--config` accepts a **file or a directory** (a `.toml` path is the config file, its parent
the config dir; otherwise the path is the dir and the file is `<dir>/config.toml`) — the
K8s ConfigMap mount is a directory while a developer's `--config ./my.toml` is a file, and
the directory must be derivable either way so the anchor is found beside the config.
`service.Open` is lazy: an empty environment still runs `convert`/`version`/`config list`/
`network list`/`wallet create`; config dir creation happens **only when a command actually
writes config** (and fails `config.read_only` on a read-only mount, never an opaque
`mkdir: permission denied`).

### 7.4 The config file schema (annotated)

`config.toml` is shallow and entirely operator-facing; every key has a built-in default
(the file is optional). The annotated example shows **all** keys:

```toml
# Daxie config — TOML. Pure-operator file: no secrets, no policy limits, no runtime
# state. RPC secrets are ${env:}/${file:} references (§7.5). Spend limits live in the
# sealed policy file, set only via `daxie policy` (admin passphrase).
schema = 1                       # file schema major; bump = forward migration (§7.10)

[defaults]
network = "mainnet"              # default chain when --network is omitted (set by `network use`)
# NOTE: there is NO defaults.account key. The default account is keystore-class
# meta.json `default_account`, written by `daxie account use`; precedence
# --from/--account > DAXIE_ACCOUNT > meta.json default_account (§3.3, §7.7).

[gas]                            # global gas strategy; per-network overrides below (§5.4)
limit-multiplier = 1.2          # eth_estimateGas × this
fee-history-blocks = 20         # eth_feeHistory window
speed = "normal"                 # default --speed: slow|normal|fast → p25/p50/p90 priority-fee pctile
base-fee-multiplier = 2.0       # maxFee = multiplier×nextBaseFee + priorityFee
min-priority-fee = "0.01gwei"   # floor for empty-block percentiles; per-network overridable
rbf-bump-percent = 12.5         # min replace-by-fee bump (protocol/node floor)
drift-tolerance = 0.10          # TTY-confirmed sends: re-confirm when the locked rebuild's
                                #   worst-case cost exceeds the confirmed quote by more (§5.1).
                                #   No effect on --yes / non-interactive.
# max-fee / priority-fee / gas-limit: intentionally NOT global config keys — they are
# per-invocation (flags), env (DAXIE_MAX_FEE/…), or per-network (below).

[tx]
wait = false                     # if true, sends behave as --wait by default
wait-timeout = "10m"             # default --wait / `tx wait` timeout (§5)
poll-interval = "4s"             # confirmation poll cadence
lock-timeout = "30s"             # account-lock wait before exit 11 (§5.1)

[receive]
timeout = "0"                    # 0 = listen forever (deliberately NOT inheriting tx.wait-timeout)
poll-interval = "4s"
max-log-range = 1000             # eth_getLogs range chunk
heartbeat-interval = "60s"       # quiet-period resume heartbeat on the NDJSON stream (§5.8)
lookback-blocks = 0              # log-based listens only; per-invoice addresses

[ens]
enabled = true                   # false makes name.eth inputs an error instead of resolving

[mcp]
# Reserved for the v1.1 HTTP transport. v1 stdio needs no config. Unknown [mcp] keys are
# preserved verbatim across config rewrites (§7.4) so a v1.1 operator can pre-stage them.
# transport = "stdio"            # v1: stdio only; --transport http is rejected
# http-addr = ":8645"            # v1.1

# ─── Networks: a chain definition. Mainnet + Sepolia are BUILT IN and appear here only
#     to OVERRIDE a built-in field. ───
[networks.mainnet]
chain-id = 1                     # immutable identity; built-in
confirmations = 2                # per-network --wait default (§5: mainnet 2)
default-rpc = "mainnet-alchemy"  # which [rpc.*] to use when --rpc is omitted (set by `rpc use`)
# legacy = false                 # pre-1559 chains set true; auto-applies --gas-price mode
# native-symbol = "ETH"          # display only
# ens-registry = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"  # built in for mainnet/Sepolia

[networks.sepolia]
chain-id = 11155111
confirmations = 1
default-rpc = "sepolia-public"

# A user-added network (chain-id + RPC, no code change). `network add base --chain-id 8453`
# writes this table; the --rpc-url convenience form also writes [rpc.base-default].
[networks.base]
chain-id = 8453
confirmations = 1                # user-added default; docs note: raise for value-bearing L1s
default-rpc = "base-default"
[networks.base.gas]              # any [gas] key, per network
speed = "fast"

# ─── RPC endpoints: a named connection BOUND to a network (strictly separate from
#     networks). Many per network; one default per network. ───
[rpc.mainnet-alchemy]
network = "mainnet"              # chain-ID-verified on add/test
url = "https://eth-mainnet.g.alchemy.com/v2/${env:ALCHEMY_API_KEY}"   # secret as a reference (§7.5)
# timeout = "30s"                # optional per-endpoint dial/request timeout; default 30s

[rpc.mainnet-infura]
network = "mainnet"
url = "https://mainnet.infura.io/v3/${env:INFURA_PROJECT_ID}"
[rpc.mainnet-infura.headers]     # custom auth headers; values may be ${env:}/${file:} refs
Authorization = "Bearer ${file:/var/run/secrets/daxie/infura-jwt}"

[rpc.sepolia-public]
network = "sepolia"
url = "https://ethereum-sepolia-rpc.publicnode.com"   # shipped public default

[rpc.base-default]
network = "base"
url = "https://mainnet.base.org"

# mTLS endpoint for corp/self-hosted infra. cert/key/ca are PATHS (files mTLS needs as
# files; the key file is permission-checked like a passphrase file), NOT secret references.
[rpc.corp-node]
network = "mainnet"
url = "https://eth.internal.corp:8545"
[rpc.corp-node.tls]
cert = "/etc/daxie/tls/client.crt"
key  = "/etc/daxie/tls/client.key"
ca   = "/etc/daxie/tls/corp-ca.pem"   # optional; omit to use the system roots
```

**Built-in presets and override model.** Mainnet and Sepolia (and their default public
RPC endpoints) are **compiled in**, not written to a fresh config file. A
`[networks.mainnet]`/`[rpc.*]` table is a **sparse override** merged field-by-field over
the built-in. The shipped public defaults are intentionally rate-limited community RPCs
(`rpc list` flags them; docs steer serious use to a user-supplied endpoint). `network
remove` of a built-in is rejected; removing a user-added network is allowed and refuses if
endpoints still reference it (`--force`).

**Resolution: built-in defaults → config file → env → flags**, then unmarshaled
(`viper.Unmarshal` with `mapstructure`) into one immutable `*config.Config` value at
`service.Open` — *not* read key-by-key at use sites (this is where TOML's no-coercion
property pays off and a bad type is caught once, at load, with `config.invalid`). The
`policy.*` subtree is **excluded** from the unmarshal entirely (§4.6). A `--config`
pointing at a *named but missing file* is an error (`config.not_found`); an absent default
file is the legitimate fresh-install case.

```go
package config
type Config struct {
    Schema int; Defaults Defaults; Gas GasDefaults; Tx TxDefaults; Receive ReceiveDefaults
    ENS ENSConfig; MCP map[string]any            // MCP preserved-verbatim; typed in v1.1
    Networks map[string]Network                  // built-ins merged with file overrides
    RPC map[string]Endpoint
    // Paths and the anchor are NOT here — paths resolved pre-Viper (§7.3), the anchor read
    // directly (§4.6). Both deliberately outside the Viper map.
}
type Network struct {
    ChainID uint64; Confirmations uint; DefaultRPC string; Legacy bool
    NativeSymbol string; ENSRegistry common.Address; Gas *GasDefaults // nil = inherit global
}
type Endpoint struct {
    Network string; URLRef string            // RAW, with ${env:}/${file:} refs still embedded
    Headers map[string]string; TLS *TLSFiles // cert/key/ca PATHS
    Timeout time.Duration
}
// Load resolves the four roots, reads config.toml + env + flags, unmarshals to Config, and
// reads policy-anchor.json directly. It NEVER resolves secret references.
func Load(flags FlagValues) (*Config, Paths, error)
func ResolveSecretRefs(s string) (string, error)   // the ONLY config-side secret resolver (§7.5)
```

`package config` deliberately **does not** import `internal/chain` and never returns a
`chain.Options` (`config → chain` is not a sanctioned leaf edge). Assembling a
`chain.Options` from an `Endpoint` (resolving refs, loading TLS files) happens in
**`service`** at dial time, so resolved secrets never enter the `Config` value, never get
logged, never get written back.

**Writing config back** (`network add`, `rpc add`, `network use`, `rpc use`): **never
serialize from Viper** (that would freeze every built-in default and env/flag-derived
value into the file). Instead Daxie loads the **raw file** into a `map[string]any` with
`go-toml/v2`, applies the single targeted change, and rewrites under the `config.lock`
sidecar via `fsx.WriteAtomic` — values the operator never set stay absent and keep
inheriting built-ins/env; unknown keys (the reserved `[mcp]` block, `x-` keys) survive.
Comments on mutated tables are lost (the known `go-toml` limitation); comments elsewhere
are preserved. `network use`/`rpc use` are config mutations and therefore **fail
`config.read_only` on a read-only mount** — by design (the K8s answer is to set the
default in the ConfigMap, pass `--network`/`--rpc` per call, or use `DAXIE_NETWORK`).

### 7.5 Network & RPC objects and secret references

**Networks and endpoints are strictly separate** (requirements §6, OQ #18): a network is
`{chain-id, confirmations, default-rpc, legacy, …}`; an endpoint is
`{network, url, headers, tls}`. `--network` selects a chain; `--rpc` selects an endpoint;
neither accepts the other's names (`--rpc mainnet` errors `ref.not_found`). One default
endpoint per network, overridable per invocation with `--rpc` (no auto-failover in v1).
Chain-ID verification is `internal/chain`'s job at `Dial` and at `rpc add`/`rpc test`
(`eth_chainId` must equal the declared chain-id or the connection fails closed,
`rpc.chain_id_mismatch`, exit 12). mTLS inputs are **file paths, not secret references**
(the key file is permission-checked by `fsx.CheckPerms` like a passphrase file).

**Secret-reference grammar** (a value in a URL or header may embed placeholders; the
config file stores the *reference*, never the resolved secret):

| Form | Resolves to | Notes |
|---|---|---|
| `${env:NAME}` | the value of env var `NAME` | missing var ⇒ hard error at connect (`secret.unresolved`) |
| `${file:/abs/path}` | the file's contents | trailing single `\n`/`\r\n` stripped; perms checked (§7.9) |
| `${file:~/rel}` | `~` expands to the home dir | `path/filepath` + home expansion |
| `$${` | a literal `${` | the escape |

An unknown scheme (`${vault:…}`) is a hard error, not a passthrough (so `${keychain:…}`
can be added later without ambiguity). **Resolution timing: in-memory, at connect time** —
the resolved string lives only inside the `chain.Options` passed to `Dial` and is not
retained after. `internal/config` never imports `internal/chain`; the `Endpoint` →
`chain.Options` assembly lives in `service`, so resolved secrets exist only transiently in
its call frame. `rpc add` runs a **literal-secret heuristic** (a URL segment/query value
matching `[A-Za-z0-9_-]{24,}` not inside a `${…}`, or an `Authorization: Bearer <literal>`)
and **warns** (some endpoints have long opaque path components that aren't secrets); a
`--strict-secrets` flag (the default in `docs/deploy/` K8s guidance) makes it a hard error.

### 7.6 Policy data outside Viper

`internal/config` owns **where the policy seal trust root lives and why it is unreachable
by Viper** (the seal semantics are §4). Two policy files in state
(`state/policy/policy.json`, `state/policy/spend/<net>/<addr>.json` counters) plus the
anchor in config (`config/policy-anchor.json`). The counters are **state** because §7a is
explicit (a restart that reset spend counters would let an attacker bypass daily limits by
crashing the pod — they must be on the PVC). The anchor is **config** because it is the one
mount genuinely read-only to the agent in K8s. The anchor is parsed by `internal/config`
with a plain `json.Unmarshal` of raw bytes — **not** a Viper key, **not** bound to any
`DAXIE_*` env var, **not** settable by any flag, **not** part of `config.toml`. If the
verify key were a config key, a compromised agent could export `DAXIE_POLICY_VERIFY_KEY`,
sign a no-limits policy with a keypair it generated, and outvote the admin passphrase
without touching the read-only ConfigMap. `daxie config set policy.max-tx …` and
`config get policy.*` are **rejected** with a message pointing to `daxie policy set`;
`config list` omits the `policy` subtree; a regression test asserts `DAXIE_POLICY_*` env
vars/`--policy-*` flags have **no effect** (the "anchor immunity" test). The anchor file
shape is in §4.6.

### 7.7 Default-account precedence (the one cross-class resolution)

`--from`/`--account` flag > `DAXIE_ACCOUNT` env > keystore `meta.json` `default_account`
(§3.3). Exactly **three** sources and exactly **one** persistent store: keystore
`meta.json`, written by `daxie account use`. There is **no** `state/default-account` file
and **no** `config.toml` `defaults.account` key — the default account references keystore
objects, must stay consistent under rename/delete in the keystore's lock, and travels with
a keystore backup. `account show` reports which source supplied the active default. Because
`meta.json` is keystore-class, `account use` **fails `keystore.read_only`** on a
Secret-mounted keystore; the workaround is `DAXIE_ACCOUNT`.

### 7.8 Registries and contacts — schemas (state class)

`internal/registry` owns these; this section specifies the on-disk file schemas and the
path/permission/atomicity conventions. **Token/NFT registry** (`registry/<network>.json`,
per-network — the same alias maps to different addresses on mainnet vs an L2; aliases
stored lowercase, matched case-insensitively):

```json
{
  "v": 1, "network": "mainnet",
  "tokens": [
    { "alias": "usdc", "address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
      "kind": "erc20", "decimals": 6, "symbol": "USDC" },
    { "alias": "usdc-bridged", "address": "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
      "kind": "erc20", "decimals": 6, "symbol": "USDC.e" }
  ],
  "collections": [
    { "alias": "punks", "address": "0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb", "kind": "erc721" }
  ],
  "nft_aliases": [ { "alias": "my-punk", "collection": "punks", "token_id": "42" } ]
}
```

`token_id` is a decimal string (token IDs exceed 2^53); `kind` is detected at `add` and
stored. **Bundled majors are compiled in** (USDC/USDT/WETH/DAI per network) and not
written to the file; a same-alias file entry overrides the bundled one. **Aliasing is
local and explicit by design** (requirements §2): resolution is registry-only — a name not
in the registry (or bundled set) is an error, never an on-chain `symbol()` lookup (symbol
spoofing is free). **Contacts** (`registry/contacts.json`, network-agnostic — an address
is an address across EVM chains) pin both name and resolved address at add-time for
ENS-backed contacts (`pinned_at`); if the name later resolves differently a send refuses
until re-added (the contact's half of the ENS-pin story, §4.8):

```json
{ "v": 1, "contacts": [
  { "name": "exchange", "address": "0xabc0000000000000000000000000000000000def" },
  { "name": "vitalik", "ens": "vitalik.eth",
    "address": "0xd8da6bf26964af9d7eed9e03e53415d37aa96045", "pinned_at": "2026-06-15T10:00:00Z" }
]}
```

Aliases follow the §3.1 name grammar; the cross-namespace collision guard (contact name
vs wallet/standalone) is enforced here best-effort at create (the authoritative guard is
`service`'s destination-context `ref.ambiguous` rule, §3.2). **No standalone pin file**: a
pin is a property of *an authorization* (a contact entry, or a sealed policy allowlist
entry), so co-locating it means the pin can never drift from the thing it protects and
revoking the entry revokes the pin atomically. Registries are state (writable on a PVC) so
`token add`/`contacts add` work on a read-only-config pod; on a read-only state mount they
fail with the state-class read-only sibling of `config.read_only` (exit 10). An operator
wanting declaratively pinned registries pre-seeds the state PVC (or the `DAXIE_REGISTRY_DIR`
volume) from an init container (the pattern ships in `docs/deploy/`).

**Contract registry (`daxie contract`, requirements #29).** Co-located in the same per-network `registry/<network>.json` as a new top-level `contracts` array (not a separate file), so it shares the token/NFT registry's per-network keying, `locks/registry.lock`, `fsx.WriteAtomic` discipline, and `internal/registry` ownership. Same anti-spoofing model: per-network, aliases stored lowercase + matched case-insensitively, resolution **registry-only** (never an on-chain `symbol()`/`name()`). The ABI is stored **inline in the same atomically-written record** (small, a few KB; one `WriteAtomic` so alias→{address, ABI} can never drift), as the canonical Solidity ABI JSON array, normalized/validated at `add` (an invalid ABI is rejected at `add` with `usage.*`, never stored). **No bundled contracts** (unlike token majors — there is no canonical "majors" set for arbitrary contracts). The per-network file's `v` bumps **1 → 2** for the additive `contracts` key; a v1 file is forward-migrated by treating a missing `contracts` as empty (§7.10). Contacts (`registry/contacts.json`) are untouched. Registry is **state class** — `contract add` fails the state-class read-only sibling of `config.read_only` (exit 10) on a read-only mount, identical to `token add`.

```json
{
  "v": 2, "network": "mainnet",
  "tokens": [ /* … unchanged … */ ],
  "collections": [ /* … unchanged … */ ],
  "nft_aliases": [ /* … unchanged … */ ],
  "contracts": [
    { "alias": "staking",
      "address": "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
      "abi": [
        { "type": "function", "name": "stake", "stateMutability": "nonpayable",
          "inputs": [ { "name": "amount", "type": "uint256" } ], "outputs": [] },
        { "type": "function", "name": "earned", "stateMutability": "view",
          "inputs": [ { "name": "account", "type": "address" } ],
          "outputs": [ { "name": "", "type": "uint256" } ] },
        { "type": "event", "name": "Staked", "anonymous": false,
          "inputs": [ { "name": "user", "type": "address", "indexed": true },
                      { "name": "amount", "type": "uint256", "indexed": false } ] }
      ] }
  ]
}
```

```go
// internal/registry — peer of Tokens/NFTs/Contacts
type Contract struct {
    Alias   string          `json:"alias"`   // lowercase; case-insensitive match; §3.1 grammar; collision needs --name
    Address common.Address  `json:"address"` // the alias binds BOTH address and ABI — the anti-spoofing unit
    ABI     json.RawMessage `json:"abi"`     // stored verbatim; parsed/validated by internal/abi at add + defensively on read
}
type Contracts struct{ /* per-network store; same path/lock/atomicity as the token registry above */ }
```

The operator curates `contracts` via CLI `daxie contract add` on a writable state mount (or pre-seeds it from an init container per `docs/deploy/`); the agent surface reaches non-standard contracts by raw address + inline ABI, never by minting registry entries (the `*_add` MCP exclusion, §6.1).

### 7.9 Shared utilities: permissions, atomic write, locks (`internal/fsx`)

The single durable-write + locking + permission helper; **no package outside `fsx`
hand-rolls temp+rename or platform-specific permission code**.

```go
package fsx
// WriteAtomic: write to <path>.tmp-<rand> in the same dir, fsync(file), rename over
// <path>, fsync(parent dir). POSIX. On Windows: no dir fsync; rename is
// MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH) / FILE_RENAME_FLAG_POSIX_SEMANTICS with a
// bounded retry-on-sharing-violation loop, opening with FILE_SHARE_DELETE.
func WriteAtomic(path string, data []byte, mode os.FileMode) error
func MkdirAll(path string, mode os.FileMode) error          // 0700 POSIX / owner DACL Windows
// Lock takes the EXCLUSIVE flock on the SIBLING <path>.lock (never the data file —
// rename breaks lock continuity; Windows LockFileEx is mandatory and would break
// temp+rename). RLock takes a SHARED lock (required on Windows so a reader holding the
// data file open does not block a concurrent writer's atomic rename).
func Lock(ctx context.Context, path string) (unlock func(), err error)
func RLock(ctx context.Context, path string) (unlock func(), err error)
func CheckPerms(path string) error                          // §7.9 permission rule
```

**`WriteAtomic` atomicity is a correctness guarantee on all three OSes** (not
best-effort): a process killed mid-write leaves either the old or the new file intact,
never a torn one. Go's stdlib `os.Rename` on Windows does **not** guarantee this when the
destination exists, so the Windows path uses `MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH)`
with `FILE_SHARE_DELETE`; `fsync`-durability remains documented best-effort on Windows
(`WRITE_THROUGH` approximates the flush). **Read locking is platform-split:** POSIX reads
are lock-free (`rename(2)` is atomic against open readers); Windows readers take a shared
`RLock` (an unlocked reader holding the data file open without `FILE_SHARE_DELETE` would
break a concurrent writer's atomic rename). **Permission rule (`CheckPerms`)** on every
secret/integrity-bearing file (keystore files, `meta.json`/`keystore.json`, sealed
`policy.json`, the anchor, day counters, `${file:}`/passphrase/mTLS-key files): created
`0600`/`0700`; **hard error** if `mode & 0o037 != 0` (any world bit or group-write);
**group-read carve-out (fsGroup-aware)** — group-read accepted **silently** iff the file's
group is the process's effective GID or a supplementary group (required by the blessed K8s
shape: a non-root pod with `securityContext.fsGroup` makes the kubelet chgrp Secret files
to the fsGroup and add group-read, so a `defaultMode: 0400` Secret lands on disk as
`0440` — which this passes soundly: group-read by a group the process belongs to grants
nothing new), else **warns**; Windows inspects the **DACL** (refuses
`Everyone`/`BUILTIN\Users`/`Authenticated Users` read). `DAXIE_SKIP_PERM_CHECK=1` disables
the check for filesystems that can't represent perms (some CSI/network mounts) — never the
documented answer for the fsGroup case. The sidecar inventory: `config.lock`,
`policy-anchor.lock` (config dir); `locks/registry.lock`, `locks/journal-<net>.lock`,
`locks/policy-<net>-<addr>.lock`, `index.lock` (state/keystore).

### 7.10 Read-only config, hot reload, versioning

**Read-only config (requirements §7a):** Daxie does not stat-probe up front (a writable
dir can still hold a read-only file; TOCTOU) — it attempts the write through
`fsx.WriteAtomic` and maps `EROFS`/`EACCES`/`EPERM` (Windows `ERROR_ACCESS_DENIED`/
`ERROR_WRITE_PROTECT`) to `config.read_only` (exit 10), naming the file and the remedy.
Commands that fail: `network add/remove`, `rpc add/remove/rename`, `network use`, `rpc
use`, `config set` (and the bootstrap `policy set`, which writes the config-class anchor —
**expected**, policy admin is out-of-band). Commands that **never** touch config (so never
fail `config.read_only`): every signing/receiving/read path. **No hot reload of
`config.toml`** — networks, endpoints, gas defaults, and timeouts are fixed at
`service.Open` (a signing service silently changing its RPC endpoint or gas ceiling
mid-flight is a footgun; K8s rolls pods on ConfigMap change anyway). **Registries and
contacts are re-read per operation** (state-class working data an agent mutates at
runtime, so a long-lived server must see them; each tool call re-reads with an mtime
check). **Policy is re-read and re-verified on every signing operation** (the seal +
watermark check runs per `Reserve`), so a `policy set` from an out-of-band Job takes
effect on the next signing call without restarting the server. **Versioning:** every
Daxie-owned file carries a version (`schema = 1` TOML, `"v": 1` JSON); a **newer major** is
refused (`config.schema_unsupported` — a wallet must not guess an unknown format); a lower
known version triggers a **forward-only migration on first write** (reads of an old version
work without migrating, so a read-only mount of an old config still functions); the journal
versions per-record (forward-compat unknown fields, back-compat missing optionals), so its
format evolves without a rewrite migration.

---

## 8. Threat model

**Security objective, in one sentence:** a fully prompt-hijacked agent holding the
keystore passphrase must not be able to (a) extract key material through Daxie, (b) spend
beyond operator-set policy, or (c) change that policy — while a thief with the disk but no
passphrase gets nothing at all. v1 is honest about its boundary: the agent, the Daxie
process, the keystore file, and the state directory all live in **one OS trust domain**
(same uid). v1 delivers *policy enforcement and tamper resistance within that domain*, not
tamper *proofness* against arbitrary code execution as that uid. The v2 signer daemon
moves keys, policy evaluation, and counters behind a real privilege boundary; §8.6 maps
every residual to whether the daemon closes it.

### 8.1 Trust boundaries (v1)

```text
┌────────────────────────── agent trust domain (one uid) ────────────────────────────┐
│  AI agent / MCP client ──stdio──► daxie mcp serve ─┐                                 │
│  AI agent / human     ──exec───► daxie <cmd>      ─┤──► internal service             │
│  holds: keystore passphrase (env/file)             │    (one core, two thin frontends)│
│  reads/writes: keystore, state dir (journal,       │                                 │
│  nonces, spend counters), cache                    ▼                                 │
│                                            signed raw tx ──► RPC endpoint (UNTRUSTED) │
└──────────────────────────────────────────────────────────────────────────────────────┘
        ▲ admin passphrase + policy-anchor.json NEVER cross this line writably
┌───────┴────────────── operator trust domain ─────────────┐
│  human operator: admin passphrase, policy mutations,      │
│  policy-anchor.json (verify key + watermark), key export  │
│  / backup — workstation or one-off K8s Job                │
└───────────────────────────────────────────────────────────┘
```

The RPC endpoint is **always untrusted for the integrity of what it tells us** and trusted
only to relay signed transactions. Everything Daxie signs is integrity-protected locally;
everything Daxie *reads* from RPC is potentially a lie (T3). The single structural fact
that makes v1 enforcement sound against an *interface-confined* agent: the policy trust
root (`policy-anchor.json`) lives in the **config** state class — the one mount the agent
genuinely cannot write in K8s (read-only ConfigMap) — and is read by a loader that
**bypasses Viper entirely**. The config-class placement protects the *file*; the Viper
carve-out protects against the env/flag bypass no file permission can stop. Both are
required; neither alone suffices (§4.6).

### 8.2 Assets

| # | Asset | Property | Where | Notes |
|---|---|---|---|---|
| A1 | BIP-39 mnemonics & private keys | Confidentiality (absolute) | Keystore — geth v3 scrypt JSON (N=2¹⁸), `0600`/`0700` (Windows owner-DACL) | Loss = total, irreversible theft of funds and identity |
| A2 | Keystore passphrase | Confidentiality | Operator's head; agent env/file; K8s Secret | Gates signing *and* the offline brute-force cost of a stolen keystore |
| A3 | Admin passphrase | Confidentiality | Operator only — **never** on agent hosts | Derives the seal key (scrypt N=2¹⁷ → HKDF → Ed25519). Compromise = attacker rewrites policy |
| A4 | Policy file (limits, gas cap, allowlist + ENS pins, sealed `self_addresses`) | Integrity, rollback-resistance | State, sealed | Confidentiality not required — `policy show` is unauthenticated by design |
| A5 | Policy anchor (`policy-anchor.json`) | Integrity, non-bypassability | **Config** class; never under Viper; read-only ConfigMap in K8s | The trust root. An env/flag-settable or agent-writable anchor would let a compromised agent self-forge and "verify" a policy |
| A6 | Daily-spend counters | Integrity, durability across restarts | State, atomic, flock | The known v1 soft spot — writable by the agent-facing process, unsealable; see R2 |
| A7 | Tx journal & nonce state | Integrity, durability | State | Prevents double-broadcast and nonce collisions; feeds `tx list` + the `policy verify` cross-audit |
| A8 | RPC credentials | Confidentiality | Stored only as `${env:}`/`${file:}` refs; resolved in-memory | Theft = quota abuse + surveillance, not direct fund loss |
| A9 | Transaction integrity (to/value/data/chainId/fees/nonce as approved) | Integrity | In-memory between policy check and signing | Cryptographically protected: only the locally signed payload leaves the process |
| A10 | Local registries (tokens, NFTs, contacts) | Integrity | State | A tampered contact silently redirects funds — same blast radius as a hijacked ENS name |
| A11 | The `daxie` binary & OCI images | Integrity, provenance | brew / install.sh / GHCR | A trojaned wallet binary defeats everything else (T7) |
| A12 | Stored contract ABIs (the `daxie contract` registry: alias → address + ABI, per-network) | Integrity | State (`registry/<network>.json`, the §7.8 `contracts[]` array) | A wrong/malicious ABI mis-decodes outputs and *display* and could mislabel a `contract send`'s args to a human reading the echo — but it **cannot** change the bytes signed or the selector the classifier sees: classification reads the calldata, not the ABI's claims (§4.2 `ClassifyCalldata`). Same registry-only anti-spoof model as tokens (A10) |

### 8.3 Cross-cutting decisions (treat as part of the spec)

1. **Policy seal = detached Ed25519, no MAC** (§4.5; OQ #22): the agent-facing process must
   *verify* on every signing op but never hold anything forgery-capable, and only an
   asymmetric signature splits "verify" from "forge".
2. **Fail closed; absence fails closed once an anchor exists** (§4.3 stage 1, §4.6): any
   seal failure halts *all* signing with **exit 8**; anchor-present + policy-missing and
   policy-present + anchor-missing are both violations; **no unpinned verification mode**.
3. **Reserve-then-commit spend accounting** (§4.4): the reservation is fsynced *before*
   signing, the journal entry after, so a crash *wastes* allowance instead of *leaking*
   it; `Release()` is valid only before signature bytes exist; counters are rolling-24h,
   per `chain_id`, aggregated across all keystore accounts. *Open gap (R2a):* the
   across-all-accounts aggregate is not concurrency-safe under per-account locking alone —
   single-account is sound; multi-account overshoot is `policy verify`-detectable, not
   prevented, until a per-`(network)` day lock lands.
4. **Key export requires the admin passphrase** (the CLI ceremony, §3.9) — defense in
   depth against casual injection. The keystore passphrase alone is useless as a guard
   (the agent holds it); export is a human recovery operation. *Honest residual:* a
   code-executing agent can still read the keystore file and attack it offline (R1).
5. **The MCP surface contains no key-extraction or policy-mutation tools** (§6.1). MCP
   tools never accept passphrases/key material as args or return them; MCP never accepts
   `--config`/`--keystore`/`--state-dir` path args — the four paths are fixed at server
   launch. *Honest caveat:* under stdio "fixed at launch" is only as strong as the
   launcher (the parent sets argv/env; when that parent is the agent itself,
   `DAXIE_STATE_DIR=/tmp/fresh` at exec is the same attack as the CLI variant) — so the
   fixed-paths property holds **when a trusted harness launches `daxie mcp serve` with
   pinned env and flags** (a deployment precondition, docs/deploy). The anchor's
   config-class placement + Viper carve-out apply regardless of launch env, so the
   *policy* trust root is unaffected by a hostile launcher; only *counter continuity* (R2)
   tracks it.
6. **Chain ID comes from config, verified per process.** The EIP-155 `chainId` in every
   signed tx comes from the network definition, never the endpoint's answer; beyond
   add/test, `eth_chainId` is re-verified once per process per endpoint before the first
   state-changing call (mismatch → exit 12 / `rpc.chain_id_mismatch`).
7. **All chain-derived strings are sanitized for terminal output** (token names/symbols,
   ENS names, NFT metadata, revert reasons): strip C0/C1 control chars and ANSI escapes
   before writing to a TTY. JSON mode is safe via the encoder.
8. **Memory & process hygiene** (§3.10): secrets as `secret.Bytes`, wiped after use;
   string-free mnemonic/seed decoders; mlock/VirtualLock; `RLIMIT_CORE=0` on Unix;
   secrets never reach argv (no secret-valued flags). Logging contract: stderr logs and
   the journal never contain mnemonics, keys, passphrases, resolved RPC secrets, or
   unmasked credentialed URLs.
9. **Pre-sign echo is unconditional.** Every signing op prints the fully resolved facts
   (from, to with ENS/contact resolution shown, amount, token contract, chain ID, fee
   ceiling) to stderr and embeds them in JSON, *even with `--yes`* (`EvResolved`).
10. **The trust root is `policy-anchor.json`; the earlier keystore "marker" is withdrawn**
    (§4.6, §11 D9). Repointed `--config`/`DAXIE_CONFIG` gains the interface-confined agent
    nothing on K8s (read-only ConfigMap it cannot redirect); `config set` cannot touch the
    `policy.*` subtree (rejected outright). On a writable laptop install, pointing
    `--config` at a forged anchor requires arbitrary file write (already R1/R2 territory —
    the same attacker reads the keystore and passphrase).
11. **`policy.*` config keys are excluded from `daxie config` entirely** — `config set`
    rejects them; it does not admin-gate them (offering an admin-gated `config set` would
    re-open the agent-adjacent channel OQ #2 closed).
12. **Verify-key anchor lifecycle** (§4.6): mandatory whenever a policy exists; written by
    the bootstrap `policy set` on writable config, else emitted to stdout/`--anchor-out`
    for the documented operator/CI ConfigMap-landing step; rotation is staged + zero-outage
    via `verify_key`/`verify_key_next` + `pin --verify` canary.
13. **Windows parity for every file-level mitigation** (requirements §8): dual-impl locks
    (`flock`/`LockFileEx`), owner-only DACLs, `CGO_ENABLED=0` everywhere. `RLIMIT_CORE=0`
    has no Windows equivalent (WER can capture memory) — there the
    passphrase-encryption layer is the backstop (R7).
14. **Arbitrary calldata is classified, never trusted as opaque** (§4.2 `ClassifyCalldata`,
    §4.3 stages 2 + 5b). `contract send` decodes the 4-byte selector before signing:
    recognized spend-equivalents (`approve`/`transfer`/`setApprovalForAll`/`permit`) become
    the **same `Check`** the typed path produces and hit the identical allowlist + unlimited
    ceremony; unrecognized selectors are **deny-by-default once a policy is active**
    (`contract_call.unknown`), opt-in only via the admin-gated per-`(network,contract,
    selector)` allow registry. The classifier matches on the **selector** (a property of the
    signed bytes), **never** on the user-supplied ABI's function names (mutable metadata that
    may lie) — same "match the bytes, not the claimed name" rule as the §4.2 typed-data
    recognizers. `--value` is ordinary `SpendWei`; value moved *inside* calldata is invisible
    to the ETH limits, which is why the contract-destination allowlist + fail-closed-no-
    allowlist rule are load-bearing here, applied a fortiori.

### 8.4 Adversaries and attack scenarios

**T1 — Compromised / prompt-injected agent** (the headline adversary). Two sub-cases:
(a) *prompt-injected, interface-confined* — hostile instructions, but the only tools are
Daxie invocations (an MCP-only toolbelt, or a sandboxed executor permitting nothing but
`daxie …` and excluding the config path); (b) *host-compromised* — arbitrary code
execution as the agent uid. An agent with a **general shell** is already (b).

| Attack | Mitigation | Refusal |
|---|---|---|
| Drain funds in one tx | Per-tx spend limit enforced in core before signing | exit 3 / `policy.denied.tx_limit` |
| Drain via many small txs | Rolling-24h window (no 2× midnight burst), gas included, durable counters, aggregated across all keystore accounts per network. **Caveat (R2a):** the aggregate is not concurrency-safe under per-account locking — concurrent sends on *different* accounts can overshoot `max-day`; single-account sends sound; multi-account overshoot journal-detectable | exit 3 / `policy.denied.day_limit` |
| Drain ERC-20/721/1155 (limits are ETH-denominated) | ETH limits cover native value + worst-case gas only; token value is bounded by the allowlist + ceremony + gas. **Fail-closed bridge:** limits set + no allowlist ⇒ token transfers/approvals refused unless the admin acknowledges the gap (§4.3 stage 3c) → residual R6 | exit 3 / `policy.denied.no_allowlist` |
| Send to attacker address | Destination allowlist (contacts/addresses/pinned ENS) | exit 3 / `policy.denied.allowlist` |
| Raise its own limits | Policy mutations require the admin passphrase the agent never has | — |
| Edit policy file directly | Ed25519 seal verified against the pinned anchor at every signing op; fail closed | exit 8 / `policy.seal_violation` |
| Repoint `--config`/`--state-dir`/`--keystore` (or `DAXIE_*` env) at a policy-free view | Anchor in config class + Viper carve-out: on K8s a read-only ConfigMap the agent cannot redirect; for the interface-confined agent no `daxie` command relocates/strips the anchor without admin auth; `config set policy.*` rejected. Counter *continuity* under a repointed state dir remains open → R2 | — |
| `policy init`/`reset` to wipe limits | `policy set` refuses to bootstrap while an anchor exists; `reset --force` authenticates against the anchor (admin passphrase) — neither replaces the trust root | exit 8 / `policy.admin_auth` |
| Exfiltrate keys via Daxie | No export over MCP; CLI export needs admin passphrase + keystore passphrase + `--yes` | — |
| `token approve` the world | Approvals are spend-equivalents: spender must pass the allowlist; unlimited requires `--unlimited --yes` / `acknowledge_unlimited`; `allow_unlimited:false` is an operator hard-deny. Residual: a hijacked agent controls its own `--yes`, so absent a per-token `allow_unlimited:false` it *can* sign an unlimited approval to an allowlist-passing spender (documented hardening: one rule per held token) | exit 3 |
| Gasless drain via spend-equivalent EIP-712 | Policy-inspected per §4.2: EIP-2612/DAI/Permit2 checked as approvals, counted at signature time; all other typed data deny-by-default. Order schemas (Seaport, 0x) under admin-allowed domains are admitted-but-not-value-checked in v1 → R5 | exit 3 / `policy.denied.*` |
| Move funds via EIP-191 `personal_sign` | Always allowed (the `\x19…` prefix makes it unusable as a tx/typed-data forgery); single `messages` kill switch. Legacy Wyvern-style protocols honoring personal-sign as fund-moving → R5. Raw-hash signing not offered at all | — |
| Waive gas cap during fee spike | Gas cap is policy, admin-gated; gas counts toward `--max-day` | exit 3 / `policy.denied.gas_cap` |
| Crash the pod to reset counters | Counters in durable state class, written pre-broadcast | see T9 |
| **"Generic noun defeats the typed nouns"** — `contract send <usdc> approve(attacker, MAX)` to dodge `token approve`'s spender-allowlist + unlimited-ack ceremony | `ClassifyCalldata` (§4.2) rewrites the calldata into the **same `KindApprove` Check** `service.Approve` builds (`To=spender`, `Unlimited=true`), so the identical stage-3 spender-allowlist, stage-3c fail-closed, and stage-6 unlimited-ack gates fire — the typed and generic paths are indistinguishable to `Evaluate` | exit 3 / `policy.denied.allowlist` \| `.no_allowlist` \| `.unlimited_unacked` |
| **Relay a permit / setApprovalForAll via raw calldata** — broadcast an on-chain `permit(...)` or `setApprovalForAll(operator,true)` to grant a spender/operator outside the typed flow | Both selectors are in the v1 recognizer set → `KindApprove` on the decoded spender/operator; `setApprovalForAll(_,true)` is `Unlimited=true` → spender allowlist + unlimited ceremony | exit 3 / `policy.denied.allowlist` \| `.unlimited_unacked` |
| **Arbitrary-call policy bypass** — `contract send` an *unrecognized* selector to drain via a non-standard fund-moving function (a vault `withdrawTo`, a custom `sweep`) | Stage-5b unknown-calldata gate: deny-by-default once a policy is active; the contract must be allowlisted **and/or** the `(network,contract,selector)` triple opted in under the admin passphrase; `--value`+gas still counted, the fail-closed-no-allowlist rule applies a fortiori | exit 3 / `policy.denied.contract_call` \| `.no_allowlist` |
| **Malicious / incorrect ABI causing mis-decode** — supply an ABI that mislabels a fund-moving function as benign, hoping the wallet classifies/displays it as safe | Classification reads the **selector + ABI-encoded args of the bytes to be signed**, not the supplied ABI's names; a lying ABI cannot recolor a recognized spend-equivalent (the selector still matches) nor make an unrecognized selector recognized; mis-decode affects only human-facing *display*, which is why the pre-sign echo (§8.3 item 9) shows the resolved `to`/`value`/`selector` and `call`/`decode` never sign | classification unaffected; unrecognized → exit 3 / `policy.denied.contract_call` |
| **Registered-alias ABI that lies about the contract** — point a `contract` registry alias at address X with an ABI describing some *other*, benign contract | The call is sent to the resolved registry **address**, and `ClassifyCalldata` decodes the **actual calldata bytes**; the ABI lie changes neither the destination (allowlist gate sees the real address) nor the classified spender/recipient (decoded from the bytes). Registry resolution is local/explicit (A10/A12), never on-chain | governed by the destination allowlist + classifier, not the ABI |

**Honest limit:** sub-case (b) can read the keystore file and already knows the
passphrase → offline decryption outside Daxie. No in-process design stops that — residual
**R1**, the primary motivation for the v2 signer daemon.

**T2 — Stolen laptop / seized disk.** scrypt-encrypted geth keystore (N=2¹⁸) — memory-hard
offline brute force (docs mandate ≥128-bit passphrases for agent deployments, the only
wall here); mnemonics only inside the encrypted envelope; RPC keys are references not
secrets; the admin passphrase lives only in the operator's head (even with the anchor on
disk, the seal key is scrypt-derived from a passphrase the disk doesn't contain).
Privacy (journal/contacts plaintext) is out of scope — full-disk encryption is the
documented recommendation. *Caveat:* a *running* stolen laptop with the passphrase in env
is T1(b), not T2.

**T3 — Malicious or hijacked RPC endpoint.** Chain ID from config + per-process
`eth_chainId` verification (exit 12) defeats wrong-chain signing; transaction tampering is
impossible by construction (signing is local; only the signed raw tx is sent); gas
inflation is bounded by the policy gas cap + fee headroom; nonce lies split by direction
(too-low caught by the journal-max nonce + `nonce too low` detection; too-high refused with
`tx.nonce_gap` (exit 9) above `nonce.max-gap` unless `--nonce` is explicit); non-TLS URLs
require explicit `--insecure` at `rpc add` except localhost. **Not fully mitigable in v1:**
fake balances / fake confirmations / spoofed `receive` events (a single endpoint is the
oracle) — user-supplied trusted endpoints + confirmation thresholds + ENS pinning are the
v1 mitigations → residual **R4** (not closed by the daemon; future multi-endpoint quorum /
light-client).

**T4 — Malicious token / NFT contract.** Symbol spoofing defeated by **registry-only
resolution** (on-chain `symbol()` never used for matching); alias collisions resolved
explicitly with `--name`; junk airdrops invisible (`balance --all`/`nft list` consult only
the registry); terminal-escape injection via names/metadata/revert strings sanitized;
gas-griefing transfer hooks bounded by the gas cap + daily limit (estimation *failure* is
a refusal, not a fallback to a huge limit); approval-phishing gated by the allowlist +
unlimited ceremony. Malicious `tokenURI` (SSRF/decompression bombs) is noted now for when
metadata rendering ships (size caps, timeout, no redirects to private ranges).

**T5 — Poisoned or re-pointed ENS name.** Re-pointing an allowlisted name to an attacker
address is refused by **allowlist pinning** (the sealed policy stores name + resolved
address; a differing resolution refuses with `policy.denied.pin_drift`, exit 3, until
re-allowed); contacts pin identically; homograph names get ENSIP-15 normalization + a
non-ASCII warning with codepoint escape; an ad-hoc `--to name.eth` send echoes the resolved
address before signing (interactive mode confirms; non-interactive `--yes` is protected
only by the allowlist — docs steer agents to allowlisted/pinned entries) → folded into
R4/R5.

**T6 — Malicious MCP client.** In v1 (stdio) the client is the parent process (it could
equally exec the CLI, so this largely reduces to T1). Bypassing guardrails via the "other
frontend" is impossible by architecture (policy in core; both frontends thin); no
key/passphrase-extracting tools exist; tool-call flooding is bounded by the spend/gas/day
limits (per-call rate limiting is the future policy engine); malformed args hit the SDK's
JSON-schema validation + the same core validation the CLI feeds; repointing state paths via
launch env tracks the trusted-harness precondition (§8.3 item 5). v1.1 HTTP transport:
reserved auth hooks from day one; chart defaults bearer/mTLS + default-deny NetworkPolicy,
no Ingress.

**T7 — Supply-chain attack on the binary.** cosign-signed binaries + SHA256 checksums on
every release; cosign-signed multi-arch OCI images; `install.sh` verifies SHA256 by
default and auto-verifies the cosign signature when `cosign` is present (mandatory with
`--verify-signature`); the Homebrew cask pins URL + sha256 (tap compromise detectable
by mismatch — R9 for users who don't verify); `go.sum` pinning + minimal pure-Go dep tree;
CI runs `govulncheck` + `go mod verify`; goreleaser emits SBOM + SLSA provenance;
reproducible-build posture (`-trimpath`, pinned toolchain, ldflags version); distroless
base. (Details in §9.)

**T8 — Multi-replica nonce collision.** flock on nonce/journal/spend state makes
single-host parallel invocations safe; two pods on different nodes sharing a key **cannot
be locked across hosts in v1** (flock over network volumes is unreliable) — the
**single-writer-per-account rule** is documented, per-agent accounts are one `account
derive` away, and collision *detection* at broadcast (`nonce too low` / `replacement
underpriced` → distinct error + journal recovery) is the v1 mitigation → R8 (closed by the
daemon, which serializes per-account nonces behind one process). Double-broadcast after a
crash is prevented by pending-before-broadcast journaling.

**T9 — Pod-restart counter reset.** Counters are never memory-only (state class on a PVC);
reserve-then-commit fsyncs the counter *before* signing; an unreadable/corrupt counter
fails closed (`policy.state_error`, exit 8) rather than resetting to zero; Daxie logs a
prominent startup warning when the state dir is empty but the keystore has prior accounts
(heuristic for lost state). Clock rollback to re-widen the rolling-24h window requires clock
control in the agent's environment (same residual trust domain as counter tampering) —
monotonic-clock sanity warning only, otherwise out of scope (closed by the daemon's clock).

**T10 — Direct state-file tampering.** Policy file edited: K8s (anchor in a read-only
ConfigMap) → **detected; signing halts** (exit 8); local/Docker (config + state
same-uid-writable) → detected against every interface-confined attacker (`config set`
rejects `policy.*`; no Daxie interface relocates the anchor without admin auth), only
tamper-*evident* against arbitrary-file-write attackers (who can swap `policy.json` +
`policy-anchor.json` together) → R2. Policy deleted → fail closed (a present anchor makes
absence a violation). Policy rolled back to an older validly-sealed version →
**prevention-grade** (the anchor's `NonceWatermark` refuses `body.nonce < watermark`, exit
8) against interface-confined attackers; only a coordinated arbitrary-file rewrite of both
files survives (R3). Counters/journal edited → **not sealable in v1** (the agent-facing
process writes them and holds no secret to seal with — the named §7a gap); per-tx limit,
allowlist, gas cap, typed-data classifier, and unlimited gate are stateless against the
sealed file and unaffected (the gap is narrow: *daily* limits only); `policy verify`
recomputes the 24h window from the append-only journal and flags divergence. Contacts/
registry edited → policy-allowlisted destinations are tamper-evident even if contacts
aren't (pins live in the sealed policy). Keystore file swapped → decryption/MAC failure →
hard error; substituting the attacker's *own* keystore is pointless (it moves attacker
funds). `policy-anchor.json` deleted/edited → anchor missing while policy exists ⇒ fail
closed; a swapped anchor only "verifies" a policy the attacker can also re-seal (needs the
admin passphrase) — on its own it bricks signing rather than enabling it.

### 8.5 Explicitly out of scope (v1)

Root/OS-level compromise of the host (no userspace wallet survives a hostile kernel;
container hygiene reduces the *path* to root but defending against root is not claimed);
hardware/physical side channels (the hardware-wallet signer backend is the future layer —
`domain.Signer` is reserved); malicious contract *logic* the operator chose to call (Daxie
is a wallet, not an auditor — it guarantees you sign what was displayed, within policy);
clipboard snooping/substitution (Daxie never reads/writes the clipboard — QR + stdout only;
contacts/aliases reduce raw-hex copying); social engineering of the operator (procedural —
docs mandate admin ops only on trusted terminals); network privacy/metadata surveillance
by RPC providers (self-hosted endpoints are the answer; Tor not in v1); DoS against public
RPC defaults (availability, not custody); quantum adversaries; cross-chain replay onto
chains that ignore EIP-155 (pre-155 chains are not in the preset list).

### 8.6 Residual risks, ranked

For each: does the **v2 signer daemon** (keys + policy + counters behind a privilege
boundary — separate uid/daemon locally, separate pod via `mcp serve --transport http` +
Helm in K8s, agents holding only an access credential) close it?

| Rank | Sev | Residual | v1 state | v2 daemon? |
|---|---|---|---|---|
| R1 | **Critical** | Agent-domain code execution reads the keystore file + passphrase → offline key extraction, all policy moot | Unmitigable in one trust domain; scrypt only buys brute-force time if the passphrase weren't co-resident — and it is | **Closed** (the headline fix): keys live only in the daemon's domain; the agent holds a revocable credential; key export from the daemon is not an API |
| R2 | **High** | Same-domain state tampering: spend counters (and journal/contacts) writable by the agent-facing process; repoint `--state-dir` at a fresh empty window; on a writable install swap `policy.json` + anchor wholesale | Named gap (§7a). Partial: pre-broadcast accounting, atomicity, fail-closed corruption, `policy verify` cross-audit, the config-class anchor + Viper carve-out (closes every interface-confined variant and, on K8s, the file-swap variant structurally) | **Closed**: counters/policy/anchor live with the daemon |
| R2a | **High** | Cross-account daily-limit overshoot under concurrency: per-`(network,account)` counter files + per-account flock cannot atomically enforce the across-all-accounts aggregate | Spec-level gap (the policy section owes a per-`(network)` day lock + an N-parallel-send test). Single-account sound; multi-account overshoot detect-after-the-fact via `policy verify` | **Closed**: the daemon is the single serialization point for the network aggregate |
| R3 | **High** | Policy rollback by arbitrary-file rewrite (replay an older validly-sealed policy + a rolled-back watermark) | **Narrowed to T1b only**: rollback is *prevented* (not just detected) against interface-confined attackers via `NonceWatermark`; on K8s the anchor is a read-only ConfigMap | **Closed**: policy state held by the daemon |
| R4 | **Medium** | Single RPC endpoint as truth oracle: fake balances, fake confirmations, spoofed `receive` events, lying ENS for non-pinned names | Partial: trusted user-supplied endpoints, chain-ID verification, confirmation thresholds, ENS pinning for allowlisted destinations | **Not closed** — the daemon trusts RPC the same way. Path: multi-endpoint quorum / light-client (post-v2) |
| R5 | **Medium** | In-policy bleed: a hijacked agent spends *up to* the limits forever; admitted signature classes (EIP-191 personal-sign a legacy protocol honors; admin-allowed EIP-712 order domains not value-checked); now also recognized-spend-equivalent `contract send`s that pass every gate (a hijacked agent can approve/transfer via the generic noun within limits + to allowlisted destinations exactly as via the typed nouns — by design; the classifier makes them equivalent, not `contract` *safer* than `token`) | Inherent to autonomous custody; limits bound rate, journal gives audit trail; domain allows are admin-gated | **Not closed** by the boundary itself. Path: the fuller policy engine (rate limits, time windows, per-asset rules, webhooks) |
| R6 | **Medium** | Token-value drain through unconfigured tokens: ETH-denominated limits cover native value + gas only — now also reached by `contract send`'s recognized `transfer`/`transferFrom` token path (same gap, same closer) | Partial: the fail-closed no-allowlist refusal; documented hardening (one rule per held token + allowlist on); approvals/permits stricter regardless; a recognized `contract send` token transfer to an allowlist-passing recipient is bounded by the same allowlist + the per-asset layer | **Not closed** by the boundary; closed by the future **per-asset policy layer** — and today by operator configuration |
| R7 | **Medium** | Secret remanence in memory/swap (Go GC copies, swapped pages); Windows has no core-dump suppression | Best-effort wipe + `zeroECDSA`, mlock/VirtualLock, `RLIMIT_CORE=0` on Unix, encrypted-swap guidance | **Narrowed**: only the daemon process ever maps keys, shrinking the surface from every invocation to one hardened process |
| R8 | **Low** | Cross-host nonce collision when the single-writer rule is violated | Documented rule, cheap per-agent accounts, broadcast-time detection + recovery | **Closed**: the daemon is the single signer per account |
| R9 | **Low** | Distribution-path compromise (tap PAT, installer mirror) for users who skip verification | Checksums + cosign exist; defaults verify SHA256; cosign opt-in | **Not closed** (orthogonal). Path: cosign-by-default in install.sh once keyless verify UX stabilizes |
| R10 | **Medium** | **Novel-selector blind spot in `ClassifyCalldata`** — a proxy/diamond (EIP-2535) dispatch selector, a non-standard approval, or a future token standard whose fund-moving selector is not in the v1 recognizer set is not re-classified as a spend-equivalent | **Caught, not silently passed:** the stage-5b unknown-calldata gate is deny-by-default once a policy is active, so a novel selector fails closed exactly like unknown typed data — the residual is *capability* (the agent can't use a novel contract until the operator allowlists it / adds the triple), not a *bypass*. A 4-byte selector collision (two functions sharing a selector, one benign one fund-moving) is the narrow sharp edge: v1 matches the 4-byte selector + decodes args to the expected shape (shape-mismatch → `ok=false` → unknown gate), catching most collisions; a same-shape collision is the documented hardening item (full-signature confirmation via the registry/ABI). Folds the "operator chose to call malicious *logic*" case into §8.5's out-of-scope line | **Not closed** by the boundary (the daemon classifies the same way); closed by **growing the recognizer set + the fuller policy engine** (per-selector rules, ABI-signature confirmation) — same forward path as R5 |

**Reading for the v1 milestone:** R1–R3 — the three worst — are exactly the ones the
signer-daemon boundary eliminates, which is why requirements §7a names it the v2 hardening
path and why the v1.1 HTTP transport + Helm chart is sequenced as the first post-v1
milestone. Two things make v1's posture stronger than a naive read suggests: (1) the policy
trust root is a **config-class anchor outside Viper**, so on K8s it is structurally beyond
the agent's reach and rollback is **prevented** (watermark), not merely detected; (2) the
seal is a **single detached Ed25519** signature whose verify key the agent holds but whose
signing key only the operator holds — the verify/forge asymmetry that makes "detect
tampering without enabling it" possible. v1's claim is deliberately scoped about who is
T1a: an agent with a general shell is T1b by this model's own definition, so the anchor's
T1a guarantee protects tool-sandboxed agents (executor permits only Daxie invocations,
excludes the config path), not arbitrary shell-wielding agents. Against agent-host code
execution (T1b), v1 bounds and detects but cannot prevent, and says so — that is precisely
the boundary the v2 daemon moves.

---

## 9. Release & CI pipeline

Modeled on the witwave `ww` client pipeline, copied where it earned its scars and hardened
where Daxie's wallet threat model differs. Two structural facts simplify everything: Daxie
is a **single-module repo** (module root = repo root — none of witwave's parent-dir
copy-hook problems apply; the `..`-glob CI guard is kept anyway), and Daxie is a **wallet**
(supply-chain integrity is a feature — tag rulesets, a gated `release` environment,
SHA-pinned actions, SLSA provenance, cosign on blobs and images, and a near-empty secrets
list).

### 9.1 Decisions at a glance

| Topic | Decision |
|---|---|
| Release tool | **goreleaser v2**, action pinned to a specific minor (`version: "~> v2.16"`, never bare `"~> v2"`), config at repo root `.goreleaser.yml` |
| Build matrix | darwin/linux/windows × amd64/arm64 (6 targets), `CGO_ENABLED=0`, `-trimpath`, **bit-reproducible** (deterministic given the pinned Go toolchain: `-buildvcs=false` + commit-pinned `mod_timestamp` + `{{ .CommitDate }}` ldflag + no wall-clock input) |
| Version embedding | ldflags `-X` into `internal/version` (`Version`, `Commit`, `Date`=**commit** date for reproducibility); read by `daxie version` **and** the MCP server-info block (one core, two frontends) |
| Signing | **cosign keyless (GitHub OIDC)** — no signing-key secret exists |
| Provenance / SBOM | SLSA L3 via `slsa-github-generator`; syft SBOM per archive |
| Homebrew | `homebrew_casks:` render-only (`skip_upload: true`); a separate `cask-publish` job (stable tags only) pushes to `daxchain-io/homebrew-tap` with `HOMEBREW_TAP_GITHUB_TOKEN` — independently re-runnable, never triggers a rebuild |
| OCI image | `ghcr.io/daxchain-io/images/daxie`, multi-arch via goreleaser **`dockers_v2:`** (the v3-default successor, not the deprecated `dockers:`/`docker_manifests:`), base `gcr.io/distroless/static-debian12:nonroot` (digest-pinned), cosign-signed manifest via the shared top-level `docker_signs:` |
| Installer | `scripts/install.sh` published as a release asset; envs under **`DAXIE_INSTALL_*`** (a sub-namespace, never bare `DAXIE_*`, §9.4) |
| Channels | `stable` = `vX.Y.Z`; `beta` = `vX.Y.Z-beta.N`/`-rc.N`. Brew, `:latest`, `:X.Y` track stable only |
| CI | `ci.yml`, `ci-install-script.yml`, `release.yml` (+ `release-helm.yml` reserved for v1.1) |
| Secrets | exactly **one** repo secret: `HOMEBREW_TAP_GITHUB_TOKEN` |
| Windows | release archives (zip) only in v1; scoop/winget later; install.sh exits 2 on Windows |
| Helm | deferred to v1.1 with the HTTP transport (§7a); workflow name reserved |

### 9.2 Versioning policy & channels

SemVer 2.0.0, flat `v*` tags, released from `main`. `release.prerelease: auto` marks any
dash-suffixed tag as a GitHub prerelease, so the channel split is mechanical:
`/releases/latest` never returns prereleases (the stable redirect, no API/rate limits).
**What semver protects** (the public API agents script against): the command tree and
flags, JSON output schemas, documented exit codes, MCP tool names/schemas, the config file
schema, `DAXIE_*` env var names, and on-disk state formats — each versioned by its owning
section (journal records `"v"`, registry/config `schema`, counters `version`, the policy
body `version`); **an un-versioned state file may not ship** (durable spend counters can't
survive an upgrade safely if a newer binary can't know what it is reinterpreting).
Migration rules within a major are **not uniform**: journal/registry/counters are
forward-only on first write (a state dir written by a newer major is refused, exit 11 —
never best-effort-parse a financial journal); the **policy file is carved out of the
automatic promise** (the agent-facing process is never given the admin passphrase, so it
*cannot* rewrite-and-reseal — an "automatic" policy migration would either break the seal,
halting signing fleet-wide, or require the agent to hold the resealing key). The policy
write-side rule (owned by §4): admin mutations emit the **oldest schema representation that
expresses the configured policy** (fields added in later minors are omitted unless set), so
a routine `policy set` from a newer out-of-band Job re-seals without bricking older agent
pods — only *configuring a newly-added feature* writes a new field, which legitimately
requires the fleet to be ≥ that version (release notes for any policy-schema-growing minor
must state "upgrade agents first, configure the feature second"). Breaking any protected
surface ⇒ major bump; new commands/tools/fields ⇒ minor. The JSON/exit-code contract is
treated as stable from the first beta (agents integrate early). **v1.0.0 criterion:** CLI
spec + MCP surface frozen, one full beta→rc cycle survived. **Channel propagation:** GitHub
Release + archives + checksums + sigs on every tag; Homebrew cask + `:X.Y`/`:latest` docker
tags on **stable only** (a `{{ if not .Prerelease }}` guard in `dockers_v2` means a beta can
never move a floating tag under a running deployment — agents pin exact versions or
digests).

### 9.3 Signing: keyless OIDC

cosign keyless via GitHub Actions OIDC — **no key to steal** (a `COSIGN_PRIVATE_KEY` secret
is exactly the standing credential this pipeline avoids); the signature binds to *this
repo's release workflow at this tag ref* via a short-lived Fulcio cert + Rekor transparency
log. Identity pinning is tighter than witwave's repo-prefix — Daxie pins the exact workflow
file + tag-ref pattern:
`--certificate-identity-regexp '^https://github.com/daxchain-io/daxie/\.github/workflows/release\.yml@refs/tags/v'`.
What gets signed: **`checksums.txt`** (blob signing — transitively covers every archive
**and `install.sh`**, which is pulled into `checksums.txt` via `checksum.extra_files`, the
load-bearing stanza without which the one script every `curl|sh` user executes would be the
only unsigned asset); **image manifests** (top-level `docker_signs:` by digest); and **SLSA
provenance** (a separate signed in-toto predicate over the archive hashes). Trade-offs
accepted: verifiers need cosign + network access (SHA256 checksums are always verified;
the installer also runs the cosign signature check automatically when cosign is on PATH,
and `--verify-signature` makes it mandatory); GitHub OIDC + Sigstore trust.

### 9.4 `.goreleaser.yml` (key stanzas)

The full config is concrete enough to paste; the load-bearing parts:

```yaml
version: 2
project_name: daxie
before:
  hooks: [go mod verify, go mod download]   # non-mutating integrity checks only (NOT go mod tidy)
builds:
  - id: daxie
    main: ./cmd/daxie
    binary: daxie
    env: [CGO_ENABLED=0]                     # §7a container hygiene: fully static, pure-Go deps
    goos: [darwin, linux, windows]
    goarch: [amd64, arm64]                    # full 6-target matrix incl. windows/arm64
    flags: [-trimpath, -buildvcs=false]       # -buildvcs=false REQUIRED for byte-identity (Go 1.18+ auto-stamps vcs.modified)
    mod_timestamp: "{{ .CommitTimestamp }}"
    ldflags:
      - -s -w
      - -X github.com/daxchain-io/daxie/internal/version.Version={{.Version}}
      - -X github.com/daxchain-io/daxie/internal/version.Commit={{.ShortCommit}}
      - -X github.com/daxchain-io/daxie/internal/version.Date={{.CommitDate}}  # commit date, NOT .Date (reproducibility)
archives:
  - id: daxie
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    formats: [tar.gz]
    format_overrides: [{ goos: windows, formats: [zip] }]
    files: [LICENSE, README.md]
checksum:
  name_template: checksums.txt
  algorithm: sha256
  extra_files: [{ glob: scripts/install.sh }]   # so the signed checksums.txt covers install.sh
signs:
  - cmd: cosign
    signature: "${artifact}.sigstore.json"
    args: [sign-blob, "--bundle=${signature}", "${artifact}", "--yes"]
    artifacts: checksum                         # keyless cosign over checksums.txt
sboms: [{ artifacts: archive }]
dockers_v2:                                      # one multi-platform entry (NOT the deprecated triple)
  - id: daxie
    dockerfile: Dockerfile.release              # COPY-only; goreleaser stages the prebuilt binary per $TARGETPLATFORM
    images: [ghcr.io/daxchain-io/images/daxie]
    platforms: [linux/amd64, linux/arm64]
    tags:
      - "{{ .Version }}"
      - "{{ if not .Prerelease }}{{ .Major }}.{{ .Minor }}{{ end }}"   # floating tags STABLE-ONLY
      - "{{ if not .Prerelease }}latest{{ end }}"
docker_signs:
  - { id: daxie-image, cmd: cosign, artifacts: "", args: [sign, "--yes", "${artifact}"] }  # '' = dockers_v2 images
release:
  github: { owner: daxchain-io, name: daxie }
  prerelease: auto
  mode: replace                                 # ONLY for a release whose core artifacts never finished publishing
  extra_files: [{ glob: scripts/install.sh }]
homebrew_casks:
  - { name: daxie, skip_upload: true, repository: { owner: daxchain-io, name: homebrew-tap } }  # render-only; cask-publish pushes
```

`Dockerfile.release` is COPY-only over `gcr.io/distroless/static-debian12:nonroot` (digest
pinned) — distroless/static over scratch (Daxie's outbound is HTTPS JSON-RPC; scratch has no
CA roots), non-root uid 65532, `CMD ["--help"]` so a bare `docker run` doesn't hang reading
empty stdin (v1.1 flips it to `["mcp","serve","--transport","http"]`). The image sets no
`DAXIE_*` env defaults (path wiring is the `docs/deploy/` manifests' job, keeping the §7a
state-class story in one place). `internal/version`:

```go
package version
var ( Version = "dev"; Commit = "none"; Date = "unknown" )
type Info struct{ Version, Commit, Date string }
func Get() Info { return Info{Version, Commit, Date} }
```

Both frontends consume `version.Get()`: the Cobra `version` command renders it; `mcp serve`
reports it in the MCP initialize handshake (agents assert wallet version over MCP without
shelling out).

### 9.5 `scripts/install.sh` and CI workflows

`install.sh` forks witwave's battle-tested POSIX sh (busybox/dash/bash clean, curl→wget
fallback, redirect-based latest-stable resolution with no API/rate-limit, atomic install,
the 0–6 exit map, `--version`/`--channel`/`--prefix`/`--dry-run`/`--uninstall`), changing
identity (`daxie_<ver>_<os>_<arch>`) and wallet-specific items: env prefix
**`DAXIE_INSTALL_*`** with a **permanently reserved `install.*` config-key namespace** (a
binding cross-section contract with §7 — the prefix alone guarantees nothing, since every
`DAXIE_*` var maps to some config key, so the reservation is the sound fix); cosign identity
pinned to the exact workflow; `--uninstall` removes **only** the binary + marker file,
**never** touches `~/.config/daxie`/keystore/state (an uninstaller that could delete key
material is a design defect — and no flag deletes key material or state, ever). A
`download-verify-run` recipe (`cosign verify-blob checksums.txt` → check `install.sh` sha256
→ run) is documented next to the plain one-liner.

CI (all actions SHA-pinned, dependabot bumps): **`ci.yml`** (pre-merge: gofmt/vet/lint/`go
test -race`/build/smoke; `test-cross-os` on macos + windows + windows-11-arm64 — keystore
permissions, path handling, and the §7a file-locking code are exactly what differs per OS;
`cross-compile` all 6 targets with `CGO_ENABLED=0`; `govulncheck`; the **anvil integration
job** — `//go:build integration`, a `internal/testchain` helper execs anvil on a free port
with a fixed mnemonic + chain-id 31337, `DAXIE_IT_REQUIRE_ANVIL=1` in CI turns skip into
failure, **no external RPC endpoints ever**); **`ci-install-script.yml`** (shellcheck;
`goreleaser check` with a deprecation-warning grep whose allowlist is empty since the config
is on `dockers_v2`; a `--snapshot` build → local http.server → real install assertion — the
drift killer; a smoke matrix of real installs of the newest existing release across
alpine/debian/ubuntu/fedora/macos, gated by a "does any release exist yet" pre-check);
**`release.yml`** (tag-triggered, `if: github.ref_type == 'tag'` on every job: a `verify`
job re-runs unit + anvil + a **pre-approval asset-name gate** against the real tag template
*before* the human-approval gate; a `goreleaser` job behind `environment: release` with
`contents/packages/id-token: write`; a standalone `cask-publish` job (stable only) holding
the PAT — a token failure fails only that job and re-runs from the already-built artifact, no
rebuild; `provenance`; post-publication `install-smoke`/`install-smoke-cosign`/`image-smoke`
jobs). **Fail-forward policy:** `mode: replace` is reserved for a release whose core
artifacts never finished publishing; once core artifacts are public, every failure is a
follow-up patch tag — never in-place mutation (deleting/mutating a Rekor-logged signed
release is itself a trust smell). The one repo secret (`HOMEBREW_TAP_GITHUB_TOKEN`) is a
fine-grained PAT scoped to the tap, stored on the `release` environment; tag rulesets +
required reviewers + read-only default `GITHUB_TOKEN` round out the settings. **Bootstrap:**
the first tag is `v0.1.0-beta.1` (exercises the whole pipeline — build/sign/SBOM/provenance/
GHCR/install-smoke — without touching brew, `:latest`, or the stable channel).

---

## 10. v1 milestones & build order

Four ordering principles drive the sequence: **(1) de-risk continuously** (the
`CGO_ENABLED=0` six-target snapshot build and the `depguard`/`arch_test` import matrix run
from M0, so MCP and packaging are *assembly*, not *discovery*); **(2) highest-stakes code
first, offline** (the keystore lands before the RPC layer — pure unit-tested crypto with
geth-compat fixtures, reviewed while the repo is small); **(3) policy lands before every
spend path except the first** (the ETH pipeline is built around a policy seam — an
always-allow stub at first — so the chokepoint is structural; M4 replaces the stub, and
every later spend-equivalent is born policy-checked); **(4) thin frontends mean MCP is late
and cheap** (each tool is an adapter whose schema is inferred from the same request struct
the CLI binds, so putting MCP earlier would churn the surface).

### 10.1 Milestone sequence

| # | Milestone | Size | Hard deps | Tag |
|---|-----------|------|-----------|-----|
| M0 | Scaffold, CI, config & output core (global flags, four state-class paths, exit-code registry, `internal/fsx` `WriteAtomic`/locks/DACLs, `arch_test.go`, `version`/`completion`/`config`/`convert`) | M | — | (untagged) |
| M1 | Keystore, wallets, accounts (`internal/keys` + the `domain.Signer` seam; BIP-39/32/44; geth v3 scrypt; one-passphrase-per-keystore; `meta.json`; `change-passphrase` crash-tested; QR) | L | M0 | `v0.1.0` |
| M2 | Networks, RPC endpoints, chain client, ETH balance (`internal/chain` interface + impl; secret refs; headers; mTLS; chain-ID verify; anvil harness debut + `chain/fake`) | M | M0 | `v0.2.0` |
| M3 | ETH tx pipeline, journal, gas, contacts (`service/tx.go` + `service/gas.go` + `internal/journal`; crash-safe recovery state machine; RBF; `contacts`; the policy seam as an always-allow stub) | L | M1, M2 | `v0.3.0` |
| M4 | Policy engine & guardrails (`internal/policy` + `policyseal`; rolling-24h window; ETH-denomination + fail-closed token rule; gas accrual + cross-link release; Ed25519 seal + `policy-anchor.json` + watermark; the full `daxie policy` surface; replaces the M3 stub) | M | M3 | `v0.4.0` |
| M5 | Token registry, ERC-20 transfers & approvals (`internal/registry` behind `Discovery`; bundled majors; alias-only resolution; `internal/erc`; approvals as spend-equivalents) | M | M3, M4 | `v0.5.0` |
| M6 | NFT: ERC-721/1155 (collection + `collection#id` aliasing; ERC-165 detection; `nft send`) | S | M5 | `v0.6.0` |
| M7 | ENS + allowlist pinning (`internal/ens`; ENS accepted wherever destinations/read-only addrs are; activate the M4-reserved pin field) | S | M2, M4 | `v0.7.0` |
| M8 | `receive` — inbound payment loop (`service/receive.go`; Transfer-log + ETH block-scan/balance-delta detection; NDJSON stream; `--new`) | M | M5, M6 | `v0.8.0` |
| M9 | `sign`/`verify` (EIP-191/712; `policy.ClassifyTypedData` recognizers; Permit policy; `policy typed allow/remove`) | S | M1, M4 | `v0.9.0` |
| M10 | `daxie contract` — arbitrary/non-standard contract interaction (`internal/abi` codec + user-string arg coercion incl. array/tuple literals; per-network **contract registry** alias+address+stored-ABI behind `internal/registry`, anti-spoof like `token`; `contract call`/`logs`/`encode`/`decode` read/pure over `chain.Client`, never sign; `contract send` enters `service.authorize` as the broadest-reach signing path — full §4.3 chokepoint, fail-closed no-allowlist; the **raw-calldata selector classifier** extends §4.2 `KindApprove`/`KindPermit` from typed data to calldata so the generic noun can't bypass the typed ceremonies) | M | M2, M4, M5, M6, M9 | `v0.10.0` |
| M11 | MCP server (stdio; transport-agnostic layer + reserved auth hook; 31 tools; parity test) | M | M1–M10 (gate); spike after M4 | `v0.11.0` |
| M12 | Packaging, release pipeline, docs, v1.0 (goreleaser full pipeline; brew; install.sh; OCI; cosign; `docs/deploy/`; Windows re-validation) | M | all | `v1.0.0-rc.1` → `v1.0.0` |

**Critical path:** M0 → M1 → M2 → M3 → M4 → M5 → M10 → M11 → M12. **Parallel slots** (second
contributor): M6, M7, M9 after M4/M5; M8 after M6; **M10 (`contract`) after M6 and M9** (its
read/registry half is M2-ready, but its calldata classifier reuses M9's recognizer set and
classifies against M5/M6's frozen typed-path selectors); the M11 (MCP) scaffold + first
tools after M4, the tool surface **frozen only once M10 (`contract`) merges** (the contract
tools and the typed-data tools both feed the inferred-schema set). **Pre-release tagging:** every milestone merge to `main` is tagged and
published as a GitHub pre-release with archives + checksums + **cosign signatures from the
first published tag** (de-risks the M11 signing pipeline eleven tags ahead). No brew/OCI
until M11. Builds are advertised as integrator-pinnable only from **`v0.4.0`** (once the
policy engine exists); `v0.3.0` signs with no guardrails and is published for CI continuity,
marked not-for-integration. **Gate for every milestone** = unit tests green on the 3-OS CI
matrix; anvil integration green (from M2); `goreleaser build --snapshot` green for all six
targets; `golangci-lint` (incl. the depguard frontend/leaf matrix) green; the checked-in
`docs/demos/mNN.sh` runs unmodified. Every command ships both human and `--json`, the
non-interactive path, and its documented exit codes.

### 10.2 Command → milestone map

Global flags (cli-spec §2) are all M0 (`--json`, `--quiet`, `--network`, `--config`,
`--keystore`, `--state-dir`, `--yes`). The full sweep, nothing unassigned:

| Command | M | Command | M |
|---|---|---|---|
| `version`, `completion`, `config get/set/list`, `convert` | M0 | `policy show` | M4 |
| `wallet create/import/list/show/rename/export/delete` | M1 | `policy set` | M4 |
| `account derive/alias/unalias/import/use/list/show/export/delete` | M1 | `policy allow/deny` (+ `--remove`) | M4 |
| `keystore change-passphrase`, `keystore info` | M1 | `policy verify/check/counters [release]/pin --print\|--verify` | M4 |
| `network list/add/use/show/remove` | M2 | `policy change-admin-passphrase` (`--stage`/`--commit`) | M4 |
| `rpc add/list/show/use/test/rename/remove` | M2 | `policy reset --force` | M4 |
| `balance` (ETH + raw addr + default acct; `--token`/`--all` → M5; ENS arg → M7) | M2 | `policy typed allow/remove` | M9 |
| `tx send` (ETH; `--token` → M5; `--to name.eth` → M7) | M3 | `token info/add/rename/list/remove` | M5 |
| `tx status/wait/list` | M3 | `token approve/allowance/revoke` (wait flags + 3 exit codes, #19) | M5 |
| `tx speedup/cancel` (RBF; wait flags + 3 exit codes, #19) | M3 | `nft add/alias/aliases/list/show/send` | M6 |
| `gas` | M3 | `ens resolve/reverse` | M7 |
| `contacts add/list/show/remove` | M3 | `receive` (all forms; default no timeout; `--new` needs a writable keystore) | M8 |
| `sign message/typed`, `verify` (ENS `--address`) | M9 | `mcp serve --transport stdio`, `mcp tools [<name>]` | M11 |
| `contract add/list/show/remove` (per-network registry: alias+address+stored ABI) | M10 | `contract call` (eth_call; decoded outputs; raw 0x/ENS; never signs) | M10 |
| `contract logs` (eth_getLogs; decode events; `--arg` indexed filter; never signs) | M10 | `contract encode`/`contract decode` (calldata utilities; pure; never sign) | M10 |
| `contract send` (sign + broadcast arbitrary call; full §4.3 chokepoint; calldata-selector classification; gas/wait flags as `tx send`) | M10 | `policy contract allow/remove` (`--selector`; admin-gated; writes §4.5 `contracts_allowed[]`; the stage-5b unknown-calldata gate's allow registry) | M10 |

**Flags that land later than their command** (the only intra-command staging):
`balance --token/--all` (M5), `tx send --token` (M5), ENS-name argument forms on
`balance`/`--to`/`policy allow`/`verify --address` (M7). Each is gated by the milestone that
owns the underlying subsystem — no dead flags (Cobra registers them in the owning
milestone).

All `contract` verbs and their flags (`--abi`/`--abi-stdin`, `--sig`, `--value`, `--block`, `--from` on `call`, `--from-block`/`--arg` on `logs`, and the full `tx send` gas/wait flag set on `send`) land **together in M10** — the noun's codec, classifier, and registry are co-built, so there is no dead-flag staging within `contract`.

### 10.3 Deferred past v1 — each with its trigger

**v1.1 (committed fast-follow):** **HTTP MCP transport** (`mcp serve --transport http`,
streamable HTTP, auth hooks) — trigger v1.0 GA; M10's transport-agnostic layer + reserved
`Authenticator`/`Principal` seam make it additive only. **Helm chart** (`charts/daxie`,
OCI-published, hardened defaults per §7a) — hard-gated on the HTTP transport (with stdio
there is no standalone service to chart); deploys Daxie as a wallet/signing service (keys in
the Daxie pod, agents holding only a credential — the signer-daemon privilege boundary).

**Later (each waits for its trigger, not a date):**

| Item | Trigger |
|---|---|
| Indexer-based discovery ("what does this address hold?") | The M5 registry sits behind `Discovery`. Activate when users can't pre-register what they hold (recurring issue volume) + a first provider integration is chosen |
| Full tx history (inbound + pre-Daxie txs in `tx list`) | Indexer interface landed; until then `tx list` stays labeled journal-only |
| Hardware wallets (Ledger/Trezor) | `domain.Signer` stable through v1.0 with zero breaking changes + a validated pure-Go HID path (`CGO_ENABLED=0` non-negotiable) + CLI-human demand |
| RPC auto-failover | A design pass producing idempotent broadcast semantics (journal-keyed dedupe across endpoints); the endpoint model already reserves priority ordering |
| Profiles (`--profile` wallet+network+RPC bundles) | Observed friction switching the trio together; the config schema reserves a `profiles` table |
| `${keychain:…}` secret source | A validated CGO-free per-OS implementation that keeps static builds |
| scoop/winget manifests | Meaningful Windows download share or direct requests; archives serve Windows from v1.0 |
| Testnet faucet integration | A stable provider-neutral key-free faucet API (decided deferral); until then `docs/` lists manual faucet URLs |
| Blob transactions (EIP-4844/7594) | A concrete agent use case posting blob data; requires extending the gas model — out of v1 scope |
| Rich NFT metadata (`tokenURI`, IPFS, image render) | Demand on `nft show`; requires an IPFS-gateway privacy decision; a nice-to-have in requirements §2 |
| WebSocket subscription upgrade for `receive` | First `wss://` endpoint support in `rpc add`; the `chain.SubscribeNewHead` seam already exists, polling remains the fallback |
| `contract_add`/`contract_remove`/registry-mutation MCP tools | The registry-add anti-spoof boundary (§6.1) defers `*_add` to v1.1 behind per-principal policy; `contract` registry mutation rides the same trigger. Raw-0x + `--abi`/`--sig` covers the agent transact path meanwhile |
| Richer ABI-arg ergonomics: nested-tuple/multidim-array literals beyond the v1 form; named-arg syntax; per-param decimal hints | v1 ships positional string args coerced by the ABI with array/tuple literals (L13); trigger = observed friction on real non-standard ABIs (governance/vault structs) |
| `contract simulate`/trace (state-diff, `debug_traceCall`, multicall batching) | Requires `trace_*`/`debug_*` RPC the shipped public endpoints lack (same constraint §5.8 notes for `receive`); trigger = a `trace`-capable endpoint class in `rpc add` + agent demand for pre-flight beyond `--dry-run` |
| Per-wallet passphrases; fuller policy engine; remote signers (KMS/4337); **the signer-daemon privilege boundary** | Named future layers (requirements §5/§7a). **Per-asset limits** are the specific trigger that closes the v1 ETH-only limit-denomination gap (R6). The **signer-daemon boundary is the v2 hardening path** that closes the spend-counter tamper gap (R2); its first concrete form is the v1.1 HTTP-transport wallet-service deployment |

---

## 11. Design decision log

Decisions this document makes **beyond requirements.md** — the delegated details and the
judgment calls — each with a one-line rationale. (Numeric defaults requirements explicitly
delegated to the design session are marked **[delegated]**; cross-part reconciliations the
synthesis performed are marked **[reconcile]**.)

| # | Decision | Rationale |
|---|---|---|
| **Delegated details (requirements asked the design session to decide)** | | |
| L1 | Default `--wait` timeout = **10m** for every broadcasting command + `tx wait`; **`receive` defaults to no timeout** | "block until paid" is `receive`'s contract; a 5m default would exit before most counterparties pay (§5). |
| L2 | Per-network confirmation defaults: **mainnet 2, Sepolia 1, user-added 1** (flag > config > built-in) | mainnet reorg depth vs testnet/L2 speed; `safe`/`finalized` keywords reserved, not in v1 (§5.2). |
| L3 | `--amount` matching: **cumulative-minimum default**, **`--exact` in v1** (per-tx-minimum deferred) | the agent-to-agent invoice loop needs both a "paid enough" and an "exact invoice" mode (§5). |
| L4 | ETH-arrival detection: **block-scan (attributable) + balance-delta (unattributed) over polling**; baseline carried forward at the head, never re-queried at a fixed block | catches exchange-withdrawal *internal* txs (the common funding path, invisible to block scanning) while working against pruning public RPCs (§5.8). |
| L5 | Secret-input precedence: **stdin-flag > file-flag > `*_FILE` env > env > TTY prompt > error** — amends cli-spec's prompt-first | explicit beats ambient; identical TTY/non-TTY behavior; deterministic error, never a hang (§3.6). |
| L6 | Keystore KDF **scrypt 2¹⁸/8/1** (geth `StandardScryptN`); **admin seal KDF scrypt 2¹⁷/8/1** | geth v3 compat for keys; one audited CGO-free primitive for both secrets (independence via distinct salts/params, not a distinct algorithm) (§3.4). |
| L7 | Policy seal = **admin-passphrase-derived Ed25519 signature** (scrypt → HKDF → Ed25519) over the exact stored body bytes, verified against a config-class `policy-anchor.json` pin, with a monotonic anti-rollback nonce watermark | OQ #22: a symmetric MAC can't split verify from forge (any verify key the agent reads is re-forgeable); asymmetry is the point (§4.5–§4.6). |
| L8 | Spend window = **rolling 24-hour**, not UTC calendar day | the UTC midnight-burst hole hands an unattended agent 2× the limit in two minutes on a schedule it chooses (§4.1). |
| L9 | v1 limits = **ETH value + gas only**; token spend bounded by allowlist + ceremony + gas, **fail-closed** when limits set but no allowlist (admin override required) | no price oracle in v1 (requirements §6 forbids provider integrations); per-asset limits are the named deferred item (§4.4). |
| L10 | Gas accrual = worst-case `gasLimit × maxFee` at sign, **down-only** reconciliation on receipt; RBF accrues only the fee delta; a `cancel` receipt **releases the linked original's value** | a one-shot invocation may never see a receipt; cross-link release prevents a cancelled send standing as phantom daily spend (§4.4, §5.5). |
| L11 | Journal format = **JSONL + flock** (not pure-Go sqlite) | a few-MB linear fold is microseconds; sqlite is ~9 MB of C in a wallet's TCB + a second crash model + disclaims network FS (§5.6). |
| L12 | Per-platform paths: macOS mirrors Linux XDG; **state under `$XDG_STATE_HOME`**; Windows **config roams, keys do not** | terminal-first audience expects `~/.config`; a `tar` of the keystore dir stays a pure key backup; roaming profiles must never replicate keys (§7.3). |
| L13 | `contract` ABI-arg syntax: **positional strings coerced by the ABI, parsed once in core** (§2.3); `address`-typed args accept account refs/contacts/ENS (resolved + echoed like any `--to`); **array/tuple literals** via `'[a,b,…]'`/`'(a,b,…)'` (JSON-subset, comma-separated, bracket/paren-delimited, double-quote escaping, type-directed recursive descent in `abi.ParseLiteral`); **large `uint` always in base units** (decimals are unknowable for an arbitrary param — `daxie convert` owns the 10^n math) | resolves cli-spec's first `[design session]` item; nested/multidim literals + named args are the §10.3-deferred ergonomics — v1 covers the staking/vault/governor 90% with literals + base-unit ints (cli-spec `daxie contract`). |
| L14 | `contract` registry = **per-network alias + address + stored ABI**, `internal/registry`-owned, **state class**, alias-only resolution (never on-chain symbol) — the **same anti-spoofing model as the token/NFT registry** (§7.8), ABI stored inline, `v` 1→2; `contract add` fails the state read-only sibling of `config.read_only` (exit 10) on a read-only state mount; `internal/abi` is a new pure-Go (CGO-free) provider leaf wrapping go-ethereum `accounts/abi` (concrete, no second impl), and `contract send` reuses `service.SendTx`'s pipeline rather than a second one (the four read/pure verbs never reach `authorize`) | the registry is a security boundary, not convenience: a name resolving to an attacker ABI/address is the spoofing primitive the local-alias rule kills (requirements §2; §7.8); the leaf keeps the §4.2 recognizers' selector source pure and shared (§2.1). |
| **Judgment calls (the design's own structural choices)** | | |
| J1 | The composition root is one composed **`service.Service`** with `Open`→use→`Close`; the privileged sequence is **concrete code (`authorize`), not an `Authorizer` interface** | the kernel already sits behind the service boundary; the v2 daemon relocation lands on `domain.Signer` + a policy proxy, so an `Authorizer` interface would have exactly one impl forever (§2.7, §2.1.1). |
| J2 | Exactly **two** exported provider interfaces (`domain.Signer`, `chain.Client`); everything else concrete | an interface is justified only by a named second impl or a security test seam — minimizing interfaces concentrates the fake surface at `chain.Client` (§2.1.1, §2.9). |
| J3 | `Principal` + `EventSink` threaded through every method in v1 (always `local` / often nil) | the HTTP frontend + auth add zero parameters to any method; one streaming seam serves stderr/NDJSON/MCP-progress/SSE (§2.4, §5.9). |
| J4 | **No float-typed field** in any request/result/value type; all user values cross as strings | decimal-exactness becomes a compile-time property, not reviewer vigilance (§2.5). |
| J5 | MCP input schemas **inferred from the same `domain` request structs** the CLI binds, pinned by a golden test | CLI/MCP drift is structurally impossible; guardrails apply identically because both frontends traverse one `authorize` (§6.2, §6.4). |
| J6 | MCP surface = **31 tools** (incl. `contract_call`/`contract_logs`/`contract_encode`/`contract_decode`/`contract_send`); **no policy-mutation, key-export/import/create, derive/alias/use, registry-add tools — `contract_add`/`contract_remove` join `token_add`/`nft_add` on the excluded side** | [reconcile] tightens the Architecture's larger list toward less agent capability — the contract registry is the **same** anti-spoof boundary as token/NFT (a redefined alias, now also binding an ABI, is a spoofing primitive); raw 0x + `--abi`/`--sig` covers the transact path without the spoofing path (§6.1). |
| J7 | The default account + aliases live in **keystore `meta.json`**; `next_index` is keystore-class despite being a monotonic counter | a wrong index derives an already-used address from the *same* mnemonic — address freshness is a key-derivation invariant that must share the mnemonic's backup/durability unit (§3.3). |
| J8 | `internal/fsx` + `internal/secret` are dedicated leaf packages; **`WriteAtomic` atomicity is a correctness guarantee on all 3 OSes** | the Windows divergence (no dir-fsync; `MoveFileEx`+`FILE_SHARE_DELETE`) and the secret-redaction discipline each live in exactly one place; stdlib `os.Rename` is not atomic-on-existing on Windows (§7.9). |
| J9 | Bare names resolve against **both** the keystore namespace and contacts in destination context; a both-match is a hard `ref.ambiguous` | a silent-preference rule turns a name collision into fund misdirection at the money-routing position; the namespaces share no lock, so create-time rejection can't be airtight (§3.2). |
| J10 | `policy deny` is a real **denylist** (denylist > allowlist > include_self), matching pinned address **or** typed name | drift must never weaken a deny entry; a real denylist is more useful than allow-removal (§4.5). |
| J11 | `include_self` resolves against a **sealed `self_addresses` snapshot**, never the live keystore | `account import` needs only the keystore passphrase, so without the snapshot a compromised agent could import an attacker key and mint itself an allowlisted destination (§4.5). |
| J12 | `policy reset --force` authenticates against the **anchor**, never `--yes` | the corrupt-file → reset-with-own-passphrase attack dies at authentication, on every deployment including laptops (§4.7). |
| J13 | One error taxonomy (dotted `domain.Error.Code` strings), two thin renderings (CLI exit code + MCP tool-error envelope) | agents branch on identical-meaning codes across both frontends because they come from the same `error` values (§5.7, §6.6). |
| J14 | MCP surface = **31 tools**: the four `contract` read/pure verbs + `contract_send` become tools; **`contract_add` + the contract-registry mutations/introspection are excluded** under the same alias-spoofing boundary as `token_add` (an alias binds an address **and** an ABI — a strictly larger spoofing primitive); the contract registry is **state-class**, co-located in `registry/<network>.json` with the ABI inline; a `contract send` journals as a normal signed tx (`kind:"contract-call"`, or the classified kind when the calldata is a recognized approve/transfer/permit) | requirements #29: `contract send` is a within-policy fund-mover bound to the typed ceremonies by the §4.2 raw-calldata classifier, so it belongs on the surface; the registry-add stays off because raw-address + inline ABI covers the transact path without the spoof path (§6.1, §7.8, §5.6). |
| **Reconciliations the synthesis performed (to the Architecture, §2)** | | |
| D1 | Package/type names canonicalized: `core.Daxie`→`service.Service`, `core.Signer`/`signer.Signer`→`domain.Signer` (with `Unlocker`), `policy.Request`→`policy.Check`, `core.Err`→`domain.Error`, `core.Options`→`config.Options` | [reconcile] the Architecture (§2) is the named canonical naming authority; every provider part's `core.*` is mapped (§2.4, §2.6, §4). |
| D2 | Secret type **`secret.Bytes`** (not `keys.Buffer`/`secret.Buffer`); durable-write/lock helper **`internal/fsx`** (not `internal/atomicfile` or journal-internal); seal package **`policyseal`** | [reconcile] the corpus converged on shared `fsx`/`secret` leaves — adopted as named packages so the Windows divergence + redaction live in one place each (§2.1). |
| D3 | **Exit-code registry = the 0–12 table (§5.7)**, superseding the Architecture's §3.8 numeric enum: policy-denied = **3** (not 5), seal/auth/state + timeout share **8**, network = **6**, `config/keystore.read_only` = **10** | [reconcile] the provider corpus (policy, MCP, threat, milestone) was written against this registry and all cite it as the single source of truth; the §3.8 dotted *strings* are preserved, only the integer projection changes (§5.7). |
| D4 | Admin seal KDF = **scrypt**, superseding an earlier Argon2id sketch | [reconcile] one audited CGO-free primitive across both secrets; matches the policy + threat parts (§3.4). |
| D5 | Secret-input precedence amends cli-spec's prompt-first ordering (already folded into cli-spec) | [reconcile] documented loudly: an exported `DAXIE_PASSPHRASE[_FILE]` is consumed even at a TTY (§3.6). |
| D6 | "Rolling-24h" wording made canonical; the txpipeline part's stray "UTC-day counter"/"UTC rollover" phrasing is reconciled to it | [reconcile] the Architecture, policy, and threat parts already specify rolling-24h; only the txpipeline wording diverged (§4.1). |
| D7 | Denied sub-code spelling canonicalized to `policy.denied.tx_limit`/`.day_limit`/`.pin_drift`; `policy.denied.spend_limit`/`.ens_pin` are **withdrawn aliases** | [reconcile] two spellings existed for the same denials (same exit code); the policy part owns the taxonomy, so its spelling wins (§4.3). |
| D8 | cli-spec/requirements refinements: wait flags on `token approve`/`revoke`; the `receive` stream is `listening → detected → confirming → confirmed(per-transfer) → complete(terminal)`; `mcp serve --transport stdio`; `mcp tools [<name>]`; the registry-add tools deferred from the MCP surface; **`daxie contract`: the two cli-spec `[design session]` items are resolved (L13 arg syntax; D12 calldata-selector classification) and the `contract` registry/verbs land in M10** | [reconcile] requirements #19 binds wait flags to *all* broadcasting commands; OQ #20 needs both a per-transfer signal and a terminal exit-carrying line; cli-spec's `daxie contract` section explicitly delegates the array/tuple syntax and the selector-classification crux to the design session (cli-spec `daxie contract`, requirements OQ #29); the rest are cli-spec-invited refinements (§5.1, §5.8, §6.1, §6.8). |
| D9 | The policy trust root is the single **`policy-anchor.json`** in the config class; the `policy.verify_key` config-key sketch and the `keystore.json` `policy_pin` sketch are **withdrawn** | [reconcile] binding policy freshness to the keystore couples it to a secret the agent holds; a config-key anchor is env/flag-forgeable — the dedicated anchor + Viper carve-out is the only sound construction (§4.6, §7.6). |
| D10 | `next_index`/aliases stay keystore-class — a **deliberate, named departure** from §7a's "monotonic counters in the state class," fail-closed via the derivation-watermark check | [reconcile] address freshness is a key-derivation invariant, not host-local runtime state; a keystore restored without its state dir would silently reuse indexes (§3.3). |
| D11 | cli-spec's account-reference table gains a `<contact>` row (destination contexts only) + the ambiguity/collision rules | [reconcile] cli-spec promises contact names for `--to`/the allowlist but omitted the row; a resolver blind to contacts leaves a `[DECIDED]` capability undecidable (§3.2). |
| D12 | **§4.2's "no `KindContractCall` in v1 … no unclassifiable path to design a bypass around" assertion is withdrawn.** `daxie contract send` (requirements #29) admits arbitrary user calldata — the unclassifiable path the sentence said v1 lacked. Replacement: `contract send` (the **only** signing path) **classifies known ERC-20/721/1155/Permit selectors in the raw calldata** via the pure `policy.ClassifyCalldata` (the calldata twin of `ClassifyTypedData`, delegating selector matching to `abi.ClassifySelector`) and routes matches through the **same `KindApprove`/`KindTransfer`/`KindPermit` Checks** the typed path emits — so the unlimited ceremony, spender allowlist, and fail-closed no-allowlist rule all fire on calldata identically. **`contract encode`/`decode` deliberately do NOT classify** — they are pure, never sign, never touch policy (§5.11, §2.4), so the security crux is closed entirely at the `send` chokepoint where signing happens; classifying a hex string `encode` merely emits would gate nothing. **No opaque `KindContractCall` Kind is added** (an opaque kind would itself be the bypass); **unrecognized** calldata hits the new deny-by-default **stage-5b `contract_call.unknown` gate** (sub-code `policy.denied.contract_call`, exit 3, an admin-gated per-`(network,contract,selector)` allow registry), with `--value`+gas counted and the contract-as-destination allowlist applied a fortiori. **No new exit code** (reuses exit 3). The old conclusion (no opaque kind) is kept for the opposite reason: all arbitrary calldata is now classified into the existing kinds or denied | [reconcile/decision] requirements #29 + cli-spec's `[design session]` security-crux bullet make the §4.2 sentence false; the generic noun must not silently defeat the typed approval ceremonies (§4.2, §4.3, §4.9, §8). |

These are the deltas this document adds on top of the binding specs. Everything else is
the faithful realization of `requirements.md`'s 29 `[DECIDED]` items (the 28 prior + #29
arbitrary contract calls) and `cli-spec.md`'s
command surface, made buildable.
