# Deploying Daxie behind an AI agent

Daxie is built for an autonomous agent to hold an account and move funds *within
operator-set limits it cannot raise*. This guide covers the MCP server, the tool
surface, the privilege model an agent deployment must preserve, and the unattended
secret/path wiring. For container manifests see [deploy/](deploy/); for the threat
model see [security.md](security.md).

- [The privilege model in one picture](#the-privilege-model-in-one-picture)
- [Running the MCP server](#running-the-mcp-server)
- [The tool surface (31 tools)](#the-tool-surface-31-tools)
- [What is NOT a tool (the security boundary)](#what-is-not-a-tool-the-security-boundary)
- [Unattended secrets and paths](#unattended-secrets-and-paths)
- [Provisioning the policy out-of-band](#provisioning-the-policy-out-of-band)
- [Per-agent accounts (nonce safety)](#per-agent-accounts-nonce-safety)
- [Honest limits](#honest-limits)

---

## The privilege model in one picture

```text
   operator domain  ───────────────────────────────────  agent domain (one uid)
   admin passphrase                                       keystore passphrase
   policy mutations         policy-anchor.json            daxie mcp serve / daxie <cmd>
   key export / backup     (verify key — read-only) ────► internal service (one core)
        │                                                        │
        └── never crosses this line writably                    └─► signed raw tx ─► RPC (untrusted)
```

The agent can sign **within policy** and read everything. It cannot raise its own
limits, change the allowlist, change what an alias means, or read a key out — those
require the admin passphrase, which lives only in the operator domain. The MCP tool
surface is the enforcement of that split at the API boundary.

---

## Running the MCP server

```sh
DAXIE_PASSPHRASE_FILE=/run/secrets/daxie-pass daxie mcp serve
```

- **Transport:** stdio in v1 (the parent process is the client). Streamable HTTP
  arrives in v1.1 with a reserved auth hook and no refactor.
- **Startup:** the keystore passphrase is verified against the keystore at boot
  (fail-fast, not on the first signing call) and held in an mlock'd buffer for the
  process lifetime. Decrypted HD seeds are cached after first use so each tool call
  does not pay ~1 s of scrypt (`--no-unlock-cache` opts out). Starting with **no**
  passphrase source is allowed — read-only tools work; signing tools return the
  structured passphrase-required error.
- **Version handshake:** the server reports the wallet version in the MCP initialize
  response, so an agent can assert what it is talking to without shelling out.

Inspect the surface without a client:

```sh
daxie mcp tools                          # all 31 tool schemas
daxie mcp tools send                     # one tool
```

The schemas are **derived from the same Go structs the CLI binds**, so CLI and MCP
can never drift; a golden-snapshot test turns any struct change into a reviewed diff.
The JSON output contract is identical across both frontends, and MCP tool errors
carry the same `code`/`exit` fields as CLI errors, so an agent branches identically.

---

## The tool surface (31 tools)

One tool per *operation*, not per asset — a single `send` covers ETH / ERC-20 /
ERC-721 / ERC-1155 (disambiguated by an `asset` field); a single `contract_send`
covers any non-standard ABI.

| Category | Tools |
|---|---|
| Read balances / registry | `balance`, `token_list`, `token_info`, `nft_list`, `wallet_list`, `wallet_show`, `accounts_list`, `account_show` |
| Move funds | `send`, `token_approve`, `token_revoke`, `contract_send` |
| Track txs | `tx_status`, `tx_wait`, `tx_list`, `tx_speedup`, `tx_cancel` |
| Inbound | `receive` |
| Read-only chain | `gas`, `token_allowance`, `ens_resolve`, `ens_reverse`, `contract_call`, `contract_logs` |
| Pure / off-chain | `convert`, `contract_encode`, `contract_decode`, `sign_message`, `sign_typed_data`, `verify` |
| Read policy | `policy_show` |

Field conventions (properties of the shared `domain` structs):

- Addresses are `0x…40-hex` in output; inputs accept **address | contact | ENS** in
  `to`/`spender`/`owner`/`account`.
- Amounts (input) are **decimal strings in asset units** — never a number
  (`10^18` is unrepresentable in IEEE-754; the `convert` tool exists so agents never
  do that math).
- Durations are Go duration strings (`"5m"`).
- Unbounded approvals require an explicit `acknowledge_unlimited` field (the same
  ceremony the CLI's `--unlimited --yes` enforces).

Every funds-moving tool runs through the **one** signing chokepoint where
`policy.Reserve` lives. Set the policy once with the CLI; every MCP `send` /
`token_approve` / `contract_send` is checked against it. The calldata classifier
binds `contract_send`'s recognized spend-equivalents (`approve`/`transfer`/
`setApprovalForAll`/`permit`) to the same allowlist + unlimited ceremony — the generic
tool cannot defeat the typed ones.

---

## What is NOT a tool (the security boundary)

A recorded, non-regressable exclusion list. None of these is reachable over MCP in
v1:

| Excluded | Why |
|---|---|
| All `policy` mutations (`set`/`allow`/`deny`/`reset`/`change-admin-passphrase`/`typed allow`/`contract allow`) | Require the admin passphrase the agent never holds. `policy_show` (read-only) **is** exposed. |
| Key export (`wallet/account export`) | A prompt-injected agent must not exfiltrate key material through its own channel. |
| Wallet/account create & import | Emits or ingests a mnemonic/key over the tool channel — operator-only. |
| `account derive`/`alias`/`use` | Keystore-index mutations; the fresh invoice address an agent legitimately needs is delivered by `receive` with `new:true`. |
| `keystore change-passphrase` | Rotating the unlocking secret from inside the agent channel is a privilege the agent must not have. |
| `network`/`rpc` mutations | Config-class deploy-time topology; they write secret references — operator acts. |
| `token_add`/`nft_add`/`contacts_add`/`contract_add` | The registry is a **security boundary**: an alias resolves only through the local registry, never on-chain. Letting an agent `token_add 0xFAKE --name usdc` (or plant an attacker ABI via `contract_add`) is a spoofing primitive. Deferred to v1.1 behind per-principal policy. |
| Registry removals + `contract_list/show` | Destruction is an operator act; the read introspection is a mild recon affordance the agent never needs (it transacts by raw address + inline ABI). |

The escape hatch costs nothing: any tool taking an asset/destination/contract accepts
a **raw `0x` address** (and `contract_call`/`contract_send` additionally accept an
inline `abi`/`sig`), so withholding the add-tools blocks the *spoofing* path without
blocking the *transacting* path.

In one sentence: **the MCP surface can move funds within policy and read everything;
it cannot change who holds the keys, what the keys may do, what an alias means, or
read a key out.**

---

## Unattended secrets and paths

```sh
export DAXIE_PASSPHRASE_FILE=/run/secrets/daxie-pass     # NOT DAXIE_PASSPHRASE (env is least-safe)
daxie tx send --from bot/0 --to exchange --amount 25 --token usdc \
  --wait --confirmations 2 --timeout 5m --json --yes
```

- Use **`DAXIE_PASSPHRASE_FILE`** (a Secret mount) — survives restarts, fits Secret
  mounts, has auditable perms. `DAXIE_PASSPHRASE` is supported but least-safe.
- Pass **`--yes`** for mutating ops without a TTY; the guardrails still enforce.
- Use a **≥ 128-bit keystore passphrase** for agent deployments — it is the only wall
  protecting a stolen keystore offline.
- Fix the four state paths at launch from a **trusted harness** (not the agent). The
  "paths fixed at server launch" property is only as strong as the launcher; an agent
  that controls argv/env at exec could otherwise repoint `DAXIE_STATE_DIR` at a fresh
  empty window. The anchor's config-class placement protects the *policy* trust root
  regardless of launch env; only counter *continuity* (residual R2) tracks the
  launcher.

A minimal trusted-harness launcher pins everything:

```sh
DAXIE_CONFIG=/etc/daxie \
DAXIE_KEYSTORE=/var/lib/daxie/keystore \
DAXIE_STATE_DIR=/var/lib/daxie/state \
DAXIE_CACHE_DIR=/tmp/daxie-cache \
DAXIE_PASSPHRASE_FILE=/run/secrets/daxie-pass \
  exec daxie mcp serve
```

---

## Provisioning the policy out-of-band

The agent never sets policy. The operator does, from a machine that holds the admin
passphrase — a workstation or a one-off Kubernetes `Job` — then lands the sealed
`policy.json` (state PVC) and the `policy-anchor.json` (read-only ConfigMap). The
write ordering (**policy first, then anchor**), the passphrase-free canary, and the
zero-outage admin-passphrase rotation are in
[deploy/policy-k8s.md](deploy/policy-k8s.md).

---

## Per-agent accounts (nonce safety)

In v1, nonce serialization is via file locks, which are reliable on a single host but
**not across hosts** (flock over network volumes is unreliable). The rule:
**single-writer-per-account.** Give each agent its own derived account — one
`daxie account derive` away — rather than sharing a key across pods. Cross-host
collisions on a shared key are *detected* at broadcast (`nonce too low` /
`replacement underpriced` → a distinct error + journal recovery), not prevented, in
v1 (residual R8; closed by the v2 signer daemon, which serializes per account behind
one process).

---

## Honest limits

The agent surface is honest about its boundary:

- **R1 (Critical) — host compromise.** Code executing as the agent's uid can read the
  keystore file *and* the co-resident passphrase, then decrypt offline outside Daxie.
  No in-process design stops that in one trust domain. The v2 signer daemon closes it
  by moving keys behind a privilege boundary (the agent then holds only a revocable
  credential).
- **R5 (Medium) — in-policy bleed.** A hijacked agent can spend *up to* the limits
  indefinitely. Limits bound the rate, the journal gives an audit trail, and the
  fuller policy engine (rate limits, time windows, per-asset rules) is the forward
  path. This is inherent to autonomous custody — Daxie bounds it, it does not pretend
  to eliminate it.

The full ranked residual table is in [security.md](security.md). Choose limits and an
allowlist that bound the worst case you are willing to accept from a fully
compromised agent.
