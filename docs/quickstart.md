# Quickstart

This walks from an empty machine to a confirmed Sepolia transaction and a wallet
served to an AI agent over MCP. It assumes Daxie is installed
([install.md](install.md)) and uses **Sepolia testnet** throughout — never practice
with mainnet funds.

- [1. Create a wallet](#1-create-a-wallet)
- [2. Point at a network + endpoint](#2-point-at-a-network--endpoint)
- [3. Read a balance](#3-read-a-balance)
- [4. Set guardrails (policy)](#4-set-guardrails-policy)
- [5. Send a transaction](#5-send-a-transaction)
- [6. The unattended / agent flow](#6-the-unattended--agent-flow)
- [7. Serve to an MCP client](#7-serve-to-an-mcp-client)
- [Exit-code branching](#exit-code-branching)

The two passphrases you will meet:

| Passphrase | Unlocks | Who holds it |
|---|---|---|
| **keystore passphrase** | signing (decrypts keys) | the operator *and* the agent |
| **admin passphrase** | policy mutation + the policy seal | the operator **only** — never an agent host |

They are independent secrets. Keep the admin passphrase off any machine an agent can
reach.

---

## 1. Create a wallet

```sh
daxie wallet create treasury
```

Daxie generates a fresh BIP-39 mnemonic, **shows it once**, and requires you to
confirm you recorded it before it encrypts the mnemonic under your keystore
passphrase (geth-compatible v3 scrypt JSON, `0600`). The mnemonic is the only
recovery path — write it down offline.

Make account 0 the default so you can omit `--from`:

```sh
daxie account use treasury/0
daxie account show treasury/0           # address, derivation path
daxie account show treasury/0 --qr      # render the address as a terminal QR code
```

Need a fresh derived account later? `daxie account derive treasury` (or
`daxie account derive treasury --index 3 --name payroll`).

> Importing instead of creating: `daxie wallet import treasury` (interactive), or
> `daxie wallet import treasury --mnemonic-file ./phrase.txt`. A single private key:
> `daxie account import ops-key --key-file ./key.hex`.

---

## 2. Point at a network + endpoint

A **network** is a chain (name + chain ID); an **endpoint** is a named connection to
it. Mainnet and Sepolia are built in.

```sh
daxie network use sepolia
daxie rpc add sepolia-default --network sepolia --url https://rpc.sepolia.org
daxie rpc test sepolia-default          # connect + verify eth_chainId matches the network
```

Endpoint secrets are stored as references, never resolved values:

```sh
daxie rpc add sepolia-alchemy --network sepolia \
  --url 'https://eth-sepolia.g.alchemy.com/v2/${env:ALCHEMY_API_KEY}'
```

Get test ETH from a current Sepolia faucet before
sending.

---

## 3. Read a balance

Read-only operations need no policy and no passphrase:

```sh
daxie balance                           # default account's ETH balance
daxie balance treasury/0 --json
daxie balance vitalik.eth               # ENS names work for read-only ops
daxie balance treasury/0 --all          # ETH + every token in the local registry
```

---

## 4. Set guardrails (policy)

This is the step that makes Daxie a *guarded* wallet. **Policy mutations require the
admin passphrase** — supply it via a TTY prompt, `--admin-passphrase-file`, or
`DAXIE_ADMIN_PASSPHRASE_FILE`. There is no `policy init`; the **first** `policy set`
bootstraps the trust root (it generates the Ed25519 seal keypair and writes
`policy-anchor.json`, the pinned verify key).

```sh
daxie policy set --max-tx 0.1eth --max-day 0.5eth       # per-tx + rolling-24h caps
daxie policy set --max-gas-price 100gwei                # refuse to sign above this fee
daxie policy allow 0xRecipient...                        # allowlist a destination
daxie policy allow exchange                              # ...or a contact name
daxie policy allow vitalik.eth                           # ...or an ENS name (name + address pinned)
daxie policy show
```

After bootstrap, the anchor (`policy-anchor.json`) is the trust root. On a writable
workstation `policy set` writes it for you; on a read-only Kubernetes ConfigMap it
emits the anchor JSON for you to land out-of-band — see
[deploy/policy-k8s.md](deploy/policy-k8s.md).

What the guardrails do, from now on, on **every** signing op (CLI or MCP):

- Per-tx and rolling-24h spend limits (gas included), aggregated across accounts.
- Destination allowlist; an allowlisted ENS that later re-points is refused
  (`pin_drift`).
- A gas-price cap the agent cannot waive.
- The policy seal is verified against the anchor; a tampered/missing policy fails
  closed (exit 8).

---

## 5. Send a transaction

The policy is enforced **in core, before signing** — `--yes` skips the human prompt
but never the guardrails.

```sh
# Interactive (prompts for confirmation + keystore passphrase):
daxie tx send --to 0xRecipient... --amount 0.05

# Wait for confirmation and emit one JSON object:
daxie tx send --to 0xRecipient... --amount 0.05 --wait --confirmations 1 --json --yes

# Dry run: build + estimate + policy-check, never sign:
daxie tx send --to 0xRecipient... --amount 0.05 --dry-run

# A stuck tx? Replace-by-fee:
daxie tx speedup 0xtxhash...
daxie tx cancel  0xtxhash...
```

Before signing, Daxie **always** echoes the resolved facts (from, to with
ENS/contact resolution, amount, chain ID, fee ceiling) — even with `--yes`. Every tx
it broadcasts is recorded in a local journal:

```sh
daxie tx status 0xtxhash...
daxie tx list --account treasury/0
daxie tx wait 0xtxhash... --confirmations 3 --timeout 10m   # resume after a timeout
```

Tokens, NFTs, approvals, and arbitrary contracts ride the same pipeline:

```sh
daxie token add 0xa0b8...                                   # register (alias defaults to symbol)
daxie tx send --to exchange --amount 100 --token usdc --wait --json --yes
daxie token approve usdc --spender 0xRouter... --amount 500 --yes
daxie nft send --to exchange --nft punks#42 --yes
daxie contract send staking stake 1000000000000000000 --from treasury/0 --yes
```

---

## 6. The unattended / agent flow

Agents run without a TTY. Provide the keystore passphrase via a file (the recommended
unattended channel) and pass `--yes` to skip confirmations:

```sh
export DAXIE_PASSPHRASE_FILE=/run/secrets/daxie-pass     # not DAXIE_PASSPHRASE (env is least-safe)
daxie balance treasury/0 --json
daxie tx send --from treasury/0 --to exchange --amount 25 --token usdc \
  --wait --confirmations 2 --timeout 5m --json --yes
```

Notes for unattended use:

- The passphrase resolution order is `--passphrase-stdin` > `--passphrase-file` >
  `DAXIE_PASSPHRASE_FILE` > `DAXIE_PASSPHRASE` > interactive prompt. If any env/file
  source is present you are **not** prompted — even at a TTY — and a wrong one fails
  fast (never a hang).
- The **admin passphrase is never set** in an agent's environment. Policy is
  configured out-of-band by the operator.
- Errors emit a structured JSON envelope on **stderr** while stdout keeps the single
  result; agents branch on the exit code (below).

See [agents.md](agents.md) for the full agent-deployment guide.

---

## 7. Serve to an MCP client

`daxie mcp serve` exposes the wallet to any MCP client over **stdio**. The same
guardrails you set in step 4 bind every tool call.

```sh
DAXIE_PASSPHRASE_FILE=/run/secrets/daxie-pass daxie mcp serve
daxie mcp tools                          # print the 31 tool schemas (debugging)
daxie mcp tools send                     # inspect one tool
```

A trusted harness (not the agent) should launch `mcp serve` with pinned env and the
four state paths fixed. The agent then drives tools like `balance`, `send`,
`token_approve`, `contract_send`, `receive` — all checked against your policy. The
MCP surface **cannot** export keys, create/import wallets, mutate policy, or add a
registry alias. See [agents.md](agents.md) for the tool list and the exclusion
boundary.

---

## Exit-code branching

The codes a send loop switches on:

| Exit | Meaning | Agent action |
|---|---|---|
| `0` | OK (with `--wait`: confirmed; no-wait `tx send`: accepted broadcast) | done |
| `3` | policy-denied (limit / allowlist / gas cap / pin drift / unack'd unlimited) | escalate to operator — do **not** retry |
| `5` | insufficient funds | top up |
| `6` | network (RPC unreachable / broadcast transport failure; resumable) | retry later |
| `7` | reverted (mined with status 0) | investigate the revert |
| `8` | timeout still pending (**not** a failure) — or a seal/state halt | `tx wait <hash>` to resume; if seal, page the operator |
| `9` | nonce/replacement conflict (replaced, underpriced, already mined) | re-quote / `tx speedup` |

The full 0–12 registry is in [design.md §5.7](design.md). The same `code`/`exit`
fields appear on MCP tool errors, so an agent branches identically on both frontends.
