# Daxie — CLI Command Surface (Working Draft)

> **Status:** draft for iteration. Companion to [requirements.md](requirements.md).
> This enumerates the proposed v1 command tree so we can react to the user
> interface before the design session locks it in. Nothing here is final.

---

## 1. Conceptual Model

Two kinds of key-holding objects, both named:

| Concept | What it is | Backed by |
|---|---|---|
| **Wallet** | A named HD wallet | BIP-39 mnemonic + BIP-44 derivation (`m/44'/60'/0'/0/N`) |
| **Account** | A named signing identity (one address) | Either an **HD index** within a wallet, or a **standalone imported private key** |

- A wallet contains accounts at derivation indexes. Indexes can be given
  **aliases** (e.g., index 3 of wallet `treasury` aliased to `payroll`).
- A standalone account is a raw private key imported directly, with its own
  name. It belongs to no wallet.
- Names and aliases are local metadata only — they live in Daxie's config or
  keystore metadata, never on-chain.

### Account references

Every command that takes an account accepts one uniform syntax:

| Form | Meaning | Example |
|---|---|---|
| `<wallet>/<index>` | HD account by index | `treasury/0` |
| `<wallet>/<alias>` | HD account by alias | `treasury/payroll` |
| `<name>` | Standalone imported account | `ops-key` |
| `0x...` | Raw address (read-only ops only — balances, history) | `0x52ae...` |
| `name.eth` | ENS name (destinations + read-only ops; resolved on-chain) | `vitalik.eth` |

**Default account:** `daxie account use bot/0` (or `DAXIE_ACCOUNT`) sets a
default, making `--from`/`--account` optional — bare `daxie balance` shows
the default account's balance.

**Naming rule:** wallet names and standalone-account names share **one
namespace** — creating a wallet named `treasury` when a standalone account
`treasury` exists (or vice versa) is an error at creation time. Bare names
are therefore always unambiguous.

### Secret input rule (applies everywhere)

Secrets (mnemonics, private keys, passphrases) are **never accepted as flag
values** — flags leak into shell history and process listings. Accepted
channels, in precedence order (first present wins — *amended by the design
session, see keys.md §6, superseding this draft's original
prompt-first-at-TTY ordering*):

1. stdin (`--mnemonic-stdin`, `--key-stdin`, `--passphrase-stdin`)
2. File (`--mnemonic-file`, `--key-file`, `--passphrase-file`) — file perms checked
3. `*_FILE` env (`DAXIE_PASSPHRASE_FILE` etc.) — the recommended unattended channel
4. Env (`DAXIE_PASSPHRASE` etc.) — documented as the least-safe option, for agents
5. Interactive prompt (fallback when stdin is a TTY and none of the above
   is set; hidden input, mnemonic confirmed)

Note the user-facing consequence: if `DAXIE_PASSPHRASE` (or `…_FILE`) is
exported, it is used and you are **not** prompted, even at a TTY. Non-TTY
invocations with no source set get a distinct error — never a hang.

Two distinct secrets exist, deliberately:

- **Keystore passphrase** — one per keystore. Unlocks signing. Unattended
  agents hold this.
- **Admin passphrase** — protects policy mutations (`daxie policy ...`).
  Set by the human operator; **never given to the agent**, so a
  compromised agent cannot raise its own spend limits.

---

## 2. Command Tree

Global flags: `--json` (machine output), `--network <name>`, `--config <path>`,
`--keystore <path>`, `--state-dir <path>`, `--quiet`, `--yes` (skip
confirmations; required for mutating ops when non-interactive).

Paths follow XDG conventions locally and are independently overridable
(`DAXIE_CONFIG`, `DAXIE_KEYSTORE`, `DAXIE_STATE_DIR`, `DAXIE_CACHE_DIR`) so
config can be a read-only ConfigMap, the keystore a Secret mount, and
mutable state (journal/nonces/spend counters) a persistent volume — see
requirements.md §7a for container/Kubernetes deployment semantics.

### `daxie wallet` — HD wallet (mnemonic) management

```sh
# Create a new wallet: generates a fresh BIP-39 mnemonic, shows it ONCE,
# requires confirmation that it was recorded, encrypts it into the keystore.
daxie wallet create treasury                          # names are positional, like every other noun
daxie wallet create treasury --words 24               # 12 (default) or 24

# Import an existing BIP-39 phrase.
daxie wallet import treasury                          # interactive prompt (hidden)
cat phrase.txt | daxie wallet import treasury --mnemonic-stdin
daxie wallet import treasury --mnemonic-file ./phrase.txt
daxie wallet import treasury --bip39-passphrase-stdin < pass.txt    # BIP-39 "25th word" supported via --bip39-passphrase-*

daxie wallet list                                     # names, address counts, created dates
daxie wallet show treasury                            # derivation path, accounts, aliases
daxie wallet rename treasury cold-storage
daxie wallet export treasury                          # prints mnemonic; guarded (passphrase + --yes + warning)
daxie wallet delete treasury                          # guarded; requires typed confirmation or --yes
```

### `daxie account` — accounts: HD-derived and standalone

```sh
# Derive accounts from an HD wallet. Default: next unused index.
daxie account derive treasury                                # derives next index
daxie account derive treasury --index 3                      # specific index
daxie account derive treasury --index 3 --name payroll       # derive + alias in one step

# Alias an index after the fact (the "name a BIP-39 index" feature).
daxie account alias treasury/3 payroll
daxie account unalias treasury/payroll                       # remove alias

# Import a standalone account from a raw private key, named.
daxie account import ops-key                                 # interactive prompt
daxie account import ops-key --key-stdin < key.hex
daxie account import ops-key --key-file ./key.hex

daxie account use bot/0                                      # set the default account (--from/--account become optional)
daxie account list                                           # all accounts, all wallets + standalone
daxie account list --wallet treasury
daxie account show treasury/payroll                          # address, path, balance summary
daxie account show treasury/payroll --qr                     # render address as a terminal QR code
daxie account export ops-key                                 # private key; guarded
daxie account delete ops-key                                 # standalone: removes key (guarded)
                                                             # HD: just forgets the index/alias (mnemonic still has it)
```

### `daxie balance` — balances (read-only; accepts raw addresses)

```sh
daxie balance                                        # default account's ETH balance
daxie balance treasury/payroll                       # ETH balance
daxie balance vitalik.eth                            # ENS names work for read-only ops
daxie balance 0x52ae...                              # any address
daxie balance treasury/payroll --token USDC          # ERC-20 by registry alias or contract address (see `daxie token`)
daxie balance treasury/payroll --all                 # ETH + every token in the local registry (see `daxie token`)
```

### `daxie tx` — transactions

```sh
daxie tx send --from treasury/payroll --to 0xabc... --amount 0.5          # ETH
daxie tx send --to exchange --amount 0.5             # --from defaults to the default account; --to accepts contacts
daxie tx send --to vitalik.eth --amount 0.1          # --to accepts ENS names (resolved + echoed before signing)
daxie tx send --from treasury/payroll --to 0xabc... --amount 100 --token USDC
# Gas: EIP-1559 by default, everything estimated unless overridden.
daxie tx send ... --gas-limit 21000                  # override estimated limit
daxie tx send ... --max-fee 30gwei --priority-fee 1gwei   # explicit 1559 fees (no dual-purpose --gas-price flag — cast's is a known confusion source)
daxie tx send ... --speed slow|normal|fast           # preset mapping to fee-history percentiles (default: normal)
daxie tx send ... --legacy --gas-price 20gwei        # pre-1559 chains; auto-enabled when the network config says legacy
daxie tx send ... --nonce 42                         # manual nonce (advanced)
daxie tx send ... --dry-run                          # build + estimate, print, don't sign/send
daxie tx send ... --yes                              # non-interactive (agents); guardrails (§policy) still enforced

# Waiting for confirmations. Default behavior: broadcast and return the
# hash immediately. --wait blocks until the tx reaches the confirmation
# target, then reports final status (including revert).
daxie tx send ... --wait                             # wait for the network's default confirmation count
daxie tx send ... --wait --confirmations 6           # override the count
daxie tx send ... --wait --timeout 5m                # bounded wait (default timeout TBD by design)

daxie tx status 0xtxhash...                          # pending/confirmed/failed + current confirmation count
daxie tx wait 0xtxhash...                            # resume waiting on a known hash (e.g. after a timeout)
daxie tx wait 0xtxhash... --confirmations 3 --timeout 10m

# Stuck-transaction recovery (replace-by-fee: same nonce, bumped fees).
# Critical for agents — one underpriced tx blocks every later nonce.
daxie tx speedup 0xtxhash...                         # rebroadcast with bumped fees (≥ +12.5% per protocol rules)
daxie tx speedup 0xtxhash... --max-fee 60gwei
daxie tx cancel 0xtxhash...                          # replace with 0-value self-send at higher fee
daxie tx list --account treasury/payroll             # Daxie-originated txs from the local journal
# Every tx Daxie signs/broadcasts is recorded in a local journal (hash,
# from/to, amount, status) — `tx list` reads it with no external deps.
# Full on-chain history (including inbound) is a later indexer add-on and
# will be labeled as such.
```

**Gas semantics (applies to everything that broadcasts):**

- **Estimation by default** (the cast model): gas limit via
  `eth_estimateGas` × a safety multiplier (config `gas.limit-multiplier`,
  default ~1.2); fees via `eth_feeHistory` — priority fee from a recent-
  blocks percentile per `--speed`, max fee = 2 × base fee + priority fee
  (headroom so the tx survives base-fee growth while pending).
- **Flag > env > config > estimated.** Env equivalents exist for agents
  (`DAXIE_MAX_FEE`, `DAXIE_PRIORITY_FEE`, `DAXIE_GAS_LIMIT` — mirroring
  cast's `ETH_GAS_PRICE` family). Config: global `gas.*` keys with
  per-network overrides (`networks.<name>.gas.*`).
- **Legacy chains:** `networks.<name>.legacy = true` switches to
  `--gas-price` legacy txs automatically (cast auto-enables similarly).
- **Gas caps are policy, not just config:** `daxie policy set
  --max-gas-price 100gwei` makes Daxie *refuse to sign* above the cap
  (admin-protected, so an agent can't waive it during a fee spike), and
  **gas spend counts toward the per-day spend limit** — fees drain wallets
  too.
- Blob transactions (EIP-4844/7594) are out of scope for v1.

```sh
daxie gas                                            # current base fee + slow/normal/fast suggestions
daxie gas --network sepolia --json
```

**Confirmation semantics (applies to `tx send`, `nft send`, `tx wait`):**

- Resolution order for the confirmation count: `--confirmations` flag >
  per-network config (`networks.<name>.confirmations`) > built-in default
  per network (mainnet: 2, Sepolia: 1; proposed — design session confirms).
- `--wait` exit codes are distinct and documented: `0` confirmed, one code
  for **reverted** (tx mined but failed), another for **timeout** (tx
  still pending — NOT a failure; resume with `daxie tx wait <hash>`).
  Agents branch on these.
- Config can flip the default (`tx.wait = true`) for operators who always
  want synchronous sends.
- `--json --wait` emits the final state as one JSON object; progress (
  confirmations so far) goes to stderr for humans, never stdout.

### `daxie receive` — wait for inbound funds

Blocks until the account receives the expected asset and it reaches the
confirmation target. Completes the agent-to-agent payment loop: derive an
address, hand it to the counterparty, block until paid.

```sh
# Wait for any inbound ETH to an existing account
daxie receive --account treasury/payroll

# Wait for a specific minimum amount (cumulative since the command started)
daxie receive --account treasury/payroll --amount 0.5
daxie receive --account treasury/payroll --token USDC --amount 100

# Wait for a specific NFT (same --nft reference forms as `daxie nft`)
daxie receive --account treasury/payroll --nft punks#42
daxie receive --account treasury/payroll --contract 0xnft... --token-id 42

# Generate a fresh receiving address first (derives the wallet's next
# index, optionally aliased), print it, then wait — invoice-style.
daxie receive --new --wallet treasury --name invoice-1042 --amount 250 --token USDC

# Same confirmation/timeout semantics as the send side
daxie receive ... --confirmations 3 --timeout 30m
daxie receive ... --qr                               # also render the receiving address as a terminal QR code
```

- The receiving **address is emitted immediately** (before blocking) so a
  human can share it / an agent can pass it to the counterparty. With
  `--json`, output is a **line-delimited event stream** on stdout:
  `{"event":"listening","address":...}` → `{"event":"detected",...}` →
  `{"event":"confirming",...}` → `{"event":"confirmed",...}` (one
  **per confirmed inbound transfer**) → `{"event":"complete",...}` (the
  **single terminal** success line, carrying the process `exit`). On
  timeout the terminal line is `{"event":"timeout",...}` instead. (The
  single-object-on-stdout rule is relaxed here by necessity — the address is
  needed up front.) **Agents wait for the terminal `complete` line** (not a
  final `confirmed`) as the success signal — see the design-session detail
  in the transaction-pipeline design (`receive` NDJSON stream).
- Confirmation counts follow the same per-network resolution as sends;
  the threshold is the reorg protection that makes "received" trustworthy.
- Exit codes mirror `tx wait`: confirmed, vs. timed-out-still-listening
  (not a failure — re-run to resume listening; detection is stateless).
- **Detection mechanics** (design session decides the details): token/NFT
  arrivals via `Transfer` event log filters; plain ETH arrivals have no
  logs, so detection is balance/block polling — and WebSocket RPC
  endpoints, where available, upgrade polling to subscriptions.
- `--amount` is a **minimum cumulative** threshold across one or more
  inbound txs; exact-match and per-tx semantics are design-session
  refinements.

### `daxie nft` — ERC-721 / ERC-1155

NFT **collections** (contracts) get registry aliases just like tokens, and
**individual NFTs** (`collection#tokenId`) can be aliased too. The
reference syntax is `<collection>#<tokenId>` — by alias or raw address —
and `--nft` accepts any form anywhere.

```sh
daxie nft add 0xnft... --name punks                  # register a collection (alias defaults to on-chain name,
                                                     # case-folded — e.g. CryptoPunks → cryptopunks; names that
                                                     # can't fold to a valid alias require --name)
daxie nft alias punks#42 my-punk                     # alias one specific NFT
daxie nft aliases                                    # list NFT aliases
daxie nft list --account treasury/payroll            # owned NFTs across registered collections

daxie nft show punks#42
daxie nft show --contract 0xnft... --token-id 42     # raw form always works

daxie nft send --from treasury/payroll --to exchange --nft my-punk
daxie nft send --from treasury/payroll --to 0xabc... --nft punks#42
daxie nft send ... --amount 5                        # ERC-1155 quantity
daxie nft send ... --wait --confirmations 3          # same wait semantics as tx send
```

### `daxie token` — token metadata

The local **token registry** is the v1 discovery mechanism: `balance --all`
and `nft list` check the registry's contracts (plus a small bundled list of
majors — USDC, USDT, WETH, DAI — pinned to their canonical addresses per
network). Indexer-based auto-discovery ("what does this address hold?") is
designed as a pluggable interface and shipped later.

**Names are local aliases, and that's a security feature.** On-chain
`symbol()` values are not unique — deploying a fake token whose symbol is
`USDC` costs nothing. So `--token <name>` resolves **only** through the
local registry (or accepts a raw contract address); Daxie never matches a
name against on-chain symbols. Registering defaults the alias to the
contract's symbol for convenience, but the user can override it, and a
collision with an existing alias must be resolved explicitly with `--name`.
Aliases are **stored lowercase and matched case-insensitively** —
`daxie token add 0xa0b8...` stores the alias `usdc` and `--token USDC`
resolves it; a symbol that can't fold to a valid alias (reserved chars
like the `.` in `USDC.e`, other illegal chars, empty) is never silently
mangled and requires an explicit `--name`. The registry is
**per-network** (the same alias can map to different addresses on
mainnet vs. an L2).

```sh
daxie token info 0xa0b8...                           # name, symbol, decimals, type detection (read-only, no registration)
daxie token add 0xa0b8...                            # register; alias defaults to on-chain symbol, case-folded
                                                     # (here: USDC → stored as `usdc`; lookups are case-insensitive)
daxie token add 0x2791... --name usdc-bridged        # explicit alias (required on collision)
daxie token rename USDT tether
daxie token list                                     # alias, address, type, network
daxie token remove tether

daxie balance bot/0 --token usdc-bridged             # aliases work anywhere --token does

# Approvals — required before any contract can pull tokens (DeFi deposits,
# marketplaces). Approvals are spend-equivalents: they count against policy
# guardrails, the spender must pass the allowlist (if one is set), and
# unlimited approvals require an explicit --unlimited acknowledged by --yes.
daxie token approve USDC --spender 0xdef... --amount 500
daxie token approve USDC --spender 0xdef... --unlimited --yes
daxie token approve USDC --spender 0xdef... --amount 500 \
    --wait --confirmations 2 --timeout 5m            # approve/revoke broadcast, so they take
                                                     # the same --wait/--confirmations/--timeout
                                                     # as tx send / nft send (design-session extension)
daxie token allowance USDC --owner bot/0 --spender 0xdef...
daxie token revoke USDC --spender 0xdef...           # sugar for approve --amount 0
daxie token revoke USDC --spender 0xdef... --wait    # wait flags apply here too
```

### `daxie contract` — arbitrary contract calls (non-standard ABIs)

The general escape hatch for any contract Daxie ships no typed command for.
`tx`, `token`, and `nft` are the ergonomic shortcuts for the ABIs built in
(ETH, ERC-20/721/1155); `contract` reaches everything else — staking pools,
vaults, governors, price feeds, your own deployments — over the same chain
client, signer, and policy chokepoint. There is deliberately no
special-casing of "non-standard": it is `cast call` / `cast send` with
Daxie's registry, account refs, gas, policy, and wait semantics layered on.

Contracts get **local, per-network registry aliases** with a stored ABI —
the same anti-spoofing model as `daxie token` (names are local metadata,
never resolved from on-chain symbols).

```sh
# --- contract registry (local, per-network aliases + stored ABI) ---
daxie contract add staking 0x7a25...AbCd --abi ./staking.json     # register address + ABI under an alias
daxie contract add staking 0x7a25...AbCd --abi-stdin < staking.json
daxie contract list                                              # aliases, addresses, network
daxie contract show staking                                      # address, ABI summary (functions/events)
daxie contract remove staking

# --- READ: eth_call, no signing, no gas ---
daxie contract call staking earned 0xUser...                    # by alias + fn; ABI gives arg+return types
daxie contract call staking earned bot/0                        # address-typed args accept account refs / ENS
daxie contract call 0x7a25...AbCd \                             # ad-hoc, no registration (cast's (in)(out) form)
    --sig "earned(address)(uint256)" 0xUser...
daxie contract call ethusd latestRoundData                      # multi-return: each value decoded + labeled
daxie contract call 0x5f4e...8419 \
    --sig "latestRoundData()(uint80,int256,uint256,uint256,uint80)"
daxie contract call staking earned 0xUser... --block 19000000   # historical state
daxie contract call staking earned bot/0 --from 0xabc... --json # set msg.sender for the call; decoded JSON

# --- SEND: sign + broadcast a state-changing call (gas, policy, wait all apply) ---
daxie contract send staking stake 1000000000000000000 --from bot/0   # uint256 base units (use `daxie convert` for math)
daxie contract send staking getReward --from bot/0                   # no args
daxie contract send weth deposit --value 0.5 --from bot/0            # payable: msg.value counts vs spend limits
daxie contract send staking withdraw 1000000000000000000 --from bot/0 --dry-run   # build+estimate+policy, no sign
daxie contract send staking getReward --from bot/0 \
    --wait --confirmations 2 --timeout 5m --json --yes
# gas flags (--max-fee/--priority-fee/--speed/--legacy/--gas-limit/--nonce) apply exactly as `tx send`

# --- EVENTS: query + decode past logs ---
daxie contract logs staking Staked --from-block 19000000
daxie contract logs staking Staked --arg user=bot/0 --from-block 19000000   # filter indexed arg (ref resolved)
daxie contract logs 0x7a25...AbCd --sig "Staked(address indexed,uint256)" --from-block 19000000

# --- calldata utilities (no chain, no signing) — for relayers / meta-tx / debugging ---
daxie contract encode airdrop claim 42 0xUser... 500000000000000000000 '[0xabc...,0xdef...]'  # bytes32[] proof
daxie contract encode staking stake 1000000000000000000                                       # → 0x… calldata
daxie contract decode --sig "stake(uint256)" 0x<calldata>                                     # calldata → values
```

**ABI source, in precedence:** (1) a registered alias's stored ABI; (2)
`--abi` / `--abi-stdin` JSON; (3) an inline `--sig` human-readable
signature. `call` needs return types (cast's `(inputs)(outputs)` form, or a
JSON ABI); `send` / `encode` need only inputs.

**Args are positional strings, coerced by the ABI** (the core accepts
user-level strings and parses once — see design §2.3). `address`-typed args
accept account refs, contacts, and ENS names, resolved and echoed before
signing like any `--to`. `--value` is named for `msg.value` (the ETH
attached to the call) to keep it distinct from `tx send --amount` and token
amounts. **[design session]** array / tuple literal syntax (the `'[…]'`
form above) and large-`uint` ergonomics (decimals are unknowable for an
arbitrary param — `daxie convert` covers the math).

**Policy — this is the broadest-reach signing command in the wallet, so it
gets the strictest reading of the guardrails (see `daxie policy`):**

- the **contract address is the destination** and must pass the allowlist
  if one is set;
- `--value` counts toward per-tx / per-day spend limits exactly like
  `tx send`; gas counts toward the daily limit and the gas cap;
- because v1 limits are ETH-denominated and **cannot see value moved
  *inside* arbitrary calldata**, `contract send` to a non-allowlisted
  contract **fails closed whenever spend limits are configured but no
  allowlist is** — the same fail-closed posture the token/approval paths
  take (requirements #29, OQ #2), applied here a fortiori because the
  calldata is opaque to the ETH limits.
- **[design session] `contract send` must not become a policy bypass.**
  Raw calldata can encode `approve` / `transfer` / `permit` — the very
  operations `daxie token approve` wraps in the `--unlimited --yes`
  ceremony. Core must classify known ERC-20/721/1155/Permit selectors in
  the calldata and route them through the *same* checks (spender
  allowlist, the `--unlimited --yes` acknowledgment on unbounded
  approvals), extending the permit-classification machinery (design §2.6,
  `KindPermit`) from typed data to raw calldata — otherwise the generic
  noun silently defeats the typed ones. Classification binds the
  **signing** verb only: `encode` and `decode` build/parse hex without
  signing, so they carry no policy (see the closing note below).

`call`, `logs`, `encode`, and `decode` **never sign** — read-only / pure, no
passphrase, no policy; they accept raw `0x` addresses and ENS refs freely.

### `daxie sign` / `daxie verify` — gasless message signing

The agent-identity primitive: prove control of an address without a
transaction (Sign-In-With-Ethereum, off-chain orders, attestations).
EIP-191 personal messages and EIP-712 typed data.

```sh
daxie sign message "hello world" --account bot/0     # EIP-191 personal_sign
echo -n "payload" | daxie sign message --stdin
daxie sign typed --data ./order.json                 # EIP-712 typed data (JSON file or stdin)
daxie sign typed --data-stdin < order.json

daxie verify --message "hello world" --signature 0xsig... --address 0xabc...
daxie verify --typed ./order.json --signature 0xsig... --address vitalik.eth
```

- Signing requires the keystore passphrase like any other signing op.
- **[design session]** Whether message signing falls under policy
  guardrails (a signed EIP-712 order can move funds indirectly — e.g.
  exchange orders, permits). At minimum, EIP-2612 `Permit` signatures are
  spend-equivalents and must be policy-checked like approvals.

### `daxie ens` — ENS resolution

ENS names work anywhere a destination or read-only address is accepted
(`--to vitalik.eth`, `daxie balance vitalik.eth`). Resolution happens
per-invocation against the connected network's registry; the resolved
address is always echoed (and included in `--json` output) before signing.

```sh
daxie ens resolve vitalik.eth                        # name → address
daxie ens reverse 0xd8dA...                          # address → primary name
```

**Agent safety — allowlist pinning:** ENS records are mutable, so the
policy allowlist never stores a bare ENS name. `daxie policy allow
vitalik.eth` resolves the name at allow-time and pins **both** name and
address; if the name later resolves differently, the send is refused with
a distinct error until the operator re-allows. Contacts (`daxie contacts
add`) pin the same way.

### `daxie keystore` — keystore maintenance

```sh
daxie keystore change-passphrase                     # re-encrypt the keystore under a new passphrase
daxie keystore info                                  # path, format, wallet/account counts
```

### `daxie contacts` — address book

Local name → address map. Any `--to` accepts a contact name; the policy
allowlist references contacts by name.

```sh
daxie contacts add exchange 0xabc...
daxie contacts list
daxie contacts show exchange
daxie contacts remove exchange
```

### `daxie network` — chain definitions

A **network** is a chain: name, chain ID, native currency. It says nothing
about *how* to reach the chain — that's an endpoint (below). Mainnet and
Sepolia are built in.

```sh
daxie network list                                   # built-ins + user-added
daxie network add base --chain-id 8453               # define a chain
daxie network add base --chain-id 8453 --rpc-url https://mainnet.base.org
                                                     # convenience: also creates endpoint "base-default"
daxie network use sepolia                            # set the default network
daxie network show mainnet
daxie network remove base                            # refuses if endpoints still reference it (--force)
```

### `daxie rpc` — named RPC endpoints

An **endpoint** is a named connection to a network. Many endpoints per
network (Alchemy + Infura + self-hosted for mainnet); each network has one
default endpoint, and any command can override with `--rpc <name>`.

```sh
# Plain public endpoint
daxie rpc add mainnet-public --network mainnet --url https://eth.llamarpc.com

# Provider with API key in the URL — secret stored as a reference, resolved at connect time
daxie rpc add mainnet-alchemy --network mainnet \
    --url 'https://eth-mainnet.g.alchemy.com/v2/${env:ALCHEMY_API_KEY}'

# Header-based auth (bearer token, API-key header, etc.)
daxie rpc add mainnet-infura --network mainnet \
    --url https://mainnet.infura.io/v3/${env:INFURA_PROJECT_ID} \
    --header 'Authorization: Bearer ${file:~/.config/daxie/secrets/infura-jwt}'

# mTLS endpoint (corp/self-hosted infrastructure)
daxie rpc add corp-node --network mainnet \
    --url https://eth.internal.corp:8545 \
    --tls-cert ~/.config/daxie/tls/client.crt \
    --tls-key  ~/.config/daxie/tls/client.key \
    --tls-ca   ~/.config/daxie/tls/corp-ca.pem

daxie rpc list [--network mainnet]                   # name, network, URL (secrets masked), default marker
daxie rpc show mainnet-alchemy                       # full detail, secrets masked
daxie rpc use mainnet-alchemy                        # make it the default for its network
daxie rpc test mainnet-alchemy                       # connect, verify eth_chainId matches the network, report latency
daxie rpc rename mainnet-public mainnet-fallback
daxie rpc remove mainnet-infura

# Per-invocation override on any command:
daxie balance treasury/0 --rpc mainnet-infura
```

**Secret-reference rule:** endpoint URLs and header values may embed
`${env:VAR}` or `${file:path}` placeholders. The config file stores the
*reference*, never the resolved secret; resolution happens in-memory at
connect time. Literal secrets in `--url`/`--header` are detected
heuristically and warned about (they'd persist in config plaintext and
shell history). A `${keychain:...}` source is a possible later addition.

**Chain-ID verification:** `rpc add` and `rpc test` call `eth_chainId` and
refuse/warn if the endpoint's chain doesn't match its network — protection
against misconfigured or malicious endpoints silently signing for the
wrong chain.

**Failover:** v1 is single-default-plus-explicit-override only — no
automatic failover (broadcast retry on a second endpoint risks
double-sends; the semantics deserve their own design pass). The endpoint
model leaves room for priority ordering later.

### `daxie policy` — agent signing guardrails

All policy **mutations require the admin passphrase** — a separate secret
from the keystore passphrase that the agent is never given (see §1, secret
input rule). A compromised agent can sign within policy but cannot change
policy. `policy show` is unauthenticated.

```sh
daxie policy show
daxie policy set --max-tx 0.1eth --max-day 0.5eth    # spend limits (admin passphrase required)
daxie policy set --max-gas-price 100gwei             # refuse to sign above this fee cap; gas counts toward --max-day
daxie policy allow exchange                          # allowlist a contact by name
daxie policy allow 0xabc...                          # or a raw address
daxie policy allow vitalik.eth                       # ENS: resolved now, name+address pinned (see `daxie ens`)
daxie policy deny exchange
```

### `daxie mcp` — MCP server

```sh
daxie mcp serve                                      # stdio transport
daxie mcp tools                                      # print the tool list/schemas (debugging)
```

### Utility

```sh
daxie version                                        # version, commit, build date
daxie completion zsh|bash|fish
daxie config get|set|list                            # Viper-backed settings. Policy keys are OUT OF SCOPE here:
                                                     # spend limits/allowlist live in the sealed policy file, set
                                                     # only via `daxie policy ...` (admin passphrase) — `config set
                                                     # policy.max-tx` is rejected; inspect with `daxie policy show`
daxie convert 1.5eth wei                             # unit conversion (eth/gwei/wei) — agents shouldn't do 10^18 math
daxie convert 30000000000wei gwei
```

---

## 3. Agent-Mode Examples

Every mutating command works without a TTY. A typical agent flow:

```sh
export DAXIE_PASSPHRASE_FILE=/run/secrets/daxie-pass    # or DAXIE_PASSPHRASE
daxie balance bot/0 --json
daxie tx send --from bot/0 --to exchange --amount 25 --token USDC \
    --wait --confirmations 2 --timeout 5m --json --yes
# exit 0: confirmed; on timeout (distinct exit code) resume with:
daxie tx wait <hash> --json
```

JSON output contract: stable schema per command, errors as structured JSON
on stderr with machine-readable codes, exit codes documented (0 ok, distinct
codes for policy-denied vs. insufficient-funds vs. network failure — agents
branch on these).

---

## 4. Resolved Questions

All first-round questions are decided; the rationale lives in the sections
above.

| # | Question | Decision |
|---|---|---|
| 1 | Token/NFT discovery | Local registry + bundled majors in v1; indexer auto-discovery behind a pluggable interface later |
| 2 | `tx list` history source | Local journal of Daxie-originated txs in v1; indexer-backed full history later |
| 3 | Policy mutation protection | Separate **admin passphrase**, never given to the agent |
| 4 | Address book in v1 | Yes — `daxie contacts`; `--to` and the policy allowlist accept contact names |
| 5 | Bare-name ambiguity | One shared namespace for wallets + standalone accounts; collisions rejected at creation |
| 6 | Passphrase granularity | Per keystore (one passphrase); per-wallet isolation deferred |
| 7 | RPC failover | Single default per network + explicit `--rpc` override; no auto-failover in v1 |
| 8 | `--network` accepting endpoint names | No — `--network` is chains, `--rpc` is endpoints, strictly separate |
