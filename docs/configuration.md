# Configuration

Daxie is configured by three independent mechanisms, in precedence order:

1. **Command-line flags** (highest)
2. **`DAXIE_*` environment variables**
3. **`config.toml`** (lowest)

Plus two things that are deliberately *not* in `config.toml`: **secrets** (referenced,
never stored) and **spend policy** (sealed, set only with the admin passphrase). This
guide covers the config file, the env vars, the four state-class paths, and the
secret-reference mechanism. The authoritative schema is [design.md §7](design.md).

- [The config file (`config.toml`)](#the-config-file-configtoml)
- [Environment variables](#environment-variables)
- [The four state classes](#the-four-state-classes)
- [Path resolution and overrides](#path-resolution-and-overrides)
- [Secret references](#secret-references)
- [What is NOT in config](#what-is-not-in-config)
- [Read-only config](#read-only-config)

---

## The config file (`config.toml`)

TOML, kebab-case keys, comment-bearing, human-owned. It is **optional** — every key
has a built-in default. It holds no secrets, no spend limits, and no runtime state.
Inspect and edit it with the `config` command or your editor:

```sh
daxie config list                       # all effective keys
daxie config get gas.limit-multiplier
daxie config set gas.limit-multiplier 1.3
```

A representative file (all keys are optional):

```toml
schema = 1                              # config schema major (forward-migration marker)

[defaults]
network = "sepolia"                     # written by `daxie network use`

[gas]
limit-multiplier = 1.2                  # eth_estimateGas safety multiplier
# max-fee / priority-fee / gas-limit are NOT global keys — they are per-invocation
# flags, env (DAXIE_MAX_FEE / DAXIE_PRIORITY_FEE / DAXIE_GAS_LIMIT), or per-network.

[tx]
wait = false                            # default to synchronous sends if true

# Networks: mainnet + sepolia are built in; a table here OVERRIDES a built-in field
# or defines a new chain. `daxie network add base --chain-id 8453` writes this.
[networks.base]
chain-id = 8453
confirmations = 2
legacy = false
native-symbol = "ETH"

# RPC endpoints: a named connection bound to a network. Secrets are references (below).
[rpc.mainnet-alchemy]
network = "mainnet"
url = "https://eth-mainnet.g.alchemy.com/v2/${env:ALCHEMY_API_KEY}"
timeout = "30s"

[rpc.mainnet-alchemy.default]           # one default endpoint per network
```

Keys are kebab-case; the env replacer maps both `.` and `-` to `_`, so
`gas.limit-multiplier` ⇒ `DAXIE_GAS_LIMIT_MULTIPLIER`.

**Value bounds (checked at `config set`).** Out-of-range tuning values are rejected
with `usage.bad_value` at set time rather than failing at runtime: poll intervals
(`receive.poll-interval`, `tx.poll-interval`) must be **≥ 100ms**; durations
(`tx.wait-timeout`, `tx.lock-timeout`, `receive.heartbeat-interval`) must be
**positive**; `receive.timeout` must be **≥ 0** (`0` = listen forever); gas
multipliers (`gas.limit-multiplier`, `gas.base-fee-multiplier`, `gas.rbf-bump-percent`)
must be **> 0** and `gas.drift-tolerance` **≥ 0**; counts (`gas.fee-history-blocks`,
`receive.max-log-range`) must be **≥ 1** and `receive.lookback-blocks` **≥ 0**. A value
that reaches the binary through a `DAXIE_*` env var or a hand-edited `config.toml`
(bypassing this check) is additionally floored at use time — poll intervals to 100ms —
so a bad value can never busy-spin the poll loops.

---

## Environment variables

Every config key has a `DAXIE_`-prefixed env equivalent. Beyond those, several env
vars are **not** config keys (they are resolved before Viper) and never appear in
`config.toml` or `config list`:

### Path overrides (resolved outside Viper)

| Var | Class | Notes |
|---|---|---|
| `DAXIE_CONFIG` | config | a file *or* a directory (a `.toml` path is the file; otherwise the dir) |
| `DAXIE_KEYSTORE` | keystore | keys directory |
| `DAXIE_STATE_DIR` | state | journal, nonces, sealed policy + counters, registries |
| `DAXIE_REGISTRY_DIR` | state (subset) | token/NFT/contact/contract registries, if split out |
| `DAXIE_CACHE_DIR` | cache | disposable caches (env-only; there is no `--cache-dir` flag) |

### Secrets (channels, never flag values)

| Var | Purpose |
|---|---|
| `DAXIE_PASSPHRASE_FILE` | **recommended** keystore-passphrase channel (Secret mount) |
| `DAXIE_PASSPHRASE` | keystore passphrase (supported, **least-safe** — visible in `/proc/<pid>/environ`) |
| `DAXIE_ADMIN_PASSPHRASE_FILE` / `DAXIE_ADMIN_PASSPHRASE` | admin passphrase — **operator only; never on an agent host** |
| `DAXIE_NEW_ADMIN_PASSPHRASE_FILE` / `DAXIE_NEW_ADMIN_PASSPHRASE` | rotation target for `policy change-admin-passphrase` |

Passphrase resolution order (first present wins; no env/file source ⇒ prompt only at
a TTY, otherwise a deterministic error, never a hang):
`--passphrase-stdin` > `--passphrase-file` > `DAXIE_PASSPHRASE_FILE` >
`DAXIE_PASSPHRASE` > interactive prompt.

> If `DAXIE_PASSPHRASE`/`DAXIE_PASSPHRASE_FILE` is exported you are **not** prompted,
> even at an interactive TTY (env beats prompt, like `PGPASSWORD`). A wrong value
> fails fast against the verifier.

### Gas / account selection

| Var | Purpose |
|---|---|
| `DAXIE_MAX_FEE` / `DAXIE_PRIORITY_FEE` / `DAXIE_GAS_LIMIT` | per-invocation gas overrides |
| `DAXIE_ACCOUNT` | default account (precedence: `--from`/`--account` > `DAXIE_ACCOUNT` > `meta.json` default) |

> **`DAXIE_INSTALL_*` is a separate namespace** owned by `install.sh` (see
> [install.md](install.md)); it never maps to a runtime config key.

---

## The four state classes

Daxie partitions its on-disk data into four classes by *durability and writability*,
so a container deployment mounts each correctly. The litmus test:

> **config** — a human/operator provisions it; **no** signing/receiving op may write
> it (K8s: read-only ConfigMap). **keystore** — it travels with key material in a
> backup (K8s: Secret mount or PVC). **state** — the agent's runtime job writes it and
> it **must survive restarts** (K8s: PVC). **cache** — reconstructible from chain;
> losing it costs only latency (K8s: emptyDir/tmpfs).

| Class | Override | Contents |
|---|---|---|
| **config** | `DAXIE_CONFIG` | `config.toml`; `policy-anchor.json` (seal verify key + salt + nonce watermark — read **directly, not via Viper**); `config.lock`, `policy-anchor.lock` |
| **keystore** | `DAXIE_KEYSTORE` | `keystore.json`, `meta.json` (names, aliases, `default_account`), `wallets/<uuid>.json`, `accounts/UTC--…`, `index.lock` |
| **state** | `DAXIE_STATE_DIR` (+ `DAXIE_REGISTRY_DIR`) | `journal/<chainID>.jsonl`; `policy.json` + `spend/<net>/<addr>.json` **durable counters**; `registry/<network>.json`, `registry/contacts.json`; `locks/` |
| **cache** | `DAXIE_CACHE_DIR` | ENS resolution cache, `tokenURI`/metadata cache, fee-history snapshots — disposable, never a source of truth, never a secret |

Two placement facts that are load-bearing for security:

- **The policy anchor is config-class** and is reachable by *no* Viper key, env var,
  or flag. The config-class placement protects the file (a read-only ConfigMap the
  agent cannot write); the Viper carve-out protects against the env/flag bypass no
  file permission can stop. Both are required.
- **Registries are state-class, not config.** An agent that meets a new token mid-task
  runs `token add`, which must succeed on a pod whose config is a read-only ConfigMap.
  Networks and RPC endpoints stay config (deploy-time topology).

---

## Path resolution and overrides

Defaults follow XDG locally (macOS deliberately mirrors Linux XDG, not `~/Library`,
because the audience is terminal-first). Windows splits config (roams) from
keys/state/cache (do **not** roam — silently copying a wallet to every domain machine
is wrong).

| Class | Linux / macOS (XDG env → else `$HOME` default) | Windows |
|---|---|---|
| config | `$XDG_CONFIG_HOME/daxie` → `~/.config/daxie` | `%APPDATA%\daxie` |
| keystore | `$XDG_DATA_HOME/daxie/keystore` → `~/.local/share/daxie/keystore` | `%LOCALAPPDATA%\daxie\keystore` |
| state | `$XDG_STATE_HOME/daxie` → `~/.local/state/daxie` | `%LOCALAPPDATA%\daxie\state` |
| cache | `$XDG_CACHE_HOME/daxie` → `~/.cache/daxie` | `%LOCALAPPDATA%\daxie\cache` |

**Override hierarchy per class (first present wins):** the global flag
(`--config`/`--keystore`/`--state-dir`) > the dedicated env var > the platform
default. `DAXIE_CONFIG`/`--config` accepts a file or a directory so a K8s ConfigMap
directory mount and a developer's `--config ./my.toml` file both work, and the anchor
is always found beside the config.

`service.Open` is lazy: an empty environment still runs
`convert`/`version`/`config list`/`network list`/`wallet create`. Config-dir creation
happens only when a command actually writes config (and fails cleanly with
`config.read_only`, never an opaque `mkdir: permission denied`).

---

## Secret references

Endpoint URLs and header values may embed `${env:VAR}` or `${file:path}`
placeholders. The config file stores the **reference**, never the resolved secret;
resolution happens in-memory at connect time and never reaches logs, the journal, or
masked output.

```sh
daxie rpc add mainnet-infura --network mainnet \
  --url 'https://mainnet.infura.io/v3/${env:INFURA_PROJECT_ID}' \
  --header 'Authorization: Bearer ${file:~/.config/daxie/secrets/infura-jwt}'
```

mTLS endpoints take cert/key/ca **paths** (mTLS needs files), not secret references;
the key file is permission-checked like a passphrase file. A literal secret in
`--url`/`--header` is detected heuristically and warned about (it would persist in
config plaintext and shell history).

---

## What is NOT in config

- **Spend limits, the allowlist, the gas cap, ENS pins** — these live in the sealed
  `policy.json`, set only via `daxie policy …` with the admin passphrase. `config set
  policy.*` is **rejected outright** (it is not even admin-gated — offering an
  admin-gated `config set` would re-open a channel the design deliberately closed).
  Inspect policy with `daxie policy show`.
- **The policy anchor** — config-class, but never a Viper key (see above).
- **Resolved secrets** — only references are stored.
- **Runtime state** — counters/journal/nonces are state-class.
- **The default account** — keystore-class (`meta.json`), so it travels with a
  keystore backup.

---

## Read-only config

On a read-only config mount (the Kubernetes default for the config class), mutating
commands (`network use`, `rpc add`, `config set`, the bootstrap-writing side of
`policy set`) fail cleanly with `config.read_only` (exit 10). Signing and receiving
**never** write config, so they are unaffected. There is no hot reload of
`config.toml`; every Daxie-owned file is version-stamped.
