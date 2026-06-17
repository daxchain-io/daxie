#!/usr/bin/env bash
#
# docs/demos/m02.sh — the M2 acceptance demo (design §10.1 gate).
#
# Exercises the M2 network / RPC-endpoint / balance surface end to end, both human
# and --json, on the NON-INTERACTIVE path, and ASSERTS the documented exit codes
# (0 OK, 2 USAGE, 10 NOT_FOUND/READONLY, 12 INTEGRITY — design §5.7).
#
# Two sections:
#   A. DRY — network/rpc config round-trips that need NO network (always run):
#      list/add/use/show/remove; rpc add/list/show/use/rename/remove; secret-ref
#      masking; the literal-secret heuristic; strict separation of networks vs
#      endpoints; read-only-config behavior.
#   B. LIVE — balance of a funded account + `rpc test` chain-id verification +
#      a deliberate MISMATCH refusal, against a local anvil. Runs ONLY when `anvil`
#      is on PATH (CI's foundry-toolchain provides it); skipped cleanly otherwise.
#
# Runs unmodified in CI; any failed assertion exits non-zero.
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m02.sh
#   defaults to ./daxie (build first:  go build -o daxie ./cmd/daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"

# ── assertion helpers (mirror m00.sh / m01.sh) ───────────────────────────────
fail() { echo "FAIL: $*" >&2; exit 1; }

# expect_exit <wanted> <cmd...> : run cmd, assert its exit status equals <wanted>.
expect_exit() {
  local want="$1"; shift
  local got=0
  "$@" >/dev/null 2>&1 || got=$?
  [ "$got" -eq "$want" ] || fail "expected exit $want from '$*', got $got"
}

# eq <actual> <expected> <label>
eq() { [ "$1" = "$2" ] || fail "$3: expected '$2', got '$1'"; }

# contains <haystack> <needle> <label>
contains() { case "$1" in *"$2"*) : ;; *) fail "$3: '$1' does not contain '$2'";; esac; }

# not_contains <haystack> <needle> <label>
not_contains() { case "$1" in *"$2"*) fail "$3: '$1' must NOT contain '$2'";; *) : ;; esac; }

echo "== daxie M2 demo =="

# ── isolated, throwaway state (every class points at temp dirs) ───────────────
WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT

export DAXIE_CONFIG="$WORK/config"
export DAXIE_KEYSTORE="$WORK/keystore"
export DAXIE_STATE_DIR="$WORK/state"
export DAXIE_CACHE_DIR="$WORK/cache"
mkdir -p "$DAXIE_CONFIG"
printf 'schema = 1\n' > "$DAXIE_CONFIG/config.toml"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION A — DRY: network + rpc config (no network required)
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 1. network list — built-ins present (mainnet + sepolia)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- network list"
out="$("$DAXIE" network list)"
contains "$out" mainnet "network list missing mainnet"
contains "$out" sepolia "network list missing sepolia"
out="$("$DAXIE" network list --json)"
contains "$out" '"name": "mainnet"' "network list --json"
contains "$out" '"chain_id": 1'     "mainnet chain-id"
contains "$out" '"builtin": true'   "mainnet builtin marker"

# ─────────────────────────────────────────────────────────────────────────────
# 2. network add — define a chain (+ --rpc-url convenience endpoint)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- network add"
"$DAXIE" network add base --chain-id 8453 --rpc-url https://mainnet.base.org >/dev/null
out="$("$DAXIE" network show base --json)"
contains "$out" '"chain_id": 8453'             "base chain-id"
contains "$out" '"default_rpc": "base-default"' "base convenience endpoint"
# the convenience endpoint exists as an endpoint object too
out="$("$DAXIE" rpc show base-default --json)"
contains "$out" '"network": "base"' "base-default not bound to base"

# duplicate add → exit 2 (USAGE); zero chain-id → exit 2; missing --chain-id → exit 2
expect_exit 2 "$DAXIE" network add base --chain-id 8453
expect_exit 2 "$DAXIE" network add nope --chain-id 0
expect_exit 2 "$DAXIE" network add nochainid

# ─────────────────────────────────────────────────────────────────────────────
# 3. network use — set the default network
# ─────────────────────────────────────────────────────────────────────────────
echo "-- network use"
"$DAXIE" network use sepolia >/dev/null
out="$("$DAXIE" network show sepolia --json)"
contains "$out" '"default": true' "sepolia not the default"
# unknown network → exit 10 (NOT_FOUND)
expect_exit 10 "$DAXIE" network use ghost
expect_exit 10 "$DAXIE" network show ghost

# ─────────────────────────────────────────────────────────────────────────────
# 4. rpc add — endpoints with secret refs / headers; masking; strict separation
# ─────────────────────────────────────────────────────────────────────────────
echo "-- rpc add (secret references masked)"
"$DAXIE" rpc add mainnet-alchemy --network mainnet \
    --url 'https://eth-mainnet.g.alchemy.com/v2/${env:ALCHEMY_API_KEY}' >/dev/null
shown="$("$DAXIE" rpc show mainnet-alchemy --json)"
# the REFERENCE is shown (the reference is not the secret); the value is never resolved
contains     "$shown" '${env:ALCHEMY_API_KEY}' "rpc show preserves the env reference"

# header-based auth with a file reference
"$DAXIE" rpc add mainnet-infura --network mainnet \
    --url 'https://mainnet.infura.io/v3/${env:INFURA_PROJECT_ID}' \
    --header 'Authorization: Bearer ${file:~/.config/daxie/secrets/jwt}' >/dev/null
out="$("$DAXIE" rpc show mainnet-infura --json)"
contains "$out" '"has_headers": true' "infura endpoint missing headers"

# literal-secret heuristic: warns by default, hard-fails under --strict-secrets
"$DAXIE" rpc add leaky-ok --network mainnet \
    --url 'https://eth.example.com/v2/abcdef0123456789abcdef0123456789' >/dev/null
expect_exit 2 "$DAXIE" rpc add leaky-strict --network mainnet \
    --url 'https://eth.example.com/v2/abcdef0123456789abcdef0123456789' --strict-secrets

# strict separation (§7.5): --rpc naming a NETWORK is ref.not_found; an unknown
# network on rpc add is ref.not_found
expect_exit 10 "$DAXIE" rpc add x --network ghost --url https://x.example.com
expect_exit 2  "$DAXIE" rpc add x --url https://x.example.com         # missing --network
# duplicate endpoint / built-in immutability
expect_exit 2  "$DAXIE" rpc add mainnet-public --network mainnet --url https://x.example.com
expect_exit 2  "$DAXIE" rpc rename mainnet-public mainnet-fallback    # built-in
expect_exit 2  "$DAXIE" rpc remove sepolia-public --yes              # built-in

# ─────────────────────────────────────────────────────────────────────────────
# 5. rpc list / use / rename / remove
# ─────────────────────────────────────────────────────────────────────────────
echo "-- rpc list/use/rename/remove"
out="$("$DAXIE" rpc list)"
contains "$out" mainnet-public "rpc list missing mainnet-public"
out="$("$DAXIE" rpc list --network sepolia --json)"
contains "$out" sepolia-public "filtered rpc list missing sepolia-public"

"$DAXIE" rpc use mainnet-alchemy >/dev/null
out="$("$DAXIE" network show mainnet --json)"
contains "$out" '"default_rpc": "mainnet-alchemy"' "rpc use did not set mainnet's default-rpc"

"$DAXIE" rpc add tmp-ep --network mainnet --url https://tmp.example.com >/dev/null
"$DAXIE" rpc rename tmp-ep tmp-renamed >/dev/null
"$DAXIE" rpc show tmp-renamed >/dev/null || fail "rpc rename target missing"
expect_exit 10 "$DAXIE" rpc show tmp-ep                # old name gone
"$DAXIE" rpc remove tmp-renamed --yes >/dev/null
expect_exit 10 "$DAXIE" rpc show tmp-renamed           # removed

# ─────────────────────────────────────────────────────────────────────────────
# 6. network remove — in-use refusal, then --force
# ─────────────────────────────────────────────────────────────────────────────
echo "-- network remove (in-use refusal)"
# base still has base-default referencing it → exit 2 without --force
expect_exit 2 "$DAXIE" network remove base --yes
"$DAXIE" network remove base --yes --force >/dev/null
expect_exit 10 "$DAXIE" network show base              # gone
# built-in remove always refused
expect_exit 2 "$DAXIE" network remove mainnet --yes

# ─────────────────────────────────────────────────────────────────────────────
# 7. balance flag plumbing — M5/M7 paths fail clean (never faked)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- balance (M5/M7 paths fail clean)"
RAW="0x52908400098527886E0F7030069857D2E4169EE7"
expect_exit 2 "$DAXIE" balance "$RAW" --token USDC     # M5
expect_exit 2 "$DAXIE" balance "$RAW" --all            # M5
expect_exit 2 "$DAXIE" balance vitalik.eth             # M7 (ENS)
expect_exit 2 "$DAXIE" balance                         # no account, no default

# ─────────────────────────────────────────────────────────────────────────────
# 8. read-only config behavior — a mutation on a read-only mount → exit 10
#    (config.read_only). Simulated by making the config dir read-only.
# ─────────────────────────────────────────────────────────────────────────────
echo "-- read-only config"
RO="$WORK/roconfig"
mkdir -p "$RO"
printf 'schema = 1\n' > "$RO/config.toml"
chmod -R a-w "$RO"
# A mutation (network use) on a read-only mount must fail config.read_only (exit 10),
# NOT an opaque permission error.
DAXIE_CONFIG="$RO" expect_exit 10 "$DAXIE" network use sepolia
chmod -R u+w "$RO"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION B — LIVE: balance + rpc test against a local anvil (if available)
# ═════════════════════════════════════════════════════════════════════════════
if ! command -v anvil >/dev/null 2>&1; then
  echo "-- anvil not on PATH; skipping live balance / rpc test section"
  echo "== M2 demo OK (dry section) =="
  exit 0
fi

echo "-- starting anvil"
ANVIL_PORT=8545
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --chain-id 31337 \
  --mnemonic "test test test test test test test test test test test junk" --silent &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null || true; chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT

ANVIL_URL="http://127.0.0.1:${ANVIL_PORT}"
# wait for anvil to answer
for _ in $(seq 1 50); do
  if curl -fsS -X POST -H 'content-type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
       "$ANVIL_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

# Define a localanvil network (chain-id 31337) + an endpoint reaching anvil.
"$DAXIE" network add localanvil --chain-id 31337 --rpc-url "$ANVIL_URL" >/dev/null
"$DAXIE" network use localanvil >/dev/null

echo "-- rpc test (chain-id verification + latency)"
out="$("$DAXIE" rpc test localanvil-default --json)"
contains "$out" '"chain_id": 31337' "rpc test verified chain-id"
contains "$out" '"ok": true'        "rpc test ok"

echo "-- balance of a funded anvil account"
FUNDED="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"   # anvil dev account 0 (10000 ETH)
out="$("$DAXIE" balance "$FUNDED" --json)"
contains "$out" "\"address\": \"$FUNDED\"" "balance address echo"
contains "$out" '"symbol": "ETH"'          "balance symbol"
# wei must be a nonzero decimal string (no float); 10000 ETH = 1e22 wei
contains "$out" '"wei": "10000000000000000000000"' "funded balance wei"
# the human form prints the ETH value as the essential output
human="$("$DAXIE" balance "$FUNDED")"
contains "$human" '10000 ETH' "human balance missing 10000 ETH"

echo "-- chain-id MISMATCH refusal (exit 12)"
# An endpoint whose declared network's chain-id is WRONG must refuse rpc test.
"$DAXIE" network add badnet --chain-id 1 --rpc-url "$ANVIL_URL" >/dev/null   # claims chain-id 1, reaches anvil(31337)
expect_exit 12 "$DAXIE" rpc test badnet-default

echo "== M2 demo OK (dry + live anvil) =="
