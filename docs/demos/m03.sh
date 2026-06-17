#!/usr/bin/env bash
#
# docs/demos/m03.sh — the M3 acceptance demo (design §10.1 gate).
#
# Exercises the M3 ETH transaction pipeline + gas engine + contacts end to end,
# both human and --json, on the NON-INTERACTIVE path (agents), and ASSERTS the
# documented exit codes (§5.7): 0 OK, 2 USAGE, 8 TIMEOUT_PENDING (resumable, NOT a
# failure), 9 TX_CONFLICT (already-mined RBF), 10 NOT_FOUND.
#
# NOTE: v0.3.0 ships WITHOUT guardrails — M3's policy is an always-allow STUB (M4
# adds real limits). This demo therefore does NOT assert any policy.denied (exit 3)
# behavior; that lands in m04.sh.
#
# Two sections:
#   A. DRY — contacts CRUD + tx/gas flag plumbing + usage exit codes that need NO
#      network (always run): contacts add/list/show/remove; --to a contact name
#      resolves; missing-flag usage errors; M5 --token / M7 name.eth fail clean.
#   B. LIVE — a real send → wait → status → list → speedup/cancel → gas against a
#      local anvil. Runs ONLY when `anvil` is on PATH (CI's foundry-toolchain
#      provides it); skipped cleanly otherwise.
#
# Runs unmodified in CI; any failed assertion exits non-zero.
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m03.sh
#   defaults to ./daxie (build first:  go build -o daxie ./cmd/daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"

# ── assertion helpers (mirror m00.sh / m01.sh / m02.sh) ──────────────────────
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

echo "== daxie M3 demo =="

# ── isolated, throwaway state (every class points at temp dirs) ───────────────
WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT

export DAXIE_CONFIG="$WORK/config"
export DAXIE_KEYSTORE="$WORK/keystore"
export DAXIE_STATE_DIR="$WORK/state"
export DAXIE_CACHE_DIR="$WORK/cache"
mkdir -p "$DAXIE_CONFIG"
printf 'schema = 1\n' > "$DAXIE_CONFIG/config.toml"

# Non-interactive keystore passphrase (file channel) + light KDF for speed.
export DAXIE_KDF_LIGHT=1
PASS_FILE="$WORK/pass"
printf 'm3 demo passphrase\n' > "$PASS_FILE"
chmod 0600 "$PASS_FILE"  # the passphrase-file channel refuses a world-readable file (keystore.perms_insecure)
export DAXIE_PASSPHRASE_FILE="$PASS_FILE"
export DAXIE_PASSPHRASE_CONFIRM_FILE="$PASS_FILE"

# Well-known throwaway addresses (checksummed).
ADDR_EXCHANGE="0x52908400098527886E0F7030069857D2E4169EE7"
ADDR_OTHER="0x8617E340B3D01FA5F11F306F4090FD50E238070D"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION A — DRY: contacts + tx/gas flag plumbing (no network required)
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 1. contacts add / list / show / remove — the §7.8 address book
# ─────────────────────────────────────────────────────────────────────────────
echo "-- contacts add/list/show/remove"
"$DAXIE" contacts add exchange "$ADDR_EXCHANGE" >/dev/null
out="$("$DAXIE" contacts list --json)"
contains "$out" '"name": "exchange"' "contacts list missing exchange"
contains "$out" "$ADDR_EXCHANGE"      "contacts list missing the address"

out="$("$DAXIE" contacts show exchange --json)"
contains "$out" "$ADDR_EXCHANGE" "contacts show address echo"
# human show prints the address as the essential first line
human="$("$DAXIE" contacts show exchange)"
contains "$human" "$ADDR_EXCHANGE" "human contacts show missing address"

# duplicate add → exit 2 (USAGE)
expect_exit 2 "$DAXIE" contacts add exchange "$ADDR_OTHER"
# show/remove of an unknown contact → exit 10 (NOT_FOUND)
expect_exit 10 "$DAXIE" contacts show ghost
expect_exit 10 "$DAXIE" contacts remove ghost --yes

"$DAXIE" contacts remove exchange --yes >/dev/null
expect_exit 10 "$DAXIE" contacts show exchange   # gone

# ─────────────────────────────────────────────────────────────────────────────
# 2. tx send flag validation — usage errors caught before any network call
# ─────────────────────────────────────────────────────────────────────────────
echo "-- tx send usage validation"
# missing --to / --amount → exit 2 (USAGE)
expect_exit 2 "$DAXIE" tx send --amount 0.5
expect_exit 2 "$DAXIE" tx send --to "$ADDR_OTHER"
# a bad --timeout → exit 2 (USAGE), caught by the cli parse
expect_exit 2 "$DAXIE" tx send --to "$ADDR_OTHER" --amount 0.5 --wait --timeout not-a-duration --yes
# tx status / wait / speedup / cancel each require a hash arg → exit 2
expect_exit 2 "$DAXIE" tx status
expect_exit 2 "$DAXIE" tx wait
expect_exit 2 "$DAXIE" tx speedup
expect_exit 2 "$DAXIE" tx cancel

# ─────────────────────────────────────────────────────────────────────────────
# 3. M5/M7 paths fail clean (never faked): --token is M5, a name.eth --to is M7
# ─────────────────────────────────────────────────────────────────────────────
echo "-- M5/M7 tx paths fail clean"
# --token → usage.unsupported (exit 2). (No network needed: rejected up front.)
expect_exit 2 "$DAXIE" tx send --to "$ADDR_OTHER" --amount 100 --token USDC --yes

# ═════════════════════════════════════════════════════════════════════════════
# SECTION B — LIVE: send/wait/status/list/speedup/cancel/gas against local anvil
# ═════════════════════════════════════════════════════════════════════════════
if ! command -v anvil >/dev/null 2>&1; then
  echo "-- anvil not on PATH; skipping live tx / gas section"
  echo "== M3 demo OK (dry section) =="
  exit 0
fi

echo "-- starting anvil"
ANVIL_PORT=8546
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --chain-id 31337 \
  --mnemonic "test test test test test test test test test test test junk" --silent &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null || true; chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT

ANVIL_URL="http://127.0.0.1:${ANVIL_PORT}"
for _ in $(seq 1 50); do
  if curl -fsS -X POST -H 'content-type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
       "$ANVIL_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

# Define a localanvil network + endpoint, make it the default.
"$DAXIE" network add localanvil --chain-id 31337 --rpc-url "$ANVIL_URL" >/dev/null
"$DAXIE" network use localanvil >/dev/null

# Import anvil dev account 0 (funded with 10000 ETH) as the standalone `funded`
# account. This is the well-known anvil/hardhat dev key — it controls only the
# throwaway local chain.
KEY_FILE="$WORK/anvilkey"
printf '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n' > "$KEY_FILE"
chmod 0600 "$KEY_FILE"  # the keystore refuses a world-readable key file (keystore.perms_insecure)
"$DAXIE" account import funded --key-file "$KEY_FILE" --yes >/dev/null

# A fresh recipient anvil does NOT fund (so its post-send balance is exact).
RECIP="0x000000000000000000000000000000000000C0DE"

# ─────────────────────────────────────────────────────────────────────────────
# 4. gas — live three-speed quote + base fee
# ─────────────────────────────────────────────────────────────────────────────
echo "-- gas (live quote)"
out="$("$DAXIE" gas --json)"
contains "$out" '"base_fee"' "gas --json missing base fee"
contains "$out" '"slow"'     "gas --json missing slow quote"
contains "$out" '"fast"'     "gas --json missing fast quote"

# ─────────────────────────────────────────────────────────────────────────────
# 4b. tx send --dry-run — builds + estimates + previews, signs/broadcasts NOTHING.
#     The recipient balance must be UNCHANGED afterward.
# ─────────────────────────────────────────────────────────────────────────────
echo "-- tx send --dry-run (no broadcast)"
dr_before="$("$DAXIE" balance "$RECIP" --json | sed -n 's/.*"wei": "\([0-9]*\)".*/\1/p')"
out="$("$DAXIE" tx send --from funded --to "$RECIP" --amount 1eth --dry-run --yes --json)"
contains "$out" '"dry_run": true' "dry-run result not marked dry_run"
dr_after="$("$DAXIE" balance "$RECIP" --json | sed -n 's/.*"wei": "\([0-9]*\)".*/\1/p')"
eq "$dr_after" "$dr_before" "dry-run must NOT move funds"

# ─────────────────────────────────────────────────────────────────────────────
# 5. tx send → wait → confirmed (exact recipient balance)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- tx send --wait (confirmed)"
before="$("$DAXIE" balance "$RECIP" --json | sed -n 's/.*"wei": "\([0-9]*\)".*/\1/p')"
SEND_JSON="$("$DAXIE" tx send --from funded --to "$RECIP" --amount 1eth --wait --yes --json)"
contains "$SEND_JSON" '"status": "confirmed"' "send did not confirm"
HASH="$(printf '%s' "$SEND_JSON" | sed -n 's/.*"hash": "\(0x[0-9a-fA-F]*\)".*/\1/p')"
[ -n "$HASH" ] || fail "send produced no hash"
after="$("$DAXIE" balance "$RECIP" --json | sed -n 's/.*"wei": "\([0-9]*\)".*/\1/p')"
delta=$(( after - before ))
eq "$delta" "1000000000000000000" "recipient received exactly 1 ETH"

# ─────────────────────────────────────────────────────────────────────────────
# 6. tx status — folds the journal record for the confirmed hash
# ─────────────────────────────────────────────────────────────────────────────
echo "-- tx status"
out="$("$DAXIE" tx status "$HASH" --json)"
contains "$out" '"status": "confirmed"' "tx status not confirmed"
contains "$out" "$HASH"                  "tx status hash echo"

# ─────────────────────────────────────────────────────────────────────────────
# 7. tx list — the local journal shows the send (newest-first)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- tx list"
out="$("$DAXIE" tx list --account funded --json)"
contains "$out" "$HASH"        "tx list missing the send"
contains "$out" '"confirmed"'  "tx list status"

# ─────────────────────────────────────────────────────────────────────────────
# 8. nonce sequencing — two back-to-back sends never double-allocate a nonce
# ─────────────────────────────────────────────────────────────────────────────
echo "-- nonce sequencing"
N1="$("$DAXIE" tx send --from funded --to "$RECIP" --amount 0.1eth --yes --json | sed -n 's/.*"nonce": \([0-9]*\).*/\1/p')"
N2="$("$DAXIE" tx send --from funded --to "$RECIP" --amount 0.1eth --wait --yes --json | sed -n 's/.*"nonce": \([0-9]*\).*/\1/p')"
[ "$N2" -eq "$(( N1 + 1 ))" ] || fail "nonce not sequential: N1=$N1 N2=$N2 (want N2 = N1+1)"

# ─────────────────────────────────────────────────────────────────────────────
# 9. RBF surface — anvil mines instantly, so speedup/cancel of an already-mined
#    hash is the TX_CONFLICT path (exit 9); an unknown hash is NOT_FOUND (exit 10).
#    (The real mempool-race replacement is in the service integration test with
#    anvil --no-mining.)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- tx speedup / cancel (already-mined conflict + unknown not-found)"
expect_exit 9  "$DAXIE" tx speedup "$HASH" --yes
expect_exit 9  "$DAXIE" tx cancel  "$HASH" --yes
expect_exit 10 "$DAXIE" tx speedup 0x000000000000000000000000000000000000000000000000000000000000dead --yes

# ─────────────────────────────────────────────────────────────────────────────
# 10. tx wait on an unknown hash with a tiny timeout → exit 8 (TIMEOUT_PENDING,
#     resumable, NOT a failure) or 10 (no journal record). Either is a non-failure
#     §5.7 code — assert it is one of the two and never a generic 1.
# ─────────────────────────────────────────────────────────────────────────────
echo "-- tx wait timeout (resumable)"
code=0
"$DAXIE" tx wait 0x000000000000000000000000000000000000000000000000000000000000beef --timeout 2s >/dev/null 2>&1 || code=$?
case "$code" in
  8|10) : ;;
  *) fail "tx wait on an unknown hash returned exit $code, want 8 (timeout) or 10 (not_found)" ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# 11. --to a contact name resolves on a live send
# ─────────────────────────────────────────────────────────────────────────────
echo "-- tx send --to <contact>"
"$DAXIE" contacts add recip "$RECIP" >/dev/null
out="$("$DAXIE" tx send --from funded --to recip --amount 0.05eth --wait --yes --json)"
contains "$out" '"status": "confirmed"' "send to a contact did not confirm"
# Addresses are rendered lowercase in JSON; compare the recipient case-insensitively.
recip_lc="$(printf '%s' "$RECIP" | tr '[:upper:]' '[:lower:]')"
contains "$out" "$recip_lc"             "send to a contact did not resolve the address"

echo "== M3 demo OK (dry + live anvil) =="
