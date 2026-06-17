#!/usr/bin/env bash
#
# docs/demos/m08.sh — the M8 acceptance demo (design §10.1 gate; v0.8.0).
#
# M8 turns on `daxie receive` — the inbound-detection engine that completes the
# agent-to-agent payment loop. The headlines:
#   - `daxie receive` BLOCKS until the account receives the expected asset and it
#     reaches the confirmation target. The receiving ADDRESS is emitted IMMEDIATELY
#     (the up-front `listening` line) so a counterparty can be paid before the
#     command blocks. With --json the output is a line-delimited NDJSON event stream
#     on stdout: listening → detected → confirming → confirmed (per inbound
#     transfer) → complete. Every line carries "v":1; amounts are base-unit decimal
#     strings.
#   - The TERMINAL line is `complete` (exit 0) or `timeout` (exit 8 — NOT a failure;
#     re-run to resume, detection is stateless). Agents wait on the terminal line.
#   - `--amount` is a cumulative minimum; --token/--nft listen for an ERC-20/NFT via
#     Transfer log filters; ETH arrivals are block-scan + balance-delta polled.
#     --confirmations / --timeout (DEFAULT NONE) / --from-block (resume) / --new
#     (a fresh invoice address) / --qr round out the surface.
#
# Exit codes asserted (§5.7):
#   0  OK             (a payment arrives + confirms ⇒ the terminal `complete` line)
#   2  USAGE          (--token + --nft together; --exact without --amount)
#   8  TIMEOUT        (bounded listen with no payment ⇒ terminal `timeout`, resumable)
#   10 NOT_FOUND      (receive on an unknown account ref)
#
# Two sections:
#   A. DRY — the command + flags exist; the mutual-exclusion + dependency rules
#      reject bad combos with exit 2; an unknown account ref ⇒ exit 10.
#   B. LIVE — start a throwaway anvil (chain-id 31337), import the funded dev key,
#      then for a CONCURRENT payment: run `receive --json` in the background, wait
#      for its up-front `listening` line, pay the address from `funded`, and assert
#      the stream reaches the terminal `complete` line (exit 0) with the right
#      cumulative. Then a bounded receive with NO payment ⇒ terminal `timeout`
#      (exit 8) carrying an executable resume string. Runs ONLY when anvil + curl
#      are on PATH.
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m08.sh   (defaults to ./daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"

# ── assertion helpers (mirror m05.sh/m06.sh/m07.sh) ──────────────────────────
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_exit() {
  local want="$1"; shift
  local got=0
  "$@" >/dev/null 2>&1 || got=$?
  [ "$got" -eq "$want" ] || fail "expected exit $want from '$*', got $got"
}
eq() { [ "$1" = "$2" ] || fail "$3: expected '$2', got '$1'"; }
contains() { case "$1" in *"$2"*) : ;; *) fail "$3: '$1' does not contain '$2'";; esac; }
# expect_code <wanted-exit> <expected-code-substr> <label> <cmd...> : assert BOTH
# the process exit AND the canonical code string in the --json stderr envelope.
expect_code() {
  local want_exit="$1" want_code="$2" label="$3"; shift 3
  local errf; errf="$(mktemp)"
  local got=0
  "$@" --json >/dev/null 2>"$errf" || got=$?
  [ "$got" -eq "$want_exit" ] || { echo "--- stderr ---"; cat "$errf" >&2; rm -f "$errf"; fail "$label: exit $got, want $want_exit"; }
  contains "$(cat "$errf")" "$want_code" "$label: envelope code"
  rm -f "$errf"
}
# rpc <method> <params-json> : a one-shot JSON-RPC call to anvil, echoing the body.
rpc() {
  curl -fsS -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$ANVIL_URL"
}

echo "== daxie M8 demo =="

# ── isolated, throwaway state ────────────────────────────────────────────────
WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT
export DAXIE_CONFIG="$WORK/config"
export DAXIE_KEYSTORE="$WORK/keystore"
export DAXIE_STATE_DIR="$WORK/state"
export DAXIE_CACHE_DIR="$WORK/cache"
mkdir -p "$DAXIE_CONFIG"
printf 'schema = 1\n' > "$DAXIE_CONFIG/config.toml"
export DAXIE_KDF_LIGHT=1

PASS_FILE="$WORK/pass"; printf 'm8 keystore passphrase\n' > "$PASS_FILE"; chmod 0600 "$PASS_FILE"
export DAXIE_PASSPHRASE_FILE="$PASS_FILE"
export DAXIE_PASSPHRASE_CONFIRM_FILE="$PASS_FILE"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION A — DRY: the command + flags exist; bad combos reject; unknown ref ⇒ 10
# ═════════════════════════════════════════════════════════════════════════════

echo "-- receive is a real command with the full flag set"
"$DAXIE" receive --help >/dev/null || fail "receive command missing"
# Capture the help ONCE (grepping the pipe directly would SIGPIPE the producer and
# trip `set -o pipefail`); then assert each flag against the captured text.
RECEIVE_HELP="$("$DAXIE" receive --help 2>&1)"
for flag in --account --new --wallet --name --amount --exact --token --nft \
            --contract --token-id --confirmations --timeout --from-block --qr; do
  contains "$RECEIVE_HELP" "$flag" "receive --help lists $flag"
done

# --token and --nft are mutually exclusive ⇒ usage (exit 2).
echo "-- receive --token X --nft Y ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" receive --account treasury/0 --token USDC --nft punks#1

# --exact without --amount ⇒ usage (exit 2).
echo "-- receive --exact (no --amount) ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" receive --account treasury/0 --exact

# --new without --wallet ⇒ usage (exit 2).
echo "-- receive --new (no --wallet) ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" receive --new --amount 0.1

echo "== M8 demo: DRY section OK =="

# ═════════════════════════════════════════════════════════════════════════════
# SECTION B — LIVE: a concurrent payment ⇒ terminal `complete`; a no-pay ⇒ timeout
# ═════════════════════════════════════════════════════════════════════════════
if ! command -v anvil >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  echo "-- anvil/curl not both on PATH; skipping live receive section"
  echo "== M8 demo OK (dry section) =="
  exit 0
fi

echo "-- starting anvil (chain-id 31337, local throwaway)"
ANVIL_PORT=8558
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --chain-id 31337 \
  --mnemonic "test test test test test test test test test test test junk" --silent &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null || true; chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT
ANVIL_URL="http://127.0.0.1:${ANVIL_PORT}"
for _ in $(seq 1 50); do
  if rpc eth_chainId '[]' >/dev/null 2>&1; then break; fi
  sleep 0.2
done

# Wire the local network (chain-id 31337, confirmations 1) + the funded signer.
"$DAXIE" network add localanvil --chain-id 31337 --rpc-url "$ANVIL_URL" >/dev/null
"$DAXIE" network use localanvil >/dev/null
KEY_FILE="$WORK/anvilkey"
printf '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n' > "$KEY_FILE"
chmod 0600 "$KEY_FILE"
"$DAXIE" account import funded --key-file "$KEY_FILE" --yes >/dev/null

# An unknown account ref ⇒ ref.not_found (exit 10) — before any blocking.
echo "-- receive --account <unknown> ⇒ ref.not_found (exit 10)"
expect_code 10 "ref.not_found" "unknown account" "$DAXIE" receive --account nope/0 --amount 0.1 --timeout 5s

# ── 1. CONCURRENT PAYMENT ⇒ terminal `complete` (exit 0) ──────────────────────
# A fresh recipient anvil does not fund, so its post-pay balance is exactly 0.5.
RECIPIENT="0x00000000000000000000000000000000000d4a1e"
RECV_OUT="$WORK/recv.ndjson"

echo "-- receive --account $RECIPIENT --amount 0.5 (blocks; address up front) &"
# Run receive in the background, streaming NDJSON to a file. The default
# poll-interval (4s) + a generous --timeout give the concurrent payment time to
# land and confirm.
( "$DAXIE" receive --account "$RECIPIENT" --amount 0.5 --json --timeout 120s > "$RECV_OUT" 2>/dev/null; echo "$?" > "$WORK/recv.code" ) &
RECV_PID=$!

# Wait for the up-front `listening` line — the address-up-front guarantee AND the
# signal that the ETH baseline is captured (a payment sent earlier would already be
# in the baseline and never detected).
echo "-- waiting for the up-front listening line"
for _ in $(seq 1 100); do
  if [ -s "$RECV_OUT" ] && grep -q '"event":"listening"' "$RECV_OUT"; then break; fi
  sleep 0.2
done
grep -q '"event":"listening"' "$RECV_OUT" || { cat "$RECV_OUT" >&2; fail "no listening line emitted"; }
contains "$(grep '"event":"listening"' "$RECV_OUT" | head -1 | tr 'A-F' 'a-f')" \
  "$(printf '%s' "$RECIPIENT" | tr 'A-F' 'a-f')" "listening carries the address up front"
contains "$(grep '"event":"listening"' "$RECV_OUT" | head -1)" '"v":1' "listening line carries v:1"

# Now pay the address (only AFTER listening, so the baseline excludes it).
echo "-- paying 0.5 ETH to $RECIPIENT (concurrent sender)"
"$DAXIE" tx send --from funded --to "$RECIPIENT" --amount 0.5 --wait --yes --json >/dev/null

# The background receive must reach the terminal `complete` line (exit 0).
echo "-- waiting for the terminal complete line (exit 0)"
wait "$RECV_PID" || true
RECV_CODE="$(cat "$WORK/recv.code" 2>/dev/null || echo 99)"
eq "$RECV_CODE" "0" "receive exit code on complete"
grep -q '"event":"complete"' "$RECV_OUT" || { cat "$RECV_OUT" >&2; fail "no terminal complete line"; }
contains "$(grep '"event":"complete"' "$RECV_OUT" | tail -1)" '"cumulative_confirmed":"500000000000000000"' "complete cumulative == 0.5 ETH"
contains "$(grep '"event":"complete"' "$RECV_OUT" | tail -1)" '"exit":0' "complete carries exit 0"
# The detection was attributable to a tx (the ETH block-scan path).
grep -q '"attribution":"tx"' "$RECV_OUT" || { cat "$RECV_OUT" >&2; fail "no attribution:\"tx\" detection"; }

# ── 2. NO PAYMENT ⇒ terminal `timeout` (exit 8) with an executable resume ──────
RECIPIENT2="0x00000000000000000000000000000000000d4a2e"
echo "-- receive --amount 5.0 --timeout 3s with NO payment ⇒ timeout (exit 8)"
TIMEOUT_OUT="$WORK/timeout.ndjson"
TO_CODE=0
"$DAXIE" receive --account "$RECIPIENT2" --amount 5.0 --json --timeout 3s > "$TIMEOUT_OUT" 2>/dev/null || TO_CODE=$?
eq "$TO_CODE" "8" "timeout exit code"
grep -q '"event":"timeout"' "$TIMEOUT_OUT" || { cat "$TIMEOUT_OUT" >&2; fail "no terminal timeout line"; }
TIMEOUT_LINE="$(grep '"event":"timeout"' "$TIMEOUT_OUT" | tail -1)"
contains "$TIMEOUT_LINE" '"exit":8' "timeout carries exit 8"
# The remaining is the full 5.0 ETH (nothing received), never rounded down.
contains "$TIMEOUT_LINE" '"remaining":"5000000000000000000"' "timeout remaining == 5.0 ETH (full precision)"
# The resume string is executable: a `daxie receive …` with --from-block + --amount.
contains "$TIMEOUT_LINE" '"resume":"daxie receive' "timeout carries a resume command"
contains "$TIMEOUT_LINE" '--from-block' "resume carries --from-block <last_scanned+1>"
contains "$TIMEOUT_LINE" '--amount' "resume carries --amount <remaining>"

echo "== M8 demo OK (dry + live) =="
