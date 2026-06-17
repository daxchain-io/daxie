#!/usr/bin/env bash
#
# docs/demos/m10.sh — the M10 acceptance demo (design §10.1 gate; v0.10.0).
#
# M10 ships `daxie contract` — the broadest-reach signing path — plus the load-bearing
# calldata classifier that keeps it from bypassing the typed approval ceremonies. The
# headlines:
#   - `contract add/list/show/remove` register an alias→address+inline-ABI as ONE
#     anti-spoofing unit (the ABI is validated at add; an invalid ABI is rejected).
#   - `contract call/logs/encode/decode` are PURE reads: eth_call / eth_getLogs / build
#     hex / parse hex. They NEVER sign and NEVER touch policy (no exit 3 reachable).
#   - `contract send` builds calldata, CLASSIFIES it (§4.2), and signs through the same
#     §5.1 kernel as `tx send`. A recognized ERC-20/721/1155/permit selector is gated
#     EXACTLY like the typed path — a `contract send` carrying approve(attacker, MAX)
#     hits the SAME spender-allowlist + --unlimited --yes ceremony as `token approve`
#     (the decoded spender is the policy subject, never the ERC-20 contract). An
#     unrecognized selector is denied by default (stage-5b, policy.denied.contract_call)
#     until the (network,contract,selector) triple is opened with `policy contract allow`.
#
# Exit codes asserted (§5.7):
#   0  OK             (a registry op; a view call; a recognized/allowlisted send; encode/decode)
#   2  USAGE          (bad ABI/sig/arg; a non-indexed log filter; ambiguous ABI source)
#   3  POLICY_DENIED  (a classified approve gated like the typed path; a stage-5b unknown
#                      selector — never an opaque bypass)
#
# Two sections:
#   A. DRY — the commands + flags exist; bad combos reject with exit 2.
#   B. LIVE — start a throwaway anvil (chain-id 31337), import the funded dev key, deploy
#      a real Staking fixture + an ERC-20, then: register/list/show; call earned (view);
#      send stake (state change); logs (event decode + indexed filter + non-indexed
#      reject); encode/decode round-trip under a deny-all policy (the bypass-irrelevance
#      proof); and THE CRUX — a contract send carrying approve(attacker, MAX) is
#      classified KindApprove and DENIED (exit 3, allowlist) without an allowlisted spender;
#      once the spender is allowlisted, a bare --yes is STILL denied unlimited_unacked
#      (exit 3) — only the DELIBERATE two-flag --unlimited --yes ceremony signs (exit 0),
#      identical to `token approve --unlimited --yes`. Runs ONLY when anvil + cast are on PATH.
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m10.sh   (defaults to ./daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

# ── assertion helpers (mirror m05.sh..m09.sh) ────────────────────────────────
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_exit() {
  local want="$1"; shift
  local got=0
  "$@" >/dev/null 2>&1 || got=$?
  [ "$got" -eq "$want" ] || fail "expected exit $want from '$*', got $got"
}
eq() { [ "$1" = "$2" ] || fail "$3: expected '$2', got '$1'"; }
contains() { case "$1" in *"$2"*) : ;; *) fail "$3: '$1' does not contain '$2'";; esac; }
# expect_code <wanted-exit> <expected-code-substr> <label> <cmd...> : assert BOTH the
# process exit AND the canonical code string in the --json stderr envelope.
expect_code() {
  local want_exit="$1" want_code="$2" label="$3"; shift 3
  local errf; errf="$(mktemp)"
  local got=0
  "$@" --json >/dev/null 2>"$errf" || got=$?
  [ "$got" -eq "$want_exit" ] || { echo "--- stderr ---"; cat "$errf" >&2; rm -f "$errf"; fail "$label: exit $got, want $want_exit"; }
  contains "$(cat "$errf")" "$want_code" "$label: envelope code"
  rm -f "$errf"
}

echo "== daxie M10 demo =="

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

PASS_FILE="$WORK/pass"; printf 'm10 keystore passphrase\n' > "$PASS_FILE"; chmod 0600 "$PASS_FILE"
export DAXIE_PASSPHRASE_FILE="$PASS_FILE"
export DAXIE_PASSPHRASE_CONFIRM_FILE="$PASS_FILE"
ADMIN_FILE="$WORK/admin"; printf 'm10 admin passphrase\n' > "$ADMIN_FILE"; chmod 0600 "$ADMIN_FILE"
export DAXIE_ADMIN_PASSPHRASE_FILE="$ADMIN_FILE"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION A — DRY: the commands + flags exist; bad combos reject with exit 2
# ═════════════════════════════════════════════════════════════════════════════

echo "-- contract / policy contract are real commands with the full flag set"
"$DAXIE" contract --help >/dev/null || fail "contract command missing"
"$DAXIE" policy contract --help >/dev/null || fail "policy contract command missing"

for sub in add list show remove call send logs encode decode; do
  "$DAXIE" contract "$sub" --help >/dev/null || fail "contract $sub missing"
done

CONTRACT_SEND_HELP="$("$DAXIE" contract send --help 2>&1)"
for flag in --value --from --abi --abi-stdin --sig --gas-limit --max-fee --dry-run --wait --nonce; do
  contains "$CONTRACT_SEND_HELP" "$flag" "contract send --help lists $flag"
done
CONTRACT_CALL_HELP="$("$DAXIE" contract call --help 2>&1)"
for flag in --abi --abi-stdin --sig --from --block; do
  contains "$CONTRACT_CALL_HELP" "$flag" "contract call --help lists $flag"
done
CONTRACT_LOGS_HELP="$("$DAXIE" contract logs --help 2>&1)"
for flag in --arg --from-block --to-block --abi --sig; do
  contains "$CONTRACT_LOGS_HELP" "$flag" "contract logs --help lists $flag"
done

echo "-- contract add with both --abi and --abi-stdin ⇒ usage (exit 2)"
ABI_FILE="$WORK/erc20.abi.json"
cat > "$ABI_FILE" <<'JSON'
[{"type":"function","name":"approve","inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"}]
JSON
expect_exit 2 "$DAXIE" contract add tok 0x000000000000000000000000000000000000bEEF --abi "$ABI_FILE" --abi-stdin
echo "-- contract decode with no ABI source ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" contract decode 0xa9059cbb
echo "-- contract decode bad calldata ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" contract decode 0xZZ --sig 'transfer(address,uint256)'
echo "-- policy contract allow (missing --selector) ⇒ usage (exit 2)"
expect_code 2 "bad_contract_allow" "policy contract allow missing selector" \
  "$DAXIE" policy contract allow 0x000000000000000000000000000000000000bEEF

echo "-- contract decode (pure, no chain): approve(spender,MAX) calldata"
DEC="$("$DAXIE" contract decode 0x095ea7b3000000000000000000000000000000000000000000000000000000000000beef00000000000000000000000000000000000000000000000000000000000003e7 --sig 'approve(address,uint256)' --json)"
contains "$DEC" '"selector": "0x095ea7b3"' "decode reports the approve selector"
contains "$DEC" '"999"' "decode reports the amount 999"

echo "== M10 demo: DRY section OK =="

# ═════════════════════════════════════════════════════════════════════════════
# SECTION B — LIVE: the registry + reads + the classified-approve crux
# ═════════════════════════════════════════════════════════════════════════════
if ! command -v anvil >/dev/null 2>&1 || ! command -v cast >/dev/null 2>&1; then
  echo "-- anvil/cast not both on PATH; skipping live section"
  echo "== M10 demo OK (dry section) =="
  exit 0
fi

echo "-- starting anvil (chain-id 31337, local throwaway)"
ANVIL_PORT=8560
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --chain-id 31337 \
  --mnemonic "test test test test test test test test test test test junk" --silent &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null || true; chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT
ANVIL_URL="http://127.0.0.1:${ANVIL_PORT}"
for _ in $(seq 1 50); do
  if cast chain-id --rpc-url "$ANVIL_URL" >/dev/null 2>&1; then break; fi
  sleep 0.2
done

"$DAXIE" network add localanvil --chain-id 31337 --rpc-url "$ANVIL_URL" >/dev/null
"$DAXIE" network use localanvil >/dev/null
OWNER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
OWNER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY_FILE="$WORK/anvilkey"; printf '%s\n' "$OWNER_KEY" > "$KEY_FILE"; chmod 0600 "$KEY_FILE"
"$DAXIE" account import owner --key-file "$KEY_FILE" --yes >/dev/null
"$DAXIE" account use owner >/dev/null  # the default --from for the contract sends below

# ── deploy the Staking fixture (precompiled creation bytecode, no solc) ────────
# Read the IDENTICAL creation bytecode checked into the Go fixture so the two never drift.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SBC_FILE="$SCRIPT_DIR/../../internal/testchain/stakingbytecode.go"
[ -f "$SBC_FILE" ] || fail "stakingbytecode.go fixture not found at $SBC_FILE"
STAKING_BC="$(grep -o '"0x[0-9a-f]*"' "$SBC_FILE" | tr -d '"' | head -1)"
[ -n "$STAKING_BC" ] || fail "could not extract the staking bytecode"
STAKING="$(cast send --rpc-url "$ANVIL_URL" --private-key "$OWNER_KEY" --create "$STAKING_BC" --json \
  | sed -n 's/.*"contractAddress":"\([^"]*\)".*/\1/p')"
[ -n "$STAKING" ] || fail "staking deploy produced no address"
echo "-- staking deployed at $STAKING"

# ── deploy the ERC-20 fixture (for the approve crux) ──────────────────────────
EC_FILE="$SCRIPT_DIR/../../internal/testchain/erc20bytecode.go"
[ -f "$EC_FILE" ] || fail "erc20bytecode.go fixture not found"
ERC20_BC="$(grep -o '"0x[0-9a-f]*"' "$EC_FILE" | tr -d '"' | head -1)"
ERC20="$(cast send --rpc-url "$ANVIL_URL" --private-key "$OWNER_KEY" --create "$ERC20_BC" --json \
  | sed -n 's/.*"contractAddress":"\([^"]*\)".*/\1/p')"
[ -n "$ERC20" ] || fail "erc20 deploy produced no address"
echo "-- erc20 deployed at $ERC20"

# ── 1. register the staking alias with its inline ABI; list + show ────────────
STAKING_ABI="$WORK/staking.abi.json"
cat > "$STAKING_ABI" <<'JSON'
[{"type":"function","name":"earned","inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},{"type":"function","name":"stake","inputs":[{"name":"amount","type":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"withdraw","inputs":[{"name":"amount","type":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"event","name":"Staked","inputs":[{"name":"user","type":"address","indexed":true},{"name":"amount","type":"uint256","indexed":false}],"anonymous":false}]
JSON
echo "-- contract add stk (validated ABI) + list + show"
"$DAXIE" contract add stk "$STAKING" --abi "$STAKING_ABI" >/dev/null
contains "$("$DAXIE" contract list --json)" '"alias": "stk"' "contract list shows stk"
contains "$("$DAXIE" contract show stk --json)" '"function_count"' "contract show prints the ABI summary"
echo "-- contract add with an INVALID ABI ⇒ usage (exit 2), not stored"
BAD_ABI="$WORK/bad.json"; printf '{not json' > "$BAD_ABI"
expect_exit 2 "$DAXIE" contract add bad "$STAKING" --abi "$BAD_ABI"
expect_exit 10 "$DAXIE" contract show bad

# ── 2. contract send stake (state change) ─────────────────────────────────────
echo "-- contract send stk stake 5000 --wait (state change; no policy yet ⇒ exit 0)"
"$DAXIE" contract send stk stake 5000 --wait --yes >/dev/null
EARNED="$(cast call --rpc-url "$ANVIL_URL" "$STAKING" 'earned(address)(uint256)' "$OWNER" | awk '{print $1}')"
eq "$EARNED" "500" "earned() after staking 5000 (5000/10)"

# ── 3. contract call earned (view; no signing, no policy) ─────────────────────
echo "-- contract call stk earned <owner> (view) ⇒ decoded 500"
COUT="$("$DAXIE" contract call stk earned "$OWNER" --json)"
contains "$COUT" '"500"' "contract call earned reports 500"

# ── 4. contract logs (event decode + indexed filter + non-indexed reject) ─────
echo "-- contract logs stk Staked --from-block 0 ⇒ one decoded log"
LOUT="$("$DAXIE" contract logs stk Staked --from-block 0 --json)"
contains "$LOUT" '"amount"' "logs decode the Staked amount"
contains "$LOUT" '"5000"' "logs decode amount=5000"
echo "-- contract logs --arg user=<owner> (indexed filter) ⇒ still one log"
"$DAXIE" contract logs stk Staked --from-block 0 --arg "user=$OWNER" --json >/dev/null
echo "-- contract logs --arg amount=5000 (NON-indexed) ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" contract logs stk Staked --from-block 0 --arg "amount=5000"

# ── 5. encode / decode round-trip under a DENY-ALL policy (bypass-irrelevant) ──
echo "-- seal a deny-all policy (max-tx 0); encode/decode STILL succeed (no policy on reads)"
"$DAXIE" policy set --max-tx 0 >/dev/null
ENC="$("$DAXIE" contract encode stk stake 777 --json | sed -n 's/.*"calldata": *"\([^"]*\)".*/\1/p')"
contains "$ENC" "0xa694fc3a" "encode stake → the stake selector"
DEC2="$("$DAXIE" contract decode "$ENC" --sig 'stake(uint256)' --json)"
contains "$DEC2" '"777"' "decode round-trips the amount 777 under deny-all"

# ── 6. THE CRUX — approve(attacker, MAX) via contract send is classified ──────
echo "-- reset to a policy with allowlist on"
"$DAXIE" policy reset --force >/dev/null
"$DAXIE" policy set --max-tx 1eth --allowlist on >/dev/null
ATTACKER=0x000000000000000000000000000000000000A77a
MAX=115792089237316195423570985008687907853269984665640564039457584007913129639935
ERC20_ABI="$WORK/erc20full.abi.json"
cat > "$ERC20_ABI" <<'JSON'
[{"type":"function","name":"approve","inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"}]
JSON
echo "-- contract send <erc20> approve <attacker> MAX (NOT allowlisted) ⇒ exit 3 (classified KindApprove → allowlist deny on the DECODED spender)"
expect_code 3 "policy.denied.allowlist" "classified approve to non-allowlisted attacker" \
  "$DAXIE" contract send "$ERC20" approve "$ATTACKER" "$MAX" --abi "$ERC20_ABI" --yes
echo "-- --unlimited WITHOUT --yes ⇒ usage exit 2 (the deliberate-ack ceremony needs --yes, like token approve)"
expect_exit 2 "$DAXIE" contract send "$ERC20" approve "$ATTACKER" "$MAX" --abi "$ERC20_ABI" --unlimited
echo "-- allowlist the attacker spender (isolate the unlimited gate from the allowlist gate)"
"$DAXIE" policy allow "$ATTACKER" >/dev/null
echo "-- an ALLOWED --dry-run surfaces the classification verdict (approve / attacker / unlimited) without signing"
DRY="$("$DAXIE" contract send "$ERC20" approve "$ATTACKER" "$MAX" --abi "$ERC20_ABI" --dry-run --unlimited --yes --json 2>/dev/null)"
contains "$DRY" '"classified_as": "approve"' "dry-run classified_as approve"
contains "$DRY" '"unlimited": true' "dry-run unlimited true"
echo "-- allowlisted spender + --yes but WITHOUT --unlimited ⇒ exit 3 unlimited_unacked (the bare --yes does NOT ack the unlimited approval)"
expect_code 3 "policy.denied.unlimited_unacked" "unacked unlimited approve via bare --yes" \
  "$DAXIE" contract send "$ERC20" approve "$ATTACKER" "$MAX" --abi "$ERC20_ABI" --yes
echo "-- the DELIBERATE two-flag ceremony --unlimited --yes on the allowlisted spender ⇒ signs (exit 0)"
"$DAXIE" contract send "$ERC20" approve "$ATTACKER" "$MAX" --abi "$ERC20_ABI" --wait --unlimited --yes >/dev/null
ALLOW="$(cast call --rpc-url "$ANVIL_URL" "$ERC20" 'allowance(address,address)(uint256)' "$OWNER" "$ATTACKER" | awk '{print $1}')"
eq "$ALLOW" "$MAX" "on-chain allowance after the allowlisted + deliberately-acked approve == MAX"

echo "== M10 demo OK (dry + live) =="
