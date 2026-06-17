#!/usr/bin/env bash
#
# docs/demos/m05.sh — the M5 acceptance demo (design §10.1 gate; v0.5.0).
#
# M5 adds the TOKEN REGISTRY + ERC-20 transfers/approvals: `daxie token`
# (info/add/rename/list/remove + approve/allowance/revoke), `tx send --token`, and
# `balance --token` / `--all`. The anti-spoofing property is the headline: an alias
# resolves REGISTRY-ONLY (a name not registered — and not a bundled major like
# usdc/usdt/weth/dai — is an error, NEVER an on-chain symbol() lookup). An ERC-20
# approval is a SPEND-EQUIVALENT governed by the same policy gates, and the policy
# destination is the RECIPIENT (transfer) / SPENDER (approval), never the token
# contract.
#
# This demo exercises the surface and ASSERTS the §5.7 exit codes:
#   0  OK
#   2  USAGE (--unlimited without --yes; an unregistered alias; mutually-exclusive flags)
#   3  POLICY_DENIED (fail-closed-no-allowlist on a token transfer)
#   10 NOT_FOUND (an unregistered token alias resolves to ref.not_found)
#
# Two sections:
#   A. DRY — token list (bundled majors) + the anti-spoofing miss + the registry
#      collision rule + the --unlimited --yes ceremony refusal, all WITHOUT a network.
#   B. LIVE — deploy a test ERC-20 to anvil, register it, balance --token == on-chain,
#      tx send --token (recipient receives it), approve/allowance/revoke, balance --all,
#      and a fail-closed-no-allowlist DENY (exit 3). Runs ONLY when `anvil` is on PATH.
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m05.sh   (defaults to ./daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"

# ── assertion helpers (mirror m04.sh) ────────────────────────────────────────
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_exit() {
  local want="$1"; shift
  local got=0
  "$@" >/dev/null 2>&1 || got=$?
  [ "$got" -eq "$want" ] || fail "expected exit $want from '$*', got $got"
}
eq() { [ "$1" = "$2" ] || fail "$3: expected '$2', got '$1'"; }
contains() { case "$1" in *"$2"*) : ;; *) fail "$3: '$1' does not contain '$2'";; esac; }
not_contains() { case "$1" in *"$2"*) fail "$3: '$1' must NOT contain '$2'";; *) : ;; esac; }
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

echo "== daxie M5 demo =="

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

# Keystore + admin passphrases (distinct secrets, distinct env names).
PASS_FILE="$WORK/pass"; printf 'm5 keystore passphrase\n' > "$PASS_FILE"; chmod 0600 "$PASS_FILE"
export DAXIE_PASSPHRASE_FILE="$PASS_FILE"
export DAXIE_PASSPHRASE_CONFIRM_FILE="$PASS_FILE"
ADMIN_FILE="$WORK/admin"; printf 'm5 admin passphrase\n' > "$ADMIN_FILE"; chmod 0600 "$ADMIN_FILE"
export DAXIE_ADMIN_PASSPHRASE_FILE="$ADMIN_FILE"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION A — DRY: registry semantics + the anti-spoofing wall + the ceremonies
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 1. token list — the compiled-in majors are present on mainnet with NO file
# ─────────────────────────────────────────────────────────────────────────────
echo "-- token list (bundled majors, no registry file)"
out="$("$DAXIE" token list --network mainnet --json)"
contains "$out" '"alias": "usdc"' "bundled USDC missing from token list"
contains "$out" '"alias": "weth"' "bundled WETH missing from token list"
contains "$out" '"bundled": true' "bundled provenance flag missing"

# ─────────────────────────────────────────────────────────────────────────────
# 2. ANTI-SPOOFING: an unregistered alias is ref.not_found (NEVER a symbol() lookup)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- unregistered alias ⇒ ref.not_found (no on-chain symbol resolution)"
expect_code 10 "ref.not_found" "unregistered token alias" \
  "$DAXIE" token info totally-not-a-real-token --network mainnet

# ─────────────────────────────────────────────────────────────────────────────
# 3. balance --token + --all are mutually exclusive (usage, before any dial)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- balance --token + --all ⇒ usage error"
expect_exit 2 "$DAXIE" balance 0x000000000000000000000000000000000000dEaD --token usdc --all

# ─────────────────────────────────────────────────────────────────────────────
# 4. token approve --unlimited WITHOUT --yes ⇒ usage (the ceremony refusal)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- token approve --unlimited without --yes ⇒ usage (ceremony)"
expect_code 2 "usage" "unlimited without yes" \
  "$DAXIE" token approve usdc --spender 0x000000000000000000000000000000000000bEEF --unlimited

# ─────────────────────────────────────────────────────────────────────────────
# 5. token approve --unlimited AND --amount ⇒ usage (mutually exclusive)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- token approve --unlimited + --amount ⇒ usage"
expect_exit 2 "$DAXIE" token approve usdc \
  --spender 0x000000000000000000000000000000000000bEEF --unlimited --amount 5 --yes

# ═════════════════════════════════════════════════════════════════════════════
# SECTION B — LIVE: deploy a test ERC-20, register, transfer/approve/balance (anvil)
# ═════════════════════════════════════════════════════════════════════════════
if ! command -v anvil >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  echo "-- anvil/curl not on PATH; skipping live token section"
  echo "== M5 demo OK (dry section) =="
  exit 0
fi

echo "-- starting anvil"
ANVIL_PORT=8549
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --chain-id 31337 \
  --mnemonic "test test test test test test test test test test test junk" --silent &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null || true; chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT
ANVIL_URL="http://127.0.0.1:${ANVIL_PORT}"
for _ in $(seq 1 50); do
  if curl -fsS -X POST -H 'content-type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
       "$ANVIL_URL" >/dev/null 2>&1; then break; fi
  sleep 0.2
done

"$DAXIE" network add localanvil --chain-id 31337 --rpc-url "$ANVIL_URL" >/dev/null
"$DAXIE" network use localanvil >/dev/null

# Funded dev account 0 (the ERC-20 deployer + the daxie signer).
KEY_FILE="$WORK/anvilkey"
printf '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n' > "$KEY_FILE"
chmod 0600 "$KEY_FILE"
"$DAXIE" account import funded --key-file "$KEY_FILE" --yes >/dev/null
FUNDED="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# ── deploy the test ERC-20 via anvil's unlocked dev account (eth_sendTransaction).
# The creation bytecode is the same minimal token the integration tests use
# (name "Test", symbol "TST", 18 decimals; constructor mints 1,000,000 TST to the
# deployer). daxie has no deploy command (that is M10 `contract`); the demo plants
# it directly so the token surface has something real to drive.
echo "-- deploying a test ERC-20 to anvil"
BYTECODE_FILE="$(dirname "$0")/../../internal/testchain/erc20bytecode.go"
# Extract the embedded hex (the quoted 0x... string) from the Go constant file.
BYTECODE="$(sed -n 's/.*"\(0x[0-9a-fA-F]*\)".*/\1/p' "$BYTECODE_FILE" | head -1)"
[ -n "$BYTECODE" ] || fail "could not read the test ERC-20 bytecode constant"
DEPLOY_HASH="$(curl -fsS -X POST -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$FUNDED\",\"data\":\"$BYTECODE\",\"gas\":\"0x2dc6c0\"}]}" \
  "$ANVIL_URL" | sed -n 's/.*"result":"\(0x[0-9a-fA-F]*\)".*/\1/p')"
[ -n "$DEPLOY_HASH" ] || fail "ERC-20 deploy returned no tx hash"
sleep 0.3
TOKEN="$(curl -fsS -X POST -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionReceipt\",\"params\":[\"$DEPLOY_HASH\"]}" \
  "$ANVIL_URL" | sed -n 's/.*"contractAddress":"\(0x[0-9a-fA-F]*\)".*/\1/p')"
[ -n "$TOKEN" ] || fail "ERC-20 deploy receipt has no contractAddress"
echo "   token deployed at $TOKEN"

# ─────────────────────────────────────────────────────────────────────────────
# 6. token add — register the deployed token, alias "tst"
# ─────────────────────────────────────────────────────────────────────────────
echo "-- token add (register the deployed ERC-20)"
"$DAXIE" token add "$TOKEN" --name tst --json >/dev/null
out="$("$DAXIE" token list --json)"
contains "$out" '"alias": "tst"' "registered token missing from list"

# A second add of the SAME alias is a duplicate (usage).
expect_code 2 "usage.duplicate" "duplicate alias" \
  "$DAXIE" token add "$TOKEN" --name tst

# ─────────────────────────────────────────────────────────────────────────────
# 7. balance --token == the on-chain balance (the deployer holds the full supply)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- balance --token tst (deployer holds the supply)"
out="$("$DAXIE" balance "$FUNDED" --token tst --json)"
contains "$out" '"base": "1000000000000000000000000"' "deployer token balance != 1,000,000 TST"

# ─────────────────────────────────────────────────────────────────────────────
# 8. tx send --token — transfer 100 TST to a fresh recipient; it receives it
# ─────────────────────────────────────────────────────────────────────────────
echo "-- tx send --token tst (transfer 100 TST)"
RECIP="0x00000000000000000000000000000000000000A1"
"$DAXIE" tx send --from funded --to "$RECIP" --amount 100 --token tst --wait --yes --json >/dev/null
out="$("$DAXIE" balance "$RECIP" --token tst --json)"
contains "$out" '"formatted": "100"' "recipient did not receive 100 TST"

# ─────────────────────────────────────────────────────────────────────────────
# 9. token approve / allowance / revoke
# ─────────────────────────────────────────────────────────────────────────────
echo "-- token approve / allowance / revoke"
SPENDER="0x00000000000000000000000000000000000000B2"
"$DAXIE" token approve tst --from funded --spender "$SPENDER" --amount 250 --wait --yes --json >/dev/null
out="$("$DAXIE" token allowance tst --owner "$FUNDED" --spender "$SPENDER" --json)"
contains "$out" '"allowance_formatted": "250"' "allowance != 250 after approve"
"$DAXIE" token revoke tst --from funded --spender "$SPENDER" --wait --yes --json >/dev/null
out="$("$DAXIE" token allowance tst --owner "$FUNDED" --spender "$SPENDER" --json)"
contains "$out" '"allowance": "0"' "allowance != 0 after revoke"

# ─────────────────────────────────────────────────────────────────────────────
# 10. balance --all — ETH + the nonzero TST balance
# ─────────────────────────────────────────────────────────────────────────────
echo "-- balance --all (ETH + nonzero tokens)"
out="$("$DAXIE" balance "$FUNDED" --all --json)"
contains "$out" '"alias": "tst"' "balance --all missing the held TST"

# ─────────────────────────────────────────────────────────────────────────────
# 11. FAIL-CLOSED: a token transfer with limits set + no allowlist ⇒ exit 3
# ─────────────────────────────────────────────────────────────────────────────
echo "-- fail-closed-no-allowlist on a token transfer ⇒ exit 3"
"$DAXIE" policy set --max-tx 1eth --allowlist off --json >/dev/null
expect_code 3 "policy.denied.no_allowlist" "token transfer fail-closed" \
  "$DAXIE" tx send --from funded --to "$RECIP" --amount 1 --token tst --yes

echo "== M5 demo OK (dry + live anvil) =="
