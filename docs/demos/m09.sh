#!/usr/bin/env bash
#
# docs/demos/m09.sh — the M9 acceptance demo (design §10.1 gate; v0.9.0).
#
# M9 turns on gasless off-chain signing — the agent-identity primitive that
# completes the wallet without a transaction. The headlines:
#   - `daxie sign message` signs an EIP-191 personal message. The
#     \x19Ethereum Signed Message prefix is ALWAYS applied (the signature is
#     unusable as a tx/typed forgery); raw unprefixed eth_sign is never offered.
#     --no-hash signs a pre-hashed 0x 32-byte digest WITH the prefix still applied.
#   - `daxie sign typed` signs an EIP-712 typed-data document, classified BEFORE the
#     key is touched: a RECOGNIZED spend-equivalent permit (EIP-2612 / DAI / Permit2)
#     is policy-checked at SIGNATURE time exactly like an on-chain approval (spender
#     allowlist + the --unlimited --yes ceremony + fail-closed + chain-mismatch deny);
#     an UNRECOGNIZED message hits the stage-5 typed-data gate (deny-by-default once a
#     policy is active).
#   - `daxie verify` recovers the signer via ecrecover and asserts it equals a claimed
#     0x address (or an ENS name). A mismatch is exit 2, not a crash.
#   - `daxie policy typed allow|remove` (admin passphrase) manages the per-domain
#     typed-data allow registry that opens a specific unknown EIP-712 domain.
#
# Exit codes asserted (§5.7):
#   0  OK             (a permit/message signs; a correct verify; an opened domain)
#   2  USAGE          (bad sources; --no-hash bad digest; --unlimited without --yes;
#                      a verify mismatch; missing policy-typed flags)
#   3  POLICY_DENIED  (a non-allowlisted permit; an unknown typed message; a
#                      wrong-chainId permit — checked at SIGNATURE time)
#
# Two sections:
#   A. DRY — the commands + flags exist; bad combos reject with exit 2.
#   B. LIVE — start a throwaway anvil (chain-id 31337), import the funded dev key,
#      deploy a real EIP-2612 permit token, then: sign a message + verify it (and a
#      mismatch); seal a policy that allowlists a spender, sign an EIP-2612 Permit,
#      SUBMIT it on-chain to the token's permit() and assert the allowance is set (the
#      real roundtrip — the executable proof a Daxie-signed permit is valid); a permit
#      to a NON-allowlisted spender is DENIED at signature time (exit 3); an unknown
#      typed message is DENIED, then `policy typed allow` opens it; a wrong-chainId
#      permit is DENIED. Runs ONLY when anvil + cast (foundry) are on PATH.
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m09.sh   (defaults to ./daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"
# Keep foundry's nightly-build banner off the demo log (cosmetic only).
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1

# ── assertion helpers (mirror m05.sh..m08.sh) ────────────────────────────────
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

echo "== daxie M9 demo =="

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

PASS_FILE="$WORK/pass"; printf 'm9 keystore passphrase\n' > "$PASS_FILE"; chmod 0600 "$PASS_FILE"
export DAXIE_PASSPHRASE_FILE="$PASS_FILE"
export DAXIE_PASSPHRASE_CONFIRM_FILE="$PASS_FILE"
ADMIN_FILE="$WORK/admin"; printf 'm9 admin passphrase\n' > "$ADMIN_FILE"; chmod 0600 "$ADMIN_FILE"
export DAXIE_ADMIN_PASSPHRASE_FILE="$ADMIN_FILE"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION A — DRY: the commands + flags exist; bad combos reject with exit 2
# ═════════════════════════════════════════════════════════════════════════════

echo "-- sign / verify / policy typed are real commands with the full flag set"
"$DAXIE" sign --help >/dev/null || fail "sign command missing"
"$DAXIE" verify --help >/dev/null || fail "verify command missing"
"$DAXIE" policy typed --help >/dev/null || fail "policy typed command missing"

SIGN_MSG_HELP="$("$DAXIE" sign message --help 2>&1)"
for flag in --account --from --stdin --no-hash; do
  contains "$SIGN_MSG_HELP" "$flag" "sign message --help lists $flag"
done
SIGN_TYPED_HELP="$("$DAXIE" sign typed --help 2>&1)"
for flag in --account --data --data-stdin --unlimited; do
  contains "$SIGN_TYPED_HELP" "$flag" "sign typed --help lists $flag"
done
VERIFY_HELP="$("$DAXIE" verify --help 2>&1)"
for flag in --message --typed --signature --address --no-hash; do
  contains "$VERIFY_HELP" "$flag" "verify --help lists $flag"
done

echo "-- sign message <arg> --stdin ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" sign message hello --stdin
echo "-- sign message (no source) ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" sign message
echo "-- sign message 0xdeadbeef --no-hash (not 32 bytes) ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" sign message 0xdeadbeef --no-hash
echo "-- sign typed (no source) ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" sign typed
echo "-- sign typed --unlimited (no --yes) ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" sign typed --data-stdin --unlimited

echo "-- verify (no --signature) ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" verify --message hi --address 0x000000000000000000000000000000000000bEEF
echo "-- verify (no scheme) ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" verify --signature 0xabcd --address 0x000000000000000000000000000000000000bEEF
echo "-- verify --message + --typed (two schemes) ⇒ usage (exit 2)"
expect_exit 2 "$DAXIE" verify --message hi --typed /tmp/x.json --signature 0xabcd --address 0x000000000000000000000000000000000000bEEF

echo "-- policy typed allow (missing --chain-id/--contract/--primary-type) ⇒ usage (exit 2)"
expect_code 2 "bad_typed_allow" "policy typed allow missing flags" \
  "$DAXIE" policy typed allow --contract 0x000000000000000000000000000000000000bEEF --primary-type Order
expect_code 2 "bad_typed_allow" "policy typed allow bad contract" \
  "$DAXIE" policy typed allow --chain-id 1 --contract not-an-address --primary-type Order

echo "== M9 demo: DRY section OK =="

# ═════════════════════════════════════════════════════════════════════════════
# SECTION B — LIVE: the real EIP-2612 permit roundtrip + sign/verify + denials
# ═════════════════════════════════════════════════════════════════════════════
if ! command -v anvil >/dev/null 2>&1 || ! command -v cast >/dev/null 2>&1; then
  echo "-- anvil/cast not both on PATH; skipping live section"
  echo "== M9 demo OK (dry section) =="
  exit 0
fi

echo "-- starting anvil (chain-id 31337, local throwaway)"
ANVIL_PORT=8559
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --chain-id 31337 \
  --mnemonic "test test test test test test test test test test test junk" --silent &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null || true; chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT
ANVIL_URL="http://127.0.0.1:${ANVIL_PORT}"
for _ in $(seq 1 50); do
  if cast chain-id --rpc-url "$ANVIL_URL" >/dev/null 2>&1; then break; fi
  sleep 0.2
done

# Wire the local network (chain-id 31337, confirmations 1) + the funded signer.
"$DAXIE" network add localanvil --chain-id 31337 --rpc-url "$ANVIL_URL" >/dev/null
"$DAXIE" network use localanvil >/dev/null
OWNER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
OWNER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
KEY_FILE="$WORK/anvilkey"; printf '%s\n' "$OWNER_KEY" > "$KEY_FILE"; chmod 0600 "$KEY_FILE"
"$DAXIE" account import owner --key-file "$KEY_FILE" --yes >/dev/null

# ── 1. sign message + verify round-trip ───────────────────────────────────────
echo "-- sign message 'hello daxie' (EIP-191) → verify (exit 0, valid)"
SIG="$("$DAXIE" sign message "hello daxie" --account owner --json | sed -n 's/.*"signature": *"\([^"]*\)".*/\1/p')"
[ -n "$SIG" ] || fail "sign message produced no signature"
VOUT="$("$DAXIE" verify --message "hello daxie" --signature "$SIG" --address "$OWNER" --json)"
contains "$VOUT" '"valid": true' "verify against the real signer is valid"
echo "-- verify against a WRONG address ⇒ mismatch (exit 2, valid:false)"
expect_exit 2 "$DAXIE" verify --message "hello daxie" --signature "$SIG" \
  --address 0x000000000000000000000000000000000000bEEF

# ── deploy a real EIP-2612 permit token (precompiled creation bytecode) ────────
# The IDENTICAL creation bytecode checked into internal/testchain/erc2612bytecode.go
# (a minimal standalone ERC20Permit: name "Permit Test", symbol "PTST", the canonical
# EIP-2612 PERMIT_TYPEHASH, and a permit() that ecrecovers + asserts recovered==owner).
# The demo reads the hex straight from that Go fixture so the two never drift, and
# needs only `cast` to deploy — no solc at run time.
echo "-- deploying a real EIP-2612 permit token"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EC_FILE="$SCRIPT_DIR/../../internal/testchain/erc2612bytecode.go"
[ -f "$EC_FILE" ] || fail "erc2612bytecode.go fixture not found at $EC_FILE"
PERMIT_BC="$(grep -o '"0x[0-9a-f]*"' "$EC_FILE" | tr -d '"' | head -1)"
[ -n "$PERMIT_BC" ] || fail "could not extract the permit-token bytecode from $EC_FILE"
TOKEN="$(cast send --rpc-url "$ANVIL_URL" --private-key "$OWNER_KEY" --create "$PERMIT_BC" --json \
  | sed -n 's/.*"contractAddress":"\([^"]*\)".*/\1/p')"
[ -n "$TOKEN" ] || fail "permit token deploy produced no address"
TOKEN_DEPLOYED=1
echo "-- permit token deployed at $TOKEN"

SPENDER=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
ROGUE=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC

# Seal a policy: allowlist the SPENDER (the permit is gated like an on-chain approval).
echo "-- seal a policy (allowlist on) + allow the spender"
"$DAXIE" policy set --max-tx 1eth --allowlist on >/dev/null
"$DAXIE" policy allow "$SPENDER" >/dev/null

# Build an EIP-2612 Permit typed-data JSON (chainId = anvil, verifyingContract = token).
permit_json() {  # $1=chainId $2=spender $3=value $4=nonce $5=deadline
  cat <<JSON
{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"Permit":[{"name":"owner","type":"address"},{"name":"spender","type":"address"},{"name":"value","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"}]},"primaryType":"Permit","domain":{"name":"Permit Test","version":"1","chainId":"$1","verifyingContract":"$TOKEN"},"message":{"owner":"$OWNER","spender":"$2","value":"$3","nonce":"$4","deadline":"$5"}}
JSON
}

VALUE=7000000000000000000   # 7 PTST
DEADLINE=9999999999
NONCE="$(cast call --rpc-url "$ANVIL_URL" "$TOKEN" 'nonces(address)(uint256)' "$OWNER" | awk '{print $1}')"

# ── 2. the REAL EIP-2612 permit roundtrip (the load-bearing one) ──────────────
echo "-- sign typed (allowlisted EIP-2612 permit) ⇒ exit 0, a 65-byte signature"
PERMIT_FILE="$WORK/permit.json"; permit_json 31337 "$SPENDER" "$VALUE" "$NONCE" "$DEADLINE" > "$PERMIT_FILE"
PSIG="$("$DAXIE" sign typed --data "$PERMIT_FILE" --account owner --json | sed -n 's/.*"signature": *"\([^"]*\)".*/\1/p')"
[ -n "$PSIG" ] || fail "sign typed (permit) produced no signature"
eq "${#PSIG}" "132" "permit signature is 0x + 65 bytes (132 chars)"

echo "-- submitting the Daxie-signed permit on-chain ⇒ allowance == value"
R="0x${PSIG:2:64}"; S="0x${PSIG:66:64}"; V=$((16#${PSIG:130:2}))
cast send --rpc-url "$ANVIL_URL" --private-key "$OWNER_KEY" "$TOKEN" \
  'permit(address,address,uint256,uint256,uint8,bytes32,bytes32)' \
  "$OWNER" "$SPENDER" "$VALUE" "$DEADLINE" "$V" "$R" "$S" >/dev/null
ALLOW="$(cast call --rpc-url "$ANVIL_URL" "$TOKEN" 'allowance(address,address)(uint256)' "$OWNER" "$SPENDER" | awk '{print $1}')"
eq "$ALLOW" "$VALUE" "on-chain allowance after the Daxie-signed permit"

# ── 3. a permit to a NON-allowlisted spender is DENIED at signature time ───────
echo "-- sign typed (permit to a NON-allowlisted spender) ⇒ exit 3 (policy.denied)"
ROGUE_FILE="$WORK/rogue.json"; permit_json 31337 "$ROGUE" "$VALUE" "$NONCE" "$DEADLINE" > "$ROGUE_FILE"
expect_code 3 "policy.denied" "non-allowlisted permit" \
  "$DAXIE" sign typed --data "$ROGUE_FILE" --account owner

# ── 4. an unknown typed message is DENIED, then opened via policy typed allow ──
echo "-- sign typed (unknown EIP-712 message) ⇒ exit 3 (typed_data.unknown)"
UNK_VERIFY=0x000000000000000000000000000000000000dEaD
UNK_FILE="$WORK/unknown.json"
cat > "$UNK_FILE" <<JSON
{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],"OrderComponents":[{"name":"offerer","type":"address"},{"name":"startAmount","type":"uint256"}]},"primaryType":"OrderComponents","domain":{"name":"Seaport","version":"1.5","chainId":"31337","verifyingContract":"$UNK_VERIFY"},"message":{"offerer":"$OWNER","startAmount":"1000000000000000000"}}
JSON
expect_code 3 "typed_data" "unknown typed deny-by-default" \
  "$DAXIE" sign typed --data "$UNK_FILE" --account owner

echo "-- policy typed allow (admin) opens the specific domain ⇒ sign typed exit 0"
"$DAXIE" policy typed allow --chain-id 31337 --contract "$UNK_VERIFY" --primary-type OrderComponents >/dev/null
USIG="$("$DAXIE" sign typed --data "$UNK_FILE" --account owner --json | sed -n 's/.*"signature": *"\([^"]*\)".*/\1/p')"
[ -n "$USIG" ] || fail "sign typed after policy typed allow produced no signature"
echo "-- policy typed remove ⇒ the unknown message is denied again (exit 3)"
"$DAXIE" policy typed remove --chain-id 31337 --contract "$UNK_VERIFY" --primary-type OrderComponents >/dev/null
expect_code 3 "typed_data" "unknown typed denied after remove" \
  "$DAXIE" sign typed --data "$UNK_FILE" --account owner

# ── 5. a wrong-chainId permit is DENIED (chain_mismatch) ──────────────────────
echo "-- sign typed (permit declaring chainId=1 while on anvil) ⇒ exit 3 (chain_mismatch)"
WRONG_FILE="$WORK/wrongchain.json"; permit_json 1 "$SPENDER" "$VALUE" "$NONCE" "$DEADLINE" > "$WRONG_FILE"
expect_code 3 "policy.denied" "wrong-chainId permit" \
  "$DAXIE" sign typed --data "$WRONG_FILE" --account owner

echo "== M9 demo OK (dry + live) =="
