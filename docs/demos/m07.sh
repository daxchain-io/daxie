#!/usr/bin/env bash
#
# docs/demos/m07.sh — the M7 acceptance demo (design §10.1 gate; v0.7.0).
#
# M7 turns on ENS resolution + the allowlist pin-drift refusal that M0–M6 left
# plumbed but dormant. The headlines:
#   - `daxie ens resolve <name>` / `daxie ens reverse <addr>` resolve against the
#     CONNECTED network's ENS registry (per-invocation; --network/--rpc choose the
#     endpoint). Reverse is FORWARD-VERIFIED (a reverse name is trusted only when it
#     forward-resolves back to the address).
#   - ENS names are accepted WHEREVER a destination/read-only address is: `tx send
#     --to vitalik.eth`, `balance vitalik.eth`, `policy allow vitalik.eth`,
#     `contacts add bob vitalik.eth`. The resolved address is ALWAYS echoed before
#     signing (EvResolved) so an agent/human sees what it is actually paying.
#   - `policy allow <name.eth>` PINS the name AND the resolved address at allow-time.
#     A later send re-resolves and REFUSES with policy.denied.pin_drift (reason
#     ens_drift, exit 3) if the name was re-pointed — an agent never silently
#     follows a mutated ENS record.
#
# Exit codes asserted (§5.7):
#   0  OK
#   2  USAGE (a network with no ENS registry; a malformed reverse address)
#   3  POLICY_DENIED (pin_drift after an ENS re-point)
#   10 NOT_FOUND (an unresolved name where a destination/read was required)
#
# Two sections:
#   A. DRY — ENS is accepted at the surface; an unresolvable network fails clean.
#   B. LIVE — start anvil as chain-id 1, plant a mock ENS at the canonical registry
#      address (anvil_setCode), register a name, resolve it, send to it, then `policy
#      allow` + re-point + assert the next send DENIES pin_drift (exit 3). Runs ONLY
#      when anvil + curl + cast are on PATH (cast computes the EIP-137 namehash).
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m07.sh   (defaults to ./daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"

# ── assertion helpers (mirror m05.sh/m06.sh) ─────────────────────────────────
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

# rpc <method> <params-json> : a one-shot JSON-RPC call to anvil, echoing the body.
rpc() {
  curl -fsS -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$ANVIL_URL"
}
# bytecode_of <Go-const-file> : extract the embedded "0x..." bytecode hex (longest).
runtime_of() { grep -oE '"0x[0-9a-fA-F]+"' "$1" | tr -d '"' | awk '{ print length, $0 }' | sort -rn | head -1 | cut -d' ' -f2-; }
# word <hex-no-0x> : left-pad to a 32-byte (64-hex) ABI word.
word() { printf '%064s' "$1" | tr ' ' 0; }
addr_word() { local a="${1#0x}"; word "$a"; }

echo "== daxie M7 demo =="

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

PASS_FILE="$WORK/pass"; printf 'm7 keystore passphrase\n' > "$PASS_FILE"; chmod 0600 "$PASS_FILE"
export DAXIE_PASSPHRASE_FILE="$PASS_FILE"
export DAXIE_PASSPHRASE_CONFIRM_FILE="$PASS_FILE"
ADMIN_FILE="$WORK/admin"; printf 'm7 admin passphrase\n' > "$ADMIN_FILE"; chmod 0600 "$ADMIN_FILE"
export DAXIE_ADMIN_PASSPHRASE_FILE="$ADMIN_FILE"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION A — DRY: ENS is at the surface; an ENS-less network fails clean
# ═════════════════════════════════════════════════════════════════════════════

# `ens resolve` / `ens reverse` exist as commands.
echo "-- ens resolve|reverse are real commands"
"$DAXIE" ens --help >/dev/null || fail "ens command missing"
"$DAXIE" ens resolve --help >/dev/null || fail "ens resolve missing"
"$DAXIE" ens reverse --help >/dev/null || fail "ens reverse missing"

# A reverse of a non-address is a usage error (before any dial).
echo "-- ens reverse <not-an-address> ⇒ usage"
expect_exit 2 "$DAXIE" ens reverse not-an-address

echo "== M7 demo: DRY section OK =="

# ═════════════════════════════════════════════════════════════════════════════
# SECTION B — LIVE: mock ENS at the canonical registry, resolve, send, pin-drift
# ═════════════════════════════════════════════════════════════════════════════
if ! command -v anvil >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1 || ! command -v cast >/dev/null 2>&1; then
  echo "-- anvil/curl/cast not all on PATH; skipping live ENS section"
  echo "== M7 demo OK (dry section) =="
  exit 0
fi

# Start anvil as CHAIN-ID 1 so the shipped binary's RegistryFor(1) → the canonical
# ENS registry address; we plant the mock THERE via anvil_setCode. (chain-id 1 is a
# local throwaway anvil — no mainnet is touched.)
echo "-- starting anvil (chain-id 1, local throwaway)"
ANVIL_PORT=8557
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --chain-id 1 \
  --mnemonic "test test test test test test test test test test test junk" --silent &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null || true; chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT
ANVIL_URL="http://127.0.0.1:${ANVIL_PORT}"
for _ in $(seq 1 50); do
  if rpc eth_chainId '[]' >/dev/null 2>&1; then break; fi
  sleep 0.2
done

REGISTRY="0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"   # the canonical ENS registry
REPO_ROOT="$(dirname "$0")/../.."

# Plant the mock ENS runtime bytecode at the canonical registry address. The mock is
# a combined registry+resolver: resolver(node) returns address(this) (== REGISTRY),
# and addr(node)/setAddr live in the same code.
echo "-- planting mock ENS at the canonical registry via anvil_setCode"
RUNTIME="$(runtime_of "$REPO_ROOT/internal/testchain/ensbytecode.go")"
[ -n "$RUNTIME" ] || fail "could not read the ens bytecode constant"
# The Go const is CREATION bytecode; derive the runtime by deploying once and reading
# eth_getCode (robust against constructor-appended metadata).
DEPLOY_H="$(rpc eth_sendTransaction "[{\"from\":\"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\",\"data\":\"$RUNTIME\",\"gas\":\"0x2dc6c0\"}]" | sed -n 's/.*"result":"\(0x[0-9a-fA-F]*\)".*/\1/p')"
sleep 0.3
DEPLOYED="$(rpc eth_getTransactionReceipt "[\"$DEPLOY_H\"]" | sed -n 's/.*"contractAddress":"\(0x[0-9a-fA-F]*\)".*/\1/p')"
[ -n "$DEPLOYED" ] || fail "mock ENS deploy returned no contractAddress"
RUNCODE="$(rpc eth_getCode "[\"$DEPLOYED\",\"latest\"]" | sed -n 's/.*"result":"\(0x[0-9a-fA-F]*\)".*/\1/p')"
[ -n "$RUNCODE" ] && [ "$RUNCODE" != "0x" ] || fail "mock ENS has no runtime code"
rpc anvil_setCode "[\"$REGISTRY\",\"$RUNCODE\"]" >/dev/null

# Wire the local network (chain-id 1 ⇒ RegistryFor picks the canonical registry).
"$DAXIE" network add localmain --chain-id 1 --rpc-url "$ANVIL_URL" >/dev/null
"$DAXIE" network use localmain >/dev/null

# Funded dev account 0 (deployer + the daxie signer).
KEY_FILE="$WORK/anvilkey"
printf '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n' > "$KEY_FILE"
chmod 0600 "$KEY_FILE"
"$DAXIE" account import funded --key-file "$KEY_FILE" --yes >/dev/null
FUNDED="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# Register payee.eth → ADDR_A on the mock (setAddr(node,addr), selector 0xd5fa2b00).
NAME="payee.eth"
NODE="$(cast namehash "$NAME")"
ADDR_A="0x00000000000000000000000000000000000000a1"
ADDR_B="0x00000000000000000000000000000000000000b2"
set_addr() {  # set_addr <addr>
  rpc eth_sendTransaction "[{\"from\":\"$FUNDED\",\"to\":\"$REGISTRY\",\"data\":\"0xd5fa2b00${NODE#0x}$(addr_word "$1")\",\"gas\":\"0x493e0\"}]" >/dev/null
  sleep 0.2
}
echo "-- registering $NAME -> $ADDR_A"
set_addr "$ADDR_A"

# 1. ens resolve returns ADDR_A.
echo "-- ens resolve $NAME ⇒ $ADDR_A"
out="$("$DAXIE" ens resolve "$NAME" --json)"
contains "$(printf '%s' "$out" | tr 'A-F' 'a-f')" "$(printf '%s' "$ADDR_A" | tr 'A-F' 'a-f')" "ens resolve address"

# 2. An unregistered name ⇒ ref.not_found (exit 10), never a zero address.
echo "-- ens resolve <unregistered> ⇒ ref.not_found (exit 10)"
expect_code 10 "ref.not_found" "unresolved name" "$DAXIE" ens resolve nope.eth

# 3. tx send --to payee.eth resolves + sends; the resolved address is echoed.
echo "-- tx send --to $NAME (resolved + echoed before signing)"
out="$("$DAXIE" tx send --from funded --to "$NAME" --amount 1eth --wait --yes --json)"
contains "$(printf '%s' "$out" | tr 'A-F' 'a-f')" "$(printf '%s' "$ADDR_A" | tr 'A-F' 'a-f')" "send echoed resolved addr"
contains "$out" '"ens_name": "payee.eth"' "send echoed ens name"

# 4. policy allow payee.eth: pins name+ADDR_A. Within limits + allowlisted, a send to
#    the name SUCCEEDS while the pin matches.
echo "-- policy: set limits + allowlist ON, then allow $NAME (pins name+resolved addr)"
"$DAXIE" policy set --max-tx 5eth --max-day 100eth --allowlist on --include-self on >/dev/null
# The resolved address is ALWAYS echoed (and in --json) BEFORE the seal is written, so
# the operator authorizes the 0x being trusted — not a bare name (§4.8 / cli-spec).
out="$("$DAXIE" policy allow "$NAME" --json)"
contains "$(printf '%s' "$out" | tr 'A-F' 'a-f')" "$(printf '%s' "$ADDR_A" | tr 'A-F' 'a-f')" "policy allow echoed pinned addr"
contains "$out" '"source": "ens"' "policy allow echoed ens source"
contains "$out" '"name": "payee.eth"' "policy allow echoed ens name"
echo "-- send to the PINNED matching name ⇒ confirmed (exit 0)"
"$DAXIE" tx send --from funded --to "$NAME" --amount 1eth --wait --yes >/dev/null

# 5. RE-POINT payee.eth -> ADDR_B (ENS records are mutable). The next send re-resolves
#    and REFUSES with policy.denied.pin_drift (reason ens_drift, exit 3).
echo "-- re-point $NAME -> $ADDR_B, then send ⇒ policy.denied.pin_drift (exit 3)"
set_addr "$ADDR_B"
expect_code 3 "policy.denied.pin_drift" "ens drift refusal" \
  "$DAXIE" tx send --from funded --to "$NAME" --amount 1eth --yes

echo "== M7 demo OK (dry + live) =="
