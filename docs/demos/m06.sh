#!/usr/bin/env bash
#
# docs/demos/m06.sh — the M6 acceptance demo (design §10.1 gate; v0.6.0).
#
# M6 adds NFTs (ERC-721 + ERC-1155): `daxie nft` (add/alias/aliases/list/show/send).
# The headlines:
#   - ERC-165 detection at `nft add` is REAL — 721 vs 1155 is decided on-chain and
#     stored; a non-NFT address is rejected (usage.not_nft).
#   - Collection + individual-NFT aliases resolve REGISTRY-ONLY (a name not
#     registered is an error, NEVER an on-chain name() lookup — the same
#     anti-spoofing wall as tokens, applied to collections).
#   - `nft send` routes the standard-correct safeTransferFrom (721:
#     safeTransferFrom(from,to,id) 0x42842e0e; 1155:
#     safeTransferFrom(from,to,id,amount,"") 0xf242432a) through the SAME policy
#     pipeline as a transfer; the policy destination is the RECIPIENT (--to), not the
#     collection contract, and the fail-closed-no-allowlist rule applies (ETH exempt,
#     NFT NOT).
#
# This demo exercises the surface and ASSERTS the §5.7 exit codes:
#   0  OK
#   2  USAGE (a non-NFT add; a bad --amount on a 721; an unregistered alias is a miss)
#   3  POLICY_DENIED (fail-closed-no-allowlist on an NFT send)
#   10 NOT_FOUND (an unregistered collection/NFT alias resolves to ref.not_found)
#
# Two sections:
#   A. DRY — the anti-spoofing miss + the `nft send` flag requirements, WITHOUT a network.
#   B. LIVE — deploy a test ERC-721 + ERC-1155 to anvil, mint, register (kind detected),
#      alias, send (721 ownerOf changes; 1155 balanceOf moves --amount), show, list, and
#      a fail-closed-no-allowlist DENY (exit 3). Runs ONLY when `anvil` + `curl` are on PATH.
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m06.sh   (defaults to ./daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"

# ── assertion helpers (mirror m05.sh) ────────────────────────────────────────
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

# rpc <method> <params-json> : a one-shot JSON-RPC call to anvil, echoing .result hex.
rpc() {
  curl -fsS -X POST -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$ANVIL_URL"
}
# bytecode_of <Go-const-file> : extract the embedded "0x..." creation bytecode hex.
bytecode_of() { sed -n 's/.*"\(0x[0-9a-fA-F]*\)".*/\1/p' "$1" | head -1; }
# word <hex-no-0x> : left-pad to a 32-byte (64-hex) ABI word.
word() { printf '%064s' "$1" | tr ' ' 0; }
# addr_word <0xaddr> : the 32-byte ABI word for an address.
addr_word() { local a="${1#0x}"; word "$a"; }

echo "== daxie M6 demo =="

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
PASS_FILE="$WORK/pass"; printf 'm6 keystore passphrase\n' > "$PASS_FILE"; chmod 0600 "$PASS_FILE"
export DAXIE_PASSPHRASE_FILE="$PASS_FILE"
export DAXIE_PASSPHRASE_CONFIRM_FILE="$PASS_FILE"
ADMIN_FILE="$WORK/admin"; printf 'm6 admin passphrase\n' > "$ADMIN_FILE"; chmod 0600 "$ADMIN_FILE"
export DAXIE_ADMIN_PASSPHRASE_FILE="$ADMIN_FILE"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION A — DRY: the anti-spoofing wall + the `nft send` flag requirements
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 1. ANTI-SPOOFING: an unregistered collection alias is ref.not_found, NEVER a name()
# ─────────────────────────────────────────────────────────────────────────────
echo "-- unregistered collection alias ⇒ ref.not_found (no on-chain name resolution)"
expect_code 10 "ref.not_found" "unregistered NFT alias" \
  "$DAXIE" nft show ghosts#1 --network mainnet

# ─────────────────────────────────────────────────────────────────────────────
# 2. nft send requires --to and --nft (usage, before any dial)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- nft send without --to / --nft ⇒ usage"
expect_exit 2 "$DAXIE" nft send --nft punks#1
expect_exit 2 "$DAXIE" nft send --to 0x000000000000000000000000000000000000bEEF

# ═════════════════════════════════════════════════════════════════════════════
# SECTION B — LIVE: deploy ERC-721 + ERC-1155, mint, register, alias, send (anvil)
# ═════════════════════════════════════════════════════════════════════════════
if ! command -v anvil >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  echo "-- anvil/curl not on PATH; skipping live NFT section"
  echo "== M6 demo OK (dry section) =="
  exit 0
fi

echo "-- starting anvil"
ANVIL_PORT=8550
anvil --host 127.0.0.1 --port "$ANVIL_PORT" --chain-id 31337 \
  --mnemonic "test test test test test test test test test test test junk" --silent &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null || true; chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT
ANVIL_URL="http://127.0.0.1:${ANVIL_PORT}"
for _ in $(seq 1 50); do
  if rpc eth_chainId '[]' >/dev/null 2>&1; then break; fi
  sleep 0.2
done

"$DAXIE" network add localanvil --chain-id 31337 --rpc-url "$ANVIL_URL" >/dev/null
"$DAXIE" network use localanvil >/dev/null

# Funded dev account 0 (the deployer + the daxie signer).
KEY_FILE="$WORK/anvilkey"
printf '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n' > "$KEY_FILE"
chmod 0600 "$KEY_FILE"
"$DAXIE" account import funded --key-file "$KEY_FILE" --yes >/dev/null
FUNDED="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

REPO_ROOT="$(dirname "$0")/../.."

# deploy <bytecode-const-file> : deploy the contract from FUNDED, echo its address.
deploy() {
  local bc; bc="$(bytecode_of "$1")"
  [ -n "$bc" ] || fail "could not read the bytecode constant in $1"
  local h; h="$(rpc eth_sendTransaction "[{\"from\":\"$FUNDED\",\"data\":\"$bc\",\"gas\":\"0x2dc6c0\"}]" \
    | sed -n 's/.*"result":"\(0x[0-9a-fA-F]*\)".*/\1/p')"
  [ -n "$h" ] || fail "deploy returned no tx hash"
  sleep 0.3
  rpc eth_getTransactionReceipt "[\"$h\"]" | sed -n 's/.*"contractAddress":"\(0x[0-9a-fA-F]*\)".*/\1/p'
}

# ── deploy the test ERC-721 + ERC-1155 (the same fixtures the integration tests use).
echo "-- deploying a test ERC-721 + ERC-1155 to anvil"
C721="$(deploy "$REPO_ROOT/internal/testchain/erc721bytecode.go")"
[ -n "$C721" ] || fail "ERC-721 deploy receipt has no contractAddress"
C1155="$(deploy "$REPO_ROOT/internal/testchain/erc1155bytecode.go")"
[ -n "$C1155" ] || fail "ERC-1155 deploy receipt has no contractAddress"
echo "   721 at $C721 ; 1155 at $C1155"

# ── mint to the deployer (the fixtures have no constructor mint).
# 721 mint(address,uint256) selector 0x40c10f19 ; token id 42.
rpc eth_sendTransaction "[{\"from\":\"$FUNDED\",\"to\":\"$C721\",\"data\":\"0x40c10f19$(addr_word "$FUNDED")$(word 2a)\"}]" >/dev/null
# 1155 mint(address,uint256,uint256) selector 0x156e29f6 ; id 9 x 100.
rpc eth_sendTransaction "[{\"from\":\"$FUNDED\",\"to\":\"$C1155\",\"data\":\"0x156e29f6$(addr_word "$FUNDED")$(word 9)$(word 64)\"}]" >/dev/null
sleep 0.3

# ─────────────────────────────────────────────────────────────────────────────
# 3. nft add — ERC-165 detection is REAL (721 vs 1155 stored)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- nft add (ERC-165 detection: 721 vs 1155)"
out="$("$DAXIE" nft add "$C721" --name punks --json)"
contains "$out" '"kind": "erc721"' "721 collection not detected as erc721"
out="$("$DAXIE" nft add "$C1155" --name items --json)"
contains "$out" '"kind": "erc1155"' "1155 collection not detected as erc1155"

# A non-NFT (a plain EOA / non-165 address) is rejected (usage.not_nft).
echo "-- nft add of a non-NFT address ⇒ usage.not_nft"
expect_code 2 "usage.not_nft" "non-NFT add rejected" \
  "$DAXIE" nft add 0x000000000000000000000000000000000000dEaD --name nope

# ─────────────────────────────────────────────────────────────────────────────
# 4. nft alias / aliases — name an individual NFT (registry-only)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- nft alias / aliases"
"$DAXIE" nft alias punks#42 my-punk --json >/dev/null
out="$("$DAXIE" nft aliases --json)"
contains "$out" '"alias": "my-punk"' "individual-NFT alias missing from aliases"
contains "$out" '"token_id": "42"' "nft alias token id missing"

# ─────────────────────────────────────────────────────────────────────────────
# 5. nft send (721) — ownerOf changes to the recipient
# ─────────────────────────────────────────────────────────────────────────────
echo "-- nft send (721): ownerOf changes"
RECIP="0x00000000000000000000000000000000000000A1"
"$DAXIE" nft send --from funded --to "$RECIP" --nft punks#42 --wait --yes --json >/dev/null
# Compare case-insensitively: the show owner is EIP-55 mixed-case; the recipient body
# is the 40-hex address. Lowercase both sides and match the address body.
out_lc="$(printf '%s' "$("$DAXIE" nft show punks#42 --json)" | tr 'A-F' 'a-f')"
recip_lc="$(printf '%s' "$RECIP" | tr 'A-F' 'a-f')"
contains "$out_lc" "$recip_lc" "721 ownerOf did not move to the recipient"

# ─────────────────────────────────────────────────────────────────────────────
# 6. nft send (1155, --amount 5) — balanceOf moves the quantity
# ─────────────────────────────────────────────────────────────────────────────
echo "-- nft send (1155 --amount 5): balanceOf moves"
RECIP2="0x00000000000000000000000000000000000000B2"
"$DAXIE" nft send --from funded --to "$RECIP2" --nft items#9 --amount 5 --wait --yes --json >/dev/null
out="$("$DAXIE" nft show items#9 --account "$RECIP2" --json)"
contains "$out" '"balance": "5"' "1155 recipient balance != 5 after send"

# ─────────────────────────────────────────────────────────────────────────────
# 7. nft list — the funded account's named NFTs it still holds
# ─────────────────────────────────────────────────────────────────────────────
echo "-- nft list (registered collections + named NFTs)"
"$DAXIE" nft list --account "$FUNDED" --json >/dev/null

# ─────────────────────────────────────────────────────────────────────────────
# 8. FAIL-CLOSED: an NFT send with limits set + no allowlist ⇒ exit 3 (NFT NOT exempt)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- fail-closed-no-allowlist on an NFT send ⇒ exit 3"
# Mint a fresh 721 token id 7 to send under the policy.
rpc eth_sendTransaction "[{\"from\":\"$FUNDED\",\"to\":\"$C721\",\"data\":\"0x40c10f19$(addr_word "$FUNDED")$(word 7)\"}]" >/dev/null
sleep 0.3
"$DAXIE" policy set --max-tx 1eth --allowlist off --json >/dev/null
expect_code 3 "policy.denied.no_allowlist" "NFT send fail-closed" \
  "$DAXIE" nft send --from funded --to "$RECIP" --nft punks#7 --yes

echo "== M6 demo OK (dry + live anvil) =="
