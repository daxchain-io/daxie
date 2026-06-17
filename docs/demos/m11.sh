#!/usr/bin/env bash
#
# docs/demos/m11.sh — the M11 acceptance demo (design §10.1 gate; v0.11.0).
#
# M11 ships the MCP server — the SECOND thin frontend over the SAME service core. It is
# the executable proof of the one-core/two-frontends architecture and of requirements
# §1a "guardrails apply identically to MCP-initiated signing." The whole demo is the MCP
# SURFACE CONTRACT plus a live stdio round-trip of the cheapest (pure) tool — NO anvil
# (the on-chain guardrail-identity proof lives in the //go:build integration MCP smoke).
#
# The headlines (design §6):
#   - `daxie mcp tools` lists EXACTLY 31 tools, one per operation, with the §6.7 footer
#     ("31 tools (23 read-only, 8 signing). Transport: stdio (v1). …"). The input schemas
#     are INFERRED from the same domain request structs the CLI binds, so CLI/MCP can
#     never drift (a golden test pins them; this demo asserts the surface SHAPE).
#   - The EXCLUSION boundary is REAL: there is NO tool for any policy mutation, key
#     export/import/create, account derive/alias/use, keystore change-passphrase,
#     network/rpc mutation, or any *_add registry mutation. A prompt-injected agent can
#     move funds WITHIN policy and read everything, but cannot change who holds the keys,
#     change what the keys may do, or redefine what an alias means. `policy_show` (read)
#     IS exposed.
#   - `daxie mcp serve --transport http` is REJECTED in v1 (exit 2, a forward-pointing
#     usage error) — stdio is the only accepted value; v1.1 flips http on with a new file,
#     not a refactor (§6.8).
#   - A scripted stdio MCP session (initialize → tools/call convert) round-trips the pure
#     `convert` tool over the REAL server — the §6.3 cheapest live smoke test.
#
# Exit codes asserted (§5.7): 0 OK; 2 USAGE (the rejected http transport).
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m11.sh   (defaults to ./daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"

# ── assertion helpers (mirror m05.sh..m10.sh) ────────────────────────────────
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_exit() {
  local want="$1"; shift
  local got=0
  "$@" >/dev/null 2>&1 || got=$?
  [ "$got" -eq "$want" ] || fail "expected exit $want from '$*', got $got"
}
eq() { [ "$1" = "$2" ] || fail "$3: expected '$2', got '$1'"; }
contains() { case "$1" in *"$2"*) : ;; *) fail "$3: '$1' does not contain '$2'";; esac; }
absent() { case "$1" in *"$2"*) fail "$3: '$2' must be ABSENT but was present";; *) : ;; esac; }

echo "== daxie M11 demo =="

# ── isolated, throwaway state ────────────────────────────────────────────────
WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT
export DAXIE_CONFIG="$WORK/config"
export DAXIE_KEYSTORE="$WORK/keystore"
export DAXIE_STATE_DIR="$WORK/state"
export DAXIE_CACHE_DIR="$WORK/cache"
mkdir -p "$DAXIE_CONFIG"
printf 'schema = 1\n' > "$DAXIE_CONFIG/config.toml"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION A — the `mcp` command exists with the documented surface
# ═════════════════════════════════════════════════════════════════════════════
echo "-- mcp / mcp serve / mcp tools are real commands"
"$DAXIE" mcp --help >/dev/null || fail "mcp command missing"
"$DAXIE" mcp serve --help >/dev/null || fail "mcp serve missing"
"$DAXIE" mcp tools --help >/dev/null || fail "mcp tools missing"

SERVE_HELP="$("$DAXIE" mcp serve --help 2>&1)"
contains "$SERVE_HELP" "--transport" "mcp serve --help lists --transport"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION B — the 31-tool surface + the §6.7 footer (never dials / never unlocks)
# ═════════════════════════════════════════════════════════════════════════════
echo "-- mcp tools prints the human table + footer"
TOOLS_HUMAN="$("$DAXIE" mcp tools)"
contains "$TOOLS_HUMAN" "31 tools" "footer reports 31 tools"
contains "$TOOLS_HUMAN" "stdio" "footer reports the stdio transport"

echo "-- mcp tools --json is the tools/list contract; assert EXACTLY 31 tools"
TOOLS_JSON="$("$DAXIE" mcp tools --json)"
# Count the registered tool names. Prefer jq; fall back to a name-key grep.
if command -v jq >/dev/null 2>&1; then
  COUNT="$(printf '%s' "$TOOLS_JSON" | jq '[.tools[].name] | length')"
else
  COUNT="$(printf '%s' "$TOOLS_JSON" | grep -o '"name"' | wc -l | tr -d ' ')"
fi
eq "$COUNT" "31" "mcp tools --json registers exactly 31 tools"

echo "-- every one of the 31 canonical tool names is present (§6.1 table)"
for t in balance token_list token_info nft_list send tx_status tx_wait tx_list \
         tx_speedup tx_cancel receive token_approve token_revoke token_allowance \
         sign_message sign_typed_data verify wallet_list wallet_show accounts_list \
         account_show gas convert ens_resolve ens_reverse policy_show contract_call \
         contract_logs contract_encode contract_decode contract_send; do
  contains "$TOOLS_JSON" "\"$t\"" "tool $t is registered"
done

echo "-- the EXCLUSION boundary is genuinely absent (the non-regressable security line)"
for forbidden in policy_set policy_allow policy_deny policy_reset \
                 wallet_export account_export wallet_create wallet_import account_import \
                 account_derive account_alias account_use keystore_change_passphrase \
                 network_add network_use rpc_add rpc_test \
                 token_add nft_add contacts_add contract_add contract_remove \
                 wallet_delete account_delete; do
  absent "$TOOLS_JSON" "\"$forbidden\"" "excluded tool $forbidden must not be registered"
done
echo "   (no policy mutation, no key export/import/create, no derive/alias/use, no *_add)"

echo "-- policy_show (read-only) IS exposed; the spend-equivalent guarantees are in the descriptions"
contains "$TOOLS_JSON" '"policy_show"' "policy_show is exposed (read-only)"

echo "-- mcp tools <name> prints ONE tool's inferred schema"
SEND_SCHEMA="$("$DAXIE" mcp tools send)"
contains "$SEND_SCHEMA" "send" "mcp tools send names the tool"
# The send/approve/contract_send descriptions carry the §6.3 guarantees verbatim.
APPROVE_SCHEMA="$("$DAXIE" mcp tools token_approve --json)"
contains "$APPROVE_SCHEMA" "SPEND-EQUIVALENT" "token_approve description carries the spend-equivalent guarantee"
CSEND_SCHEMA="$("$DAXIE" mcp tools contract_send --json)"
contains "$CSEND_SCHEMA" "classified" "contract_send description carries the selector-classifier guarantee"

echo "-- §6.2/§6.3: the confirmation flag is INVISIBLE over MCP; the unlimited ack is a NAMED field"
SEND_JSON="$("$DAXIE" mcp tools send --json)"
# `confirm` is NEVER an agent-facing property on any signing tool (json:"-"; wired
# server-side). The grep is whitespace-insensitive (the --json output is pretty-printed):
# a `"confirm"` PROPERTY KEY would appear as `"confirm":` — assert it is absent.
absent "$SEND_JSON" '"confirm":' "send schema does NOT expose a confirm property (§6.2)"
# `send` requires ONLY `to` (from/amount optional, §6.3). Prefer jq for the exact required
# set; fall back to a normalized (whitespace-stripped) substring match.
if command -v jq >/dev/null 2>&1; then
  SEND_REQ="$(printf '%s' "$SEND_JSON" | jq -c '.inputSchema.required')"
  eq "$SEND_REQ" '["to"]' "send requires only [\"to\"] (§6.3)"
else
  SEND_NOSPACE="$(printf '%s' "$SEND_JSON" | tr -d ' \n\t')"
  contains "$SEND_NOSPACE" '"required":["to"]' "send requires only [\"to\"] (§6.3)"
fi
# The unlimited acknowledgement is the ONE named field acknowledge_unlimited across the
# three signing tools that can grant an unbounded allowance (§6 reconciliation).
contains "$APPROVE_SCHEMA" "acknowledge_unlimited" "token_approve carries the named acknowledge_unlimited ack"
contains "$CSEND_SCHEMA" "acknowledge_unlimited" "contract_send carries the named acknowledge_unlimited ack"
STYPED_SCHEMA="$("$DAXIE" mcp tools sign_typed_data --json)"
contains "$STYPED_SCHEMA" "acknowledge_unlimited" "sign_typed_data carries the named acknowledge_unlimited ack"
# sign/verify use snake_case optional network/rpc (no Go-cased required fields, §6.2).
VERIFY_SCHEMA="$("$DAXIE" mcp tools verify --json)"
absent "$VERIFY_SCHEMA" '"Network":' "verify schema has no Go-cased Network property (snake_case json tags, §6.2)"
absent "$VERIFY_SCHEMA" '"RPC":' "verify schema has no Go-cased RPC property (snake_case json tags, §6.2)"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION C — the §6.8 transport switch: stdio only in v1, http rejected
# ═════════════════════════════════════════════════════════════════════════════
echo "-- mcp serve --transport http is REJECTED in v1 (exit 2, forward-pointing usage error)"
expect_exit 2 "$DAXIE" mcp serve --transport http
echo "-- mcp serve --transport bogus is REJECTED (exit 2)"
expect_exit 2 "$DAXIE" mcp serve --transport bogus

# ═════════════════════════════════════════════════════════════════════════════
# SECTION D — a live stdio MCP round-trip of the pure `convert` tool (§6.3 smoke)
# ═════════════════════════════════════════════════════════════════════════════
# The MCP stdio framing is newline-delimited JSON (NDJSON). Drive a minimal
# initialize → initialized → tools/call(convert) handshake and assert the result
# carries the converted value — the cheapest live proof the OTHER frontend works.
echo "-- stdio MCP round-trip: tools/call convert 1eth->gwei == 1000000000"
REQ="$WORK/mcp.ndjson"
{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"m11-demo","version":"0.0.0"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"convert","arguments":{"amount":"1eth","to":"gwei"}}}'
} > "$REQ"

# Feed the requests on stdin, then hold the pipe open briefly so the server can write
# its responses BEFORE it sees EOF (the SDK's stdio loop shuts down on EOF; a real
# client keeps the pipe open). The trailing sleep is the portable equivalent — no
# dependency on `timeout` (absent on stock macOS). `timeout`, when present (CI/Linux),
# bounds the whole pipe as a belt-and-suspenders hang guard.
OUT="$WORK/mcp.out"
TO=""
command -v timeout >/dev/null 2>&1 && TO="timeout 20"
{ cat "$REQ"; sleep 2; } | $TO "$DAXIE" mcp serve --transport stdio > "$OUT" 2>/dev/null || true

RESP="$(cat "$OUT")"
[ -n "$RESP" ] || fail "stdio MCP session produced no response on stdout"
# The convert result carries 1 ETH in gwei (1e9) — present in either the structured
# content or the text content the SDK packs from the same struct (§6.2).
contains "$RESP" "1000000000" "convert tool over stdio returned 1 ETH = 1000000000 gwei"
# A successful tool call is NOT an error envelope.
absent "$RESP" '"isError":true' "the convert tool call did not error"

echo "== M11 demo OK =="
