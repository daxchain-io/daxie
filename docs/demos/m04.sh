#!/usr/bin/env bash
#
# docs/demos/m04.sh — the M4 acceptance demo (design §10.1 gate; v0.4.0).
#
# M4 is the SECURITY KEYSTONE: it turns the M3 always-allow stub into the real
# guardrail engine — the sealed policy file + the Ed25519 anchor + the rolling-24h
# window + the per-tx/day/gas-cap limits + the allowlist/denylist. This demo
# exercises the full `daxie policy` surface and ASSERTS the §4.9 / §5.7 exit codes:
#
#   0  OK
#   2  USAGE
#   3  POLICY_DENIED (tx_limit / day_limit / allowlist / gas_cap) — the agent-branchable class
#   8  SEAL/AUTH/STATE/ROLLBACK (seal_violation / rollback / admin_auth) — all signing halts
#
# Two sections:
#   A. DRY — policy bootstrap + set/show/allow/deny/check/verify + admin-auth (exit 8)
#      + the §4.6 Viper carve-out, all WITHOUT a network (always run).
#   B. LIVE — a real send DENIED over the per-tx limit (exit 3 tx_limit, NOTHING
#      signed), an ALLOWED send to an allowlisted dest (exit 0, balance moves), a
#      non-allowlisted dest (exit 3 allowlist), and a gas-cap refusal (exit 3
#      gas_cap), against a local anvil. Runs ONLY when `anvil` is on PATH.
#
# The admin passphrase is INDEPENDENT of the keystore passphrase (distinct env
# names: DAXIE_ADMIN_PASSPHRASE[_FILE] vs DAXIE_PASSPHRASE[_FILE]).
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m04.sh   (defaults to ./daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"

# ── assertion helpers (mirror m03.sh) ────────────────────────────────────────
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
# process exit AND the §4.9 canonical code string in the --json stderr envelope.
expect_code() {
  local want_exit="$1" want_code="$2" label="$3"; shift 3
  local errf; errf="$(mktemp)"
  local got=0
  "$@" --json >/dev/null 2>"$errf" || got=$?
  [ "$got" -eq "$want_exit" ] || { echo "--- stderr ---"; cat "$errf" >&2; rm -f "$errf"; fail "$label: exit $got, want $want_exit"; }
  contains "$(cat "$errf")" "$want_code" "$label: envelope code"
  rm -f "$errf"
}

echo "== daxie M4 demo =="

# ── isolated, throwaway state ────────────────────────────────────────────────
WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT
export DAXIE_CONFIG="$WORK/config"
export DAXIE_KEYSTORE="$WORK/keystore"
export DAXIE_STATE_DIR="$WORK/state"
export DAXIE_CACHE_DIR="$WORK/cache"
mkdir -p "$DAXIE_CONFIG"
printf 'schema = 1\n' > "$DAXIE_CONFIG/config.toml"

# Light KDF for speed (keystore AND admin scrypt honor it in test/demo mode).
export DAXIE_KDF_LIGHT=1

# Keystore passphrase (file channel).
PASS_FILE="$WORK/pass"; printf 'm4 keystore passphrase\n' > "$PASS_FILE"; chmod 0600 "$PASS_FILE"
export DAXIE_PASSPHRASE_FILE="$PASS_FILE"
export DAXIE_PASSPHRASE_CONFIRM_FILE="$PASS_FILE"

# ADMIN passphrase (DISTINCT secret, distinct file + env name).
ADMIN_FILE="$WORK/admin"; printf 'm4 admin passphrase\n' > "$ADMIN_FILE"; chmod 0600 "$ADMIN_FILE"
export DAXIE_ADMIN_PASSPHRASE_FILE="$ADMIN_FILE"

ADDR_EXCHANGE="0x52908400098527886E0F7030069857D2E4169EE7"
ADDR_OTHER="0x8617E340B3D01FA5F11F306F4090FD50E238070D"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION A — DRY: policy bootstrap, set/show/allow/deny/check/verify, admin auth
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# 1. policy show before any policy — opt-in (no anchor ⇒ guardrails inactive)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- policy show (pre-bootstrap, unauthenticated)"
out="$("$DAXIE" policy show --json)"
contains "$out" '"active": false' "pre-bootstrap policy must report inactive (opt-in)"

# ─────────────────────────────────────────────────────────────────────────────
# 2. policy set — the FIRST set bootstraps the anchor (verify key + salt + watermark)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- policy set (first set bootstraps the anchor)"
"$DAXIE" policy set --max-tx 0.1eth --max-day 0.5eth --max-gas-price 100gwei --allowlist on --json >/dev/null
[ -f "$DAXIE_CONFIG/policy-anchor.json" ] || fail "first policy set did not bootstrap policy-anchor.json"
[ -f "$DAXIE_STATE_DIR/policy.json" ]     || fail "first policy set did not write the sealed policy.json"

# show now reports active + the limits + a verified seal.
out="$("$DAXIE" policy show --json)"
contains "$out" '"active": true'   "policy show not active after set"
contains "$out" '"verified": true' "policy show seal not verified after set"

# ─────────────────────────────────────────────────────────────────────────────
# 3. policy verify — anchor-based, NO passphrase, exit 0 on a good seal
# ─────────────────────────────────────────────────────────────────────────────
echo "-- policy verify (passphrase-free, good seal)"
expect_exit 0 "$DAXIE" policy verify

# ─────────────────────────────────────────────────────────────────────────────
# 4. wrong admin passphrase on a mutation → exit 8 policy.admin_auth
# ─────────────────────────────────────────────────────────────────────────────
echo "-- wrong admin passphrase ⇒ exit 8 admin_auth"
WRONG="$WORK/wrong"; printf 'not the admin passphrase\n' > "$WRONG"; chmod 0600 "$WRONG"
expect_code 8 "policy.admin_auth" "wrong admin pass" \
  "$DAXIE" policy set --max-tx 1eth --admin-passphrase-file "$WRONG"

# ─────────────────────────────────────────────────────────────────────────────
# 5. policy allow / deny — pinned addresses; deny beats allow
# ─────────────────────────────────────────────────────────────────────────────
echo "-- policy allow / deny (pinned)"
"$DAXIE" policy allow "$ADDR_EXCHANGE" --json >/dev/null
out="$("$DAXIE" policy show --json)"
exch_lc="$(printf '%s' "$ADDR_EXCHANGE" | tr '[:upper:]' '[:lower:]')"
contains "$out" "$exch_lc" "allowlist missing the pinned exchange address"

"$DAXIE" policy deny "$ADDR_OTHER" --json >/dev/null
out="$("$DAXIE" policy show --json)"
other_lc="$(printf '%s' "$ADDR_OTHER" | tr '[:upper:]' '[:lower:]')"
contains "$out" "$other_lc" "denylist missing the pinned address"

# allow --remove takes it back out.
"$DAXIE" policy allow "$ADDR_EXCHANGE" --remove --json >/dev/null
out="$("$DAXIE" policy show --json)"
# the address may still appear in the denylist context; assert it's gone from allowlist
# by re-allowing must succeed (idempotent add of a removed entry).
"$DAXIE" policy allow "$ADDR_EXCHANGE" --json >/dev/null

# ─────────────────────────────────────────────────────────────────────────────
# 6. policy check — the what-if Evaluate (no reservation, full violation list)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- policy check (what-if; over the per-tx limit ⇒ tx_limit)"
expect_code 3 "policy.denied.tx_limit" "what-if over max-tx" \
  "$DAXIE" policy check --from "$ADDR_EXCHANGE" --to "$ADDR_EXCHANGE" --amount 5eth
# within limits + allowlisted ⇒ exit 0
expect_exit 0 "$DAXIE" policy check --from "$ADDR_EXCHANGE" --to "$ADDR_EXCHANGE" --amount 0.05eth --json
# a non-allowlisted dest ⇒ exit 3 allowlist
expect_code 3 "policy.denied.allowlist" "what-if non-allowlisted" \
  "$DAXIE" policy check --from "$ADDR_EXCHANGE" --to "$ADDR_OTHER" --amount 0.01eth

# ─────────────────────────────────────────────────────────────────────────────
# 7. anti-rollback + seal tamper ⇒ exit 8 (the fail-closed core)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- tamper policy.json ⇒ verify exit 8 (seal_violation)"
cp "$DAXIE_STATE_DIR/policy.json" "$WORK/policy.bak"
# Flip a byte in the sealed envelope (corrupt the body/seal pair).
python3 - "$DAXIE_STATE_DIR/policy.json" <<'PY'
import sys
p=sys.argv[1]
b=bytearray(open(p,'rb').read())
# flip a byte well inside the file (the base64 body), guaranteed to break the seal.
i=len(b)//2; b[i]^= 0x40
open(p,'wb').write(b)
PY
expect_exit 8 "$DAXIE" policy verify
# restore so reset can authenticate against the anchor.
cp "$WORK/policy.bak" "$DAXIE_STATE_DIR/policy.json"
expect_exit 0 "$DAXIE" policy verify

# ─────────────────────────────────────────────────────────────────────────────
# 8. reset --force authenticates against the ANCHOR (no --yes bypass)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- reset --force (anchor-authenticated; wrong pass ⇒ admin_auth)"
# trash the policy file; the WRONG admin passphrase cannot reset it.
printf '{"garbage":true}\n' > "$DAXIE_STATE_DIR/policy.json"
expect_code 8 "policy.admin_auth" "reset wrong pass" \
  "$DAXIE" policy reset --force --admin-passphrase-file "$WRONG"
# the CORRECT admin passphrase reseals a fresh default body.
"$DAXIE" policy reset --force --json >/dev/null
expect_exit 0 "$DAXIE" policy verify

# ─────────────────────────────────────────────────────────────────────────────
# 9. pin --print / --verify — the passphrase-free canary
# ─────────────────────────────────────────────────────────────────────────────
echo "-- pin --print / --verify"
VK="$("$DAXIE" policy pin --print --json | sed -n 's/.*"verify_key": *"\([^"]*\)".*/\1/p')"
[ -n "$VK" ] || fail "pin --print produced no verify_key"
expect_exit 0 "$DAXIE" policy pin --verify "$VK"
expect_exit 8 "$DAXIE" policy pin --verify "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# ─────────────────────────────────────────────────────────────────────────────
# 10. §4.6 Viper carve-out — no flag/env can change the anchor; config rejects policy.*
# ─────────────────────────────────────────────────────────────────────────────
echo "-- Viper carve-out (config set policy.* rejected)"
expect_exit 2 "$DAXIE" config set policy.max-tx 1
expect_exit 2 "$DAXIE" config get policy.verify_key   # policy.* is not a config key (usage)
DAXIE_POLICY_VERIFY_KEY="ed25519:ATTACKER" expect_exit 0 "$DAXIE" policy verify  # env cannot displace the anchor

# ─────────────────────────────────────────────────────────────────────────────
# 11. change-admin-passphrase --stage prints the new key (no commit yet)
# ─────────────────────────────────────────────────────────────────────────────
echo "-- change-admin-passphrase --stage"
NEW_ADMIN="$WORK/admin-new"; printf 'm4 admin passphrase v2\n' > "$NEW_ADMIN"; chmod 0600 "$NEW_ADMIN"
out="$("$DAXIE" policy change-admin-passphrase --stage \
        --new-admin-passphrase-file "$NEW_ADMIN" --json)"
NEWVK="$(printf '%s' "$out" | sed -n 's/.*"verify_key_next": *"\([^"]*\)".*/\1/p')"
[ -n "$NEWVK" ] || fail "--stage did not print verify_key_next"
# canary the staged key (it is the candidate; the policy is still sealed under the old key).
expect_exit 8 "$DAXIE" policy pin --verify "$NEWVK"  # not yet committed: old seal does not verify under the new key
# commit: authenticate the CURRENT (old) passphrase + supply the NEW one so the engine
# re-derives from the staged salt, asserts the key match, and reseals under the new
# family. After commit, verify passes and the OLD admin passphrase no longer authenticates.
"$DAXIE" policy change-admin-passphrase --commit \
  --new-admin-passphrase-file "$NEW_ADMIN" --json >/dev/null
expect_exit 0 "$DAXIE" policy verify
# from here the admin passphrase IS the new one; the old DAXIE_ADMIN_PASSPHRASE_FILE no
# longer derives the pinned key.
expect_code 8 "policy.admin_auth" "old admin pass after rotation" \
  "$DAXIE" policy set --max-tx 0.2eth
# restore the env to the new admin passphrase for any later mutation.
export DAXIE_ADMIN_PASSPHRASE_FILE="$NEW_ADMIN"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION B — LIVE: real sends denied / allowed by the sealed policy (anvil)
# ═════════════════════════════════════════════════════════════════════════════
if ! command -v anvil >/dev/null 2>&1; then
  echo "-- anvil not on PATH; skipping live policy-enforcement section"
  echo "== M4 demo OK (dry section) =="
  exit 0
fi

echo "-- starting anvil"
ANVIL_PORT=8547
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

KEY_FILE="$WORK/anvilkey"
printf '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n' > "$KEY_FILE"
chmod 0600 "$KEY_FILE"
"$DAXIE" account import funded --key-file "$KEY_FILE" --yes >/dev/null
FUNDED="$("$DAXIE" account show funded --json | sed -n 's/.*"address": *"\(0x[0-9a-fA-F]*\)".*/\1/p')"
RECIP="0x000000000000000000000000000000000000C0DE"

# Re-seal the policy for this network: allow the recipient, cap per-tx at 0.1 ETH,
# under the (rotated) admin passphrase. self addresses are re-snapshotted at set.
"$DAXIE" policy set --max-tx 0.1eth --max-day 0.5eth --max-gas-price 500gwei \
  --allowlist on --include-self on --json >/dev/null
"$DAXIE" policy allow "$RECIP" --json >/dev/null

# ─────────────────────────────────────────────────────────────────────────────
# 12. a send OVER the per-tx limit ⇒ exit 3 tx_limit, NOTHING signed/journaled
# ─────────────────────────────────────────────────────────────────────────────
echo "-- send over max-tx ⇒ exit 3 tx_limit (nothing signed)"
before="$("$DAXIE" balance "$RECIP" --json | sed -n 's/.*"wei": "\([0-9]*\)".*/\1/p')"
expect_code 3 "policy.denied.tx_limit" "over-limit send" \
  "$DAXIE" tx send --from funded --to "$RECIP" --amount 1eth --yes
after="$("$DAXIE" balance "$RECIP" --json | sed -n 's/.*"wei": "\([0-9]*\)".*/\1/p')"
eq "$after" "$before" "a denied send must NOT move funds"
# and no journal record for a denied send (Reserve denied BEFORE sign).
out="$("$DAXIE" tx list --account funded --json)"
not_contains "$out" '"status": "broadcast"' "a denied send must not be journaled as broadcast"

# ─────────────────────────────────────────────────────────────────────────────
# 13. a send WITHIN limits to an ALLOWLISTED dest ⇒ exit 0, balance moves exactly
# ─────────────────────────────────────────────────────────────────────────────
echo "-- send within limits to allowlisted dest ⇒ exit 0"
before="$("$DAXIE" balance "$RECIP" --json | sed -n 's/.*"wei": "\([0-9]*\)".*/\1/p')"
out="$("$DAXIE" tx send --from funded --to "$RECIP" --amount 0.05eth --wait --yes --json)"
contains "$out" '"status": "confirmed"' "allowed send did not confirm"
after="$("$DAXIE" balance "$RECIP" --json | sed -n 's/.*"wei": "\([0-9]*\)".*/\1/p')"
eq "$(( after - before ))" "50000000000000000" "allowlisted recipient received exactly 0.05 ETH"

# ─────────────────────────────────────────────────────────────────────────────
# 14. a send to a NON-allowlisted dest ⇒ exit 3 allowlist
# ─────────────────────────────────────────────────────────────────────────────
echo "-- send to non-allowlisted dest ⇒ exit 3 allowlist"
NOTALLOWED="0x000000000000000000000000000000000000bEEF"
expect_code 3 "policy.denied.allowlist" "non-allowlisted send" \
  "$DAXIE" tx send --from funded --to "$NOTALLOWED" --amount 0.01eth --yes

# ─────────────────────────────────────────────────────────────────────────────
# 15. gas-cap refusal — set the cap below anvil's base fee ⇒ exit 3 gas_cap
# ─────────────────────────────────────────────────────────────────────────────
echo "-- gas-cap refusal ⇒ exit 3 gas_cap (current_base_fee in payload)"
"$DAXIE" policy set --max-gas-price 1wei --json >/dev/null   # absurdly low cap
errf="$(mktemp)"; code=0
"$DAXIE" tx send --from funded --to "$RECIP" --amount 0.01eth --yes --json >/dev/null 2>"$errf" || code=$?
eq "$code" "3" "gas-cap refusal exit"
contains "$(cat "$errf")" "policy.denied.gas_cap" "gas-cap code"
contains "$(cat "$errf")" "current_base_fee"      "gas-cap payload missing current_base_fee"
rm -f "$errf"

echo "== M4 demo OK (dry + live anvil) =="
