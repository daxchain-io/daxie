#!/usr/bin/env bash
#
# docs/demos/m01.sh — the M1 acceptance demo (design §10.1 gate).
#
# Exercises the M1 keystore/wallet/account surface end to end on the
# NON-INTERACTIVE path (no TTY): wallet create/import/list/show/rename/export/
# delete; account derive/alias/unalias/import/use/list/show (+ --qr)/export/delete;
# keystore change-passphrase/info. Both human and --json modes, and ASSERTS the
# documented exit codes (0 OK, 2 USAGE, 4 AUTH, 10 NOT_FOUND/READONLY — design §5.7).
# Runs unmodified in CI; any failed assertion exits non-zero.
#
# Secrets are supplied the unattended way (§3.6): the keystore passphrase via
# DAXIE_PASSPHRASE_FILE (+ DAXIE_PASSPHRASE_CONFIRM_FILE for first-init double-
# entry), the mnemonic/key via --mnemonic-file/--key-file, and mutating ops via
# --yes. DAXIE_KDF_LIGHT=1 against a light-created keystore keeps scrypt fast.
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m01.sh
#   defaults to ./daxie (build first:  go build -o daxie ./cmd/daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"

# ── assertion helpers (mirrors m00.sh) ───────────────────────────────────────
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

echo "== daxie M1 demo =="

# ── isolated, throwaway state (every class points at temp dirs) ───────────────
WORK="$(mktemp -d)"
trap 'chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"' EXIT

export DAXIE_CONFIG="$WORK/config"
export DAXIE_KEYSTORE="$WORK/keystore"
export DAXIE_STATE_DIR="$WORK/state"
export DAXIE_CACHE_DIR="$WORK/cache"
mkdir -p "$DAXIE_CONFIG"
printf 'schema = 1\n' > "$DAXIE_CONFIG/config.toml"

# Light KDF so the demo is fast; the keystore is CREATED light so this is honored.
export DAXIE_KDF_LIGHT=1

# Non-interactive keystore passphrase + first-init confirmation (must match).
PASS_FILE="$WORK/pass"
printf 'm01 demo passphrase\n' > "$PASS_FILE"
chmod 600 "$PASS_FILE"
export DAXIE_PASSPHRASE_FILE="$PASS_FILE"
export DAXIE_PASSPHRASE_CONFIRM_FILE="$PASS_FILE"

# ─────────────────────────────────────────────────────────────────────────────
# 1. keystore info on a FRESH keystore — uninitialized, exit 0
# ─────────────────────────────────────────────────────────────────────────────
echo "-- keystore info (fresh)"
"$DAXIE" keystore info >/dev/null
"$DAXIE" keystore info --json | grep -q '"initialized": false' \
  || fail "fresh keystore should report initialized=false"

# ─────────────────────────────────────────────────────────────────────────────
# 2. wallet create — mnemonic shown ONCE; first init writes the verifier
# ─────────────────────────────────────────────────────────────────────────────
echo "-- wallet create"
CREATE_JSON="$("$DAXIE" wallet create treasury --json --yes)"
echo "$CREATE_JSON" | grep -q '"sensitive": true' || fail "create --json missing sensitive=true"
echo "$CREATE_JSON" | grep -q '"mnemonic"'         || fail "create --json missing the one-time mnemonic"
echo "$CREATE_JSON" | grep -q '"account0": "treasury/0"' || fail "create did not auto-derive index 0"

# 24-word variant.
"$DAXIE" wallet create cold --words 24 --json --yes | grep -q '"mnemonic"' \
  || fail "24-word create missing mnemonic"

# ─────────────────────────────────────────────────────────────────────────────
# 3. wallet import — a known BIP-39 vector derives the known index-0 address
# ─────────────────────────────────────────────────────────────────────────────
echo "-- wallet import (BIP-44 vector)"
MN_FILE="$WORK/mnemonic"
printf 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n' > "$MN_FILE"
chmod 600 "$MN_FILE"
IMPORT_JSON="$("$DAXIE" wallet import vector --mnemonic-file "$MN_FILE" --json --yes)"
# m/44'/60'/0'/0/0 for the all-"abandon…about" mnemonic (well-known vector).
contains "$IMPORT_JSON" "0x9858EfFD232B4033E47d90003D41EC34EcaEda94" "imported index-0 address"

# ─────────────────────────────────────────────────────────────────────────────
# 4. wallet list / show — counts and derivation path
# ─────────────────────────────────────────────────────────────────────────────
echo "-- wallet list / show"
"$DAXIE" wallet list >/dev/null
"$DAXIE" wallet list --json | grep -q '"name": "treasury"' || fail "list missing treasury"
"$DAXIE" wallet show treasury --json | grep -q "m/44'/60'/0'/0" || fail "show missing path prefix"

# unknown wallet -> exit 10 (NOT_FOUND)
expect_exit 10 "$DAXIE" wallet show no-such-wallet

# ─────────────────────────────────────────────────────────────────────────────
# 5. account derive / alias / unalias
# ─────────────────────────────────────────────────────────────────────────────
echo "-- account derive / alias"
# index 0 is auto-derived on create; next is 1.
D1="$("$DAXIE" account derive treasury --json)"
echo "$D1" | grep -q '"index": 1' || fail "first derive-next should be index 1"
# explicit index + inline alias.
"$DAXIE" account derive treasury --index 3 --name payroll --json | grep -q '"alias": "payroll"' \
  || fail "derive+alias failed"
# show by alias resolves.
"$DAXIE" account show treasury/payroll --json | grep -q '"kind": "hd"' || fail "show by alias failed"
# alias after the fact + unalias.
"$DAXIE" account alias treasury/1 hot >/dev/null
"$DAXIE" account unalias treasury/hot >/dev/null
# index 1 survives the unalias.
"$DAXIE" account show treasury/1 --json | grep -q '"kind": "hd"' || fail "index 1 should survive unalias"

# ─────────────────────────────────────────────────────────────────────────────
# 6. account import (standalone) + export round-trip
# ─────────────────────────────────────────────────────────────────────────────
echo "-- account import / export (standalone)"
KEY_FILE="$WORK/key"
RAW_KEY="4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
printf '%s\n' "$RAW_KEY" > "$KEY_FILE"
chmod 600 "$KEY_FILE"
"$DAXIE" account import ops-key --key-file "$KEY_FILE" --json --yes | grep -q '"name": "ops-key"' \
  || fail "standalone import failed"

# export WITHOUT --yes and no TTY -> confirmation required -> exit 2 (USAGE)
expect_exit 2 "$DAXIE" account export ops-key

# export --yes round-trips the key.
EXP_KEY="$("$DAXIE" account export ops-key --yes --json | sed -n 's/.*"private_key": "\(0x\)\{0,1\}\([0-9a-fA-F]*\)".*/\2/p')"
eq "$EXP_KEY" "$RAW_KEY" "exported standalone key round-trip"

# ─────────────────────────────────────────────────────────────────────────────
# 7. account use / list (default marked) / show --qr
# ─────────────────────────────────────────────────────────────────────────────
echo "-- account use / list / show --qr"
"$DAXIE" account use treasury/0 >/dev/null
"$DAXIE" account list --json | grep -q '"default": "treasury/0"' || fail "default account not set"
# show --qr renders block glyphs; the address line is always present.
QR_OUT="$("$DAXIE" account show treasury/0 --qr)"
contains "$QR_OUT" "0x" "show --qr address line"
case "$QR_OUT" in *"█"*|*"▀"*|*"▄"*) : ;; *) fail "show --qr produced no QR block" ;; esac
# --quiet suppresses the QR but keeps the address (essential output).
QQ="$("$DAXIE" account show treasury/0 --qr --quiet)"
contains "$QQ" "0x" "address under --quiet"
case "$QQ" in *"█"*|*"▀"*|*"▄"*) fail "--quiet must suppress the QR block" ;; *) : ;; esac

# ─────────────────────────────────────────────────────────────────────────────
# 8. wallet export (guarded) + rename + delete
# ─────────────────────────────────────────────────────────────────────────────
echo "-- wallet export / rename / delete"
# export without --yes (no TTY) -> exit 2
expect_exit 2 "$DAXIE" wallet export treasury
# export --yes prints the mnemonic.
"$DAXIE" wallet export treasury --yes | grep -Eq '([a-z]+ ){11}[a-z]+' || fail "wallet export did not print a mnemonic"
# rename then the old name 404s.
"$DAXIE" wallet rename cold cold-storage >/dev/null
expect_exit 10 "$DAXIE" wallet show cold
# delete the renamed wallet.
"$DAXIE" wallet delete cold-storage --yes >/dev/null
expect_exit 10 "$DAXIE" wallet show cold-storage

# account delete: HD forget; index never reused.
"$DAXIE" account delete treasury/1 --yes >/dev/null
NEXT="$("$DAXIE" account derive treasury --json | sed -n 's/.*"index": \([0-9]*\).*/\1/p')"
[ "$NEXT" -ge 4 ] || fail "derive-next reused a forgotten index (got $NEXT, want >= 4)"

# ─────────────────────────────────────────────────────────────────────────────
# 9. wrong passphrase -> exit 4 (AUTH); one-passphrase-per-keystore guard
# ─────────────────────────────────────────────────────────────────────────────
echo "-- wrong passphrase -> exit 4"
WRONG="$WORK/wrong"
printf 'not the passphrase\n' > "$WRONG"
chmod 600 "$WRONG"
expect_exit 4 "$DAXIE" wallet export treasury --passphrase-file "$WRONG" --yes

# ─────────────────────────────────────────────────────────────────────────────
# 10. keystore change-passphrase (atomic) + info after
# ─────────────────────────────────────────────────────────────────────────────
echo "-- keystore change-passphrase"
NEW_PASS="$WORK/newpass"
printf 'rotated m01 passphrase\n' > "$NEW_PASS"
chmod 600 "$NEW_PASS"
"$DAXIE" keystore change-passphrase \
  --new-passphrase-file "$NEW_PASS" --new-passphrase-confirm-file "$NEW_PASS" --yes >/dev/null

# The OLD passphrase (the env DAXIE_PASSPHRASE_FILE) is now rejected -> exit 4.
expect_exit 4 "$DAXIE" wallet export treasury --yes
# The NEW passphrase works.
"$DAXIE" wallet export treasury --passphrase-file "$NEW_PASS" --yes >/dev/null \
  || fail "export under the rotated passphrase failed"

# keystore info reflects the wallets/accounts.
"$DAXIE" keystore info --json | grep -q '"initialized": true' || fail "keystore should be initialized"

# ─────────────────────────────────────────────────────────────────────────────
# 11. exit-code sanity
# ─────────────────────────────────────────────────────────────────────────────
echo "-- exit codes"
expect_exit 2 "$DAXIE" wallet create        # missing name -> usage
expect_exit 0 "$DAXIE" keystore info        # plain read -> ok

echo "m01 OK"
