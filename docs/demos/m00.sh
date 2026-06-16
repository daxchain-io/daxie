#!/usr/bin/env bash
#
# docs/demos/m00.sh — the M0 acceptance demo (design §10.1 gate).
#
# Exercises every M0 surface (version, convert, config get/set/list, completion) in
# both human and --json modes, on the non-interactive path, and ASSERTS the documented
# exit codes (0 OK, 2 USAGE, 10 NOT_FOUND/READONLY — design §5.7). Runs unmodified in
# CI; any failed assertion exits non-zero.
#
# Usage:  DAXIE=/path/to/daxie docs/demos/m00.sh
#   defaults to ./daxie (build first:  go build -o daxie ./cmd/daxie)
set -euo pipefail

DAXIE="${DAXIE:-./daxie}"

# ── tiny assertion helpers (note: under `set -e`, a failing command in an `if`
#    condition or with `|| ...` does NOT abort, so exit-code checks are explicit) ──

fail() { echo "FAIL: $*" >&2; exit 1; }

# expect_exit <wanted> <cmd...> : run cmd, assert its exit status equals <wanted>.
expect_exit() {
  local want="$1"; shift
  local got=0
  "$@" >/dev/null 2>&1 || got=$?
  [ "$got" -eq "$want" ] || fail "expected exit $want from '$*', got $got"
}

# eq <actual> <expected> <label>
eq() {
  [ "$1" = "$2" ] || fail "$3: expected '$2', got '$1'"
}

echo "== daxie M0 demo =="
"$DAXIE" --version >/dev/null 2>&1 || true   # tolerate either --version or version

# ─────────────────────────────────────────────────────────────────────────────
# 1. version — human + --json
# ─────────────────────────────────────────────────────────────────────────────
echo "-- version"
"$DAXIE" version
"$DAXIE" version --json | grep -q '"version"' || fail "version --json missing version key"
"$DAXIE" version --json | grep -q '"commit"'  || fail "version --json missing commit key"
"$DAXIE" version --json | grep -q '"date"'    || fail "version --json missing date key"
# --quiet must NOT suppress the version string — it IS the essential output (§5.7).
vq="$("$DAXIE" version --quiet)"
[ -n "$vq" ] || fail "version --quiet produced no output (essential output must never be suppressed)"

# ─────────────────────────────────────────────────────────────────────────────
# 2. convert — exact integer round-trips, no float drift (design utility, §convert)
#    Documented output is the bare canonical value (so agents can use it directly).
# ─────────────────────────────────────────────────────────────────────────────
echo "-- convert"
eq "$("$DAXIE" convert 1.5eth wei)"        "1500000000000000000" "1.5eth -> wei"
eq "$("$DAXIE" convert 1eth gwei)"         "1000000000"          "1eth -> gwei"
eq "$("$DAXIE" convert 30000000000wei gwei)" "30"                "30 gwei in wei -> gwei"
eq "$("$DAXIE" convert 1000000000gwei eth)"  "1"                 "1e9 gwei -> eth"
# round-trip: eth -> wei -> eth is lossless
wei="$("$DAXIE" convert 0.123456789eth wei)"
eq "$("$DAXIE" convert "${wei}wei" eth)"   "0.123456789"         "eth->wei->eth round-trip"
# --json carries a value field
"$DAXIE" convert 1eth gwei --json | grep -q '"value"' || fail "convert --json missing value key"
# bad unit -> exit 2 (USAGE)
expect_exit 2 "$DAXIE" convert 1eth foo

# ─────────────────────────────────────────────────────────────────────────────
# 3. config — list / set / get round-trip in a throwaway config dir
# ─────────────────────────────────────────────────────────────────────────────
echo "-- config"
CFGDIR="$(mktemp -d)"
trap 'chmod -R u+w "$CFGDIR" 2>/dev/null || true; rm -rf "$CFGDIR"' EXIT
export DAXIE_CONFIG="$CFGDIR"

"$DAXIE" config list >/dev/null
"$DAXIE" config set defaults.network sepolia
eq "$("$DAXIE" config get defaults.network)" "sepolia" "config get after set"
"$DAXIE" config list --json | grep -q 'defaults.network' || fail "config list --json missing key"

# policy.* is OUT OF SCOPE for `config set` -> exit 2 (USAGE)
expect_exit 2 "$DAXIE" config set policy.max-tx 1

# unknown key on get -> exit 10 (NOT_FOUND)
expect_exit 10 "$DAXIE" config get no.such.key

# read-only config dir -> config.read_only -> exit 10 (READONLY)
# (skipped when running as root, where chmod a-w does not prevent writes)
if [ "$(id -u)" -ne 0 ]; then
  chmod -R a-w "$CFGDIR"
  expect_exit 10 "$DAXIE" config set defaults.network mainnet
  chmod -R u+w "$CFGDIR"
else
  echo "   (running as root; skipping read-only assertion)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. completion — each shell emits a script
# ─────────────────────────────────────────────────────────────────────────────
echo "-- completion"
for sh in bash zsh fish; do
  "$DAXIE" completion "$sh" | head -1 >/dev/null || fail "completion $sh produced no output"
done

# ─────────────────────────────────────────────────────────────────────────────
# 5. exit-code sanity
# ─────────────────────────────────────────────────────────────────────────────
echo "-- exit codes"
# unknown command -> exit 2 (USAGE)
expect_exit 2 "$DAXIE" no-such-command
# a plain successful command -> exit 0
expect_exit 0 "$DAXIE" version

echo "m00 OK"
