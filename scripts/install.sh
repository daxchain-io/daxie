#!/bin/sh
# install.sh — universal installer for the `daxie` CLI (the Ethereum wallet for AI).
#
# Usage:
#
#   curl -fsSL https://github.com/daxchain-io/daxie/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/daxchain-io/daxie/releases/latest/download/install.sh | sh -s -- --version v1.0.0
#   curl -fsSL https://github.com/daxchain-io/daxie/releases/latest/download/install.sh | sh -s -- --prefix "$HOME/.local"
#
# Or — recommended — download + inspect first, then run:
#
#   curl -fsSL -o install.sh https://github.com/daxchain-io/daxie/releases/latest/download/install.sh
#   less install.sh
#   sh install.sh
#
# Flags (all optional, env var equivalents in parens — every env is DAXIE_INSTALL_*):
#
#   --version <tag>     Pin to a specific release tag (e.g. v1.0.0). Accepts the tag
#                       with or without a leading 'v'. Default: latest stable.
#                       (env: DAXIE_INSTALL_VERSION)
#   --channel <c>       'stable' (default) or 'beta'. Beta includes -beta.N / -rc.N tags.
#                       (env: DAXIE_INSTALL_CHANNEL)
#   --prefix <dir>      Install root. Binary lands in <prefix>/bin. Default: /usr/local
#                       or $HOME/.local depending on writability.
#   --install-dir <dir> Set the bin dir directly, overriding --prefix.
#                       (env: DAXIE_INSTALL_DIR)
#   --use-sudo          Allow `sudo` for /usr/local writes. Default: skip sudo silently
#                       and fall back to $HOME/.local/bin.
#                       (env: DAXIE_INSTALL_USE_SUDO=1)
#   --no-verify         Skip SHA256 verification. NOT recommended — leaves the download
#                       unverified. Prefer the default (verify) or --verify-signature.
#                       (env: DAXIE_INSTALL_NO_VERIFY=1)
#   --verify-signature  Additionally verify the cosign keyless signature on checksums.txt
#                       against this repo's release workflow identity. Requires `cosign`
#                       on PATH. (env: DAXIE_INSTALL_VERIFY_SIGNATURE=1)
#   --dry-run           Print what would happen, change nothing.
#                       (env: DAXIE_INSTALL_DRY_RUN=1)
#   --quiet, -q         Suppress progress output (errors still go to stderr).
#                       (env: DAXIE_INSTALL_QUIET=1)
#   --force             Reinstall even when the same version is already present at the
#                       destination. Default: detect an existing same-version install and
#                       exit 0 with a no-op message. Different-version installs always
#                       proceed (no --force needed for upgrades).
#                       (env: DAXIE_INSTALL_FORCE=1)
#   --uninstall         Remove ONLY the installed binary + the .daxie.install-info marker.
#                       NEVER touches ~/.config/daxie, the keystore, or wallet state.
#   --help, -h          Print this help and exit 0.
#
# Advanced (for local snapshot testing — not part of the public install flow):
#
#   DAXIE_INSTALL_BASE_URL=<url>
#                       Override the release-asset base URL. Default:
#                       https://github.com/daxchain-io/daxie/releases/download/<tag>
#                       Setting this lets you point the script at a
#                       `goreleaser release --snapshot --clean` dist/ served over a local
#                       http server (see the ci-install-script.yml snapshot-install job for
#                       the recipe). cosign verification is auto-skipped under this override
#                       since snapshot artifacts are unsigned.
#
# Windows is NOT installable via install.sh (no Linux/Darwin uname match) — it exits 2
# and points you at the release .zip archive. Download daxie_<ver>_windows_<arch>.zip from
# the GitHub release and unzip daxie.exe onto your PATH.
#
# Exit codes:
#
#   0   success
#   1   generic failure
#   2   unsupported platform (OS / arch — incl. Windows)
#   3   download failure
#   4   verification failure (checksum or signature)
#   5   install location not writable and --use-sudo not granted
#   6   no http client (curl or wget) found
#
# Repo: https://github.com/daxchain-io/daxie
# License: Apache-2.0 (see LICENSE in the same release)

set -eu

# ---- constants -------------------------------------------------------------

REPO_OWNER="daxchain-io"
REPO_NAME="daxie"
GITHUB_REPO="${REPO_OWNER}/${REPO_NAME}"
BIN_NAME="daxie"
MARKER_NAME=".${BIN_NAME}.install-info"

# Canonical install URL — baked into the marker file as a record of how this
# binary was installed. Keep in sync with whatever the README documents.
INSTALL_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/install.sh"

# cosign keyless identity (design §9.3). Daxie pins the EXACT workflow file +
# tag-ref pattern (tighter than a repo-prefix match): the signature must come
# from this repo's release.yml running on a vX.Y.Z[-...] tag. The OIDC issuer
# is GitHub Actions' token endpoint.
COSIGN_IDENTITY_REGEXP="^https://github.com/${GITHUB_REPO}/\.github/workflows/release\.yml@refs/tags/v"
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"

# ---- defaults --------------------------------------------------------------

daxie_version="${DAXIE_INSTALL_VERSION:-}"
daxie_channel="${DAXIE_INSTALL_CHANNEL:-stable}"
daxie_prefix=""
daxie_install_dir="${DAXIE_INSTALL_DIR:-}"
daxie_use_sudo="${DAXIE_INSTALL_USE_SUDO:-}"
daxie_no_verify="${DAXIE_INSTALL_NO_VERIFY:-}"
daxie_verify_sig="${DAXIE_INSTALL_VERIFY_SIGNATURE:-}"
daxie_dry_run="${DAXIE_INSTALL_DRY_RUN:-}"
daxie_quiet="${DAXIE_INSTALL_QUIET:-}"
daxie_force="${DAXIE_INSTALL_FORCE:-}"
daxie_uninstall=""

# DAXIE_INSTALL_BASE_URL is the dev-only escape hatch for pointing the script at
# a local goreleaser --snapshot dist/. Strip a trailing slash so the URL concat
# below doesn't double up. Empty = use the canonical release URL.
daxie_base_url="${DAXIE_INSTALL_BASE_URL:-}"
daxie_base_url="${daxie_base_url%/}"

# ---- io helpers ------------------------------------------------------------

log() {
  if [ -z "$daxie_quiet" ]; then
    printf '%s\n' "$*"
  fi
}

warn() {
  printf 'daxie-install: warning: %s\n' "$*" >&2
}

die() {
  code="$1"
  shift
  printf 'daxie-install: error: %s\n' "$*" >&2
  exit "$code"
}

usage() {
  # Print the comment block at the top of this file (everything between the
  # shebang and the first non-comment line). Saves maintaining two copies of
  # the help text.
  sed -n '2,/^[^#]/p' "$0" | sed 's/^# \{0,1\}//'
}

# ---- arg parsing -----------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
  --version)
    [ $# -ge 2 ] || die 1 "--version requires an argument"
    daxie_version="$2"
    shift 2
    ;;
  --version=*)
    daxie_version="${1#*=}"
    shift
    ;;
  --channel)
    [ $# -ge 2 ] || die 1 "--channel requires an argument"
    daxie_channel="$2"
    shift 2
    ;;
  --channel=*)
    daxie_channel="${1#*=}"
    shift
    ;;
  --prefix)
    [ $# -ge 2 ] || die 1 "--prefix requires an argument"
    daxie_prefix="$2"
    shift 2
    ;;
  --prefix=*)
    daxie_prefix="${1#*=}"
    shift
    ;;
  --install-dir)
    [ $# -ge 2 ] || die 1 "--install-dir requires an argument"
    daxie_install_dir="$2"
    shift 2
    ;;
  --install-dir=*)
    daxie_install_dir="${1#*=}"
    shift
    ;;
  --use-sudo)
    daxie_use_sudo=1
    shift
    ;;
  --no-verify)
    daxie_no_verify=1
    shift
    ;;
  --verify-signature)
    daxie_verify_sig=1
    shift
    ;;
  --dry-run)
    daxie_dry_run=1
    shift
    ;;
  --quiet | -q)
    daxie_quiet=1
    shift
    ;;
  --force)
    daxie_force=1
    shift
    ;;
  --uninstall)
    daxie_uninstall=1
    shift
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  --)
    shift
    break
    ;;
  -*) die 1 "unknown flag: $1 (try --help)" ;;
  *) die 1 "unexpected positional arg: $1" ;;
  esac
done

case "$daxie_channel" in
stable | beta) : ;;
*) die 1 "unknown channel '$daxie_channel' (expected 'stable' or 'beta')" ;;
esac

# --no-verify and --verify-signature are mutually exclusive: one says "don't
# check at all", the other says "check harder". Refusing the combination avoids
# a confusing half-verified state.
if [ -n "$daxie_no_verify" ] && [ -n "$daxie_verify_sig" ]; then
  die 1 "--no-verify and --verify-signature are mutually exclusive"
fi

# ---- dependency probe -------------------------------------------------------

# Pick the http client once; fall back order is curl → wget. We never need both.
# tar + uname + sed + grep are assumed (POSIX baseline + busybox).
if command -v curl >/dev/null 2>&1; then
  http_client=curl
elif command -v wget >/dev/null 2>&1; then
  http_client=wget
else
  die 6 "neither curl nor wget found on PATH — install one and retry"
fi

# Pick the SHA256 tool once. GNU coreutils ships sha256sum; macOS / BSD ships
# shasum (with -a 256). busybox provides sha256sum. Only fatal when we actually
# intend to verify (the default); --no-verify users can proceed without one.
sha256_cmd=""
if command -v sha256sum >/dev/null 2>&1; then
  sha256_cmd="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  sha256_cmd="shasum -a 256"
else
  if [ -z "$daxie_no_verify" ]; then
    die 4 "no sha256sum/shasum found and --no-verify not set; cannot verify download"
  fi
fi

# ---- http helpers -----------------------------------------------------------

# fetch <url> <dest>  — downloads, fails non-zero on http error.
fetch() {
  _url="$1"
  _dest="$2"
  case "$http_client" in
  curl) curl -fsSL --retry 3 --retry-delay 2 -o "$_dest" "$_url" ;;
  wget) wget -q --tries=3 --waitretry=2 -O "$_dest" "$_url" ;;
  esac
}

# fetch_url_effective <url>  — follow redirects, print the final URL. Used to
# discover the latest stable release tag without an API call (sidesteps the
# GitHub API rate limit for unauthenticated callers).
fetch_url_effective() {
  _url="$1"
  case "$http_client" in
  curl) curl -fsSLI -o /dev/null -w '%{url_effective}' "$_url" ;;
  wget)
    # wget has no clean equivalent; parse the redirect chain from the -S header
    # dump. Last 'Location:' header wins; echo the input on none.
    _hdrs="$(wget -q -S --max-redirect=20 --method=HEAD -O /dev/null "$_url" 2>&1 || true)"
    _loc="$(printf '%s\n' "$_hdrs" | awk '/^[[:space:]]*Location:/ {print $2}' | tail -1)"
    if [ -n "$_loc" ]; then
      printf '%s' "$_loc"
    else
      printf '%s' "$_url"
    fi
    ;;
  esac
}

# ---- platform detection -----------------------------------------------------

# detect_platform  — sets daxie_os (linux|darwin) and daxie_arch (amd64|arm64)
# from `uname -s` / `uname -m`. Dies with exit 2 on anything else, matching the
# OS/arch matrix the goreleaser config publishes installable archives for.
#
# Windows: the goreleaser matrix builds windows/amd64 + windows/arm64 .zip
# archives, but this POSIX-sh script cannot install them. A user on Git Bash /
# MSYS gets uname=MINGW*; we treat any non-Linux/Darwin OS as "download the zip"
# rather than guessing.
detect_platform() {
  _os="$(uname -s)"
  _arch="$(uname -m)"

  case "$_os" in
  Linux) daxie_os=linux ;;
  Darwin) daxie_os=darwin ;;
  MINGW* | MSYS* | CYGWIN* | Windows*)
    die 2 "Windows is not installable via install.sh — download daxie_<version>_windows_<arch>.zip from https://github.com/${GITHUB_REPO}/releases and unzip daxie.exe onto your PATH"
    ;;
  *) die 2 "unsupported OS: $_os (supported: Linux, Darwin)" ;;
  esac

  case "$_arch" in
  x86_64 | amd64) daxie_arch=amd64 ;;
  aarch64 | arm64) daxie_arch=arm64 ;;
  *) die 2 "unsupported architecture: $_arch (supported: x86_64/amd64, aarch64/arm64)" ;;
  esac
}

# ---- version resolution -----------------------------------------------------

# resolve_version  — sets daxie_version to a concrete vX.Y.Z[-suffix] tag. When
# the caller passed --version explicitly we trust it as-is (normalising the
# leading 'v'). Otherwise we look up the channel's latest tag.
resolve_version() {
  if [ -n "$daxie_version" ]; then
    # Normalise: allow callers to pass either "v1.0.0" or "1.0.0".
    case "$daxie_version" in
    v*) : ;;
    *) daxie_version="v$daxie_version" ;;
    esac
    return
  fi

  if [ "$daxie_channel" = "stable" ]; then
    # /releases/latest never returns prereleases — perfect for stable. Resolve
    # via the redirect target (no API rate limit, no auth).
    _final="$(fetch_url_effective "https://github.com/${GITHUB_REPO}/releases/latest")"
    # Final URL shape: https://github.com/<owner>/<repo>/releases/tag/vX.Y.Z
    daxie_version="${_final##*/}"
    case "$daxie_version" in
    v*) : ;;
    *) die 3 "could not resolve latest stable tag (got '$daxie_version' from $_final)" ;;
    esac
    return
  fi

  # Beta channel: hit the API and pick the first tag (the API returns releases
  # sorted newest-first by created_at).
  _api="https://api.github.com/repos/${GITHUB_REPO}/releases?per_page=20"
  _tmp="$(mktemp)"
  if ! fetch "$_api" "$_tmp"; then
    rm -f "$_tmp"
    die 3 "failed to query $_api (rate limited? set DAXIE_INSTALL_VERSION=vX.Y.Z to skip the lookup)"
  fi
  # Pluck "tag_name": "vX.Y.Z..." with grep+sed; avoids a jq dependency.
  daxie_version="$(grep -E '"tag_name"' "$_tmp" | head -n 1 | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')"
  rm -f "$_tmp"
  case "$daxie_version" in
  v*) : ;;
  *) die 3 "could not parse latest beta tag from $_api" ;;
  esac
}

# ---- install path resolution ------------------------------------------------

# resolve_install_dir  — sets daxie_bindir to the directory we'll mv the binary
# into. Honors --install-dir > --prefix > /usr/local fallback > ~/.local
# fallback. Sets daxie_use_sudo_cmd to "" or "sudo" depending on whether we'll
# need elevation.
resolve_install_dir() {
  daxie_use_sudo_cmd=""

  if [ -n "$daxie_install_dir" ]; then
    daxie_bindir="$daxie_install_dir"
  elif [ -n "$daxie_prefix" ]; then
    daxie_bindir="${daxie_prefix}/bin"
  else
    # Default policy: prefer /usr/local/bin if writable as the current user. If
    # not, use sudo when explicitly granted; otherwise fall back to ~/.local/bin
    # (no-sudo, always works for the current user).
    if [ -w /usr/local/bin ] || { [ ! -e /usr/local/bin ] && [ -w /usr/local ]; }; then
      daxie_bindir="/usr/local/bin"
    elif [ -n "$daxie_use_sudo" ] && command -v sudo >/dev/null 2>&1; then
      daxie_bindir="/usr/local/bin"
      daxie_use_sudo_cmd="sudo"
    else
      daxie_bindir="${HOME}/.local/bin"
      # No need to mark "didn't exist" — the PATH check at the end of do_install
      # fires whenever daxie_bindir isn't on PATH regardless.
    fi
  fi

  # If the caller pointed us somewhere we can't write, surface that before we
  # download anything.
  if [ -e "$daxie_bindir" ] && [ ! -w "$daxie_bindir" ] && [ -z "$daxie_use_sudo_cmd" ]; then
    die 5 "$daxie_bindir is not writable (re-run with --use-sudo, or pass --prefix=\$HOME/.local)"
  fi
}

# ---- download + verify ------------------------------------------------------

# download_and_verify  — fetches the release archive matching daxie_os /
# daxie_arch / daxie_version into daxie_workdir and (unless --no-verify) checks
# the sha256 entry from the release's checksums.txt. With --verify-signature,
# additionally cosign-verifies the checksums file against this repo's exact
# release-workflow OIDC identity; skipped silently when DAXIE_INSTALL_BASE_URL
# points at an unsigned local snapshot. Falls through to a tar -xzf and asserts
# the BIN_NAME file landed in daxie_workdir.
download_and_verify() {
  # goreleaser archive name template:
  #   daxie_<version_no_v>_<os>_<arch>.tar.gz
  _ver_noprefix="${daxie_version#v}"
  _archive="${BIN_NAME}_${_ver_noprefix}_${daxie_os}_${daxie_arch}.tar.gz"
  _checksums="checksums.txt"

  if [ -n "$daxie_base_url" ]; then
    # Local snapshot mode: caller pointed us at their own URL prefix (e.g. a
    # `python3 -m http.server` over goreleaser's dist/). Skip the canonical
    # /releases/download/<tag>/ path; snapshots don't have one.
    _base="$daxie_base_url"
  else
    _base="https://github.com/${GITHUB_REPO}/releases/download/${daxie_version}"
  fi
  _archive_url="${_base}/${_archive}"
  _checksums_url="${_base}/${_checksums}"

  log "Downloading ${_archive_url}"
  if ! fetch "$_archive_url" "${daxie_workdir}/${_archive}"; then
    die 3 "failed to download ${_archive_url} (does the tag '${daxie_version}' have a ${daxie_os}/${daxie_arch} build?)"
  fi

  if [ -z "$daxie_no_verify" ]; then
    log "Verifying SHA256"
    if ! fetch "$_checksums_url" "${daxie_workdir}/${_checksums}"; then
      die 4 "failed to download checksums.txt from $_checksums_url"
    fi
    # Find the line matching our archive and verify just that one. POSIX grep +
    # filter to keep busybox happy.
    _line="$(grep " ${_archive}\$" "${daxie_workdir}/${_checksums}" || true)"
    if [ -z "$_line" ]; then
      die 4 "checksums.txt has no entry for ${_archive}"
    fi
    printf '%s\n' "$_line" >"${daxie_workdir}/${_archive}.sha256"
    (cd "$daxie_workdir" && $sha256_cmd -c "${_archive}.sha256") >/dev/null 2>&1 ||
      die 4 "SHA256 verification failed for ${_archive}"
  else
    warn "skipping SHA256 verification (--no-verify) — the download is unverified and NOT recommended"
  fi

  if [ -n "$daxie_verify_sig" ] && [ -n "$daxie_base_url" ]; then
    warn "skipping cosign verification: DAXIE_INSTALL_BASE_URL is set (snapshot artifacts are unsigned)"
    daxie_verify_sig=""
  fi

  if [ -n "$daxie_verify_sig" ]; then
    if ! command -v cosign >/dev/null 2>&1; then
      die 4 "--verify-signature requested but 'cosign' is not on PATH"
    fi
    log "Verifying cosign keyless signature on checksums.txt"
    # If checksums.txt wasn't downloaded above for any reason, fetch it now so
    # cosign has the blob to verify.
    if [ ! -f "${daxie_workdir}/${_checksums}" ]; then
      fetch "$_checksums_url" "${daxie_workdir}/${_checksums}" ||
        die 4 "failed to download checksums.txt from $_checksums_url"
    fi
    _sig_url="${_base}/${_checksums}.sig"
    _cert_url="${_base}/${_checksums}.pem"
    fetch "$_sig_url" "${daxie_workdir}/${_checksums}.sig" || die 4 "failed to download ${_sig_url}"
    fetch "$_cert_url" "${daxie_workdir}/${_checksums}.pem" || die 4 "failed to download ${_cert_url}"
    cosign verify-blob \
      --certificate "${daxie_workdir}/${_checksums}.pem" \
      --signature "${daxie_workdir}/${_checksums}.sig" \
      --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
      --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
      "${daxie_workdir}/${_checksums}" >/dev/null 2>&1 ||
      die 4 "cosign signature verification failed (identity must match this repo's release workflow)"
  fi

  log "Extracting ${_archive}"
  (cd "$daxie_workdir" && tar -xzf "$_archive")
  if [ ! -f "${daxie_workdir}/${BIN_NAME}" ]; then
    die 1 "extracted archive does not contain '${BIN_NAME}' binary"
  fi
}

# ---- existing-install detection --------------------------------------------

# read_marker_version <bindir>  — prints the `version=` line value from the
# marker file in <bindir>, or empty if no marker / no version line. Pure POSIX.
read_marker_version() {
  _marker="$1/${MARKER_NAME}"
  [ -f "$_marker" ] || {
    printf ''
    return
  }
  # Strip 'version=' prefix from the matching line. Whitespace around the value
  # is tolerated.
  grep -E '^[[:space:]]*version[[:space:]]*=' "$_marker" 2>/dev/null |
    head -n 1 |
    sed -E 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*//' |
    sed -E 's/[[:space:]]*$//'
}

# check_existing_install  — if <daxie_bindir>/<BIN_NAME> exists AND its marker
# reports the same version we're about to install AND --force wasn't passed,
# print a "no-op" message and exit 0. Different-version installs print an
# "upgrading from X to Y" line and proceed (no --force needed for upgrades).
check_existing_install() {
  [ -n "$daxie_force" ] && return 0
  [ -e "${daxie_bindir}/${BIN_NAME}" ] || return 0

  _existing="$(read_marker_version "$daxie_bindir")"
  if [ -z "$_existing" ]; then
    # Binary present but no marker — could be a hand-installed tarball or a
    # pre-marker install. Don't surprise the user by silently overwriting; warn
    # and proceed (they got what they asked for either way).
    warn "${daxie_bindir}/${BIN_NAME} exists but has no install marker — replacing it."
    return 0
  fi

  if [ "$_existing" = "$daxie_version" ]; then
    log "${BIN_NAME} ${daxie_version} is already installed at ${daxie_bindir}/${BIN_NAME}."
    log "Pass --force (or set DAXIE_INSTALL_FORCE=1) to reinstall."
    # Exit cleanly so curl|sh callers don't see a non-zero status. The trap
    # cleans up the workdir on the way out.
    exit 0
  fi

  log "Upgrading ${BIN_NAME}: ${_existing} → ${daxie_version}"
}

# ---- install ----------------------------------------------------------------

# do_install  — moves the verified binary from daxie_workdir to
# ${daxie_bindir}/${BIN_NAME} atomically (cp + chmod 0755 + mv onto a sibling
# tmp path), then writes a sibling install marker recording
# installer/version/channel/install_url/installed_at. Honours --dry-run,
# --use-sudo, and emits a shell-aware PATH advisory if daxie_bindir isn't on
# PATH.
do_install() {
  _dest="${daxie_bindir}/${BIN_NAME}"
  _tmp_dest="${daxie_bindir}/.${BIN_NAME}.new.$$"

  if [ -n "$daxie_dry_run" ]; then
    log "[dry-run] would install ${daxie_workdir}/${BIN_NAME} → ${_dest}"
    log "[dry-run] would write ${daxie_bindir}/${MARKER_NAME}"
    return
  fi

  # Make sure the bin dir exists. mkdir -p; if that needs sudo the caller
  # already opted in via --use-sudo (daxie_use_sudo_cmd is set). Otherwise bail
  # with a clear message.
  if [ ! -d "$daxie_bindir" ]; then
    if ! ${daxie_use_sudo_cmd} mkdir -p "$daxie_bindir" 2>/dev/null; then
      die 5 "cannot create $daxie_bindir — re-run with --use-sudo or --prefix=\$HOME/.local"
    fi
  fi

  # Atomic install: copy to a sibling tmp path, chmod, then mv. The mv within
  # the same filesystem is atomic on POSIX; either the old or the new binary is
  # at $_dest at all times — no half-written state.
  ${daxie_use_sudo_cmd} cp "${daxie_workdir}/${BIN_NAME}" "$_tmp_dest"
  ${daxie_use_sudo_cmd} chmod 0755 "$_tmp_dest"
  ${daxie_use_sudo_cmd} mv "$_tmp_dest" "$_dest"

  # Drop a sibling marker recording how this binary was installed. Keep the
  # schema forward-compatible: simple key=value lines.
  _marker="${daxie_bindir}/${MARKER_NAME}"
  _marker_tmp="${daxie_workdir}/marker.$$"
  {
    printf 'installer=curl\n'
    printf 'version=%s\n' "$daxie_version"
    printf 'channel=%s\n' "$daxie_channel"
    printf 'install_url=%s\n' "$INSTALL_URL"
    printf 'installed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$_marker_tmp"
  ${daxie_use_sudo_cmd} mv "$_marker_tmp" "$_marker"

  log "Installed ${BIN_NAME} ${daxie_version} → ${_dest}"

  # Run the binary so the user gets the same `daxie version` line they'd see
  # otherwise — confirms the install works (right arch, not corrupted) and shows
  # the commit + build date inline. Don't fail the overall install on a `daxie
  # version` non-zero exit (defensive — shouldn't happen for a release binary).
  if [ -x "$_dest" ]; then
    log ""
    "$_dest" version 2>&1 || true
  fi

  # PATH advisory when the install dir isn't on PATH. Shell-aware: show the line
  # matching the user's current shell, plus an unconditional "add for the
  # current process" hint. Falls through to listing all options when SHELL is
  # unset/unknown (cron, CI runner, etc.).
  case ":$PATH:" in
  *":${daxie_bindir}:"*) : ;;
  *)
    log ""
    warn "${daxie_bindir} is not on your PATH."
    warn "Add it for the current shell:"
    warn "  export PATH=\"${daxie_bindir}:\$PATH\""
    _shell_name=""
    [ -n "${SHELL:-}" ] && _shell_name="$(basename "$SHELL")"
    case "$_shell_name" in
    bash)
      warn "Persist it (bash):"
      warn "  echo 'export PATH=\"${daxie_bindir}:\$PATH\"' >> ~/.bashrc"
      ;;
    zsh)
      warn "Persist it (zsh):"
      warn "  echo 'export PATH=\"${daxie_bindir}:\$PATH\"' >> ~/.zshrc"
      ;;
    fish)
      warn "Persist it (fish):"
      warn "  fish_add_path ${daxie_bindir}"
      ;;
    *)
      warn "Persist it (pick the file matching your shell):"
      warn "  echo 'export PATH=\"${daxie_bindir}:\$PATH\"' >> ~/.bashrc"
      warn "  echo 'export PATH=\"${daxie_bindir}:\$PATH\"' >> ~/.zshrc"
      warn "  fish_add_path ${daxie_bindir}    # fish"
      ;;
    esac
    ;;
  esac
}

# ---- uninstall path ---------------------------------------------------------

do_uninstall() {
  # Locate a previously-installed daxie. Prefer the marker file; otherwise fall
  # back to `command -v daxie`.
  _candidates="/usr/local/bin ${HOME}/.local/bin"
  _found=""
  for _d in $_candidates; do
    if [ -f "${_d}/${MARKER_NAME}" ] && [ -f "${_d}/${BIN_NAME}" ]; then
      _found="$_d"
      break
    fi
  done
  if [ -z "$_found" ]; then
    _bin="$(command -v ${BIN_NAME} 2>/dev/null || true)"
    if [ -n "$_bin" ]; then
      _found="$(dirname "$_bin")"
    fi
  fi
  if [ -z "$_found" ]; then
    die 1 "could not find an installed ${BIN_NAME} to uninstall"
  fi

  _sudo=""
  if [ ! -w "$_found" ] && [ -n "$daxie_use_sudo" ] && command -v sudo >/dev/null 2>&1; then
    _sudo="sudo"
  fi

  if [ -n "$daxie_dry_run" ]; then
    log "[dry-run] would remove ${_found}/${BIN_NAME} and ${_found}/${MARKER_NAME}"
    log "[dry-run] would NOT touch ~/.config/daxie (keystore, policy, state)"
    return
  fi

  # Remove ONLY the binary + marker. NEVER the keystore, policy, counters, or
  # any other state — an uninstaller that could delete key material is a design
  # defect (design §9.5). No flag of this script ever deletes key material.
  ${_sudo} rm -f "${_found}/${BIN_NAME}" "${_found}/${MARKER_NAME}"
  log "Uninstalled ${BIN_NAME} from ${_found}"
  log "Note: config, keystore, and state under ~/.config/daxie are NOT removed."
  log "      (To wipe them yourself — IRREVERSIBLE, includes key material: rm -rf ~/.config/daxie)"
}

# ---- main -------------------------------------------------------------------

main() {
  if [ -n "$daxie_uninstall" ]; then
    do_uninstall
    return
  fi

  detect_platform
  resolve_version
  resolve_install_dir
  # Existing-install short-circuit: only after we know what version the user is
  # asking for AND where it would land. May exit 0 without doing anything if the
  # same version is already there.
  check_existing_install

  log "Installing ${BIN_NAME} ${daxie_version} (${daxie_os}/${daxie_arch}) → ${daxie_bindir}"
  if [ -n "$daxie_use_sudo_cmd" ]; then
    log "Using sudo for writes to ${daxie_bindir}"
  fi

  # Workdir: per-run temp dir cleaned up on exit (success or failure).
  daxie_workdir="$(mktemp -d 2>/dev/null || mktemp -d -t "${BIN_NAME}-install")"
  # shellcheck disable=SC2064  # intentional early-binding of $daxie_workdir
  trap "rm -rf '$daxie_workdir'" EXIT INT HUP TERM

  if [ -n "$daxie_dry_run" ]; then
    log "[dry-run] would download ${BIN_NAME} ${daxie_version} for ${daxie_os}/${daxie_arch}"
    do_install
    return
  fi

  download_and_verify
  do_install
  # do_install execs the binary itself, so no separate "Run 'daxie version' to
  # confirm" tail is needed here.
}

main
