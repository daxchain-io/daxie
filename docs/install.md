# Installing Daxie

Daxie ships as a single static binary (`CGO_ENABLED=0`, pure Go) for
darwin/linux/windows × amd64/arm64, plus a multi-arch container image. Every
release carries SHA256 checksums and a **cosign keyless** signature (Rekor
transparency log, no long-lived key — see [security.md](security.md) and
[design.md §9.3](design.md)).

This guide covers every install path and, importantly, **how to verify what you
install**. The supply-chain controls only protect you if you use them: residual R9
(in [security.md](security.md)) is exactly "users who skip verification".

- [Homebrew (cask)](#homebrew-cask)
- [curl one-liner](#curl-one-liner)
- [Download-verify-run (recommended for production)](#download-verify-run)
- [Cosign signature verification](#cosign-signature-verification)
- [Container image (GHCR)](#container-image-ghcr)
- [Direct release archive](#direct-release-archive)
- [Windows](#windows)
- [go install](#go-install)
- [`install.sh` flags and env vars](#installsh-flags-and-env-vars)
- [Verifying the install](#verifying-the-install)
- [Uninstalling](#uninstalling)

---

## Homebrew (cask)

```sh
brew install --cask daxchain-io/daxie/daxie
```

The cask lives in the tap `daxchain-io/homebrew-daxie` (directory `Casks/`). It pins
both the download URL **and** its SHA256, so a compromised tap is detectable by a
checksum mismatch at install time. On macOS the cask's post-install hook clears the
`com.apple.quarantine` attribute so the binary runs without a Gatekeeper prompt.

Upgrade / remove:

```sh
brew upgrade --cask daxie
brew uninstall --cask daxie
```

Homebrew tracks the **stable** channel only — prereleases (`-beta.N` / `-rc.N`) are
never published to the tap.

---

## curl one-liner

```sh
curl -fsSL https://github.com/daxchain-io/daxie/releases/latest/download/install.sh | sh
```

`install.sh` **verifies the SHA256 of the downloaded archive against the signed
`checksums.txt` by default.** It resolves the latest *stable* release via the
`/releases/latest` redirect (no GitHub API call, no rate limit), downloads the
archive for your OS/arch, verifies it, and installs the binary atomically. It writes
to `/usr/local/bin` if that is writable, otherwise falls back to `~/.local/bin`
**without sudo** (and prints a PATH hint if needed).

Pin a version or pass options with `sh -s --`:

```sh
curl -fsSL .../install.sh | sh -s -- --version v1.0.0
curl -fsSL .../install.sh | sh -s -- --prefix "$HOME/.local" --verify-signature
```

> Piping a script straight to a shell means trusting the redirect chain. For
> production, prefer [download-verify-run](#download-verify-run) below.

---

## Download-verify-run

The cautious path: fetch `install.sh`, verify its signature, read it, then run it.
`install.sh` is itself an asset covered by the signed `checksums.txt` (it is pulled
into the checksum manifest via goreleaser's `checksum.extra_files`), so the same
cosign signature that protects the binaries protects the installer.

```sh
REL=https://github.com/daxchain-io/daxie/releases/latest/download

# 1. Download the installer, the signed checksum manifest, and its Sigstore bundle.
curl -fsSLO "$REL/install.sh"
curl -fsSLO "$REL/checksums.txt"
curl -fsSLO "$REL/checksums.txt.sigstore.json"

# 2. Verify checksums.txt with cosign keyless (the identity is pinned to THIS repo's
#    release workflow at a tag ref — see "Cosign signature verification" below).
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/daxchain-io/daxie/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  checksums.txt

# 3. Confirm install.sh matches its line in the verified manifest.
grep ' install.sh$' checksums.txt | sha256sum -c -    # macOS: shasum -a 256 -c -

# 4. Read it, then run it.
less install.sh
sh ./install.sh --verify-signature
```

---

## Cosign signature verification

The keyless cosign identity is pinned tighter than a repo prefix — it binds to
*this repo's release workflow file at a `v`-prefixed tag ref*:

```text
--certificate-identity-regexp '^https://github.com/daxchain-io/daxie/\.github/workflows/release\.yml@refs/tags/v'
--certificate-oidc-issuer     'https://token.actions.githubusercontent.com'
```

What is signed:

- **`checksums.txt`** — a blob signature that transitively covers every archive **and
  `install.sh`** (both are entries in the manifest).
- **The OCI image manifests** — signed by digest (`cosign verify` below).
- **SLSA provenance** — a separate signed in-toto predicate over the archive hashes.

`install.sh --verify-signature` runs step 2 above for you (it requires `cosign` on
`PATH`). SHA256 checksum verification is the **default** layer and needs no extra
tooling; cosign is the **opt-in stronger** layer.

---

## Container image (GHCR)

```sh
docker pull ghcr.io/daxchain-io/daxie:1.0.0
docker run --rm ghcr.io/daxchain-io/daxie:1.0.0 version
```

Tags: an immutable `:X.Y.Z` per release; floating `:X.Y` and `:latest` track the
**stable** channel only (a prerelease never moves them). The image is multi-arch
(amd64 + arm64), **distroless/static, runs as non-root uid 65532**, has no shell and
no baked-in secrets, and is cosign-signed by digest:

```sh
cosign verify ghcr.io/daxchain-io/daxie:1.0.0 \
  --certificate-identity-regexp '^https://github.com/daxchain-io/daxie/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

The image sets **no** `DAXIE_*` env defaults — path wiring is the deployment's job.
See [deploy/](deploy/) for the four-mount pattern (config / keystore / state / cache).
Pin a digest (`ghcr.io/daxchain-io/daxie@sha256:...`) in production.

---

## Direct release archive

Every release has per-target archives plus `checksums.txt` on the
[releases page](https://github.com/daxchain-io/daxie/releases):

```text
daxie_1.0.0_linux_amd64.tar.gz      daxie_1.0.0_linux_arm64.tar.gz
daxie_1.0.0_darwin_amd64.tar.gz     daxie_1.0.0_darwin_arm64.tar.gz
daxie_1.0.0_windows_amd64.zip       daxie_1.0.0_windows_arm64.zip
```

```sh
tar -xzf daxie_1.0.0_linux_amd64.tar.gz
sha256sum -c checksums.txt 2>/dev/null | grep daxie_1.0.0_linux_amd64.tar.gz
sudo install -m 0755 daxie /usr/local/bin/daxie
daxie version
```

Each archive bundles `LICENSE` and `README.md`.

---

## Windows

v1 distributes Windows builds as the release **zip** (amd64 and arm64). Extract it
and place `daxie.exe` on your `PATH`.

`install.sh` is a POSIX shell script and **does not install on Windows** — run on a
Windows host (or under a non-WSL Windows shell) it exits with code **2** (unsupported
platform) and prints a pointer to the release zip. scoop/winget manifests are a later
add-on; the zip serves Windows from v1.0.

All Windows file-level mitigations are present (owner-only DACLs on key/secret files,
`LockFileEx`-based locking). Daxie is pure-Go and built `CGO_ENABLED=0` on every
target, so there is no native toolchain dependency.

---

## go install

```sh
go install github.com/daxchain-io/daxie/cmd/daxie@latest
```

Convenient for Go developers; it **does not** perform checksum or signature
verification (Go module integrity via `go.sum` aside), so prefer a verified release
artifact for anything holding funds.

---

## `install.sh` flags and env vars

Every flag has a `DAXIE_INSTALL_*` env equivalent (a deliberate sub-namespace — never
bare `DAXIE_*`, which is reserved for the wallet's own runtime config).

| Flag | Env | Behavior |
|---|---|---|
| `--version <tag>` | `DAXIE_INSTALL_VERSION` | Install a specific tag (`v1.0.0` or `1.0.0`). Default: latest stable. |
| `--channel stable\|beta` | `DAXIE_INSTALL_CHANNEL` | `stable` (default, via the `/releases/latest` redirect); `beta` selects the newest `-beta.N`/`-rc.N`. |
| `--prefix <dir>` | — | Install root; binary goes to `<prefix>/bin`. Default `/usr/local`, else `~/.local`. |
| `--install-dir <dir>` | `DAXIE_INSTALL_DIR` | Set the bin dir directly (overrides `--prefix`). |
| `--use-sudo` | `DAXIE_INSTALL_USE_SUDO=1` | Permit sudo for a non-writable system prefix. Default: skip sudo, fall back to `~/.local/bin`. |
| `--no-verify` | `DAXIE_INSTALL_NO_VERIFY=1` | Skip SHA256 verification. **Not recommended** (defeats supply-chain integrity). |
| `--verify-signature` | `DAXIE_INSTALL_VERIFY_SIGNATURE=1` | Additionally cosign-verify `checksums.txt` (requires `cosign` on PATH). |
| `--dry-run` | `DAXIE_INSTALL_DRY_RUN=1` | Print the actions; change nothing. |
| `--quiet`, `-q` | `DAXIE_INSTALL_QUIET=1` | Suppress progress (errors still go to stderr). |
| `--force` | `DAXIE_INSTALL_FORCE=1` | Reinstall the same version (default: no-op when already current). |
| `--uninstall` | — | Remove **only** the binary + install marker (see below). |
| `--help`, `-h` | — | Print help and exit 0. |

`install.sh` exit codes: `0` success · `1` generic · `2` unsupported platform (incl.
Windows) · `3` download failure · `4` verification failure (checksum or signature) ·
`5` install location not writable and no sudo · `6` no HTTP client (neither curl nor
wget).

---

## Verifying the install

```sh
daxie version            # daxie 1.0.0 (commit <short>, built <commit-date>)
daxie version --json     # {"version":"1.0.0","commit":"<short>","date":"<commit-date>"}
```

The version is stamped at build time via ldflags into `internal/version` and read by
**both** frontends: the `version` command renders it, and `daxie mcp serve` reports it
in the MCP initialize handshake (so an agent can assert the wallet version over MCP
without shelling out).

---

## Uninstalling

`install.sh --uninstall` removes **only** the binary and its install marker
(`.daxie.install-info`). It **never** touches your configuration, keystore, or state:

```sh
curl -fsSL https://github.com/daxchain-io/daxie/releases/latest/download/install.sh \
  | sh -s -- --uninstall
```

> **By design, no Daxie command or installer flag ever deletes key material or spend
> state.** An uninstaller that could erase a keystore would be a defect. Your wallet
> and policy live under the [state-class paths](configuration.md#the-four-state-classes)
> and must be removed manually if you really mean to:
>
> - config: `~/.config/daxie` (Linux/macOS) / `%APPDATA%\daxie` (Windows)
> - keystore: `~/.local/share/daxie/keystore` / `%LOCALAPPDATA%\daxie\keystore`
> - state: `~/.local/state/daxie` / `%LOCALAPPDATA%\daxie\state`
>
> **Back up your mnemonic before deleting anything — it is the only recovery path.**

Homebrew users uninstall with `brew uninstall --cask daxie` (same guarantee: it
removes the binary, not your wallet).
