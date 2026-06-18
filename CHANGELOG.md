# Changelog

All notable changes to Daxie are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Daxie adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The semver-protected public API is: the command tree and flags, JSON output schemas,
documented exit codes, MCP tool names/schemas, the config file schema, `DAXIE_*` env
var names, and on-disk state formats. See [README.md](README.md#versioning).

Pre-1.0 tags (`v0.1.0`..`v0.11.0`) were per-milestone GitHub pre-releases published for
CI continuity; builds were advertised as integrator-pinnable from `v0.4.0` (once the
policy engine existed). The JSON/exit-code contract has been treated as stable since the
first beta — agents could integrate early.

## [Unreleased]

## [1.0.0-rc.1] — 2026-06-17

First release candidate. The CLI surface and the MCP tool surface are **frozen** for
v1.0; the operator promotes `v1.0.0-rc.1` to `v1.0.0` after a soak. This release adds
no wallet behavior over `v0.11.0` — it ships the M0–M11 binary safely and documents it
(milestone M12).

### Added

- **Release pipeline** (goreleaser v2): 6-target reproducible builds
  (darwin/linux/windows × amd64/arm64, `CGO_ENABLED=0`, `-trimpath`, commit-pinned
  timestamps), tar.gz/zip archives, `checksums.txt`.
- **Supply-chain integrity:** cosign **keyless OIDC** signing of `checksums.txt`
  (transitively covering every archive and `install.sh`) via the Rekor transparency
  log; syft SBOMs; SLSA provenance; the identity pinned to this repo's release workflow
  at a `v`-tag ref.
- **Container image** `ghcr.io/daxchain-io/images/daxie`: multi-arch (amd64/arm64),
  distroless/static, non-root (uid 65532), cosign-signed by digest; `:X.Y` and `:latest`
  track the stable channel only.
- **`scripts/install.sh`:** universal POSIX installer published as a release asset —
  `--version`/`--channel`/`--prefix`/`--dry-run`/`--uninstall`/`--help`, SHA256
  verification by default, optional `--verify-signature` (cosign keyless), sudo-less
  `~/.local/bin` fallback, `DAXIE_INSTALL_*` env vars; `--uninstall` removes only the
  binary + marker, never key material or state.
- **Homebrew cask** in `daxchain-io/homebrew-tap` (stable channel only), pinning URL +
  SHA256.
- **Docs:** v1.0 [README](README.md), [install](docs/install.md),
  [quickstart](docs/quickstart.md), [configuration](docs/configuration.md),
  [agents](docs/agents.md), and [security](docs/security.md) guides;
  [deploy manifests](docs/deploy/) (Docker Compose + Kubernetes ConfigMap/Secret/PVC/
  Deployment) consistent with the four state classes.
- **Guarded `release.yml` pipeline:** least-privilege per-job tokens, a human-approval
  `release` environment, SHA-pinned third-party actions, and a `DAXIE_RELEASE_ENABLED`
  guard so the pipeline cannot publish until an operator explicitly arms it.

### Notes

- Windows re-validation: `GOOS=windows GOARCH=amd64`/`arm64` `CGO_ENABLED=0` builds and
  `go vet` pass; Windows ships as release zip; `install.sh` exits 2 on Windows.
- The Helm chart (`charts/daxie`) is deferred to **v1.1** with the HTTP MCP transport;
  v1 ships example deploy manifests only.
- Honest residuals R1 (host-compromise key extraction) and R2 (same-domain counter
  continuity) are acknowledged, not hidden — both are closed by the v2 signer daemon.
  See [docs/security.md](docs/security.md).

## [0.11.0] — 2026-06-17 — M11: MCP server

- `daxie mcp serve` (stdio transport) and `daxie mcp tools [<name>]`.
- **31 MCP tools**, one per operation, with input/output schemas derived from the same
  `domain` structs the CLI binds (CLI/MCP drift impossible; golden-snapshot tested).
- A transport-agnostic server layer with a reserved auth hook (HTTP transport is v1.1).
- The MCP version handshake reports the wallet version.
- The recorded MCP exclusion boundary: no key export, wallet/account create-import,
  policy mutation, registry-add, or path-relocation tools (`policy_show` is exposed
  read-only). The guardrails bind identically below both frontends.

## [0.10.0] — 2026-06-17 — M10: arbitrary contract interaction

- `daxie contract` noun: `add`/`list`/`show`/`remove` (per-network registry of alias +
  address + stored ABI), `call`/`logs`/`encode`/`decode` (read-only/pure, never sign),
  and `contract send` (sign + broadcast any call through the full policy chokepoint).
- `internal/abi` codec with user-string arg coercion (incl. array/tuple literals).
- The **raw-calldata selector classifier**: `contract send` decodes the 4-byte selector
  before signing — recognized spend-equivalents (`approve`/`transfer`/
  `setApprovalForAll`/`permit`) hit the same allowlist + unlimited ceremony as the typed
  paths; unrecognized selectors deny-by-default once policy is active (stage 5b).
- `daxie policy contract allow/remove --selector` (admin-gated opt-in registry).

## [0.9.0] — 2026-06-17 — M9: sign / verify

- `daxie sign message` (EIP-191) and `daxie sign typed` (EIP-712); `daxie verify` (with
  ENS `--address`).
- Permit recognizers (EIP-2612 / DAI / Permit2) classified as spend-equivalents and
  policy-checked like approvals; all other typed data deny-by-default.
- `daxie policy typed allow/remove`.

## [0.8.0] — 2026-06-17 — M8: receive

- `daxie receive`: blocks until an account receives the expected asset and it confirms;
  Transfer-log + ETH block-scan/balance-delta detection; NDJSON stream; `--new` invoice
  address (the one derivation path on the agent surface).

## [0.7.0] — 2026-06-17 — M7: ENS + allowlist pinning

- `daxie ens resolve/reverse`; ENS names accepted wherever destinations/read-only
  addresses are (`balance`, `--to`, `policy allow`, `verify --address`).
- Allowlist **pinning**: an allowlisted ENS/contact stores name + resolved address; a
  later re-point is refused (`pin_drift`) until re-allowed.

## [0.6.0] — 2026-06-17 — M6: NFTs (ERC-721 / ERC-1155)

- `daxie nft add/alias/aliases/list/show/send`; `collection#tokenId` aliasing; ERC-165
  detection; the same wait semantics as `tx send`.

## [0.5.0] — 2026-06-17 — M5: token registry + ERC-20

- `daxie token info/add/rename/list/remove`; alias-only resolution (anti-spoofing) with
  a small bundled set of majors per network.
- `daxie token approve/allowance/revoke`; approvals as spend-equivalents (allowlist +
  unlimited ceremony); `balance --token/--all`, `tx send --token`.

## [0.4.0] — 2026-06-17 — M4: policy engine & guardrails

- `internal/policy` + `internal/policyseal`: rolling-24h window, ETH-denominated limits
  with the fail-closed token rule, gas accrual, and the Ed25519 seal +
  `policy-anchor.json` + nonce watermark.
- The full `daxie policy` surface: `show`/`set`/`allow`/`deny`/`verify`/`check`/
  `counters`/`pin`/`reset --force`/`change-admin-passphrase`. Replaces the M3 always-allow
  stub.

> Builds are advertised as integrator-pinnable from this release onward (the guardrails
> now exist). Earlier tags signed with no policy and are CI-continuity only.

## [0.3.0] — 2026-06-17 — M3: ETH tx pipeline, journal, gas, contacts

- `daxie tx send/status/wait/list`, `tx speedup`/`cancel` (RBF), `daxie gas`,
  `daxie contacts add/list/show/remove`.
- `internal/journal` (crash-safe recovery state machine, nonce management) and the gas
  engine; the policy seam present as an always-allow stub.

## [0.2.0] — 2026-06-16 — M2: networks, RPC, chain client, ETH balance

- `daxie network list/add/use/show/remove`, `daxie rpc add/list/show/use/test/rename/
  remove`, `daxie balance` (ETH; raw address + default account).
- The chain-client interface + impl; `${env:}`/`${file:}` secret references; headers;
  mTLS; per-process `eth_chainId` verification; the anvil test harness.

## [0.1.0] — 2026-06-16 — M1: keystore, wallets, accounts

- `daxie wallet create/import/list/show/rename/export/delete`,
  `daxie account derive/alias/unalias/import/use/list/show/export/delete`,
  `daxie keystore change-passphrase/info`.
- `internal/keys` + the `domain.Signer` seam; BIP-39/32/44; geth v3 scrypt keystore;
  one passphrase per keystore; `meta.json` (aliases, default account); crash-tested
  re-encryption; QR address rendering.

## M0 — scaffold, CI, config & output core (untagged)

- The four state-class paths, the exit-code registry, `internal/fsx`
  (`WriteAtomic`/locks/DACLs), the `arch_test.go` one-core/two-frontends guard,
  `internal/version`, and the `version`/`completion`/`config`/`convert` commands; the
  goreleaser snapshot build and the CI matrix from day one.

[Unreleased]: https://github.com/daxchain-io/daxie/compare/v1.0.0-rc.1...HEAD
[1.0.0-rc.1]: https://github.com/daxchain-io/daxie/compare/v0.11.0...v1.0.0-rc.1
[0.11.0]: https://github.com/daxchain-io/daxie/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/daxchain-io/daxie/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/daxchain-io/daxie/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/daxchain-io/daxie/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/daxchain-io/daxie/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/daxchain-io/daxie/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/daxchain-io/daxie/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/daxchain-io/daxie/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/daxchain-io/daxie/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/daxchain-io/daxie/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/daxchain-io/daxie/releases/tag/v0.1.0
