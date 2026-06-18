# Security Policy

Daxie handles wallet material, transaction signing, RPC traffic, and release
artifacts. Please treat security reports with care and do not publish exploit
details, private keys, seed phrases, RPC credentials, live wallet addresses with
sensitive balances, or reproducible attacks against third-party systems in a
public issue.

## Supported Versions

Security fixes are planned for the current stable `v1.x` release line. Older
pre-release builds and release candidates are not supported unless a maintainer
explicitly asks you to reproduce against them.

## Reporting a Vulnerability

Use GitHub's private vulnerability reporting for this repository from the
repository's Security tab.

If that private reporting path is unavailable, open a minimal public issue
requesting a private security contact path. Do not include exploit details,
secrets, wallet material, or proof-of-concept code in the public issue.

Useful reports include:

- The Daxie version or commit tested.
- The operating system and architecture.
- Whether the issue affects CLI use, MCP server use, release artifacts,
  install scripts, Homebrew packaging, GHCR images, key storage, signing,
  policy enforcement, RPC handling, or transaction broadcast.
- A minimal reproduction using testnets, local Anvil chains, or throwaway
  wallets only.
- The expected impact and any mitigations you have already tested.

## Scope

Security-sensitive areas include:

- Private-key, mnemonic, passphrase, or keystore disclosure.
- Signing or broadcasting a transaction without the expected user or policy
  approval.
- Policy bypasses, spend-limit bypasses, ENS pin drift bypasses, or incorrect
  destination handling.
- Unsafe defaults in RPC, transaction, token, NFT, or receive flows.
- Release integrity problems, including checksum, Sigstore, SLSA provenance,
  Homebrew, install script, or GHCR image issues.
- MCP server behavior that could expose wallet state or trigger unexpected
  signing behavior.

Out of scope:

- Reports requiring compromised local administrator/root access without a
  Daxie-specific privilege boundary.
- Attacks against third-party RPC providers, wallets, chains, package managers,
  or GitHub itself unless Daxie materially worsens the impact.
- Denial-of-service reports that do not affect wallet safety, release integrity,
  or local secret handling.

## Safe Testing

Use local development chains, testnets, throwaway wallets, and small balances.
Daxie signs and broadcasts blockchain transactions; mainnet transactions may be
irreversible and may result in loss of funds.

## Disclosure

Please allow a maintainer reasonable time to investigate and release a fix before
public disclosure. Daxie is maintained as public source for transparency, but
security coordination should still happen privately until users have a safe path
to update.
