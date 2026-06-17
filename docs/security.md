# Security overview

This is the operator-facing summary of Daxie's threat model. The canonical, exhaustive
version is [design.md §8](design.md); this page condenses it and is deliberately honest
about what v1 does **not** guarantee.

- [The objective](#the-objective)
- [Trust boundaries](#trust-boundaries)
- [The controls](#the-controls)
- [Supply-chain integrity](#supply-chain-integrity)
- [Residual risks (ranked)](#residual-risks-ranked)
- [Out of scope (v1)](#out-of-scope-v1)
- [Operational recommendations](#operational-recommendations)

---

## The objective

> A fully prompt-hijacked agent holding the keystore passphrase must not be able to
> (a) extract key material through Daxie, (b) spend beyond operator-set policy, or
> (c) change that policy — while a thief with the disk but no passphrase gets nothing
> at all.

v1 is honest about its boundary: the agent, the Daxie process, the keystore file, and
the state directory all live in **one OS trust domain** (same uid). v1 delivers
*policy enforcement and tamper resistance within that domain*, not tamper *proofness*
against arbitrary code execution as that uid. The **v2 signer daemon** moves keys,
policy evaluation, and counters behind a real privilege boundary; the residual table
below maps every gap to whether the daemon closes it.

---

## Trust boundaries

```text
   agent trust domain (one uid)                         operator trust domain
   ───────────────────────────                          ─────────────────────
   AI agent / MCP client ─stdio─► daxie mcp serve       admin passphrase
   AI agent / human      ─exec──► daxie <cmd>           policy mutations
   holds: keystore passphrase                           policy-anchor.json (verify key + watermark)
   reads/writes: keystore, state (journal,              key export / backup
   nonces, spend counters), cache                       workstation or one-off K8s Job
        │
        └─► signed raw tx ─► RPC endpoint (ALWAYS UNTRUSTED for what it tells us)
```

Two structural facts make the v1 boundary stronger than a naive read suggests:

1. **The policy trust root (`policy-anchor.json`) is a config-class file outside
   Viper.** On Kubernetes it is a read-only ConfigMap the agent cannot write, and it
   is reachable by no env var or flag — so the trust root is structurally beyond the
   agent's reach, and policy rollback is *prevented* (a nonce watermark), not merely
   detected.
2. **The policy seal is a single detached Ed25519 signature.** The agent holds the
   public verify key (verify on every signing op) but never the signing key
   (operator-only). That verify/forge asymmetry is what makes "detect tampering
   without enabling it" possible.

The RPC endpoint is **always untrusted for the integrity of what it tells us** (it can
lie about balances and confirmations) and trusted only to relay signed transactions.
Everything Daxie signs is integrity-protected locally; everything it reads from RPC is
potentially a lie.

---

## The controls

| Control | What it stops |
|---|---|
| **Two passphrases** (keystore = signing; admin = policy) — independent salts/params | The keystore secret an agent holds buys nothing toward forging policy or raising a limit. |
| **Ed25519-sealed policy + pinned anchor**, fail-closed | Editing/deleting `policy.json` halts all signing (exit 8). Rollback to an older sealed policy is refused by the watermark. |
| **Per-tx + rolling-24h spend limits**, gas included, durable counters | One-shot drains and slow many-tx drains; a reset/corrupt counter fails closed rather than re-widening the window. |
| **Destination allowlist + ENS/contact pinning** | Sends to attacker addresses; a re-pointed allowlisted ENS is refused (`pin_drift`). |
| **Approvals as spend-equivalents** + unlimited ceremony | `approve` the world: spender must pass the allowlist; unbounded approvals need explicit acknowledgment. |
| **Calldata classifier** (`contract send` decodes the selector before signing) | The generic noun bypassing the typed ceremonies: recognized spend-equivalents hit the same gates; unrecognized selectors deny-by-default once policy is active. |
| **Chain-ID from config, verified per process** | A hijacked RPC signing for the wrong chain (exit 12). |
| **Secrets as references; memory hygiene** | Secrets in config plaintext / logs / the journal; best-effort wipe, mlock, `RLIMIT_CORE=0` (Unix). |
| **MCP exclusion boundary** | The agent channel becoming a key-export / policy-mutation / alias-spoofing path (see [agents.md](agents.md)). |

Admin operations (policy mutation, key export) require the admin passphrase through a
TTY/stdin/file channel only — **never** a flag value, and never present in an agent
pod's environment.

---

## Supply-chain integrity

A trojaned wallet binary defeats every other control, so the release pipeline treats
integrity as a feature (full detail in [design.md §9](design.md); install-side
verification in [install.md](install.md)):

- **cosign keyless OIDC** signing — no `COSIGN_PRIVATE_KEY` secret exists to steal.
  The signature binds to *this repo's release workflow at this tag ref* via a
  short-lived Fulcio cert and the **Rekor transparency log**. Identity is pinned to
  the exact workflow file + `v`-tag-ref pattern.
- **What is signed:** `checksums.txt` (transitively covers every archive **and**
  `install.sh`, the one script every `curl|sh` user runs); the OCI image manifests by
  digest; and a separate SLSA provenance predicate over the archive hashes.
- **`install.sh` verifies SHA256 by default**; cosign signature verification is
  opt-in (`--verify-signature`). A `--no-verify` exists but is documented
  not-recommended.
- **The OCI image is distroless/static, non-root (uid 65532)**, no shell, no baked-in
  secrets, multi-arch, cosign-signed by digest.
- **Build hygiene:** `CGO_ENABLED=0` everywhere, a minimal pure-Go dependency tree,
  `go.sum` pinning, `go mod verify` + `govulncheck` in CI, SHA-pinned third-party
  GitHub actions, reproducible builds (`-trimpath`, commit-pinned `mod_timestamp`,
  commit-date ldflag, no wall-clock input).
- **Least-privilege release pipeline:** a read-only default token; `contents`/
  `packages`/`id-token: write` confined to the single gated goreleaser job behind a
  human-approval `release` environment; the tap PAT confined to the cask job; every
  job hard-gated so it cannot fire without an explicit repo variable.

The Homebrew cask pins both URL and SHA256, so a tap compromise is detectable by a
mismatch (residual R9 covers users who skip verification entirely).

---

## Residual risks (ranked)

What v1 does **not** fully solve, and whether the v2 signer daemon (keys + policy +
counters behind a privilege boundary) closes it. Guarantees are scoped honestly — not
hidden.

| Rank | Sev | Residual | v1 state | v2 daemon? |
|---|---|---|---|---|
| **R1** | Critical | Agent-domain code execution reads the keystore file **and** the co-resident passphrase → offline key extraction; all policy moot | Unmitigable in one trust domain (scrypt only buys time if the passphrase weren't co-resident — and it is) | **Closed** — the headline fix: keys live only in the daemon's domain; the agent holds a revocable credential; key export is not an API |
| **R2** | High | Same-domain state tampering: spend counters writable by the agent process; repoint `--state-dir` at a fresh window; on a writable install swap `policy.json` + anchor wholesale | Partial: pre-broadcast accounting, atomicity, fail-closed corruption, `policy verify` cross-audit, the config-class anchor + Viper carve-out (closes every interface-confined variant and, on K8s, the file-swap variant structurally) | **Closed** — counters/policy/anchor live with the daemon |
| **R2a** | High | Cross-account daily-limit overshoot under concurrency (per-account locks can't atomically enforce the across-accounts aggregate) | Single-account sound; multi-account overshoot is `policy verify`-detectable, not prevented | **Closed** — the daemon is the single serialization point |
| **R3** | High | Policy rollback by an arbitrary-file rewrite of both files together | Narrowed to host-compromise only: rollback is *prevented* (watermark) against interface-confined attackers; on K8s the anchor is a read-only ConfigMap | **Closed** |
| **R4** | Medium | Single RPC endpoint as truth oracle: fake balances/confirmations, spoofed `receive`, lying ENS for non-pinned names | Partial: trusted user-supplied endpoints, chain-ID verification, confirmation thresholds, ENS pinning | **Not closed** — the daemon trusts RPC the same way. Path: multi-endpoint quorum / light-client |
| **R5** | Medium | In-policy bleed: a hijacked agent spends *up to* the limits forever; admitted signature classes within limits | Inherent to autonomous custody; limits bound rate; journal gives an audit trail | **Not closed** by the boundary. Path: the fuller policy engine (rate limits, time windows, per-asset rules) |
| **R6** | Medium | Token-value drain through unconfigured tokens (ETH-denominated limits cover native value + gas only) | Partial: fail-closed no-allowlist refusal; documented hardening (one rule per held token + allowlist on) | **Not closed** by the boundary; closed by the future per-asset policy layer — and today by operator configuration |
| **R7** | Medium | Secret remanence in memory/swap; Windows has no core-dump suppression | Best-effort wipe, mlock/VirtualLock, `RLIMIT_CORE=0` (Unix), encrypted-swap guidance | **Narrowed** — only the daemon ever maps keys |
| **R8** | Low | Cross-host nonce collision when single-writer is violated | Documented rule, cheap per-agent accounts, broadcast-time detection + recovery | **Closed** — the daemon is the single signer per account |
| **R9** | Low | Distribution-path compromise for users who skip verification | Checksums + cosign exist; default verifies SHA256; cosign opt-in | **Not closed** (orthogonal). Path: cosign-by-default once keyless verify UX stabilizes |
| **R10** | Medium | Novel-selector blind spot in the calldata classifier (a proxy/diamond dispatch or future fund-moving selector not in the v1 recognizer set) | **Caught, not silently passed:** the unknown-calldata gate is deny-by-default once policy is active — the residual is *capability* (operator must allowlist the contract/triple), not a *bypass* | **Not closed** by the boundary; closed by growing the recognizer set + the fuller policy engine |

**Reading for v1 operators:** R1–R3 — the three worst — are exactly the ones the v2
signer-daemon boundary eliminates, which is why the v1.1 HTTP transport + Helm chart is
sequenced as the first post-v1 milestone. v1's claim is deliberately scoped: an agent
with a general shell is host-compromised by this model's own definition, so the
anchor's tamper-prevention guarantee protects **tool-sandboxed** agents (an executor
that permits only `daxie …` invocations and excludes the config path), not arbitrary
shell-wielding agents. Against agent-host code execution, v1 bounds and detects but
cannot prevent — and says so.

---

## Out of scope (v1)

Root/OS-level compromise of the host (no userspace wallet survives a hostile kernel);
hardware/physical side channels (the hardware-wallet signer backend is a future
layer); malicious *contract logic* the operator chose to call (Daxie is a wallet, not
an auditor — it guarantees you sign what was displayed, within policy); clipboard
snooping (Daxie never touches the clipboard); social engineering of the operator
(procedural — admin ops only on trusted terminals); network privacy/metadata
surveillance by RPC providers (self-hosted endpoints are the answer); DoS against
public RPC defaults; quantum adversaries; cross-chain replay onto chains that ignore
EIP-155.

---

## Operational recommendations

- Use a **≥ 128-bit keystore passphrase** for any agent deployment — it is the only
  wall protecting a stolen keystore offline.
- Keep the **admin passphrase off every machine an agent can reach**; run policy
  mutations from a workstation or a one-off Job.
- Enable **full-disk encryption** (the documented mitigation for journal/contacts
  plaintext privacy, which is out of scope as a Daxie feature).
- **Verify downloads** — SHA256 by default, cosign for production (see
  [install.md](install.md)).
- On Kubernetes, deploy with the four-mount pattern (config read-only, keystore
  read-only Secret, state durable PVC, cache emptyDir), non-root + read-only root
  filesystem; see [deploy/](deploy/) and [deploy/policy-k8s.md](deploy/policy-k8s.md).
- **One writer per account** across hosts; give each agent its own derived account.
- Choose limits and an allowlist that bound the worst case you accept from a fully
  compromised agent — R5 means a hijacked agent spends up to the limits, by design.
