# Docker / Compose deployment

This pattern runs Daxie's MCP server in (or alongside) the agent container with the
four state classes mounted correctly and a hardened runtime. The companion
[`compose.yaml`](compose.yaml) is a runnable starting point.

The image (`ghcr.io/daxchain-io/images/daxie`) is distroless/static, non-root (uid 65532),
has no shell, and bakes in **no** `DAXIE_*` defaults — path wiring is the deployment's
job, kept here in one place.

> **Stdio transport (v1).** The MCP server speaks **stdio**, so the agent process is
> the MCP *client* and typically launches `daxie mcp serve` as a subprocess. The
> standalone-service pattern (a long-lived Daxie container an agent connects to over
> the network) arrives with the **v1.1 HTTP transport**. The
> Compose example below shows the wallet container holding state durably and an agent
> container that mounts the binary / shares the keystore; adapt to your harness.

---

## The four mounts

| Class | Host source | Container path (`DAXIE_*`) | Mode |
|---|---|---|---|
| config | `./config` (config.toml + policy-anchor.json) | `/etc/daxie` (`DAXIE_CONFIG`) | **read-only** |
| keystore | `daxie-keystore` volume / full-directory secret sync | `/var/lib/daxie/keystore` (`DAXIE_KEYSTORE`) | read-only |
| state | `daxie-state` named volume (**durable**) | `/var/lib/daxie/state` (`DAXIE_STATE_DIR`) | read-write |
| cache | tmpfs | `/var/cache/daxie` (`DAXIE_CACHE_DIR`) | read-write (disposable) |
| passphrase | Docker secret | `/run/secrets/daxie-pass` (`DAXIE_PASSPHRASE_FILE`) | read-only |

The **state volume must be durable** — it holds the tx journal, nonces, and the
rolling-24h spend counters. A wiped state volume re-opens the daily window (Daxie logs
a prominent startup warning when state is empty but the keystore has prior accounts).

---

## Hardened runtime flags

```yaml
read_only: true                      # read-only root filesystem
user: "65532:65532"                  # non-root (the distroless nonroot user)
cap_drop: [ALL]                      # no Linux capabilities
security_opt:
  - no-new-privileges:true
tmpfs:
  - /var/cache/daxie                 # the only ephemeral writable area
```

The only writable mounts are the **state** named volume (durable) and the **cache**
tmpfs (disposable). Everything else, including the root filesystem, is read-only.

---

## Secrets

- **Keystore passphrase** via `DAXIE_PASSPHRASE_FILE` pointing at a Docker secret —
  never `DAXIE_PASSPHRASE` (visible in `docker inspect` / `/proc`), never a flag value.
- **Admin passphrase is absent.** Policy administration (`policy set/allow/…`) is a
  one-off operator run, not part of the long-running container's environment. See
  [policy-k8s.md](policy-k8s.md) for the write ordering (the same two-domain rule
  applies to a bind-mounted config dir).
- RPC provider keys stay as `${env:}`/`${file:}` references in `config.toml`; the
  resolved value is supplied at runtime (env from a secret, or a mounted file).

---

## Provisioning the policy (once, before the agent runs)

The policy must exist before the agent pod starts. Run the bootstrap from a host that
holds the admin passphrase, against the same config + state dirs:

```sh
DAXIE_CONFIG=./config \
DAXIE_STATE_DIR=./state \
DAXIE_KEYSTORE=./keystore \
DAXIE_ADMIN_PASSPHRASE_FILE=./admin-pass \
  daxie policy set --max-tx 0.1eth --max-day 0.5eth
# Writes ./state/policy.json (sealed) and ./config/policy-anchor.json (the verify key).
# Then mount ./config read-only into the agent container.
```

Pin the image by digest and verify it before running:

```sh
cosign verify ghcr.io/daxchain-io/images/daxie@sha256:... \
  --certificate-identity-regexp '^https://github.com/daxchain-io/daxie/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
docker run --rm ghcr.io/daxchain-io/images/daxie@sha256:... version
```

See [`compose.yaml`](compose.yaml) for the full example, and [kubernetes.md](kubernetes.md)
for the equivalent K8s manifests.
