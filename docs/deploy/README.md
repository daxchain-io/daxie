# Deploying Daxie

These manifests run Daxie as a non-root, read-only-rootfs wallet alongside (or inside)
an AI agent container, mounting each of the four state classes correctly. They are
**example manifests** — adapt namespaces, image digests, resource limits, and secret
sourcing to your cluster.

| Guide | What |
|---|---|
| [docker.md](docker.md) + [compose.yaml](compose.yaml) | Docker / Compose pattern: Daxie with the agent container, four mounts, hardened runtime |
| [kubernetes.md](kubernetes.md) + [k8s/](k8s/) | Kubernetes manifests: Deployment, ConfigMap, Secret, PVC |
| [policy-k8s.md](policy-k8s.md) | The policy runbook: two-domain write ordering, the passphrase-free canary, zero-outage admin-passphrase rotation |

> **Helm chart: v1.1.** A `charts/daxie` Helm chart ships in **v1.1** alongside the
> HTTP MCP transport (`mcp serve --transport http`). With stdio-only v1 there is no
> standalone service to chart — the agent launches `daxie mcp serve` as a subprocess —
> so v1 ships these **example manifests only**. The chart will deploy Daxie as a
> wallet/signing service (keys in the Daxie pod, agents holding only a credential — the
> signer-daemon privilege boundary). See [design.md §7a / §10.3](../design.md).

---

## The four state classes (the deployment backbone)

Every Daxie file falls into one of four classes. The mount type follows from the
class — this is the single rule the manifests implement:

| Class | Override | Contents | Mount | Writable? |
|---|---|---|---|---|
| **config** | `DAXIE_CONFIG` | `config.toml`, `policy-anchor.json` (the seal verify key — the policy trust root) | **read-only ConfigMap** | no (a signing op never writes config) |
| **keystore** | `DAXIE_KEYSTORE` | `keystore.json`, `meta.json`, `wallets/<uuid>.json`, `accounts/UTC--...`, `index.lock` | Secret/external secret sync or PVC | read-only at runtime |
| **state** | `DAXIE_STATE_DIR` | tx journal + nonces, sealed `policy.json` + **durable spend counters**, registries | **PVC** | yes — and **must persist** (a reset counter re-widens the daily window) |
| **cache** | `DAXIE_CACHE_DIR` | ENS / metadata / fee-history caches | emptyDir / tmpfs | yes — disposable |

Why it matters:

- The **policy anchor** sits in the config class precisely so it can be a read-only
  ConfigMap the agent cannot write — the one mount that structurally protects the
  trust root. It is also reachable by no env var or flag (the Viper carve-out).
- The **spend counters** sit in the state class on a durable PVC. Losing them would
  re-open the rolling-24h window; corruption fails closed (exit 8) rather than zeroing.
- **Registries are state, not config**, so an agent can `token add` mid-task on a pod
  whose config is read-only.

## Runtime hardening (applies to both Docker and Kubernetes)

- **non-root** uid/gid **65532** (the distroless `nonroot` user)
- **read-only root filesystem**; the only writable mounts are state (PVC) and cache
  (tmpfs/emptyDir)
- **drop ALL Linux capabilities**, `no-new-privileges` / `allowPrivilegeEscalation:
  false`, `seccompProfile: RuntimeDefault`
- the keystore passphrase via **`DAXIE_PASSPHRASE_FILE`** pointing at a Secret mount —
  never `DAXIE_PASSPHRASE` (env is least-safe) and never a flag value
- the **admin passphrase is absent** from the agent pod — policy administration is an
  out-of-band operator act ([policy-k8s.md](policy-k8s.md))
- pin the image by **digest** (`ghcr.io/daxchain-io/daxie@sha256:…`) and
  cosign-verify it (see [../install.md](../install.md))

## One writer per account

In v1, nonce serialization is file-lock based — reliable on one host, not across
hosts. Run **one writer per account** (replicas sharing a key risk nonce collisions;
v1 detects them at broadcast but does not prevent them). Give each agent its own
derived account. The cross-host single-signer guarantee arrives with the v2 daemon.
