# Kubernetes deployment

Example manifests that run Daxie non-root with a read-only root filesystem, mounting
the four state classes by durability and writability. They live in [`k8s/`](k8s/):

| File | Class / role |
|---|---|
| [`k8s/configmap.yaml`](k8s/configmap.yaml) | **config** — `config.toml` + `policy-anchor.json` (read-only) |
| [`k8s/secret.yaml`](k8s/secret.yaml) | **keystore** + the keystore passphrase |
| [`k8s/pvc.yaml`](k8s/pvc.yaml) | **state** — durable spend counters, journal, nonces |
| [`k8s/deployment.yaml`](k8s/deployment.yaml) | the pod: hardened `securityContext`, the four mounts |

> **Helm chart: v1.1.** These are example manifests for v1's stdio transport. The
> packaged `charts/daxie` Helm chart arrives in **v1.1** with the HTTP MCP transport
> (`mcp serve --transport http`), where Daxie runs as a standalone signing service
> (keys in the Daxie pod, agents holding only a credential). See
> [README.md](README.md) and [design.md §10.3](../design.md).

---

## The mapping (state class → K8s primitive)

| Class | Primitive | Why |
|---|---|---|
| **config** | ConfigMap, mounted **read-only** | A signing op never writes config; the read-only ConfigMap is the one mount the agent cannot write — it structurally protects `policy-anchor.json`, the policy trust root. |
| **keystore** | Secret (or PVC), mounted **read-only** | Travels with key material in a backup; read-only at runtime (metadata mutations fail `keystore.read_only` by design). |
| **state** | **PVC** (ReadWriteOnce) | The agent's runtime job writes it and it **must survive restarts** — the durable spend counters live here; a fresh PVC re-opens the rolling-24h window. |
| **cache** | `emptyDir` | Reconstructible from chain; losing it costs only latency. |

The two-file policy split is deliberate: the sealed `policy.json` lives on the
**writable state PVC**, while `policy-anchor.json` (the verify key + nonce watermark)
lives in the **read-only config ConfigMap**. A compromised agent can write the state
PVC but cannot write the ConfigMap, and cannot reach the anchor by any env var or flag
(the Viper carve-out). Both protections are required. See
[policy-k8s.md](policy-k8s.md) for the write ordering, the passphrase-free canary, and
zero-outage admin-passphrase rotation.

During the release-candidate phase, replace image placeholders with an exact
published prerelease tag such as `ghcr.io/daxchain-io/daxie:1.0.0-rc.N`, or with a
verified digest. Floating Docker tags (`:latest`, `:X.Y`) move only on stable
releases.

---

## securityContext (the hardening)

The Deployment runs as the distroless nonroot user with a locked-down container:

```yaml
securityContext:                 # pod-level
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532                 # so the PVC is writable by the non-root uid
  seccompProfile:
    type: RuntimeDefault
# container-level:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
```

The only writable mounts are the **state PVC** (durable) and the **cache emptyDir**
(disposable). Everything else, including the root filesystem, is read-only.

---

## Secrets

- The **keystore passphrase** is a Secret key, surfaced as a file via
  `DAXIE_PASSPHRASE_FILE` (mount the Secret and point the env var at it) — never
  `DAXIE_PASSPHRASE` and never a flag value. Use a **≥ 128-bit** passphrase.
- The **admin passphrase is never in the agent pod.** Run policy mutations from a
  one-off `Job` (or a workstation) that mounts the admin Secret; the long-running
  Deployment does not. See [policy-k8s.md](policy-k8s.md).
- RPC provider keys stay as `${env:}`/`${file:}` references in `config.toml`; supply
  the resolved values via additional Secret-backed env/files.

---

## Apply

```sh
# Pin the image by digest and verify before rollout (see ../install.md):
cosign verify ghcr.io/daxchain-io/daxie@sha256:... \
  --certificate-identity-regexp '^https://github.com/daxchain-io/daxie/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

# Provision the policy out-of-band FIRST (see policy-k8s.md), landing policy.json on
# the state PVC and policy-anchor.json into the ConfigMap, in that order. THEN:
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/deployment.yaml
```

Edit the placeholder base64 in `secret.yaml`, the anchor/config in `configmap.yaml`,
and the storage class / size in `pvc.yaml` before applying — they ship with obvious
placeholders, not real material.

---

## One writer per account

A `ReadWriteOnce` PVC plus a single replica gives one writer per account, which is the
v1 nonce-safety rule (file locks are reliable on one host, not across hosts). If you
scale out, give **each replica its own derived account** rather than sharing a key —
cross-host collisions on a shared key are detected at broadcast in v1 but not
prevented (residual R8). A default-deny NetworkPolicy and no Ingress are recommended;
the HTTP transport's auth hooks land with v1.1.
