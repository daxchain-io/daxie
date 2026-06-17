# Deploying Daxie's policy guardrails on Kubernetes

This runbook covers the **two-domain write ordering** the sealed policy engine
requires on Kubernetes, plus the passphrase-free **canary** and the **staged,
zero-outage admin-passphrase rotation**. It is the operational companion to design
§4.5–§4.7.

## The two domains

Daxie's guardrails live in **two files in two different state classes**, on purpose:

| File | State class | K8s mount | Who may write |
|---|---|---|---|
| `policy.json` (sealed body + Ed25519 seal) | **state** | a writable PVC | the admin, via `daxie policy …` |
| `policy-anchor.json` (verify key + scrypt salt/params + nonce watermark) | **config** | a **read-only ConfigMap** | the operator/CI, out of band |

The split is the security model, not an accident:

- The **ConfigMap** is the one mount the agent process genuinely cannot write —
  it protects the *anchor file*.
- The **Viper carve-out** (no flag, no `DAXIE_*` env var, no `config get|set` key
  can reach the anchor) protects against the env/flag bypass no file permission can
  stop. A compromised agent cannot pair a self-forged `policy.json` with a verify
  key it injected from its own environment.

Both are required; neither alone suffices.

## The anchor is the trust root — the agent has the *public* key only

The seal is an **asymmetric Ed25519 signature**, never a symmetric MAC. The agent
host holds only the pinned **public** verify key (`anchor.verify_key`), so it can
**verify** a seal on every signing op but **cannot forge** one. Forging needs the
private key, which only the admin passphrase re-derives (scrypt → HKDF → ed25519).
The admin passphrase is **independent** of the keystore passphrase (a distinct salt
and scrypt params), so an agent that holds the keystore secret gains nothing toward
forging policy.

## Bootstrapping (first deploy)

There is **no separate `policy init`** — the **first** `daxie policy set` against a
config dir with no anchor *bootstraps* it (generates the verify keypair, the salt,
and watermark 0).

On a **writable** workstation config, `policy set` writes both files directly. On a
**read-only** ConfigMap, it cannot write the anchor — so it **emits the anchor JSON
to stdout** (or to `--anchor-out <path>`), and you land it into the ConfigMap
out of band:

```sh
# Run once, somewhere with the admin passphrase, against a STAGING config dir:
DAXIE_ADMIN_PASSPHRASE_FILE=/run/secrets/daxie-admin \
  daxie policy set --max-tx 0.1eth --max-day 0.5eth --allowlist on \
  --anchor-out ./policy-anchor.json --json

# 1. land the sealed body on the state PVC (write policy FIRST — see ordering):
kubectl cp ./state/policy.json <pod>:/var/lib/daxie/policy.json
# 2. then publish the anchor into the read-only ConfigMap (anchor SECOND):
kubectl create configmap daxie-policy-anchor \
  --from-file=policy-anchor.json=./policy-anchor.json --dry-run=client -o yaml \
  | kubectl apply -f -
```

Provisioning **seeds both files before the first agent pod starts**.

## The write ordering — policy FIRST, then anchor (do not invert)

Every mutation (`policy set`, `policy allow/deny`, `policy change-admin-passphrase`,
`policy counters release`, `policy reset --force`) bumps the body nonce, re-seals,
and advances the watermark. When you land the two files, **always write the sealed
`policy.json` first, then publish the anchor**:

- A failure *between* the two writes leaves `file.nonce > anchor.watermark`. The
  runtime **accepts** this and self-heals the watermark forward when the config is
  writable — no outage.
- The inverse order (anchor first) would publish a watermark *above* the body's
  nonce, which the loader reads as a rollback and **halts all signing**
  (`policy.rollback`, exit 8). Anchor-first is a self-inflicted fleet outage.

On a writable config the engine writes them in this order automatically; on a
read-only ConfigMap you enforce it in your CI/landing step.

## Canary before cutover — `policy pin --verify`

`daxie policy pin --verify <key>` reports whether the on-disk `policy.json`
verifies under a **supplied** verify key (exit 0 = verifies, exit 8 = does not). It
takes **no passphrase**, so run it as a one-off Job against the *candidate*
ConfigMap value **before** you cut over:

```sh
# Does the new anchor's verify key actually verify the deployed policy?
daxie policy pin --verify "$(yq '.data["policy-anchor.json"]' candidate-cm.yaml | jq -r .verify_key)"
echo "exit=$?"   # 0 ⇒ safe to roll out; 8 ⇒ a fat-finger — do NOT cut over
```

A fat-finger becomes a canary, not a fleet-wide refusal.

`daxie policy pin --print` re-emits the current anchor JSON any time (for diffing or
re-publishing).

## Verifying running pods — `policy verify`

`daxie policy verify` checks the deployed `policy.json` against the **pinned**
anchor (exit 0 / 8, no passphrase). Run it as a readiness probe or a periodic Job:

```sh
daxie policy verify --json   # exit 0 ok; exit 8 = seal/rollback halt (page someone)
```

## Staged, zero-outage admin-passphrase rotation

The loader accepts `verify_key` (current) **and** an optional `verify_key_next`;
signing verifies against either. That is what makes rotation outage-free across a
fleet whose pods observe the ConfigMap update at different times.

```sh
# 1. STAGE: authenticate the CURRENT passphrase, supply the NEW one. This records
#    a staged_salt and prints the NEW verify key. policy.json is NOT yet resealed.
DAXIE_ADMIN_PASSPHRASE_FILE=/run/secrets/daxie-admin \
DAXIE_NEW_ADMIN_PASSPHRASE_FILE=/run/secrets/daxie-admin-new \
  daxie policy change-admin-passphrase --stage --anchor-out ./anchor-staged.json --json
#    → land anchor-staged.json (now carrying verify_key_next) into the ConfigMap.

# 2. CANARY the new key with pin --verify against the candidate ConfigMap value.

# 3. COMMIT: re-derive from the staged salt, assert the derived key == verify_key_next,
#    reseal policy.json under the NEW key family. On a read-only config, --commit BLOCKS
#    until the new anchor is observed on the mount before retiring the old key.
DAXIE_NEW_ADMIN_PASSPHRASE_FILE=/run/secrets/daxie-admin-new \
  daxie policy change-admin-passphrase --commit --anchor-out ./anchor-committed.json --json
#    → land policy.json (state PVC) FIRST, then anchor-committed.json (ConfigMap).

# 4. At leisure, promote verify_key_next → verify_key (drop the old key from the anchor).
```

## Recovery — `policy reset --force`

If `policy.json` is corrupted or tampered, `daxie policy reset --force` reseals a
**fresh default body** (nonce restarts at watermark+1, `self_addresses`
re-snapshotted) under the *same* key family — no rotation, no ConfigMap change.

It authenticates against the **anchor**, not the file (real proof that survives body
tampering), and there is **no `--yes` bypass**: a prompt-compromised agent that
trashes `policy.json` cannot follow up with a reset under a passphrase of its own
choosing, because its passphrase never derives the pinned key.

When the anchor itself is missing/destroyed, reset refuses — recovery moves out of
band (remove the anchor and re-run the bootstrap `policy set`).

## Passphrase channels (never a flag value)

The admin passphrase is accepted **only** through:

- a TTY prompt (interactive),
- `--admin-passphrase-stdin` / `--admin-passphrase-file <path>`,
- `DAXIE_ADMIN_PASSPHRASE` / `DAXIE_ADMIN_PASSPHRASE_FILE`.

It is **never** a flag value (flags leak into shell history and `ps`) and is
**never** present in an agent pod's environment — only the operator's `policy …`
Job sees it. The rotation target uses the `--new-admin-passphrase-*` /
`DAXIE_NEW_ADMIN_PASSPHRASE[_FILE]` channels, mirroring the same rules.
