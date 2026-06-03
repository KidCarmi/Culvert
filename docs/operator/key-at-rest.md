# Key-at-Rest Encryption — Operator Runbook (CA-3)

How to **enable**, **verify**, **troubleshoot**, and **recover** Culvert's
CA-3 private-key-at-rest encryption.

This is the operator-facing companion to the design ADR
[`roadmap/CA-3-KEY-AT-REST-DESIGN.md`](../../roadmap/CA-3-KEY-AT-REST-DESIGN.md).
It documents the shipped behavior; the ADR explains the threat model and the
rules behind it.

> **TL;DR**
>
> - Encryption is **opt-in and off by default**. Plaintext behavior is
>   unchanged until you set a per-subsystem flag.
> - Pick **one** KEK (key-encryption-key) mode: an **environment KEK**
>   (`CULVERT_KEK`, recommended for containers/automation) **or** the
>   **auto-generated local file KEK** (zero config, single host).
> - Turn it on, restart, then **verify** with
>   `GET /api/diagnostics` → the `key_at_rest` check.
> - Migration quarantines your old plaintext key as `<key>.plaintext.bak`.
>   Confirm recovery, then **delete the `.bak`** — it is a plaintext key.
> - **If you lose the KEK, the encrypted key is unrecoverable.** Back the KEK
>   up **separately** from the key/backup tarball.

---

## Contents

1. [What this protects (and what it does not)](#1-what-this-protects-and-what-it-does-not)
2. [Concepts: envelope, KEK, fail-closed](#2-concepts-envelope-kek-fail-closed)
3. [The three protected keys](#3-the-three-protected-keys)
4. [Supported KEK modes](#4-supported-kek-modes)
5. [Enabling encryption](#5-enabling-encryption)
6. [Migration runbook (plaintext → encrypted)](#6-migration-runbook-plaintext--encrypted)
7. [Verifying via `/api/diagnostics`](#7-verifying-via-apidiagnostics)
8. [Audit events](#8-audit-events)
9. [Troubleshooting (missing / invalid / wrong KEK, corruption)](#9-troubleshooting-missing--invalid--wrong-kek-corruption)
10. [Disaster recovery & break-glass](#10-disaster-recovery--break-glass)
11. [Security do's and don'ts](#11-security-dos-and-donts)
12. [Quick reference](#12-quick-reference)

---

## 1. What this protects (and what it does not)

CA-3 adds **encryption at rest** for the three private keys Culvert persists
that were previously plaintext PEM on disk:

| Subsystem  | Private key it protects |
|------------|-------------------------|
| `cluster-ca` | The **cluster CA private key** — the trust anchor that signs every Data Plane node's gRPC client cert. |
| `dp-node`    | The **Data Plane node client key** used to authenticate to the Control Plane. |
| `cdr-client` | The **CDR/Sluice client key** for each enrolled CDR instance. |

The Root CA bundle (`ca.bundle`) is **already** encrypted (AES-256-GCM +
passphrase) and is **not** part of CA-3 — see the deployment guide for
`CULVERT_CA_PASSPHRASE`.

**Out of scope for this runbook (by design):** no mandatory KMS, no change to
backup/restore, no config-version rollback or `ConfigSnapshot` behavior, no new
metrics, and no UI input for keys. Private key material is **never** placed in
rollback snapshots, audit details, logs, or metrics.

---

## 2. Concepts: envelope, KEK, fail-closed

- **Encrypted envelope.** When encryption is enabled, the private-key file is
  written as an encrypted **envelope** (the same `PSCA`-magic AES-256-GCM
  format used by `ca.bundle`) instead of plaintext PEM. The matching public
  certificate (`*.crt`) stays plaintext — only the private key is encrypted.
- **KEK (key-encryption key).** A 256-bit (32-byte) key that unlocks the
  envelope. Culvert never stores the KEK inside the encrypted file; you supply
  it via one of the two [KEK modes](#4-supported-kek-modes).
- **Content-driven read, fail-closed.** On load, Culvert decides plaintext vs.
  encrypted by **looking at the file**, not the flag. An encrypted key is
  **always** decrypted on read, even if the enable flag is later turned off. If
  decryption fails (missing/wrong KEK or a corrupt file), Culvert **fails
  closed**: it surfaces an error and refuses to start that path. It will
  **never** silently regenerate the CA or re-enroll a node to "fix" a key it
  cannot decrypt.

---

## 3. The three protected keys

| Subsystem  | Enable flag | Key file (default) | File-KEK location |
|------------|-------------|--------------------|-------------------|
| `cluster-ca` | `CULVERT_CLUSTER_CA_ENCRYPT` | `<ca-dir>/cluster-ca.key` | `<ca-dir>/cluster-ca.kek` |
| `dp-node`    | `CULVERT_DP_NODE_KEY_ENCRYPT` | `./dp-node.key` (next to the DP working dir / `-dp-key` path) | `<dp-key-dir>/dp-node.kek` |
| `cdr-client` | `CULVERT_CDR_CLIENT_KEY_ENCRYPT` | each instance's client-key path | `<client-key-path>.kek` (per instance) |

Notes:

- The `cdr-client` KEK is anchored **per key file** (`<key>.kek`), so one CDR
  instance's KEK never affects another.
- The file-KEK locations above apply only in **local file-KEK mode**. In
  **environment-KEK mode** (`CULVERT_KEK`), no `.kek` file is created or read.

---

## 4. Supported KEK modes

Culvert supports exactly two KEK sources. **`CULVERT_KEK` takes precedence:**
if it is set to a non-empty value, it is used for **all** subsystems and the
local `.kek` files are ignored.

### 4a. Environment KEK — `CULVERT_KEK` (recommended for containers/automation)

- **Format:** a **hex-encoded 32-byte** key — exactly **64 hex characters**.
  Anything else (wrong length, non-hex) is rejected and the affected
  key operations **fail closed**.
- **Scope:** process-global. The same `CULVERT_KEK` unlocks `cluster-ca`,
  `dp-node`, and `cdr-client`.
- **Provisioning:** inject it from your platform's secret store. Never bake it
  into an image, a committed `.env`, or a Dockerfile.

Generate a fresh random KEK (the value below is illustrative — generate your
own and never reuse this placeholder):

```bash
# Produces a 64-hex-character (32-byte) value. Capture it into your secret
# manager, NOT into the shell history or a committed file.
openssl rand -hex 32
# example shape only (DO NOT USE):
#   CULVERT_KEK=0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
```

**Docker / Compose** — pass it from an already-exported secret, never inline:

```yaml
# docker-compose.yml (excerpt)
services:
  culvert:
    environment:
      - CULVERT_CLUSTER_CA_ENCRYPT=1
      - CULVERT_KEK            # value comes from the host/secret store, not here
```

```bash
# CULVERT_KEK is sourced from your secret manager into the shell, then:
docker compose up -d
```

**Kubernetes** — store the KEK in a `Secret` and project it as an env var:

```yaml
# placeholder values only
env:
  - name: CULVERT_DP_NODE_KEY_ENCRYPT
    value: "1"
  - name: CULVERT_KEK
    valueFrom:
      secretKeyRef:
        name: culvert-kek         # kubectl create secret generic culvert-kek --from-literal=kek=<64-hex>
        key: kek
```

**systemd** — load it from a root-only `EnvironmentFile` (mode `0600`), not the
unit file:

```ini
# /etc/culvert/kek.env   (chmod 0600, root:root, NOT world-readable)
#   CULVERT_KEK=<64-hex-characters>
[Service]
EnvironmentFile=/etc/culvert/kek.env
Environment=CULVERT_CLUSTER_CA_ENCRYPT=1
```

### 4b. Local file KEK (zero-config default for a single host)

If `CULVERT_KEK` is **not** set, Culvert uses a **local file KEK**: a 32-byte
random key it **auto-generates** (mode `0600`) next to the key it protects, on
first use. See the [file-KEK locations](#3-the-three-protected-keys) table.

- **Pros:** no key provisioning; works out of the box.
- **Cons:** the KEK lives on the same host as the key. It protects against an
  attacker who copies *only* the key/backup tarball, **not** against one who can
  read the whole data directory. For multi-host or "backup must not contain the
  unlock secret" requirements, prefer the [environment KEK](#4a-environment-kek--culvert_kek-recommended-for-containersautomation).
- **Backup rule:** the `.kek` file **must not** be stored in the same archive as
  the encrypted key — that would defeat the encryption. See
  [§10](#10-disaster-recovery--break-glass).

---

## 5. Enabling encryption

1. **Choose a KEK mode** ([§4](#4-supported-kek-modes)). For production /
   clusters, prefer the environment KEK.
2. **Set the per-subsystem flag(s)** to a truthy value. Accepted truthy values
   (case-insensitive): `1`, `true`, `yes`, `on`. Anything else (including unset)
   means **off**.
   - `CULVERT_CLUSTER_CA_ENCRYPT` — on the Control Plane / CA host.
   - `CULVERT_DP_NODE_KEY_ENCRYPT` — on each Data Plane node.
   - `CULVERT_CDR_CLIENT_KEY_ENCRYPT` — where CDR client keys live.
3. **Restart** the affected process. On startup Culvert will:
   - encrypt **new** key writes (enrollment / renewal), and
   - **migrate** an existing plaintext key (see [§6](#6-migration-runbook-plaintext--encrypted)).
4. **Verify** with [`/api/diagnostics`](#7-verifying-via-apidiagnostics).

You can enable subsystems independently and incrementally; each is governed by
its own flag.

---

## 6. Migration runbook (plaintext → encrypted)

When a subsystem's flag is on and Culvert finds an **existing plaintext** key,
it migrates that key to the encrypted envelope at the load point (CP/CA init,
DP startup, or CDR load). The migration is **safe and ordered** so a readable
key always exists:

1. **Quarantine** — copy the current plaintext key to `<key>.plaintext.bak`
   (mode `0600`) *before* touching the original.
2. **Encrypt + write** — atomically write the encrypted envelope to the key
   path.
3. **Verify** — re-read, decrypt, and confirm the round-trip matches the source.
4. **Roll back on failure** — if any step fails, the original key is restored
   from the `.bak` and a `keyatrest.migrate.failed` audit event is emitted.

**Idempotent:** if the key is already an encrypted envelope, migration is a
no-op. A key that does not parse is **refused** (not rewritten), so a malformed
file never gets clobbered.

**After a successful migration:**

- You will see a `keyatrest.migrate.completed` audit event and a log line noting
  the quarantined `.plaintext.bak`.
- **Verify recovery** (restart and confirm the service comes up and
  `/api/diagnostics` is green), then **delete `<key>.plaintext.bak`**. That file
  is your old key in the clear — treat it like a secret and remove it once
  you've confirmed the encrypted key works.

> Migration affects only the **private key**. Matching `*.crt` files and the
> trusted CA cert stay plaintext.

---

## 7. Verifying via `/api/diagnostics`

`GET /api/diagnostics` (viewer role or above) returns the operator contract,
which includes a `key_at_rest` check. It reports **mode** and **KEK source** as
enums only — it never reads or returns key/KEK bytes.

| `status` | When | Example `message` | What to do |
|----------|------|-------------------|------------|
| `ok`   | All subsystems disabled. | `key-at-rest encryption disabled (opt-in; private keys stored as plaintext PEM 0600)` | Nothing — this is the default posture. |
| `ok`   | ≥1 subsystem enabled, KEK usable. | `key-at-rest encryption enabled for: cluster-ca, dp-node; KEK source: env` | Healthy. `KEK source` is `env` (`CULVERT_KEK`) or `file`. |
| `warn` | All disabled **but** `CULVERT_KEK` is set to an **invalid** value. | `key-at-rest encryption disabled, but CULVERT_KEK is set to an invalid value` | Fix or unset `CULVERT_KEK` **before** enabling any subsystem — it will fail the moment you do. |
| `fail` | ≥1 subsystem enabled **and** `CULVERT_KEK` is set but **invalid**. | `... enabled for: cluster-ca, but CULVERT_KEK is set to an invalid value — key unlock/migration will fail closed` | Set `CULVERT_KEK` to a valid 64-hex value (or unset it to fall back to a file KEK) and restart. See [§9](#9-troubleshooting-missing--invalid--wrong-kek-corruption). |

The check distinguishes a **missing** `CULVERT_KEK` (→ falls back to a file KEK,
healthy) from a **set-but-malformed** one (→ the env provider is still selected
and operations fail closed). A malformed env KEK is never reported as a healthy
`file` fallback.

---

## 8. Audit events

CA-3 emits three audit events. They carry the synthetic actor
`system@key-at-rest` and a **logical subsystem name** as the object
(`cluster-ca`, `dp-node`, or `cdr-client`). They contain **no** key bytes,
KEK material, fingerprints, paths, or file contents — the detail field is
intentionally empty.

| Action | Meaning | Object |
|--------|---------|--------|
| `keyatrest.migrate.completed` | A plaintext key was successfully migrated to the encrypted envelope. | the subsystem migrated |
| `keyatrest.migrate.failed`    | A migration attempt failed; the original key was restored from `<key>.plaintext.bak`. Investigate before retrying. | the subsystem |
| `keyatrest.unlock.failed`     | An encrypted key could **not** be decrypted on load (missing/wrong KEK or corrupt envelope). The path fails closed. | the subsystem |

Find them in the audit log (UI **Audit** panel, the audit JSONL file, or any
configured syslog/SIEM sink) by filtering on actor `system@key-at-rest` or the
`keyatrest.*` action prefix.

---

## 9. Troubleshooting (missing / invalid / wrong KEK, corruption)

All of the failures below are **fail-closed**: Culvert refuses the affected path
rather than running insecurely or regenerating keys. None of them are fixed by
deleting the encrypted key — that destroys it. Work the cause instead.

| Symptom | Likely cause | Safe remediation |
|---------|--------------|------------------|
| `/api/diagnostics` `key_at_rest` = `fail`; startup error `cannot decrypt at-rest key`; `keyatrest.unlock.failed` audit event. | **`CULVERT_KEK` set but malformed** (not 64 hex chars). | Restore the correct 64-hex `CULVERT_KEK` from your secret store and restart. If you intended file-KEK mode, **unset** `CULVERT_KEK` so the `.kek` file is used. |
| Startup error `cannot decrypt at-rest key`; `keyatrest.unlock.failed`; diagnostics may be `ok` (env unset) yet the service won't start. | **File KEK missing** — the `.kek` next to the key was deleted/not restored, or you switched to env mode with the **wrong** `CULVERT_KEK`. | Restore the original `.kek` from your secret backup, **or** set the `CULVERT_KEK` that the key was actually encrypted with. The key and its KEK must match. |
| Decrypt fails after migrating between hosts / restoring a partial backup. | **Wrong KEK for this key** — the key was encrypted with a different KEK than the one now present. | Supply the KEK that encrypted this specific key. A key encrypted under KEK-A cannot be opened with KEK-B. If the correct KEK is gone, treat it as KEK loss ([§10](#10-disaster-recovery--break-glass)). |
| `keyatrest.migrate.failed` audit event; key still loads as plaintext. | Migration step failed (e.g. disk full, permissions); Culvert **rolled back** to the plaintext key. | Fix the underlying cause (space, `0600` perms, ownership), confirm the `.plaintext.bak`/key are intact, and restart to retry migration. |
| `existing key not parseable; refusing to migrate`. | The on-disk key is corrupt or not a valid private key. | Do **not** force it. Restore a known-good key from backup, then re-enable migration. |

General rules:

- **Never** "fix" a decrypt failure by deleting the encrypted key or the
  `.kek`. That is unrecoverable.
- Diagnostics + the `keyatrest.unlock.failed` audit event together tell you
  *which subsystem* is failing without exposing any secret.
- A flag toggled **off** does **not** decrypt your files back to plaintext;
  encrypted files are still read as encrypted. To return to plaintext you must
  intentionally restore a plaintext key (e.g. from `<key>.plaintext.bak`, if you
  kept it) — see DR below.

---

## 10. Disaster recovery & break-glass

### 10a. The `<key>.plaintext.bak` files

Migration leaves a `0600` plaintext copy of the pre-migration key at
`<key>.plaintext.bak`. It is a **break-glass artifact**:

- **Keep it** until you have verified the encrypted key works (service starts,
  diagnostics green).
- **Then delete it.** It is a plaintext private key; leaving it around defeats
  the purpose of CA-3.
- If you ever need to **revert** a subsystem to plaintext: stop the process,
  copy the `.bak` back over the key path, **unset** that subsystem's flag, and
  restart. (You did not delete it yet because you hadn't verified recovery.)

### 10b. Encrypted key files need their KEK

An encrypted key file is useless without the KEK that unlocks it. Plan backups
accordingly:

- **Environment-KEK mode:** the KEK lives only in your secret manager. **Back up
  `CULVERT_KEK` there**, with the same care as any root secret. A backup of
  `/data` alone does **not** contain the unlock secret — that is the point.
- **File-KEK mode:** the `.kek` file lives next to the key. To survive host
  loss you must back the `.kek` up **separately** from the encrypted key — store
  them in **different** archives / locations. Never put the `.kek` in the same
  tarball as the key it unlocks.

### 10c. KEK loss

If the KEK is permanently lost, the encrypted key **cannot** be recovered. Plan
the rebuild per subsystem:

- **`cluster-ca`:** re-initialize the cluster CA and **re-enroll** all Data
  Plane nodes against the new trust anchor (the old DP client certs are no
  longer trusted).
- **`dp-node`:** re-enroll the affected node to obtain a fresh client key/cert.
- **`cdr-client`:** re-enroll the affected CDR instance.

(Rotation, when supported, follows the same migration/verify flow with the new
KEK; until then, treat a KEK change as a re-encrypt-on-next-write operation and
verify via diagnostics.)

---

## 11. Security do's and don'ts

**Do**

- Source `CULVERT_KEK` from a secret manager (K8s `Secret`, systemd
  `EnvironmentFile` `0600`, Vault, cloud secret store).
- Keep `.kek` files and encrypted keys at `0600`, owned by the service user.
- Back up the KEK **separately** from the key/backup tarball.
- Delete `<key>.plaintext.bak` once recovery is verified.
- Verify with `/api/diagnostics` after every enable/rotate.

**Don't**

- **Don't** commit a KEK to git, bake it into an image, or put it in a
  committed `.env`.
- **Don't** store the `.kek` file in the same archive as the key it unlocks.
- **Don't** reuse the illustrative placeholder values from this document.
- **Don't** delete an encrypted key or its KEK to "fix" a decrypt error — that
  is permanent data loss.
- **Don't** expect the audit/diagnostics surfaces to show key material; they
  never will, by design.

---

## 12. Quick reference

**Enable flags** (truthy: `1` / `true` / `yes` / `on`; default off)

| Variable | Subsystem |
|----------|-----------|
| `CULVERT_CLUSTER_CA_ENCRYPT` | cluster CA private key |
| `CULVERT_DP_NODE_KEY_ENCRYPT` | DP node client key |
| `CULVERT_CDR_CLIENT_KEY_ENCRYPT` | CDR/Sluice client key |

**KEK**

| Item | Value |
|------|-------|
| Env KEK | `CULVERT_KEK` = 64 hex chars (32 bytes); process-global; takes precedence |
| File KEK | auto-generated 32-byte file, `0600`, next to the key |
| File-KEK names | `cluster-ca.kek`, `dp-node.kek`, `<cdr-client-key>.kek` |

**Verify**

```
GET /api/diagnostics   →  check "code": "key_at_rest"
  ok   = disabled, or enabled with a usable KEK
  warn = disabled but CULVERT_KEK invalid
  fail = enabled but CULVERT_KEK invalid (fails closed)
```

**Audit actions** (actor `system@key-at-rest`, object = subsystem)

```
keyatrest.migrate.completed   keyatrest.migrate.failed   keyatrest.unlock.failed
```

**Files to know**

| File | What |
|------|------|
| `<key>` | encrypted private key (PSCA envelope) when enabled |
| `<key>.plaintext.bak` | pre-migration plaintext key — delete after verifying recovery |
| `<key>.kek` / `*.kek` | local file KEK (file-KEK mode only) |

---

*See also:*
[`roadmap/CA-3-KEY-AT-REST-DESIGN.md`](../../roadmap/CA-3-KEY-AT-REST-DESIGN.md)
(threat model & design),
[`docs/operator/docker-compose-backup-restore.md`](./docker-compose-backup-restore.md)
(backup/restore),
[`docs/deployment-guide.md`](../deployment-guide.md) (`CULVERT_CA_PASSPHRASE`
for the Root CA bundle).
