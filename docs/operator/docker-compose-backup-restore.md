# Docker Compose — Backup & Restore

This is the supported operator path for Culvert backup, restore, and cleanup
when running under Docker Compose. Manual filesystem-level `tar` of `/data`
is **not** supported — see § 12 and `docs/OPERATIONS.md § 4` for why and what
to do instead.

> **TL;DR**
>
> Ensure `CULVERT_BACKUP_PASSPHRASE` is already exported in your shell
> env (sourced from `.env`, `pass`/`gopass`, or a secrets manager — see
> § 9). Then:
>
> ```bash
> # Encrypted backup — production default.
> docker compose --profile cli run --rm \
>   -e CULVERT_BACKUP_PASSPHRASE \
>   cli --encrypt \
>       --backup /backup/culvert-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.enc
> ```

---

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Layout: `/data` vs `/backup`](#2-layout-data-vs-backup)
3. [Encrypted backup (production default)](#3-encrypted-backup-production-default)
4. [Unencrypted backup (dev / lab only)](#4-unencrypted-backup-dev--lab-only)
5. [Restore — dry-run](#5-restore--dry-run)
6. [Restore — commit (offline)](#6-restore--commit-offline)
7. [List restore leftovers](#7-list-restore-leftovers)
8. [Cleanup restore leftovers](#8-cleanup-restore-leftovers)
9. [Passphrase handling](#9-passphrase-handling)
10. [Runtime vs offline matrix](#10-runtime-vs-offline-matrix)
11. [Where to find backups and logs](#11-where-to-find-backups-and-logs)
12. [What NOT to do](#12-what-not-to-do)

---

## 1. Prerequisites

- Docker Compose **v2** (`docker compose` — two words; `docker-compose` v1 is not supported).
- The supplied `docker-compose.yml` (or your own derived from it) defines a
  profile-gated `cli` service. Inspect it with:
  ```bash
  docker compose --profile cli config | grep -A20 '^  cli:'
  ```
- The `cli` service uses the **same image** as `proxy`, so there is no
  separate pull. If you build locally, uncomment the `# build: .` line on
  both services.

The `cli` service is profile-gated — `docker compose up -d` does **not**
start it. Every backup/restore/cleanup invocation is a one-shot
`docker compose --profile cli run --rm cli <flags>`.

---

## 2. Layout: `/data` vs `/backup`

| Mount | Volume | Mounted in | Contents |
|---|---|---|---|
| `/data` | `proxy-data` | `proxy` (rw), `cli` (rw) | Product state: identity, policy, audit, blocklists, request log, CA bundle, `cluster.json`, `config_versions/`, `ui_users.json`, etc. |
| `/backup` | `culvert-backups` | **`cli` only** | Backup archives (`*.tar.gz` / `*.tar.gz.enc`). The long-running `proxy` cannot read its own backups. |

Two consequences worth knowing:

1. **The proxy cannot read backups at runtime.** A compromise of the proxy
   process cannot exfiltrate prior archives. `/backup` only exists inside
   the ephemeral `cli` container.
2. **`/backup` can be redirected to off-host storage** (NFS, SMB, a host
   bind mount, or an operator-managed sync target) without exposing
   `/data`. Override the volume in your `docker-compose.override.yml`:
   ```yaml
   services:
     cli:
       volumes:
         - ./backups:/backup   # host bind-mount alternative to the named volume
   ```

---

## 3. Encrypted backup (production default)

```bash
docker compose --profile cli run --rm \
  -e CULVERT_BACKUP_PASSPHRASE \
  cli --encrypt \
      --backup /backup/culvert-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.enc
```

What this does:

- Reads every Tier-1 + Tier-2 artifact under `/data` (per the D1.3a list).
- Builds a `manifest.json` (sha256 / size / mode per file) and writes
  `manifest.json` first inside the tarball.
- Compresses with gzip, then seals the whole compressed blob with
  AES-256-GCM. The passphrase is stretched with PBKDF2-SHA256 using
  600 000 iterations. The 43-byte header is bound to the ciphertext via
  AAD — header tampering (e.g. iter-count downgrade) fails authentication.
- Refuses to overwrite an existing output path.
- Prints `Backup written to /backup/… (encrypted, AES-256-GCM,
  PBKDF2-SHA256/600000)` on success.

**Always allowed while `proxy` is up.** Backup is a read-mostly walk of
`/data`; mid-rotation log files are excluded (Tier 3) and the manifest
captures point-in-time content.

### Common variations

| Goal | Flag |
|---|---|
| Custom path | `--backup /backup/<your-name>.tar.gz.enc` |
| Verbose-ish (operator wants the cipher/KDF audit line) | already printed on success |
| Different filename convention | filename is cosmetic; magic-byte sniff is authoritative |

---

## 4. Unencrypted backup (dev / lab only)

```bash
docker compose --profile cli run --rm cli \
  --backup /backup/culvert-$(date -u +%Y%m%dT%H%M%SZ).tar.gz
```

> **Dev / lab only.** Unencrypted backups must not leave the host. They
> contain ui_users hashes, TOTP secrets, the cluster CA private key,
> session HMAC, alert-webhook endpoint URLs (which are themselves
> bearer credentials for most receivers), IdP profiles (OIDC client
> secrets and LDAP bind credentials — reusable credentials against an
> external SSO system, not just Culvert), and full policy state. For
> anything outside an ephemeral lab, use § 3 instead.

---

## 5. Restore — dry-run

Always do this first. Prints the validation result and the mode-aware
restore plan **without touching `/data`**.

```bash
docker compose --profile cli run --rm \
  -e CULVERT_BACKUP_PASSPHRASE \
  cli --restore /backup/culvert-20260501T030000Z.tar.gz.enc
```

The passphrase env var is required only if the backup is encrypted.
Magic-byte sniffing decides — there is no `--encrypted` flag on the
restore side. If the backup is encrypted and the env var is unset, the
dry-run fails fast and names the missing variable.

The dry-run validates:

- Manifest schema (`schema_version=1`).
- Bidirectional presence (every manifest entry has a tar entry and
  vice-versa).
- Per-file sha256 / size / mode match.
- CA bundle decrypts (when present, with `CULVERT_CA_PASSPHRASE`).
- Cluster CA cross-references (`cluster.json` ↔ `cluster-ca.crt`).
- DP re-enrollment guard: would the restored CA fingerprint orphan
  any currently-enrolled DP?
- TOTP counter rollback guard: would any user's TOTP counter regress?

It then prints the full restore plan: file source counts, user delta,
guard outcomes, and any flags you'd need to pass on commit
(`--accept-dp-reenrollment`, `--allow-counter-rollback`).

### Dry-run with mode

```bash
docker compose --profile cli run --rm \
  -e CULVERT_BACKUP_PASSPHRASE \
  cli --restore /backup/culvert-20260501T030000Z.tar.gz.enc \
      --mode trust-root-only
```

Modes: `full` (default), `trust-root-only` (only restore CA material),
`state-only` (everything except CA material).

**Always allowed while `proxy` is up.** Dry-run is read-only.

---

## 6. Restore — commit (offline)

Restore commit is **destructive and offline-only**. It swaps the CONTENT of
`/data` in place: the restored tree is staged inside the volume, the current
entries are moved aside into `/data/.restore-bak.<ts>-<pid>/`, and the staged
entries are promoted. The proxy must be stopped first — and that is now
enforced, not merely documented: the running proxy holds an advisory lock on
`/data/.culvert.lock`, and a commit against a live stack is refused with
`data directory is locked by another Culvert process`. The lock works in both
directions: while a commit or `--recover-restore` holds it, a proxy that is
started (an operator, or `restart: unless-stopped`) refuses to boot with
`FATAL: … refusing to start the proxy over a data directory another Culvert
process … is mutating` and comes back by itself once the commit has finished.
A lock that cannot be created at all (first boot before the directory exists,
read-only filesystem) is only a warning.

> **Why in place?** `/data` is a Docker volume, i.e. a mount point inside the
> container, and `rename(2)` refuses to move a mount point. Earlier builds
> renamed `/data` itself to `/data.bak.<ts>` and therefore could never commit
> on a real deployment (and a sibling of the mount would have been outside
> the volume, lost with the container). The in-place swap is also the
> behaviour on a bare host.

```bash
# 1. Stop the running stack.
docker compose down

# 2. Run the destructive commit in an ephemeral container.
docker compose --profile cli run --rm \
  -e CULVERT_BACKUP_PASSPHRASE \
  cli --restore /backup/culvert-20260501T030000Z.tar.gz.enc \
      --confirm \
      --mode full

# 3. Bring the stack back up.
docker compose up -d
```

### What the commit does

1. Re-runs the dry-run validation. Refuses on any failure.
2. Honours `--mode` (full / trust-root-only / state-only).
3. Refuses on guard violations unless explicitly acknowledged:
   `--accept-dp-reenrollment` (cluster CA changes with DPs enrolled),
   `--allow-counter-rollback` (TOTP counters would roll back),
   `--accept-root-ca-change` (the inspection root `ca.bundle` would be
   replaced or REMOVED — every client trusting the current root loses
   inspected HTTPS, and a removed bundle is silently re-minted as a NEW
   root at the next boot). A commit that would leave **no admin account**
   while the node has one is refused outright (it would reopen
   unauthenticated first-time setup): use a backup that carries
   `ui_users.json`, or `--mode trust-root-only`.
4. Refuses if any entry of `/data` is itself a mount point (for example a
   `./yara:/data/yara:ro` bind) — those cannot be moved aside; unmount them
   for the restore.
5. Stages the new content under `/data/.restore-staging.<ts>-<pid>/`.
6. Writes `/data/.restore-journal.json`, moves every current top-level entry
   into `/data/.restore-bak.<ts>-<pid>/` (phase `evacuating`), then moves
   every staged entry into `/data` (phase `promoting`), removes the empty
   staging directory and the journal, and fsyncs.

The previous content is preserved as `/data/.restore-bak.<ts>-<pid>/`
indefinitely — inside the volume, so it survives container recreation.
Once you have verified the restored state, clean it up with the cleanup
command (§ 8). It is never auto-deleted.

### Recovery if the commit is interrupted

A commit killed during step 6 leaves the journal in place. The proxy
**refuses to start** while it exists (the data directory holds a mix of
previous and restored entries) and prints the recovery command. Nothing is
resumed automatically: you choose the direction.

```bash
# Inspect (read-only): phase, where the previous and staged data are.
docker compose --profile cli run --rm cli --recover-restore

# EITHER undo the restore (previous data becomes live again) ...
docker compose --profile cli run --rm cli --recover-restore --confirm=revert

# ... OR finish it (staged data lands, previous data stays in .restore-bak).
docker compose --profile cli run --rm cli --recover-restore --confirm=complete

docker compose up -d
```

Both directions are deterministic for every phase, and a recovery is itself
restartable: the journal records the chosen direction and each sub-step as
it completes (`recovery: revert|complete`, `progress: unpromoted | returned |
promoted`), so if the recovery is interrupted, **run the same command
again** and it resumes where it stopped. Two refusals follow from that:

* **The direction cannot be switched once a recovery has started.** The
  recorded direction is always finishable; the other one would act on a
  layout the journal no longer describes. Finish the recorded direction,
  then run a fresh restore if the other outcome is wanted.
* **Missing recovery material is never read as finished work.** A revert
  whose `.restore-bak.*` directory is absent, or a complete whose
  `.restore-staging.*` directory is absent, refuses without moving anything
  and keeps the journal — unless the journal's own `returned` / `promoted`
  marker proves that directory had already been emptied. Put the directory
  back and re-run; the journal is removed by hand only after inspecting the
  `.restore-*` directories.

A journal the binary cannot parse (including one carrying a direction or
marker this build does not know) is never acted on; the proxy refuses to
start and the operator inspects `/data/.restore-journal.json` and the
`.restore-*` directories by hand.

---

## 7. List restore leftovers

Inventory the `.restore-bak.<ts>-<pid>` / `.restore-staging.<ts>-<pid>`
directories inside `/data` left behind by past restore commits or killed
restores (and, for installs upgraded from older builds, any legacy
`/data.bak.<ts>-<pid>` siblings).

```bash
docker compose --profile cli run --rm cli --list-restore-leftovers
```

Output:

```
PATH                                                   TYPE     AGE      SIZE
/data/.restore-bak.20260428T101500Z-1234               bak      4d 2h    412.3 MB
/data/.restore-staging.20260501T030000Z-9876           staging  1d 11h   8.2 MB
```

Read-only; safe any time. A staging/bak pair referenced by an unresolved
restore journal is reported as protected (`WARN: ... referenced by an
unresolved interrupted restore`) and is never a cleanup candidate until
`--recover-restore` resolves it.

---

## 8. Cleanup restore leftovers

Always **dry-run first**, then add `--confirm` to actually delete.

```bash
# Dry-run plan
docker compose --profile cli run --rm cli \
  --cleanup-restore-leftovers \
  --older-than 720h \
  --keep-last 3

# Execute (add --confirm)
docker compose --profile cli run --rm cli \
  --cleanup-restore-leftovers \
  --older-than 720h \
  --keep-last 3 \
  --confirm
```

Filters:

- `--older-than DURATION` — only candidates whose **timestamp parsed
  from the directory name** is older than DURATION. Strict
  `time.ParseDuration` syntax (e.g. `168h`, `720h`); the parsed
  timestamp is used (not mtime, which is forgeable).
- `--keep-last N` — always preserve the N newest `.bak` directories.
  Applies to `.bak` only; `.staging` leftovers (killed-restore
  wreckage) are always candidates if they pass other filters.

**Both dry-run and `--confirm` are runtime-OK** — cleanup operates only
on `/data/.restore-{bak,staging}.<ts>-<pid>` children (and legacy
`/data.bak.*` / `/data.staging.*` siblings), never on `/data` itself or
any other entry of it, with anchored-regex discovery, Lstat at admission
**and** immediately before deletion (TOCTOU re-check), never follows
symlinks, and never touches a directory an unresolved restore journal
references. The proxy holds no descriptors under `.restore-*`, so live
load is safe.

---

## 8b. Recovering from an interrupted restore (RISK-005)

A restore commit swaps the content of `/data` in place under a journal
(§ 6). If the process is killed inside the swap, `/data/.restore-journal.json`
remains and the directory holds a mix of previous and restored entries.
Culvert **refuses to start** in this state and prints:

```
FATAL: interrupted restore detected: a restore commit in "/data" was interrupted
in phase "promoting" (previous data at "/data/.restore-bak.<ts>-<pid>", staged
data at "/data/.restore-staging.<ts>-<pid>"). Resolve it with the stack stopped,
then start Culvert again:
    INSPECT:   --recover-restore
    REVERT:    --recover-restore --confirm=revert
    COMPLETE:  --recover-restore --confirm=complete
```

Choose deliberately, offline (`docker compose down` first; the recovery
also refuses while the proxy's data-dir lock is held):

- **REVERT** — undo the in-flight restore; the previous data is live again
  and the staged restore content is kept as a `.restore-staging` leftover
  for inspection. Safe default if you are unsure.
- **COMPLETE** — finish the restore you intended; the previous data stays
  in `.restore-bak`.

Both are deterministic for every phase and idempotent (interrupted again ⇒
run the same command again). Afterwards `docker compose up -d`, verify, and
remove the leftover with `--cleanup-restore-leftovers` (§ 8).

Installs upgraded from a build that used the old sibling layout
(`/data.bak.<ts>-<pid>` next to a missing `/data`) still get the legacy
`mv`-based instructions at startup; nothing in that layout is touched by
the new build.
## 9. Passphrase handling

`CULVERT_BACKUP_PASSPHRASE` controls encrypted-backup creation and
encrypted-backup decrypt during restore. Three operator-supported
channels, ranked from least to most production-grade:

### 9.1 Inline `-e VAR=value` *(throwaway tests only)*

```bash
docker compose --profile cli run --rm \
  -e CULVERT_BACKUP_PASSPHRASE='lab-only-please' \
  cli --encrypt --backup /backup/lab.tar.gz.enc
```

The value lands in shell history and in `ps` for the parent shell. **Do
not use in production.**

### 9.2 Bare `-e VAR` forwarding from shell env *(standard operator workflow)*

Source the value from a `.env` file (chmod `0600`, gitignored), a
password store like `pass`/`gopass`, or a secrets manager:

```bash
# Read from a file the operator owns:
set -a; source ./prod.env; set +a

# Forward the env without echoing it into argv:
docker compose --profile cli run --rm \
  -e CULVERT_BACKUP_PASSPHRASE \
  cli --encrypt --backup /backup/culvert-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.enc
```

The bare `-e VAR` form (no `=value`) tells Docker to forward the
existing env-var value without it appearing in argv.

For ad-hoc use, prefix the line with a space and `set +o history` first
so the env-source line itself doesn't land in shell history:

```bash
set +o history
 source ./prod.env       # leading space skips history, plus history is off
docker compose --profile cli run --rm -e CULVERT_BACKUP_PASSPHRASE cli ...
set -o history
```

### 9.3 Docker / Compose secret *(production / multi-operator)*

Mount the secret as a file; have a wrapper entrypoint or operator shell
read it into `CULVERT_BACKUP_PASSPHRASE` for the one-shot `cli`
invocation. Requires Compose v2 secret support or Swarm.

This option is recommended for production deployments with multiple
operators or when the passphrase is rotated by a non-human process.

### 9.4 CA-3 key-at-rest: KEK handling & recovery

CA-3 (key-at-rest) optionally encrypts the **private keys** Culvert stores —
the cluster CA key (`cluster-ca.key`), the Data Plane node key
(`dp-node.key`), and CDR/Sluice client keys — each enabled by its own opt-in
env var (`CULVERT_CLUSTER_CA_ENCRYPT`, `CULVERT_DP_NODE_KEY_ENCRYPT`,
`CULVERT_CDR_CLIENT_KEY_ENCRYPT`). When enabled, those files become encrypted
`PSCA` envelopes on disk, unwrapped at load time by a **key-encryption key
(KEK)** resolved as:

1. `CULVERT_KEK` (a hex-encoded 32-byte key supplied via env / mounted secret), or
2. a local model-B KEK file next to the key it wraps —
   `cluster-ca.kek`, `dp-node.kek`, `<cdr-client-key>.kek`.

**The backup archive never contains a KEK.** The Culvert backup format is a
strict named allowlist, and the packer additionally refuses any `*.kek` file
as defense-in-depth (so a KEK can never share an archive with the encrypted
key it unwraps — that would defeat at-rest encryption). This means:

- **Which keys `--backup` actually captures.** The backup allowlist includes
  the **cluster CA key only** (`data/cluster-ca.key`, encrypted or plaintext).
  The **DP node key** (`dp-node.key`, written relative to the node's working
  dir) and **CDR/Sluice client keys** (under `/data/integrations/sluice/…`)
  are **not** in `defaultBackupArtifacts` and are therefore **not archived by
  `--backup`** — encrypting them does not change that. Those identities are
  designed to be **re-issued by re-enrollment**, not restored from a Culvert
  backup, so there is no DP/CDR key to "back up together with its KEK."
- **Encrypted cluster CA key backup + its KEK must be restored *together
  operationally*, but are *never stored together* by default.** Back up the
  encrypted `cluster-ca.key` via the normal `--backup` flow; provision its KEK
  out-of-band (the `CULVERT_KEK` secret, or a separately-stored copy of the
  local `cluster-ca.kek`). Restoring the archive alone is not sufficient to
  bring an encrypted cluster CA back up — the KEK must be supplied through its
  normal env/secret path.
- **If a KEK is lost, the keys it wraps are unrecoverable by design.** For the
  **cluster CA** (the one key that *is* in the backup) this means generating a
  new cluster CA and **re-enrolling** DP nodes. For a **DP node or CDR
  instance** key — which is not backed up at all — recovery is likewise
  **re-enrollment** of that node/instance. Store each KEK in a separate secret
  system (password manager / KMS / sealed secret) **before** enabling
  encryption.
- **Restore dry-run validates an encrypted key on its cert alone.** Because the
  validator has no KEK, it confirms the `PSCA` envelope is recognized and the
  paired public cert parses; it does **not** decrypt the key. Plaintext keys
  still get full cert/key cross-validation. (Full KEK-based decrypt during
  restore is intentionally deferred.)

### 9.5 Alert-webhook signing secrets are not portable

Alert webhooks (`alert_webhooks.json`) **are** in the backup, and their HMAC
signing secrets are AES-GCM encrypted at rest under a **node-local** key file,
`<dataDir>/.alert_webhook_key`. That key follows the same rule as a KEK: it is
never archived, and the packer refuses it explicitly, because shipping it in
the same tarball as the ciphertext it unwraps would make the encryption
decorative for anyone holding the archive.

So after restoring onto a host that does not have the original
`.alert_webhook_key`:

- The webhooks come back — name, URL, events, enabled state — but their
  signing secrets **cannot be unwrapped**, so deliveries go out **unsigned**
  (no `X-Culvert-Signature` header). A receiver that verifies the signature
  will reject this node's alerts.
- This is **visible, not silent**: the affected webhooks are badged
  *"Unsigned — secret unusable"* in **Security → Alert Webhooks**, and
  `/api/diagnostics` carries an `alert_webhook_signing` warn row.
- **Recovery — two paths, and the order matters:**
  1. **If you still have the node's original `.alert_webhook_key`** (kept
     out-of-band, the same way you would keep a KEK — § 9.4): restore it and
     restart **first**. The stored ciphertext is preserved untouched, so every
     affected webhook recovers with no re-entry.
  2. **Otherwise:** edit each affected webhook and re-enter its signing secret.

  Do **not** restore the old key file *after* re-entering secrets. A re-entered
  secret is sealed under this node's current key, so putting the old key back
  would recover the restored webhooks and break the re-entered ones instead.
  (Culvert no longer creates a key as a side effect of a failed decrypt, so a
  node in this state has no key file at all until you supply one or write a
  secret — that is what makes path 1 clean.)

  A config *import*, which replaces the webhook list wholesale, discards the
  preserved ciphertext; take path 1 before importing if you intend to use it.

---

## 10. Runtime vs offline matrix

| Operation | Mode | Why |
|---|---|---|
| `--backup` (unencrypted) | **Runtime** | Read-mostly walk of `/data`. Manifest sha256 captures point-in-time content. |
| `--backup --encrypt` | **Runtime** | Same as above. Encryption is in-process, no extra fs interaction. |
| `--restore <tar>` (dry-run) | **Runtime** | No writes. Tarball decoded in memory. |
| `--restore <tar> --confirm` | **Offline (mandatory)** | Atomic swap of `/data`. Open file descriptors held by the daemon would become invalid; admin actions during the swap would race. |
| `--list-restore-leftovers` | **Runtime** | Read-only Lstat walk of `/data`'s siblings. |
| `--cleanup-restore-leftovers` (dry-run) | **Runtime** | Read-only. |
| `--cleanup-restore-leftovers --confirm` | **Runtime** | Operates on siblings of `/data` only. The proxy holds no descriptors there. |

---

## 11. Where to find backups and logs

| Path | Mounted at | Volume / Source | Contains |
|---|---|---|---|
| `/data/proxy.log` | proxy + cli | `proxy-data` | Rotating proxy request log |
| `/data/audit.jsonl` | proxy + cli | `proxy-data` | Persistent audit trail |
| `/data/config_versions/v{N}.json` | proxy + cli | `proxy-data` | Auto-snapshotted config (50 max) |
| `/backup/culvert-*.tar.gz[.enc]` | cli only | `culvert-backups` | Backup archives created by § 3 / § 4 |

To copy backups off the host (named-volume case):

```bash
# One-shot cp out of the named volume via a transient container:
docker compose --profile cli run --rm \
  --entrypoint sh \
  cli -c 'cat /backup/culvert-20260501T030000Z.tar.gz.enc' \
  > ./culvert-20260501T030000Z.tar.gz.enc
```

For routine off-host transfers, prefer the host-bind-mount override
shown in § 2.

---

## 12. What NOT to do

- **Don't put the passphrase in `docker-compose.yml`.** The supplied
  compose file references `CULVERT_BACKUP_PASSPHRASE` symbolically
  only. Committing a value to git defeats the entire D1.4 design.
- **Don't pass the passphrase as an inline value in production.**
  Use the bare `-e VAR` form (§ 9.2) so the value never appears in
  argv, in `ps`, or in `docker compose logs`.
- **Don't run restore commit while `proxy` is up.** Always
  `docker compose down` first. The CLI does not detect a running
  daemon on the same host — operator discipline enforces this.
- **Don't use a manual `tar -C /data -czf …` recipe.** Manual tarballs
  bypass the manifest, sha256, schema-version, and CA-bundle
  cross-validation that the Culvert backup format provides — the
  restore tool will refuse anything not produced by `--backup`. There
  is no supported workflow for restoring from a filesystem-level
  `tar`.
- **Don't off-host copy unencrypted backups.** They contain ui_users
  hashes, TOTP secrets, the cluster CA private key (plaintext unless CA-3
  encryption is enabled — see § 9.4), session HMAC, and IdP profiles (OIDC
  client secrets and LDAP bind credentials). Use `--encrypt` for anything
  that leaves the host.
- **Don't store a CA-3 KEK in the same place as the backup.** The KEK
  (`CULVERT_KEK` or a local `*.kek` file) unwraps the encrypted private keys;
  keeping it beside the archive defeats at-rest encryption. The backup format
  already excludes `*.kek` files (§ 9.4) — provision the KEK out-of-band, and
  remember that losing it makes encrypted keys unrecoverable.
- **Don't mount `/var/run/docker.sock` into `cli`.** The `cli` service
  is intentionally socket-free. Maintenance ops that need the socket
  belong to the D1.6 Maintenance Agent (see
  [`release-management-agent.md`](release-management-agent.md)), which runs
  host-side, not inside this container.
- **Don't mount `/backup` into `proxy`.** The proxy must not be able
  to read its own prior backups. `/backup` is `cli`-only by contract.
