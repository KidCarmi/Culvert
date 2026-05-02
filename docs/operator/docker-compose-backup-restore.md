# Docker Compose — Backup & Restore

This is the supported operator path for Culvert backup, restore, and cleanup
when running under Docker Compose. It supersedes the legacy
`tar -C /data -czf …` guidance in `docs/OPERATIONS.md § 4`, which bypasses
Culvert's manifest, sha256, schema-version, and CA-bundle cross-validation.

> **TL;DR**
>
> ```bash
> # Encrypted backup — production default.
> CULVERT_BACKUP_PASSPHRASE=… docker compose --profile cli run --rm \
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
| `/data` | `proxy-data` | `proxy` (rw), `cli` (rw), `updater` (ro) | Product state: identity, policy, audit, blocklists, request log, CA bundle, `cluster.json`, `config_versions/`, `ui_users.json`, etc. |
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
> session HMAC, and full policy state. For anything outside an
> ephemeral lab, use § 3 instead.

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

Restore commit is **destructive and offline-only**. It performs an
atomic swap of `/data` (current `/data` → `/data.bak.<ts>-<pid>`,
staging dir → `/data`). The proxy must be stopped first or its open
file descriptors will outlive the swap and admin actions during the
swap will race.

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
3. Refuses on guard violations unless explicitly acknowledged with
   `--accept-dp-reenrollment` or `--allow-counter-rollback`.
4. Stages the new content under `/data.staging.<ts>-<pid>`.
5. Renames current `/data` → `/data.bak.<ts>-<pid>` (preserved for
   rollback; see § 8 to clean up later).
6. Renames the staging dir → `/data`.
7. fsyncs the parent directory.

The previous `/data` is preserved as `/data.bak.<ts>-<pid>` indefinitely.
Once you've verified the restored state, clean it up with the cleanup
command (§ 8). The `.bak` directory is never auto-deleted.

### Recovery if step 2 fails after rename A

If the process is killed between the two renames, the error message
names the exact `mv` recovery command. Worst case: `mv /data.bak.<ts>-<pid>
/data` brings the prior state back.

---

## 7. List restore leftovers

Inventory `.bak.<ts>-<pid>` and `.staging.<ts>-<pid>` siblings of `/data`
left behind by past restore commits or killed restores.

```bash
docker compose --profile cli run --rm cli --list-restore-leftovers
```

Output:

```
PATH                                            TYPE     AGE      SIZE
/data.bak.20260428T101500Z-1234                 bak      4d 2h    412.3 MB
/data.staging.20260501T030000Z-9876             staging  1d 11h   8.2 MB
```

Read-only; safe any time.

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
on siblings of `/data`, never on `/data` itself, with sibling-only
discovery, anchored regex, Lstat at admission **and** immediately
before deletion (TOCTOU re-check), and never follows symlinks. The
proxy holds no descriptors under `/data.bak.*` or `/data.staging.*`,
so live load is safe.

---

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
- **Don't use the legacy `tar -C /data -czf …` recipe.** It bypasses
  the manifest, sha256, schema-version, and CA-bundle cross-validation
  that D1.3 introduced. The Culvert restore tool will not accept tarballs
  that were not produced by `--backup`.
- **Don't off-host copy unencrypted backups.** They contain ui_users
  hashes, TOTP secrets, the cluster CA private key, and session HMAC.
  Use `--encrypt` for anything that leaves the host.
- **Don't mount `/var/run/docker.sock` into `cli`.** The `cli` service
  is intentionally socket-free. Maintenance ops that need the socket
  belong to the future D1.6 Maintenance Agent.
- **Don't mount `/backup` into `proxy`.** The proxy must not be able
  to read its own prior backups. `/backup` is `cli`-only by contract.
