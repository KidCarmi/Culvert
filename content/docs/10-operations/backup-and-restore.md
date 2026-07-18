# Backup & restore

Culvert's state is a single data volume. Backup and restore are performed by a
dedicated, profile-gated **operator container** — never by the running proxy —
so an operator can snapshot and recover a deployment with encrypted archives and
a safe, offline restore-commit path.

Prerequisite reading: [Quick start](../02-getting-started/quick-start.md).

---

## Purpose

Produce encrypted backups of Culvert's persistent state and restore them, with a
clear separation between a safe dry-run analysis and the destructive commit.

## The operator contract

All operations run through the profile-gated `cli` service in
`docker-compose.yml`, invoked one-shot:

```bash
docker compose --profile cli run --rm cli <flags>
```

The `cli` service uses the **same image** as the proxy (the shared
`culvert/proxy:pinned` tag), so the CLI and the daemon never version-skew. It
mounts the data volume and the backup volume, exposes **no ports**, and does
**not** mount the Docker socket (`docker-compose.yml:215-234`). A bare
`docker compose up -d` does not start it.

### Security boundaries baked into the contract

- The backup volume (`culvert-backups`, mounted at `/backup`) is mounted **only
  in `cli`**, not in the proxy container — the running proxy cannot read its own
  backups (`docker-compose.yml:227-239`).
- The `cli` service never mounts `/var/run/docker.sock`.
- The **restore commit is offline-only**: stop the daemon before committing
  (`docker-compose.yml:219-221`).

---

## Backup

Encrypted backup is the production default. Supply the passphrase via the
environment (never on the command line):

```bash
docker compose --profile cli run --rm \
  -e CULVERT_BACKUP_PASSPHRASE \
  cli --encrypt \
      --backup /backup/culvert-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.enc
```

The archive is a compressed tar of the data volume, sealed with **AES-256-GCM**;
the key is derived from `CULVERT_BACKUP_PASSPHRASE` with **PBKDF2-SHA256 at
600,000 iterations** (`internal/backupcrypt/backupcrypt.go:56`). The envelope is
versioned (magic, KDF id, cipher id, GCM tag) so future formats remain
decodable.

## Restore

Restore has two phases. **The dry-run is safe while the proxy is running; the
commit is offline-only.**

### 1. Dry-run (analysis) — runtime-safe

```bash
docker compose --profile cli run --rm \
  -e CULVERT_BACKUP_PASSPHRASE \
  cli --restore /backup/culvert-20260501T030000Z.tar.gz.enc
```

This validates and analyzes the archive without replacing live state.

### 2. Commit — offline only

```bash
docker compose down                                  # stop the daemon first
docker compose --profile cli run --rm \
  -e CULVERT_BACKUP_PASSPHRASE \
  cli --restore /backup/culvert-20260501T030000Z.tar.gz.enc --confirm
docker compose up -d                                 # bring it back
```

Committing while the daemon is running is intentionally not supported — bring
it down, commit, bring it up.

## Restore leftovers

A restore may quarantine files it replaces. List and clean them up:

```bash
# List (runtime-safe)
docker compose --profile cli run --rm cli --list-restore-leftovers
# Clean up (dry-run, then --confirm)
docker compose --profile cli run --rm cli --cleanup-leftovers
docker compose --profile cli run --rm cli --cleanup-leftovers --confirm
```

---

## Validation steps

1. Take an encrypted backup.
2. Run a restore **dry-run** against it and confirm it validates.
3. (In a test environment) stop the daemon, commit the restore, bring it up, and
   verify `/ready` returns `200` (see
   [Quick start → readiness](../02-getting-started/quick-start.md#validation-steps)).

## Failure modes

| Condition | Behavior |
|---|---|
| Wrong passphrase | Decryption fails; AES-GCM returns the same error class as tampering (indistinguishable by design) |
| Corrupt / tampered archive | GCM authentication fails; restore refuses |
| `--confirm` while the daemon runs | Not supported — stop the daemon first |
| Backup path outside `/backup` | The backup volume is only mounted at `/backup` in `cli` |

## Security implications

- Treat `CULVERT_BACKUP_PASSPHRASE` as a high-value secret; without it, an
  encrypted backup is unrecoverable (there is no escrow).
- The proxy cannot read the backup volume — keep it that way; do not mount
  `/backup` into the proxy service.
- Store backup archives off-host; the archive contains sensitive state (keys,
  policy, sessions) protected only by the passphrase.

## Known limitations

- Restore commit requires downtime (offline-only by contract).
- Wrong-passphrase and tamper are indistinguishable at decrypt time (a property
  of authenticated encryption, not a bug).
- The `cli` service shares the proxy image tag; upgrading the proxy retags it in
  lockstep — restore with a matching image version.

## Related documentation

- [Quick start](../02-getting-started/quick-start.md) ·
  [Control Plane / Data Plane](../08-distributed/control-plane-data-plane.md).
- In-repo operator how-to:
  [`../../../docs/operator/docker-compose-backup-restore.md`](../../../docs/operator/docker-compose-backup-restore.md).

## Source evidence

Claim-evidence ledger: [`backup-and-restore.evidence.md`](backup-and-restore.evidence.md).
