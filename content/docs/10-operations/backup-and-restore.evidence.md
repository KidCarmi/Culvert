# Claim-Evidence Ledger — "Backup & restore"

Article: [`backup-and-restore.md`](backup-and-restore.md). Verified against repo
revision `ca60d83`.

| Claim | Type | Evidence |
|---|---|---|
| Backup/restore via profile-gated `cli` service, one-shot `run --rm` | cfg | `docker-compose.yml:192-234` |
| `cli` shares the proxy image tag (no version skew) | cfg | `docker-compose.yml:215-223` |
| `cli` mounts `/data` + `/backup`, no ports, no docker.sock | cfg | `docker-compose.yml:219-234` |
| `/backup` volume mounted only in `cli`, not the proxy | cfg | `docker-compose.yml:227-239` (proxy service has no `culvert-backups` mount) |
| Encrypted backup default: `--encrypt --backup …` + `CULVERT_BACKUP_PASSPHRASE` | cfg | `docker-compose.yml:199-203` |
| AES-256-GCM, PBKDF2-SHA256 @ 600,000 iters, versioned envelope | src | `internal/backupcrypt/backupcrypt.go:2,14-20,56` |
| Restore dry-run is runtime-safe | cfg | `docker-compose.yml:205-208` (dry-run "safe while proxy is up") |
| Restore commit (`--confirm`) is offline-only | cfg | `docker-compose.yml:219-221` |
| List/cleanup restore leftovers | cfg | `docker-compose.yml:210-211`; operator doc |
| Wrong-passphrase indistinguishable from tamper (GCM Open error class) | src | `internal/backupcrypt/backupcrypt.go:27` (comment) |

## Notes

- The article's commands mirror the shipped compose examples verbatim; the crypto
  parameters are read from `backupcrypt` (the same 600k-iter PBKDF2 / AES-256-GCM
  envelope family used for the CA key at rest).
- Full operator surface (all flags, edge cases) is delegated to the in-repo
  operator how-to rather than re-derived.
