# Persistent state, backup scope and key custody

Source: inventory of every writer under `/data` (`backup.go`
`defaultBackupArtifacts`, `restore.go` mode predicates, `data_dir.go`,
`internal/secret`, `cluster_ca_keyatrest.go`, `internal/alerts/secret.go`,
`internal/upstream/credkey.go`). Executed evidence for the "verified by
restore" column: `test/e2e/appliance/lifecycle-qualify.sh` scenario D
(encrypted backup → offline in-place restore on the mounted volume → boot →
login + policy + enforcement + `ssl_inspection=ready`).

Legend — **Upgrade**: preserved across an image upgrade (volume is untouched)
· **Backup**: in the archive (T1 required, T2 optional) · **Restore full**:
what a `--mode full` commit leaves live · **Custody**: must be kept OUTSIDE
the archive for a restore to be usable.

## 1. Trust roots and identity

| Path | Holds | Upgrade | Backup | Restore full | Custody / after restore |
|---|---|---|---|---|---|
| `ca.bundle` | SSL-inspection root CA cert+key (AES-GCM under `CULVERT_CA_PASSPHRASE`) | kept | T1 | from archive; **removal/replacement now guarded** (`--accept-root-ca-change`) | `CULVERT_CA_PASSPHRASE` (in `/srv/culvert/.env`, generated per install) must match the archive's; without it dry-run fails and inspection is disabled. Clients must trust this root |
| `cluster-ca.crt/.key` | Cluster (DP enrollment) CA | kept | T1 | from archive; DP guard (`--accept-dp-reenrollment`) | `cluster-ca.kek` or `CULVERT_KEK` when CA-3 encryption is on — never archived; losing it means a new cluster CA + DP re-enrollment. **Single-node compose writes these to `/app` (ephemeral), not `/data` — not relevant to the pilot, gap for clusters** |
| `cluster-ca.kek`, `*.kek` | File KEKs wrapping encrypted keys | kept | **excluded** (node-local) | carried over from current `/data` in every mode | separate custody if the encrypted key is to be restored onto a NEW host; a missing KEK is re-minted and the key then fails closed |
| `cluster.json` | Enrolled DP roster + token hashes | kept | T1 | from archive | — |
| `ui_tls_cert.pem` / `ui_tls_key.pem` | Custom admin-UI certificate | kept | **excluded** | dropped (full) | re-upload after a full restore; self-signed fallback otherwise |
| `ha_config.json`, `dp_*` | HA / DP identity | kept | excluded | dropped | OUT of the pilot |
| session-signing key | admin cookie HMAC | **not persisted** (random per process unless `CULVERT_SESSION_SECRET`) | n/a | n/a | set `CULVERT_SESSION_SECRET` in `.env` to keep sessions across restarts (optional) |

## 2. Admin accounts and settings

| Path | Holds | Upgrade | Backup | Restore full | Custody / after restore |
|---|---|---|---|---|---|
| `ui_users.json` | Admin roster, password hashes, TOTP secrets/backup codes/replay counter, default auth outcome | kept | T1 | from archive; TOTP counter rollback guarded; **a restore leaving no admin is refused** | archive is sensitive (hashes + TOTP secrets): encrypt backups |
| `admin_settings.json` | Runtime settings incl. `metrics_token`, OTLP headers, traffic pseudonym key, sealed upstream v2 credentials | kept | T2 (upstream credentials **stripped**, `requiresReplacement`) | from archive | upstream parent-proxy passwords must be **re-entered** (T2 replace) after restore; `.upstream_cred_key` is never archived |
| `idp_profiles.json` | OIDC/SAML/LDAP profiles incl. client secrets / bind passwords (plaintext) | kept | T2 | from archive | archive is sensitive; encrypt backups |
| `alert_webhooks.json` + `.alert_webhook_key` | Webhook URLs + sealed HMAC secrets / the node-local key | kept | T2 / **excluded** | from archive / carried over | without the original key deliveries are **unsigned** (`signing_degraded`); restore the key file first or re-enter secrets |
| `policy.json(.meta)`, `policy_draft.json` | Access rules / draft | kept | T2 / excluded | from archive / dropped | — |
| `categories.json`, `category_groups.json`, `decryption_profiles.json`, `blocklist.txt*`, `pac_*.json`, `fileprofiles.json`, `fileblock.json`, `ssl_bypass.json`, `dpi_patterns.json`, `scan_exclusions.json`, `bandwidth.json`, `node_groups.json`, `cdr_policies.json`, `config_versions/` | Policy objects and config history | kept | T2 (config_versions T1) | from archive | — |
| `release_dispatch_state.json` | In-flight release dispatch record (new) | kept | excluded | dropped | bookkeeping only; a dropped record means "no dispatch recorded" |

## 3. Operational data (never archived — survives upgrades, lost on full restore except in `.restore-bak`)

`proxy.log`, `audit.jsonl`, `requests.jsonl`, `logstore/` + `logstore.salt`
(encrypted request history), `threatfeeds.json`, `catfeeddb/`, `yara/`,
`release_catalog/` + `release_catalog_state.json`, `support/`, `hit_counters.json`,
`policy_learning*`, `cdr_instances.json` + `integrations/sluice/*` (CDR mTLS
identity — re-enroll CDR after a full restore), MCP state. These are
retention/cache data; a full restore keeps the previous copies in
`/data/.restore-bak.<ts>-<pid>/` until cleaned up.

**Request history is recoverable separately:** `POST /api/logs/history/export`
(Logs → Retention → Export history) produces an archive encrypted under an
operator-chosen passphrase, independent of the node-local log key; `culvert
--history-import <file> --confirm` writes it into any store under that store's
key — the recovery path after volume loss and the re-key path for a log
passphrase change (`docs/operator/request-history-recovery.md`).

## 4. Keys and secrets requiring SEPARATE custody (never in the archive)

| Secret | Where it lives | Lose it and… |
|---|---|---|
| `CULVERT_BACKUP_PASSPHRASE` | operator secret store | the archive is unreadable |
| request-history archive passphrase (`CULVERT_HISTORY_PASSPHRASE` at import) | operator secret store, with the archive | the history archive is unreadable |
| `CULVERT_CA_PASSPHRASE` / `CULVERT_LOG_PASSPHRASE` | `/srv/culvert/.env` (mode 600, generated by the installer) | `ca.bundle` cannot be decrypted → inspection disabled; `logstore/` unreadable |
| `cluster-ca.kek` / `CULVERT_KEK` | `/data` (file) or env | encrypted cluster CA key fails closed (clusters only) |
| `.alert_webhook_key`, `.upstream_cred_key` | `/data` | webhooks unsigned; upstream credentials need re-entry regardless |
| `CULVERT_SESSION_SECRET` (optional) | `.env` | sessions reset on restart |
| DP node keys, CDR client keys | DP working dir / `integrations/sluice` | re-enroll |

**Operator rule:** back up `/srv/culvert/.env` (contains the CA/log
passphrases) to the secret store SEPARATELY from the archive; a VM snapshot
is not an application-consistent backup and does not replace the archive +
passphrase pair.
On the OVA the values are read from the authenticated VM console:
`[0]` Recovery → `[4]` Show recovery secrets (password asked again; only the
two passphrase keys are printed; screen and scrollback cleared afterwards;
audited by name, never by value). See `first-boot.md` §5.

## 5. What a restore proves (executed here)

Scenario D of the harness: backup taken while running → an admin created
after the backup → commit refused while the proxy runs (data-dir lock) →
offline commit → boot → the original admin logs in, the post-backup admin is
gone, the rule is present, allow/block behaves, `ssl_inspection=ready`
(the restored `ca.bundle` decrypted under the install passphrase), previous
data preserved inside the volume, leftovers listed and cleaned. Scenario E
proves the interrupted-restore refusal and explicit recovery.
