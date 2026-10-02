# Persistent state, backup scope and key custody (pilot)

Evidence class per row: `src` (file:line), `test` (named test), `exec`
(executed in this work). Everything is under `<dataDir>` (`/data` in the
shipped compose, the `proxy-data` named volume) unless stated.

Legend for the Backup column: **B1/B2** = archived (tier 1 trust root /
tier 2 config), **S** = archived with sanitisation, **X** = deliberately
excluded, **—** = not under the data dir. Preserved-on-upgrade is "yes"
for everything on the volume: an image update replaces the container and
never touches `/data` (`cmd/culvert-maint` apply = pull, tag, `compose up`).

| Path | Holds | Preserved on image upgrade | Backup | Key needing separate custody | If missing/unusable after restore | Evidence |
|---|---|---|---|---|---|---|
| `ca.bundle` | Inspection root CA (ECDSA P-256), PSCA-encrypted under `CULVERT_CA_PASSPHRASE` (plain PEM if the passphrase is unset) | yes | B1 | **CA passphrase** (env, from the deployment `.env`) | Without the passphrase dry-run and commit refuse; without the file a NEW root is minted at boot and every client trust distribution is invalidated | `restore.go:609-629`; `internal/ca/ca.go:208-222` |
| `cluster-ca.crt/.key`, `cluster.json` | Enrollment trust root + DP roster (control-plane mode only) | yes only if `-cluster-db` points into `/data` (shipped compose did not; corrected in this PR) | B1 (first-run optional) | `cluster-ca.kek` / `CULVERT_KEK` when key-at-rest is on | Enrollment disabled; DPs must re-enroll | `cluster_startup_config.go:81`, `backup.go:70-72,305-308` |
| `ui_users.json` | Admin roster: bcrypt hashes, roles, TOTP secret/backup codes/replay counter, `default_auth_outcome` | yes | B1 | none | Appliance reopens unauthenticated first-time setup; TOTP counter rollback is refused unless `--allow-counter-rollback` | `store.go:1461-1483`; `restore.go:690-702,970-973` |
| `admin_settings.json` | All admin settings incl. sealed `upstream_proxies_v2`, IP filter, rewrite rules, OTLP headers, metrics token, traffic pseudonym key, default action sentinel (new) | yes | S (upstream credentials stripped, entries marked `requiresReplacement`) | `.upstream_cred_key` | Upstream entries boot into `requiresReplacement` and need T2/T3 re-entry; other settings restored as-is. Note: `otlp_headers`, `metrics_token`, `traffic_pseudonym_key` travel in PLAINTEXT inside the archive unless `--encrypt` | `backup.go:386-395`, `upstream_backup_strip.go`, `config_surfaces.go:347-350,499` |
| `.upstream_cred_key` | AES key sealing upstream credentials | yes | X | **yes** (node-local; never archived, never minted on a failed read) | `credentialState: unusable`; re-enter credentials (T2) or clear (T3) | `internal/upstream/credkey.go:41-56`; `backup.go:198-201` |
| `alert_webhooks.json` + `.alert_webhook_key` | Webhooks with AES-GCM sealed secrets / their key | yes | B2 / X | **yes** (`.alert_webhook_key`) | Deliveries continue UNSIGNED and are badged `signing_degraded`; restore the original key file first, else re-enter each secret | `internal/alerts/secret.go:52-66` |
| `idp_profiles.json` | OIDC/SAML/LDAP profiles including client secrets / bind passwords | yes | B2 (raw) | none (plaintext in archive; use `--encrypt`) | re-create profiles | `backup.go:122-133` |
| `policy.json(.meta)`, `blocklist.txt*`, `categories.json`, `category_groups.json`, `ssl_bypass.json`, `dpi_patterns.json`, `decryption_profiles.json`, `fileblock.json`, `fileprofiles.json`, `pac_*.json`, `scan_exclusions.json`, `alert_settings.json`, `bandwidth.json`, `node_groups.json`, `saas_feed/overrides.json`, `cdr_policies.json` | Policy and feature configuration | yes | B2 | none | Re-create; config versions (below) can roll back | `backup.go:64-164` |
| `config_versions/` | Numbered config snapshots (max 50) | yes | B1 (walked; key files skipped) | none | Lose rollback history only | `internal/configver` |
| `cdr_instances.json`, `cdr_enroll_receipts.json`, `integrations/sluice/*` (+`.kek`), `cdr_enabled` | CDR (Sluice) enrollment identity + mTLS | yes | X (deliberate) | `.kek` | Re-enroll CDR instances; restoring these would block re-enrollment (409) | `backup.go:148-161` |
| `audit.jsonl`, `requests.jsonl`, `proxy.log` | Compliance/request/process logs (rotating) | yes | X (tier 3) | none | History lost; forward to syslog/SIEM for retention | `backup_test.go:205-217` |
| `logstore/` + `logstore.salt` | Encrypted request-history store + KDF salt | yes | X | `logstore.salt` (never minted over existing content) | History lost; the salt is a sibling so a quarantined copy stays decryptable | `internal/logstore/logstore.go:199-230` |
| `catfeeddb/`, `threatfeeds.json`, `hashcache.json`, `hit_counters.json`, `alert_retry_queue.json` | Caches / feeds / counters | yes | X | none | Re-synced or regenerated | `backup_test.go:205-217` |
| `release_catalog/`, `release_catalog_state.json` | Verified release catalog + monotonic version floor | yes | X | none | Re-seeded from the catalog origin at boot; rollback floor restarts | `release_catalog_freshness.go:69-71` |
| `release_dispatch_state.json` (new) | In-flight update dispatch record (resume context) | yes | X (runtime) | none | A control-plane restart mid-update can no longer resume automatically | this PR |
| `mcp_distribution/`, `mcp_tooltrust/`, other MCP state | MCP gateway durable state (feature OFF in pilot) | yes | X | none | re-distributed from CP | `backup.go` allowlist |
| `policy_learning.json` + `policy_learning_subject.key` | Learning sessions / pseudonym key (feature OFF in pilot) | yes | X | key (minted if missing, refused if wrong length) | sessions lost; `subject_key_changed` | `internal/policylearn/pseudonym.go:57-79` |
| `ui_tls_cert.pem`, `ui_tls_key.pem` | Customer-issued admin UI certificate | yes | X | **yes** (private key; re-upload from the customer's PKI) | falls back to self-signed on boot | `ui_tls_custom.go:43-44` |
| `.restore/` (new), `.culvert.lock` (new) | Restore work dir + journal; advisory data-dir lock | n/a | X (must never be archived) | none | n/a | this PR |
| `dp_enrollment.json`, `dp-node.crt/.key(.kek)` | Data-plane identity (cluster mode) | **no** — CWD-relative in the container layer today | — | `dp-node.kek` | re-enrollment by design | `dp_enrollment.go:37,192` (finding, cluster-only) |
| Session HMAC key | Admin session signing key | n/a (not on disk) | — | `CULVERT_SESSION_SECRET` in the deployment `.env` (generated by the installer in this PR) | all admin sessions invalidated on restart if unset | `session.go:41-77` |

## Separate-custody checklist (what the customer must keep outside the appliance)

1. `CULVERT_CA_PASSPHRASE` and `CULVERT_SESSION_SECRET` from `/srv/culvert/.env`.
2. `CULVERT_BACKUP_PASSPHRASE` for encrypted archives ("lose the passphrase, lose the backup").
3. Node-local key files, copied with restricted permissions to the customer vault if they want restores that need no re-entry: `/data/.upstream_cred_key`, `/data/.alert_webhook_key`, any `*.kek`, `/data/logstore.salt`. These are NEVER in an archive by design; a restore onto a fresh volume without them requires credential re-entry (upstream T2/T3, webhook secrets) and that is the intended, documented posture.
4. The admin UI private key (`ui_tls_key.pem`) is the customer PKI's to re-issue.

## Credentials or identities that must be re-established after a restore to a NEW volume

| Item | Action |
|---|---|
| Upstream proxy credentials | T2 replace or T3 clear per entry (`requiresReplacement` badge) |
| Alert webhook secrets | restore `.alert_webhook_key` or re-enter |
| CDR (Sluice) instances | re-enroll (feature OFF in pilot) |
| Data-plane nodes (cluster mode) | re-enroll if the cluster CA fingerprint changed (`--accept-dp-reenrollment` acknowledges this) |
| Clients' trust in the inspection CA | unchanged if `ca.bundle` + passphrase restored; otherwise redistribute the new CA |

## Verification performed in this work

See `qualification-evidence.md` for the executed restore round-trips
(in-volume journaled commit on a real bind mount, interruption at every
phase, lock refusal) and the real-predecessor upgrade runs (v1.0.235,
v1.0.250, v1.0.258 → v1.0.259 with seeded roster, sealed upstream
credential, webhook and policy, then the reverse leg).
