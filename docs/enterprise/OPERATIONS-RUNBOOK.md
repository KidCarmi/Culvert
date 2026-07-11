# Enterprise Operations Runbook

Day-2 procedures for operators. Each runbook: **trigger → symptoms → customer impact → diagnosis → command/UI → expected output → recovery → verification → rollback → escalation.**

Interfaces referenced:
- **Liveness/readiness:** `:8080/health`, `:8080/ready`, `:9090/healthz` (HA).
- **Operator contract:** Admin UI → Infrastructure → Diagnostics (`GET :9090/api/diagnostics`, viewer).
- **Host CLI:** `docker compose` from the stack dir (default `/srv/culvert`), `--profile cli` for backup/restore.

> Where a step needs host/container shell, it is marked **[HOST]**. A no-SSH operating model must retain a break-glass path for these (see the Gap Register: GAP-BAK-01, GAP-IAM-01, GAP-UPD-02).

---

## Startup

- **Trigger:** bring up a node. **Command:** `docker compose up -d` **[HOST]** (or the platform's start).
- **Expected:** ClamAV health passes (first run ~2–5 min for signatures), then proxy. `:8080/health`=200.
- **Verification:** `curl :8080/ready` → 200; Diagnostics verdict ≥ warn-with-known-warnings.
- **Escalation:** `/ready` stays 503 → check the gating rows (`session_secret`, `config_snapshot_validator`, `clamav`); see "Service failure".

## Shutdown

- **Command:** `docker compose down` **[HOST]** (graceful — drains active tunnels).
- **Verification:** `docker compose ps` shows no running services.
- **Note:** required before a **restore commit** (restore is offline-only).

## Restart

- **Command:** `docker compose restart proxy` **[HOST]**.
- **Note:** a restart **clears in-memory brute-force lockouts** — this is the documented break-glass for a stuck lock.

## Health validation

- **Diagnosis:** `curl :8080/ready` (LB view) and Diagnostics (operator view). `/ready` gates on hard-fail only; Diagnostics shows warnings too.
- **Expected `/ready`:** `{"status":"ready","checks":{...}}`. `policy_loaded: fail` on a fresh install is expected (default-deny).
- **Escalation:** persistent `not_ready` after restart → investigate the failing subsystem's logs.

## Service failure (proxy won't become ready)

- **Symptoms:** `/ready`=503; clients can't proxy.
- **Diagnosis:** `docker compose logs --tail=100 proxy` **[HOST]**; check Diagnostics gating rows.
- **Recovery:** fix the flagged subsystem (session secret, ClamAV reachability, storage). Restart.
- **Rollback:** if a recent config/image change caused it — config-version rollback (settings) or image auto-rollback should already have fired; else roll back the image (see Updates).
- **Escalation:** collect logs + Diagnostics + config export for support (no support bundle exists — GAP-MON-01).

## Proxy failure (traffic errors, inspection breaks)

- **Symptoms:** TLS errors at clients; `/health` `ssl_inspection: load_failed|unavailable`.
- **Diagnosis:** `/health`; Diagnostics `ca` row; logs for `ca_load_failed`.
- **Recovery:** confirm `CULVERT_CA_PASSPHRASE` + `-ca-path`; restore `ca.bundle` from backup if corrupt; restart. If an imported CA "disappeared" after restart, that is expected (GAP-PKI-01) — re-stage the on-disk bundle.
- **Verification:** `/health` `ssl_inspection: ready`; pilot endpoint browses cleanly.

## Management-plane failure (admin UI down; CP down)

- **Symptoms:** `:9090` unreachable; DP nodes can't sync.
- **Diagnosis:** `docker compose ps`/`logs` **[HOST]**; `:9090/healthz`.
- **Impact:** DP nodes keep serving on last-known-good config (`dp_last_config_snapshot.json`); no new config/enrollment lands.
- **Recovery:** restart the CP; for HA, promote the standby (`-ha-auto-failover` off by default → manual promote unless an etcd fencing lease is armed).
- **Escalation:** if `/data` is corrupt, restore (below).

## Database / storage failure

- **Symptoms:** Diagnostics `storage_path: fail`; writes failing.
- **Diagnosis:** confirm the `/data` volume is mounted, writable, owned by the proxy UID, not full, not read-only, no SELinux denial (`docs/OPERATIONS.md §4`).
- **Recovery:** fix mount/permissions/space; **restart** (the writability probe is one-shot). If the disk is lost → "Disk-loss DR".
- **Note:** there is no relational DB — state is flat files under `/data`.

## Disk pressure

- **Symptoms:** "no space left on device"; log writes failing.
- **Diagnosis:** `df -h` **[HOST]**; check log sizes under `/data`.
- **Recovery:** logs rotate at fixed sizes; if pressure persists, prune old Docker images (`docker image prune`), lower `-log-max-mb`/`-request-log-max-mb`, ensure config-versions cap (50) is holding.

## Certificate expiry (inspection CA)

- **Trigger:** CA ≤30 days to expiry.
- **Diagnosis:** `GET /api/ca/status` `expiresIn`; `cert_expiry` webhook (fires on rotation — GAP-PKI-05).
- **Recovery:** auto-rotation handles it with dual-CA overlap; or `POST /api/ca/rotate` (admin, 2-step). **Distribute the new root** to endpoints within the 24h leaf window.
- **Verification:** `/api/ca/status` shows `dualCAActive`; pilot endpoint trusts new leaves.

## DNS failure

- **Symptoms:** proxy can't resolve destinations / IdP / catalog.
- **Diagnosis:** host resolver (`resolv.conf`), internal DNS reachability **[HOST]**.
- **Recovery:** fix host DNS (Culvert uses host DNS). GeoIP/policy fail closed on unknown — expect denies until resolved.

## NTP / time failure

- **Symptoms:** SAML/OIDC assertions rejected (clock skew); TLS validity errors.
- **Diagnosis:** `timedatectl` / `chronyc tracking` **[HOST]**.
- **Recovery:** fix host NTP (Culvert makes no NTP calls). Re-test SSO after sync.

## Authentication-provider outage (proxy IdP)

- **Symptoms:** proxy users can't log in (fail-closed); admins unaffected (local).
- **Diagnosis:** IdP reachability; the profile's built-in test action; logs.
- **Recovery:** restore the IdP or fix the profile. Existing signed sessions keep validating (cluster HMAC). In-flight SSO callbacks need LB affinity to the initiating node.
- **Escalation:** if egress must continue during a prolonged outage, consider a temporary policy exception (change-controlled).

## Policy compilation / load failure

- **Symptoms:** Diagnostics/logs show policy load warnings; conflict warnings.
- **Diagnosis:** conflict detection surfaces same-priority/different-action overlaps; config-version `config_rollback_validation` row.
- **Recovery:** fix or roll back to a known-good config version (dry-run first).

## Threat-feed failure

- **Symptoms:** feed sync errors in logs; stale `threat_feed_entries` on `/health`.
- **Diagnosis:** egress to `urlhaus.abuse.ch`/`openphish.com` (hard-coded, GAP-NET-02); logs.
- **Recovery:** restore egress or disable the feature (there is no internal-mirror option). Blocking still works from the last-synced DB.

## Update failure

- **Trigger:** a dispatched upgrade fails health/verify.
- **Behaviour:** **inline auto-rollback is default-on** — the agent re-pins the prior digest within the same operation. Outcome is classified `FAILED_ROLLED_BACK` (prior image confirmed) or `FAILED_NEEDS_ATTN`.
- **Diagnosis:** Release panel dispatch status; `POST /api/releases/dispatch/resume` to reconcile if the CP lost the watch.
- **Recovery:** if `FAILED_NEEDS_ATTN`, or to deliberately roll back, use the agent's `/v1/rollbacks` **[HOST]** (`mode=image`) — no CP/GUI route exists (GAP-UPD-02). Confirm the running digest afterward.
- **Note:** without a wired `compose_override_file`, an agent-driven recreate can drop the agent socket → "Agent unreachable" (GAP-UPD-04); re-wire per `docs/operator/release-management-agent.md`.

## Backup

- **Command [HOST]:**
  ```bash
  docker compose --profile cli run --rm -e CULVERT_BACKUP_PASSPHRASE \
    cli --encrypt --backup /backup/culvert-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.enc
  ```
- **Expected:** an encrypted archive in the `culvert-backups` volume; runtime-safe (proxy can stay up).
- **Contents:** `ca.bundle`, cluster CA + `cluster.json`, `ui_users.json`, `config_versions/`, policy/blocklist/categories/pac/ssl-bypass/admin_settings. Tier-3 (logs/caches) excluded.
- **Off-host:** copy the archive off the host (there is no built-in remote target — GAP-BAK-02). Automate with cron **[HOST]**.
- **Verification:** `docker compose --profile cli run --rm cli --list-restore-leftovers`; run a restore **dry-run** (below).

## Restore

- **Dry-run (safe, runtime-OK) [HOST]:**
  ```bash
  docker compose --profile cli run --rm -e CULVERT_BACKUP_PASSPHRASE \
    cli --restore /backup/<archive>            # no --confirm ⇒ dry-run
  ```
  **Expected:** `Validation: PASS` with admin count, DP count, CA fingerprint, bundle decrypt. Writes nothing.
- **Commit (offline, destructive) [HOST]:**
  ```bash
  docker compose down
  docker compose --profile cli run --rm -e CULVERT_BACKUP_PASSPHRASE \
    cli --restore /backup/<archive> --confirm --mode full
  docker compose up -d
  ```
  Guards may require `--accept-dp-reenrollment` (CA fingerprint changed with enrolled DPs) or `--allow-counter-rollback` (TOTP).
- **Rollback of a restore:** the previous `/data` is preserved as `/data.bak.<ts>-<pid>` (never auto-deleted); swap it back **[HOST]** if needed.
- **Verification (post-restore — do all):** `docker compose up -d` → `:8080/ready`=200 → admin login works → policy spot-check via Policy Tester → Diagnostics clean. (No automated post-restore check exists — GAP-BAK-04.)

## Rollback (image / config)

- **Config/settings:** Settings → Config Versions → dry-run → rollback (GUI, no shell).
- **Image (on failed upgrade):** automatic (default-on).
- **Image (deliberate):** agent `/v1/rollbacks mode=image` **[HOST]** (GAP-UPD-02).
- **`/data`:** restore from backup (offline, above).

## Log collection / support bundle

- **No support bundle exists (GAP-MON-01).** Collect manually:
  - `GET /api/diagnostics` (health verdict, redacted)
  - `GET /api/audit?source=file` (full audit JSONL)
  - `GET /api/export?format=json` (traffic/request log)
  - `GET /api/config/export` (config, creds excluded)
  - `docker compose logs proxy` **[HOST]** (system log) + `--backup` for `/data` state.
- Bundle these for the support ticket.

## Administrator recovery (break-glass)

- **Trigger:** sole admin locked out / password lost.
- **First:** if it's a *lockout* (not lost password) → `docker compose restart proxy` **[HOST]** clears in-memory locks; or wait the 15-min cooldown; a trusted-IP admin bypasses the account-wide tier.
- **Password reset [HOST]:**
  ```bash
  docker compose run --rm proxy --reset-password admin:NewStr0ngPass
  # or against a running container:
  docker exec culvert ./culvert --reset-password admin:NewStr0ngPass --ui-users-file /data/ui_users.json
  ```
- **Expected:** `Password reset for "admin" (role=admin).` Log in with the new password.
- **Prevention:** always keep ≥2 admins; retain host-exec break-glass; keep a current `/data` backup. There is no in-band recovery (GAP-IAM-01).

## Escalation criteria

Escalate to vendor/engineering when: `/ready` stays 503 after restart with an unclear gating row; a restore dry-run fails validation; an upgrade lands `FAILED_NEEDS_ATTN`; the CA bundle is corrupt with no backup; or a P0/P1 gap blocks a change-controlled operation with no acceptable workaround.

## Decommissioning

1. Drain: remove from the LB; `docker compose down` **[HOST]**.
2. Preserve evidence: final encrypted `--backup` copied off-host; export audit (`/api/audit?source=file`).
3. Revoke: revoke enrolled DP nodes / IdP client secrets / webhook secrets; remove trust of the Culvert root CA from endpoints (GPO/MDM).
4. Destroy data: `docker compose down -v` **[HOST]** removes volumes (`proxy-data`, `clamav-db`, `culvert-backups`); wipe the host disk per policy (the CA key + secrets live in `/data`).
5. Remove the host agent: stop/disable `culvert-maint`, remove the sudoers entry and user **[HOST]**.
