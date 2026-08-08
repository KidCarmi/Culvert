# Culvert Day-2 Operations Readiness

> **Owner:** Overnight Failure-Mode Audit · **Status:** Point-in-time · **Date:** 2026-07-11 · **Tree:** `7c64699`
> **Companion:** `PRODUCTION-FAILURE-MODE-AUDIT.md` (findings F-01…F-30 referenced throughout).
>
> This document states what an operator must know to run Culvert in production: startup checks, health
> semantics, diagnostics, backup/restore expectations, upgrade safety, certificate lifecycle, disk
> management, recovery procedures, the support-bundle requirement, and the minimum acceptance criteria
> that must be true before a production or "appliance" claim. Every semantic below was traced to code;
> where behavior differs from operator intuition or documentation, it is flagged **⚠**.

---

## 1. Startup checks (what boot enforces vs what it lets through)

Startup is an ordered sequence of contract-tested slices (`main.go:165-216`). Two classes:

**Fail-CLOSED (container refuses to boot — a crash-loop trigger under `restart: unless-stopped`):**
- Malformed `policy.json` (`main.go:690`), `pac.json`, `categories.json`
  (`urlcategories_startup.go:22`), blocklist on non-`IsNotExist` error (`blocklist_startup.go:59`).
- Malformed HA-lease config (`cluster_startup.go:44 armHALease`), CP gRPC enable failure (`:96`).
- Config-file load, logger setup, IdP-profiles, legacy auth providers, inspection rules
  (`main.go:481,515,588,606,744`).
- Proxy / admin-UI **port bind failure** (`main.go:993`, `ui.go:118`) — asynchronous, so it can
  crash-loop *after* an earlier boot succeeded (e.g. a port taken on the second start).
- **Interrupted-restore boot guard** (`main.go:173 checkInterruptedRestore`) — refuses to boot if
  `/data` is absent while an interrupted-restore `.bak` sibling exists, printing exact `mv` recovery.
  ✅ This is the model corrupt-store handling should copy.

**Fail-OPEN (boots degraded, logs and continues — ⚠ know these):**
- **Root CA load failure** → SSL inspection disabled, tunnel-only bypass (F-02). Visible on the
  **proxy** `/health`+`/ready` (the `ssl_inspection` field + `ca` row) + `ca_load_failed` alert — **not**
  the admin `/healthz`, which is HA-only.
- **Default policy = allow** when no rules and no `default_action` (F-01) — advisory log only. ⚠
- Session revocations, file-blocking, GeoIP, scanning/ClamAV, log-store, CDR, upstream pool, cluster
  CA init — all non-fatal/degrading.
- **Read-only `/data`** — a writability probe runs (`diagnostics.go:81`) but is **advisory only**; boot
  "succeeds" and runtime saves silently degrade (F-19). ⚠
- **Corrupt `ui_users.json`/`cluster.json`** — reset to empty, then overwritten (F-03/04). ⚠

**Operator takeaway:** a *green boot* means "no fatal config error," **not** "inspection on, auth on,
policy deny-by-default, storage writable." Verify posture explicitly via §2/§3.

---

## 2. Health semantics (verified — do not assume Kubernetes conventions)

There are **three probes on two servers**. They mean different things:

| Probe | Server | Returns | Gates on | Use for |
|---|---|---|---|---|
| `/healthz` | Admin/CP | 200 standalone/leader, **503 on HA standby** | HA leadership only (`ha.go:858`) | CP write-authority routing |
| `/health` | Proxy (data) | **always 200** `status:"ok"` (`healthcheck.go:61`) | nothing (liveness) | liveness only; reports `ca_expires_days`, `ssl_inspection`, `clamav` as **info** |
| `/ready` | Proxy (data) | 200 / **503** | `session_secret` + `config_snapshot_validator` (+ `clamav` if initialized) (`healthcheck.go:151-169`) | load-shedding gate |

⚠ **`/ready` does NOT gate on:** CA-load failure (report-only), CP-poll failure, node-cert expiry,
policy-loaded, GeoIP, YARA. **A DP that lost its CP or whose cert is expiring still returns `/ready`
200** (F-08). A load balancer using `/ready` will **not** eject a degraded-but-live data plane.

**LB configuration guidance (until F-08 is fixed):** point the LB liveness at the proxy `/health` and
readiness at the proxy `/ready`, **and additionally** scrape `/api/diagnostics` (authenticated) for
`dpControlPlanePollFailing` and node-cert expiry — these two signals are **not** exported to Prometheus
(`metrics.go` carries only aggregate enrollment/HA counters + a successful-poll latency histogram;
`dpControlPlanePollFailing` is read only at `diagnostics.go:196`; see audit §8). Do not rely on `/ready`
alone, or on a Prometheus-only alert, to detect a stale or cert-expiring DP.

---

## 3. Diagnostics

- **`/api/diagnostics`** (authenticated operator contract) is the richest source: storage writability
  (`storageStateUnwritable`), DP last-good-snapshot age, CP-poll status. This is where degraded-DP state
  actually surfaces today (not `/ready`).
- **Prometheus (`/metrics`)** exposes `culvert_*`: per-rule hit counters, latency histogram, threat-feed
  entries/blocked, scan cache. ⚠ **Missing** metrics that this audit recommends: `culvert_scan_errors_total`
  (F-10), threat-feed staleness (F-27), upstream pool-empty transition (F-09), CP-poll-failing gauge (F-08).
- **Proxy `/health` fields** (`ca_expires_days`, `ssl_inspection: ready|unavailable|load_failed`,
  `clamav`, `threat_feed_entries`) are the fastest at-a-glance posture check — but note `ca_expires_days`
  is the **inspection** CA, not the DP↔CP node cert. (These fields are on the **proxy** `/health`, not
  the admin `/healthz`.)
- **Structured logs** (`logger.Printf`, JSON mode) carry the fail-open advisories (default-allow,
  CA-load, scan errors) — but log-only signals are not alerting; treat the advisory-log-only items
  (F-01, F-10) as **must-monitor externally** until they gain metrics/alerts.

---

## 4. Backup / restore expectations

**What backup does (`--backup`, offline CLI one-shot):** gzipped tar with a `manifest.json`
(`schema_version`, `culvert_version`, per-file sha256+mode), published atomically (temp→fsync→rename),
optional passphrase encryption (`--encrypt`, `CULVERT_BACKUP_PASSPHRASE`, PBKDF2 600k → AES-256-GCM).

**Expectations an operator MUST internalize:**
- ✅ Backup is **atomic and refuses to overwrite** an existing file; a failed/interrupted backup leaves
  the previous archive intact.
- ✅ Restore **detects corruption before touching `/data`** (gzip/tar/AEAD/sha256), and an interrupted
  restore swap is caught at next boot (RISK-005).
- ⚠ **Backup does not capture everything.** DP/CDR node keys are excluded **by design** (DR model =
  re-enrollment, not restore). Also **not** in the allowlist: `idp_profiles.json` (SSO config),
  `revocations.json` (session revocations), `fileprofiles.json`, any `*.kek` (F-18). **Plan DR around
  re-configuring SSO and re-issuing revocations.**
- ⚠ **Encrypted cluster-CA DR requires separate KEK custody.** If `CULVERT_CLUSTER_CA_ENCRYPT` is on,
  the backed-up `cluster-ca.key` is encrypted and its KEK is **not** in the archive. Restoring onto a
  fresh host **passes validation but fails closed at boot** unless you separately transport the KEK
  (`CULVERT_KEK` env or the `.kek` file). **Store the KEK out-of-band with the backup.**
- ⚠ **No cross-version safety.** Restore enforces `schema_version` only; a downgrade or a data-shape
  drift restores silently. **Restore onto the same Culvert version you backed up from**; if you must
  cross versions, test in staging first.
- ⚠ **Full-restore replaces `/data`.** A backup missing `ui_users.json`/`cluster.json` will pass
  validation and, in full mode, replace a good `/data` with one lacking admins → lockout (recover via
  the auto-created `.bak`). **Verify the manifest's Tier-1 counts before committing a full restore.**

**Restore drill (recommended cadence: quarterly):** `--restore` **dry-run** first (validates without
committing, prints the plan + Tier-1/Tier-2 counts + version), then the offline commit path
(`docker compose down` → `cli --restore --confirm` → `up -d`).

---

## 5. Upgrade safety expectations

**How upgrades work:** the Control Plane dispatches a verified catalog target to the host maintenance
agent (`/v1/upgrades/apply`), which pulls a **digest-pinned** image, retags `culvert/proxy:pinned`,
`docker compose up -d`, then **health-gates and digest-verifies** before declaring success. On failure
it **auto-rolls-back and verifies the revert** (revert + digest + health).

**What is safe (verified):**
- ✅ Digest-pinned, signature/identity-verified images (catalog Sigstore + sudoers hex-bound pull).
- ✅ Retag is fused with restart, so a timeout can't strand an advanced tag mid-flight.
- ✅ Rollback confirms the node actually reverted and is healthy (closes the RISK-011 concern).
- ✅ Concurrent applies are rejected (409, in-process lock).

**What is NOT safe yet (⚠ operator must compensate):**
- ⚠ **Agent-death mid-apply is unrecoverable** (F-05): no operation journal, no reconciliation on
  agent restart. **Do not kill/restart the maintenance-agent host during an apply.** If an apply is
  interrupted, manually inspect `docker compose ps` + the running image digest before retrying.
- ⚠ **No disk preflight** (F-20): ensure ample free space (image size × 2 headroom) before applying.
- ⚠ **No runtime compatibility gate** (F-07): a signed-but-incompatible release is only caught if it
  becomes *unhealthy*. Stage upgrades in a canary before fleet-wide dispatch.
- ⚠ **Rollback failure = service down + manual** (F-06): have the prior known-good digest recorded so
  you can manually repin if auto-rollback fails.

---

## 6. Certificate lifecycle

| Cert | Lifetime / rotation | Failure behavior | ⚠ |
|---|---|---|---|
| Inspection root CA | auto-rotate 24h check, 30-day overlap (`internal/ca/ca.go:489`) | load fail → inspection off (F-02); rotation-save fail logs-only (reverts on restart) | passphrase custody is critical |
| Inspection leaf | 24h, LRU/TTL cache | re-signed on demand | — |
| DP↔CP node cert | renew <30d, 6h loop (`dp_enrollment.go:306`) | **renewal persists but doesn't hot-reload** (F-25) → expiry during CP outage bricks DP | restart DP after a renewal if the link was flapping |
| UI TLS | regenerated self-signed every boot, 10y | no expiry brick; anchored to boot wall-clock | clock-before-`NotBefore` breaks UI TLS |
| Backup encryption | passphrase-derived, no stored key | lose passphrase = lose backup | store passphrase with the backup custody plan |

**Operator actions:** (1) protect `CULVERT_CA_PASSPHRASE` — its loss silently disables inspection on
the next reboot; (2) if a DP was disconnected from the CP for weeks, restart it after reconnect to pick
up any renewed cert; (3) subscribe a webhook to `cert_expiry` — since CHAOS-30 Culvert fires it
proactively for the inspection Root CA (≤30d / ≤7d / expired, latched per escalation, evaluated at
startup and after every rotation attempt), alongside `culvert_ca_expires_in_seconds` and
`culvert_ca_sign_failures_total` on `/metrics`, `ca_expired` + `ssl_inspection:"expired"` on
`/health`, and a failing (report-only) `ca` row on `/ready`. Note that an expired Root CA now
fails **closed**: leaf signing is refused rather than emitting certificates no client can validate.

---

## 7. Disk-capacity management

- **Store writes are fail-closed under ENOSPC** — a full disk does **not** corrupt existing files
  (`AtomicWrite` removes the temp and returns; the target is untouched). ✅
- ⚠ But several callers **discard** the returned error (e.g. `saveRetryQueueLocked`,
  `go SaveAdminSettings`), so a disk-full save can be silently lost (F-13).
- ⚠ **No orphan-`.tmp` sweep** — crash-between-CreateTemp-and-rename leaves uniquely-named `*.tmp.*`
  and `.culvert-writability-probe-*` files that accumulate across crashes (hygiene only, not corruption).
- ⚠ **No free-space preflight before an upgrade pull** (F-20).
- **Log growth:** request/audit logs rotate (`internal/fileutil/rotating.go`, disk-full-safe after the
  F3 fix — a failed reopen preserves the `.1` archive). Community BadgerDB feed and log-store are the
  largest growers; both are on named volumes.
- **Guidance:** size `/data` for config_versions (50 snapshots) + logstore + threat/category feeds +
  image layers; alert on volume utilization externally (Culvert has no disk-full self-alert); keep
  ≥ 2× the proxy image size free for upgrades.

---

## 8. Administrator recovery procedures

| Incident | Procedure | Status |
|---|---|---|
| Interrupted restore (`/data` gone, `.bak` present) | Boot prints exact `mv` (REVERT vs COMPLETE); run it, restart | ✅ Guided |
| Corrupt `ui_users.json` (admin lockout) | Today: file was overwritten empty → restore from backup or re-bootstrap via legacy env admin. **After P0-3:** quarantined `.corrupt.<ts>` + refuse-boot message | ⚠ manual/data-loss |
| Revoked node revalidated (corrupt `cluster.json`) | Re-issue revocations, re-verify roster from backup | ⚠ manual |
| DP cert-expiry brick | Restart the DP; if past expiry, revoke + re-enroll | ⚠ manual |
| Interrupted upgrade / agent death | Inspect `docker compose ps` + running digest; manually `docker tag <prior>@sha256 culvert/proxy:pinned` + `up -d` if needed | ⚠ manual (F-05) |
| Rollback failed (service down) | Manually repin the recorded prior digest; restart | ⚠ manual (F-06) |
| Lost CA passphrase | Inspection stays off; restore `.env` or accept plaintext CA regeneration only if the file is absent | ⚠ |
| Host reboot | Automatic (compose + volumes) | ✅ |
| CP outage (DP side) | Automatic — DP serves last-known-good; auto-reconnects | ✅ |

**Standing recommendation:** keep an **out-of-band record** of (a) the CA passphrase, (b) the cluster-CA
KEK if encryption is on, (c) the current pinned image digest — these three cover the manual-recovery
paths above.

---

## 9. Support-bundle requirements

Culvert has **no single "generate support bundle" command** today (gap). A field engineer diagnosing an
incident needs, at minimum:

- `docker compose ps` + `docker logs` for `proxy`/`clamav` (crash-loop detection, F-23 — the only
  signal for a dead container).
- Proxy `/health` (posture: `ssl_inspection`, `ca_expires_days`, `clamav`) and proxy `/ready` (which
  gates failed); admin `/healthz` (HA role/write-authority).
- `/api/diagnostics` (storage writability, DP last-good age, CP-poll status — where degraded-DP state
  actually lives).
- `/metrics` scrape (rule hits, threat-feed entries, latency).
- The startup log (which fail-open advisories fired: default-allow, CA-load, RO-filesystem).
- `manifest.json` from the relevant backup (version + Tier-1 counts) when diagnosing a restore.
- The maintenance-agent op logs (`OpenOpLog`) for an upgrade incident.

**Recommendation (P2-class):** add a `culvert --support-bundle` (or an admin-API endpoint) that
collects the above into a redacted archive — it would materially cut the "why did my appliance stop
inspecting/serving" ticket resolution time and is directly aligned with the observability gaps (§8 of
the audit).

---

## 10. Minimum production-readiness acceptance criteria

A deployment should not be called "production" / "appliance-grade" until **all** of the following are
true (each maps to an audit finding + backlog item):

**Must (P0 — block the claim):**
1. A fresh/unconfigured proxy in passthrough+no-auth mode is **not silent**: degraded `/ready` +
   admin banner + alert (F-01 / P0-1). Ideally the proxy port does not serve open before setup.
2. The maintenance agent can **recover from its own death mid-apply** — a persisted op journal and a
   working `MarkAllInterrupted()` reconciliation (F-05 / P0-2).
3. Corrupt `ui_users.json` / `cluster.json` **quarantine-and-refuse** instead of reset-and-overwrite
   (F-03/04 / P0-3).

**Should (P1 — required for unattended operation):**
4. `/ready` degrades on sustained CP-poll failure and imminent node-cert expiry; DP hot-reloads after
   cert renewal (F-08/F-25 / P1-1).
5. Config-rollback and admin-settings saves surface disk-write failures instead of reporting success
   (F-12/F-13 / P1-2).
6. A lost/unmounted volume does not silently fresh-start; RO `/data` is a loud degraded state
   (F-24/F-19 / P1-3).
7. Restore warns on version skew, checks required-file presence, and surfaces the KEK-custody
   requirement (F-18 / P1-4).
8. Upstream-pool bypass and scanner-error fail-opens are operator-selectable + counted
   (F-09/F-10 / P1-5).

**Verified already met (do not re-litigate):**
- Atomic, fsynced durability across all crown-jewel stores; ENOSPC-safe writes.
- Backup corruption detection before `/data` mutation; interrupted-restore boot guard.
- Digest-pinned, identity-verified upgrades with revert+health-verified auto-rollback.
- HA fencing lease clock-decoupled; split-brain structurally prevented in lease mode.
- DP serves last-known-good with the CP down; host reboot auto-recovers via volumes + restart policy.
- No SQL/migration risk class (JSON + atomic writes; snapshots parse-or-reject).

---

*Companion: `PRODUCTION-FAILURE-MODE-AUDIT.md` (full matrix + evidence),
`FAILURE-INJECTION-TEST-PLAN.md` (tests that would enforce the criteria above).*
