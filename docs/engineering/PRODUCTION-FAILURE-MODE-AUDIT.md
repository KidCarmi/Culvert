# Culvert Production Failure-Mode & Day-2 Operations Audit

> **Owner:** Overnight Failure-Mode Audit (evidence-gathering pass) · **Status:** Point-in-time
> **Date:** 2026-07-11 · **Tree:** HEAD `7c64699` (branch `claude/culvert-failure-mode-audit-jvrdt4`)
> **Method:** Six parallel failure-domain evidence sweeps (upgrade/rollback · backup/restore ·
> persistence/corruption/disk · health/cert/clock · installer/first-boot · external-dependency
> fail-open), each returning `file:line:symbol` evidence, plus ~12 findings independently
> hand-verified (`HV`) by the auditor at HEAD.
>
> **This is an evidence audit, not a redesign.** No production behavior was changed. Every finding
> carries a repository citation; documentation was **not** accepted as evidence. Where the code
> contradicts a `CLAUDE.md` / register claim, the code wins and the discrepancy is called out.
>
> **Relationship to the CHAOS reviews:** Culvert already runs a mature chaos-engineering review
> series (`CHAOS-ENGINEERING-REVIEW-2026-07-{05,07,09,10}.md`, findings CHAOS-01…43). This audit
> **validates those findings at current HEAD** (several have since been fixed; several remain open),
> **extends** them to the surfaces they never deep-dived (the maintenance-agent upgrade/rollback
> execution path, backup-into-a-different-version, RO-filesystem boot, first-boot default posture),
> and **re-frames** everything for the appliance / day-2 operator. It does not re-report a CHAOS
> finding without re-verifying it.

---

## 1. Executive verdict

**Production-readiness verdict: CONDITIONAL-GO for a single-node, network-restricted, operator-attended
deployment; NOT-READY for an unattended / internet-exposed "appliance" deployment without closing the
P0/P1 items below.**

Culvert's *engineered* failure paths are genuinely strong: the write layer is uniformly atomic+fsynced
(`fileutil.AtomicWrite`), the restore path has a boot guard that refuses to start on a half-completed
swap (RISK-005), backup corruption is caught by layered integrity checks *before* any data is touched,
the HA fencing lease is correctly decoupled from the local wall clock, the upgrade path digest-pins and
verifies image identity, and the auto-rollback **does** now verify revert + health (closing the concern
behind RISK-011, whose cited code has been removed).

The risk mass is concentrated in three themes, all of which are **silent** — the proxy keeps serving
while a control degrades:

1. **Fail-open-by-default and fail-open-on-dependency-loss.** A fresh, unconfigured appliance runs in
   **allow/passthrough with no authentication** (§5, F-01). CA-load failure silently drops SSL
   inspection to tunnel-only bypass (F-02). Parent-proxy pool exhaustion falls open to direct egress,
   bypassing the DLP boundary (F-09). Scanner errors on two paths forward content unscanned (F-10).
   None of these stop traffic; several have no metric.

2. **Corrupt-state and lost-volume handling that loses data or reopens security holes.** A corrupt
   `ui_users.json` or `cluster.json` is silently reset to empty and then overwritten — permanently
   losing admin/TOTP enrollment or revalidating revoked node certs (F-03, F-04). A wiped or unmounted
   `/data` volume is indistinguishable from a first boot, so the appliance silently starts fresh (F-24).

3. **Day-2 orchestration whose recovery path is undefined.** If the maintenance agent dies mid-apply
   there is **no persisted operation journal and no reconciliation** — `MarkAllInterrupted()` is a
   literal no-op — leaving Docker in an unknown partial state (F-05). Config-rollback swallows every
   persistence error and reports success (F-12). Admin-settings saves are fire-and-forget (F-13).

None of these are exotic; each is triggered by an ordinary operational event (first boot, a lost
passphrase, an unmounted volume, a corrupt file, a killed process, a full disk). That is what moves the
verdict to conditional.

---

## 2. Tested system boundaries (what "the appliance" actually is)

**Documentation-vs-reality:** the task framed Culvert as an ISO/OVA appliance. **There is no
ISO/OVA/packer/cloud-init/kickstart tooling in the repository** (exhaustive search: zero image-build
artifacts). The real, tested delivery unit is:

- **Docker Compose** (`docker-compose.yml`): `clamav` + `proxy` (`culvert/proxy:pinned`) + optional
  `etcd` (HA witness) + optional `cli` (backup/restore) profiles, all `restart: unless-stopped`, state
  on **named volumes** (`proxy-data`, `clamav-db`, `culvert-backups`, `etcd-data`).
- A **host-side maintenance agent** (`packaging/systemd/culvert-maint.service`, `Restart=on-failure`)
  that drives Docker over a sudo boundary for day-2 upgrade/rollback.
- A curl-to-bash **quick-start** (`scripts/install.sh`) that installs Docker, extracts the compose
  bundle from the image's `/app/deploy`, seeds `.env`, and runs `docker compose up -d --wait`.

**Persistence model:** there is **no SQL database and no schema-migration engine.** All durable
security/config state is JSON flat files under `/data`, written through one primitive
(`internal/fileutil/fileutil.go:19 AtomicWrite`: unique temp → fsync → rename → parent-dir fsync). The
only embedded KV store is an **optional, rebuildable** BadgerDB cache for the community URL-category
feed (`urlcategories_startup.go:44`; Layer-1 JSON is authoritative). **Consequence: the task's
"database unavailable / migration failure / partial migration" scenarios are N/A as classically framed.**
The nearest analogues are (a) JSON field-envelope migrations (sentinel flags) that degrade to defaults,
and (b) config-version snapshots that either parse fully or are rejected — a partial-migration state
cannot form. This is a genuine architectural strength and is treated as such below.

**Boundaries NOT exercised in this audit (static read only; flagged for the test plan):** no process
was killed with SIGKILL mid-write; no real ENOSPC/EROFS was injected; no registry-network fault was
injected during `docker pull`; no clock was actually stepped. All "actual behavior" claims are from
code paths, cross-checked across agents and against the CHAOS reviews.

---

## 3. Lifecycle map (traced, with the failure surface at each stage)

| Stage | Entry point (file:line) | Durable effect | Dominant failure surface |
|---|---|---|---|
| Fresh install | `scripts/install.sh` | `/srv/culvert`, `.env` (0600), named volumes | passphrase auto-seed; idempotent re-run (CI-pinned) |
| First boot | `main.go:165-216` startup slices | seeds CA, empty stores | **default policy = allow + no auth (F-01)**; CA plaintext if `.env` absent |
| Configuration | admin UI setup wizard `apiSetupComplete` `ui_auth.go:386` | `ui_users.json`, `default_auth_outcome` | one-time gate; open-mode is explicit `OutcomeExempt` |
| Normal request | `handleRequest` `proxy.go` | stats, logs (async) | fail-open holes on dependency loss (F-09/10); scan-buffer OOM (F-14) |
| Restart | `restart: unless-stopped` | reload from `/data` | crash-loop on fatal config (F-23); lost-volume = fresh start (F-24) |
| Host reboot | compose + systemd | volumes survive | ✅ automatic recovery |
| Upgrade | agent `/v1/upgrades/apply` → `buildUpgradeApplyStages` | retag `culvert/proxy:pinned`, `up` | agent-death mid-apply undefined (F-05); no ENOSPC preflight (F-20); no compat gate (F-21) |
| Rollback | inline `imageRollbackStages` `rollback_stages.go:70` | repin prior digest | ✅ verifies revert+health; worst-case service-down + manual (F-06) |
| Backup | `--backup` one-shot `main.go:415` | gzip tar + manifest | ✅ atomic; silent omission of some durable state (F-18) |
| Restore | `--restore` one-shot `restore.go` | move-aside + swap | ✅ corruption caught pre-swap; no cross-version gate (F-18); interrupted-swap boot guard ✅ |
| Degraded mode | last-known-good config | serves cached config | ✅ DP serves LKG with CP down; but invisible to LB (F-08) |
| Recovery | various | — | corrupt-store recovery is manual/undefined (F-03/04) |

---

## 4. Failure-mode matrix

Legend — **Enf** (enforced by code): Y/N. **Test**: has a test. **Vis** (admin-visible): Y (metric/alert/probe),
L (log-only), N. **Mode**: OPEN (fail-open) / CLOSED (fail-closed) / SAFE (last-known-good) / N-A.
**Rec** (recovery): A(uto) / M(anual) / U(ndefined). **Sev**: severity. **Conf**: confidence. `HV` = hand-verified.

| # | Scenario | Current behavior (evidence) | Enf | Test | Vis | Mode | Rec | Sev | Conf |
|---|---|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| F-01 | Fresh/unconfigured proxy exposed | Default policy → **allow/passthrough**, no auth: `rewrite_default_action_startup.go:23-25` (empty `default_action`+0 rules ⇒ `setDefaultPolicyAction("allow")`), `AuthEnabled()` false `store.go:470`. Advisory log only. `HV` | N | Y(slice) | L | OPEN | M | **HIGH** | High |
| F-02 | CA passphrase lost / bundle corrupt on reboot | SSL inspection → tunnel-only bypass, keeps serving: `rootca_startup.go:63-73`; does NOT re-mint CA (`internal/ca/ca.go:194`). Now visible: proxy `/health` `ssl_inspection` field + proxy `/ready` `ca` row + `ca_load_failed` alert (CHAOS-06 mitigation; admin `/healthz` is HA-only, no `/readyz` route) | N (fail-open by design) | Y `rootca_failure_visibility_test.go` | Y | OPEN | M | **HIGH** | High |
| F-03 | Corrupt `ui_users.json` at boot (CHAOS-05) | **MITIGATED (2026-07-12):** corrupt roster quarantined to `.corrupt.<ts>` before any save can overwrite (`state_corruption.go`, hooked at `store.go` `LoadUIUsersFile`), `state_file_corrupt` alert + report-only `/readyz` row. Roster still boots empty (env fallback creds live) — refuse-to-boot is the recorded remainder | Y (quarantine) | Y `state_corruption_test.go` | Y | SAFE (evidence kept) | M | MED | High |
| F-04 | Corrupt `cluster.json` at boot (CHAOS-07) | **MITIGATED (2026-07-12):** corrupt DB quarantined before the "starting fresh" save (`state_corruption.go`, hooked at `enrollment.go` `ClusterStore.Load`), alert + `/readyz` row. `IsRevoked` amnesia persists until the operator restores the quarantined file — the revoked-cert list is no longer silently destroyed, but fail-closed refusal is the recorded remainder | Y (quarantine) | Y `state_corruption_test.go` | Y | SAFE (evidence kept) | M | MED | High |
| F-05 | Maintenance agent dies mid-apply | **No persisted op journal**; `MarkAllInterrupted()` returns 0 (`ops.go:468`); op vanishes from memory; Docker left in partial state (tag advanced, `up` half-done); no reconciliation, no auto-rollback. `HV` | N | N | N | **U** | **U** | **HIGH** | High |
| F-06 | Rollback itself fails | `rollbackFailed` → `OutcomeFailed`, reason promoted `rollback_failed`, `final_running_digest` reported; worst case new unhealthy image still running (service down): `inline_rollback.go:78-79,102,158-173` | Y | Y `inline_rollback_test.go:132` | Y | CLOSED (paged) | **M** | **HIGH** | High |
| F-07 | Validly-signed but incompatible release | No runtime min-version/compat gate (only catalog `schema_version` `release_catalog.go:381`); relies **reactively** on post-apply health probe → rollback: `handlers_upgrade_apply.go:315`. Silent-misbehaving-but-healthy release undefined | N (preventively) | N | Y (if unhealthy) | OPEN (compat) | A/U | **MED-HIGH** | High |
| F-08 | DP unhealthy while UI healthy (CHAOS-09) | **MITIGATED (2026-07-16 run B):** `/ready` gains DP-only `cp_poll` (fail after 5-min sustained CP-poll failure) + `node_cert` (fail while renewal failing inside the window) rows (`readyz_dp_health.go`); report-only on the default verdict (a CP outage must not eject the whole DP fleet), opt-in gating via `/ready?strict=1` (any fail row → 503) for LBs that should eject (`readyz_dp_health_test.go`) | Y | Y | Y (/ready rows) | SAFE (opt-in strict) | A | LOW-MED | High |
| F-09 | Upstream pool all-down (CHAOS-11/22/23) | `Pool.Next()` nil ⇒ **direct** egress `upstream.go:291-298`; breaker `RecordFailure/Success` **dead code** (0 non-test callers, `HV`); probe = hardcoded `detectportal.firefox.com` SPOF `upstream.go:302`; CONNECT/SOCKS5 never traverse pool | N | Y (breaker unit only) | L | **OPEN** | A | MED (HIGH for DLP) | High |
| F-10 | Scanner error mid-request (CHAOS-10/17) | **MITIGATED (2026-07-26):** plain-HTTP body read error now fails **closed** (502, nothing forwarded — `proxy_http.go` `scanHTTPResponseBody`, mirrors the inspect `scanReadError` contract); ClamAV *error* stays fail-open per request (sidecar-posture parity) but is now **counted** (`culvert_clam_scan_errors_total`, `stat_clam_scan_error`) + **alerted** (`scan_clam_error`) and no longer caches a "clean" verdict computed while the daemon was dark (cache-poisoning closed). Remainder: admin-selectable `scan.on_error=block` posture (needs GUI-parity surface) | partial | Y `clam_error_test.go`, `proxy_http_scanfail_test.go` | Y | mixed (HTTP read = CLOSED; clam error = OPEN, alerted) | A | LOW-MED | High |
| F-11 | Auth IdP outage (CHAOS-16) | Fail-CLOSED (deny) but **caches error negatives** 5m LDAP / 2m OIDC ⇒ denies valid creds past recovery; no LDAP post-dial deadline; no OIDC breaker (`auth_ldap.go:115,128-131`, `auth_oidc.go:123,141`) | Y | N (behavior absent) | L | CLOSED (amplified) | A(TTL) | MED | High |
| F-12 | Config rollback with a failing disk (CHAOS-27) | `applyConfigBackup` returns nothing, **discards every `.Save()` error** ⇒ 200 on partial-durability apply; restart reloads mixed state: `configversion.go:274-362`. `HV` | N | N | N | **OPEN** | M | MED | High |
| F-13 | Admin-settings save fails (CHAOS-33) | `go SaveAdminSettings()` fire-and-forget `admin_settings.go:437`; mutation API returns 200 regardless; security setting silently vanishes on restart. `HV` | N | N | N | OPEN | M | MED | High |
| F-14 | Concurrent large downloads (CHAOS-26) | 64 MB decompress cap × N (`secscan.go:48`), connlimit **default-disabled** (`internal/connlimit` `enabled=false`, `HV`), no global connection/scan-concurrency cap ⇒ remote OOM-kill → restart | N | N | N | OPEN | A(restart) | MED | High |
| F-15 | Wedged RPC during SIGTERM (CHAOS-25/36) | Early shutdown phase runs with `context.Background()` (no budget); `GracefulStop()` blocks on in-flight RPC; 2nd SIGTERM ignored (signal read once): `main_shutdown.go:22-39` | N | Y (ordering only) | L | OPEN | M(SIGKILL) | MED | High |
| F-16 | Two instances on one `/data` (CHAOS-28) | **No data-dir lock**; last-writer-wins silently corrupts every store (only KEK has an `os.Link` guard) | N | N | N | OPEN | M | MED | Med |
| F-17 | `CULVERT_SESSION_SECRET` invalid (CHAOS-29) | Env-invalid → boot **panic/crash-loop**; same in config → silent random key (fleet logout). Divergent handling of one error | partial | N | L | mixed | M | MED | Med |
| F-18 | Restore into a different version / partial backup | Backup stamps `schema_version`(=1)+`culvert_version` (`backup.go:24,158`); restore gates **schema only** (`restore.go:345`), product-version printed-not-enforced; **no required-Tier-1-presence check** (`restore.go:415`) ⇒ empty backup overwrites good `/data` in full mode; encrypted cluster-CA KEK **excluded** from backup ⇒ cert-only validation passes, boot fails closed on fresh KEK; `idp_profiles.json`/`revocations.json`/`fileprofiles.json` silently **not** in the allowlist (`backup.go:57-87`) | partial | partial | L | mixed | M | MED | High |
| F-19 | Read-only `/data` filesystem | Writability probe exists but **advisory only** (`diagnostics.go:81 probeStorageWritability`, wired step 1 `persistent_admin_state_startup.go:38`) — never blocks boot; runtime saves silently degrade per-caller (`HV` note: many callers discard the error) | N | Y (probe unit) | Y(diag) | OPEN | M | MED | High |
| F-20 | Insufficient disk during upgrade | **No free-space preflight** anywhere in the agent apply path; ENOSPC surfaces only as opaque `ReasonCommandError`; ENOSPC during `up` → post-restart → rollback (which may also ENOSPC) | N | N | L | CLOSED (undiagnosed) | A/M | MED | High |
| F-21 | Image digest mismatch / interrupted pull | `docker pull <repo>@sha256:<digest>` content-addressable + post-restart `verifyRunningImage` digest check (`handlers_upgrade_apply.go:387`); pull runs before restart ⇒ mismatch/interruption leaves running stack untouched | Y | Y `handlers_upgrade_apply_test.go:382` | Y | CLOSED | A | LOW | High |
| F-22 | Clock drift / NTP failure | **TOTP ±30s** ⇒ clock off >60s **locks out MFA admins** (`internal/totp/totp.go:20`); session forward-skew ⇒ mass logout (`session.go:409`); cert NotBefore/After wall-clock ⇒ TLS breaks on VM-snapshot restore; catalog runtime freshness watchdog has **no skew tolerance** (`release_alerts.go:128`); **HA lease correctly clock-decoupled** (etcd-as-clock, `halease.go:40`) | mixed | partial | L | CLOSED (availability) | M(NTP) | MED | High |
| F-23 | Crash loop on fatal config | Fatal: bad policy `main.go:690`, blocklist `blocklist_startup.go:59`, malformed HA lease `cluster_startup.go:44`, url-cat/BadgerDB `urlcategories_startup.go:22,46`, port-bind `main.go:993`/`ui.go:118`; `restart: unless-stopped` ⇒ **indefinite crash loop**; installer `--wait` catches first-boot, **no self-alert after day-1** | Y (fail-closed) | partial | L (docker logs) | CLOSED | M | MED | High |
| F-24 | Lost/unmounted `/data` volume | Missing `ui_users.json`/`cluster.json` treated as **first boot** (`store.go:696`, `enrollment.go:130`) — indistinguishable from a wiped/unmounted volume ⇒ silent fresh start (empty roster + legacy admin, empty CRL). `HV` | N | N | N | OPEN | U | MED | High |
| F-25 | DP cert renewal (CHAOS-12) | **MITIGATED (2026-07-11 + 2026-07-16):** renewal now hot-reloads the live gRPC client, checks immediately at loop start, and fires latched escalating expiry alerts (`dp_cert_renewal_test.go`); the residual brick — CP outage spanning the whole renewal window — is no longer permanent: an expired-but-registered node re-enrolls with a fresh admin-issued token (`admitEnrollment` expiry gate), superseded serial CRL'd + audit + `cluster_node_reenrolled` alert (`enroll_expired_reenroll_test.go`) | Y | Y | Y | CLOSED (recoverable) | M (token) | LOW-MED | High |
| F-26 | Abrupt SIGKILL | Atomic writes cap blast radius (no torn config); lost: last ≤9 heartbeats' `LastSeen` (`enrollment.go:391`), buffered syslog/log-store, Badger value-log replay; restore-interrupt guarded (RISK-005) | partial | Y (hooks, not kill-9) | L | SAFE (mostly) | A | MED | Med |
| F-27 | Threat-feed sync failure | F1 carry-forward present (`threatfeed.go:214-264`) → last-known-good, blocking stays ON; **staleness not in Prometheus** (CHAOS-20, `metrics.go:350`) | Y | Y `sync_carryforward_test.go` | L(JSON) | SAFE | A | LOW-MED | High |
| F-28 | GeoIP DB unavailable | Fail-CLOSED (rule doesn't match) `policy.go:929`; **nuance:** a country *block* rule silently becomes ineffective when the DB is down | Y | Y `geoip_test.go` | L | CLOSED | A | LOW | High |
| F-29 | DNS failure | Geo-tracker bounded by 256-slot semaphore + drop (`proxy.go:636`); invalid-host fail-closed gate (RISK-013, `proxy.go:713`); resolver itself uncancellable (`geoip.go:41` noctx) but dial capped 10s | Y | Y `proxy_geotrack_test.go` | L | CLOSED | A | LOW | High |
| F-30 | Corrupt config / policy / PAC / URL-cat at boot | Fail-CLOSED refuse-to-boot (`main.go:690`, `pac_startup.go`, `urlcategories_startup.go:22`); well-formed-dangerous access rules dropped fail-closed (`policy.go:208-229`); **inconsistency:** `category_groups` fails **open** (`urlcategories_startup.go:29`) | Y | Y `policy_authz_bypass_test.go` | L | CLOSED (mostly) | M | LOW-MED | High |

---

## 5. Silent-failure findings (the operator sees green while a control is off)

These are the highest-priority class: the proxy keeps serving and dashboards stay green.

- **F-01 — Fresh appliance is default-allow + no-auth.** The zero-value default is deny
  (`proxy.go:16`), but the first-boot slice **deliberately flips it to `allow`** for onboarding
  when no rules and no `default_action` exist (`rewrite_default_action_startup.go:23-25`), and compose
  passes no `default-action` flag. Combined with credential-only `AuthEnabled()` (false until an admin
  exists, `store.go:470`), a fresh appliance with port 8080 reachable is an **open forwarding proxy**.
  The only signal is one advisory log line — no degraded `/ready` state, no alert, no admin banner.
  This is a documented usability tradeoff, but it contradicts the headline "Default deny (Zero Trust)"
  architecture claim and is the single most dangerous first-boot behavior.
- **F-02 — CA-load failure = inspection off.** A rotated/lost `CULVERT_CA_PASSPHRASE` or a `.env`
  loss on reboot silently downgrades the core control (MITM scanning/DLP/YARA/CDR) to tunnel-only.
  **Now mitigated to visible** post-CHAOS-06 (proxy `/health`+`/ready`+alert) — this is the model the
  other silent fail-opens should copy.
- **F-09 — Parent-proxy bypass.** When the upstream pool empties (all unhealthy, or the single
  hardcoded probe endpoint is down), egress falls open to **direct**, silently bypassing the
  parent-proxy/DLP boundary. No alert on the transition. The circuit breaker that should protect this
  is dead code.
- **F-10 — Unscanned content forwarded.** A ClamAV daemon error (not timeout) and a plain-HTTP body
  read error both forward content **unscanned**, while the equivalent inspect-path errors fail closed.
  No counter distinguishes an outage from clean traffic.
- **F-12 / F-13 — Persisted state that didn't persist.** Config rollback and admin-settings saves
  both report success to the API while the disk write may have failed — the operator believes a
  security change landed when a restart will silently revert it.
- **F-08 — Degraded DP looks ready.** A DP that lost its CP (stale config) or whose cert is about to
  expire still answers `/ready` 200; the load balancer keeps routing to it.
- **F-24 — Silent fresh start.** An unmounted or wiped volume is indistinguishable from a first boot,
  so the appliance comes up empty (open, legacy-admin, no revocations) rather than refusing.

---

## 6. Fail-open vs fail-closed findings

**Fail-CLOSED (correct posture, verified):** policy/PAC/URL-category malformed-at-boot (refuse boot);
dangerous access rules dropped at load; GeoIP unknown; invalid host (RISK-013); OCSP responder outage;
release-catalog anti-rollback floor; store writes under ENOSPC (old data preserved); backup corruption
(caught pre-swap); interrupted restore (boot guard); auth when IdP down (deny).

**Fail-OPEN (by omission or by design):** F-01 default-allow; F-02 CA-load; F-09 upstream-pool→direct;
F-10 ClamAV-error + plain-HTTP scan; F-19 RO-filesystem (boots, degrades at runtime); F-30
`category_groups` (fails open while sibling categories fail closed — an internal inconsistency).

**Divergent handling of one error (F-17):** an invalid `CULVERT_SESSION_SECRET` crash-loops when it
comes from the env but silently generates a random key (fleet logout) when it comes from config — the
same mistake fails loud on one path and silent on the other.

---

## 7. Recovery gaps (automatic / manual / undefined)

| Scenario | Recovery today | Gap |
|---|---|---|
| Agent dies mid-apply (F-05) | **Undefined** | no op journal; `MarkAllInterrupted` no-op; Docker unreconciled |
| Rollback fails (F-06) | Manual (paged) | operator must re-pull/retry or data-rollback |
| Corrupt `ui_users.json`/`cluster.json` (F-03/04) | **Manual (guided)** — quarantined `.corrupt.<ts>` + alert + `/readyz` row (2026-07-12) | restore-from-quarantine is manual; refuse-to-boot posture still open |
| Lost/unmounted volume (F-24) | **Undefined** → silent fresh start | no "expected state present" boot assertion |
| Incompatible healthy-but-wrong release (F-07) | Undefined | health probe only catches *unhealthy* |
| Config rollback partial-disk (F-12) | Manual | errors swallowed; re-apply after disk fixed |
| DP cert renewal brick (F-25) | Manual restart | no hot-reload after renewal |
| Wedged shutdown (F-15) | SIGKILL (skips drain/flush) | early phase unbudgeted; 2nd signal ignored |
| **Interrupted restore (RISK-005)** | **Guided (boot guard prints `mv`)** | ✅ closed |
| **Host reboot / CP outage / threat-feed / OCSP / ENOSPC-on-write** | **Automatic** | ✅ resilient |

---

## 8. Observability gaps

The recurring theme across every review remains: **the failure path has no counter.** Missing signals
with a concrete home:

- `culvert_scan_errors_total{engine,path}` (F-10) — the ClamAV-error/plain-HTTP fail-open is invisible.
- Upstream **pool-went-empty / all-direct transition** alert+metric (F-09).
- Threat-feed **staleness / sync-failure** gauge to Prometheus (F-27, CHAOS-20; JSON-only today).
- Readiness gates for **CP-poll-failing** and **imminent node-cert expiry** (F-08/F-25, CHAOS-09/12).
- **Crash-loop** self-signal after day-1 (F-23) — the process is dead, so only external monitoring
  catches it; document the external-probe requirement.
- Config-rollback **partial-apply** warning in the API response + alert (F-12).
- Admin-settings **save-failed** surfaced to the mutating API instead of fire-and-forget (F-13).
- Effective-config **precedence/source** diagnostics (DEBT-009 residual) — an operator cannot see
  which of CLI/YAML/`admin_settings.json` won.

---

## 9. Upgrade & rollback risks

The maintenance-agent apply/rollback path (never previously chaos-audited) is **stronger than the
register implies** but has two structural gaps:

- **Strong:** digest-pinned pulls (`ComposePullDigest` + sudoers hex-bound + `validatePinnedDigestRef`);
  retag fused into the restart stage so a timeout can't strand an advanced tag; real health-gate +
  digest-verify before declaring success; **auto-rollback verifies revert + digest + health**
  (`rollback_stages.go:70-124`, gated at `inline_rollback.go:118`) — this closes the concern behind
  **RISK-011, whose cited symbol `update_cluster.go:triggerAutoRollback` no longer exists** (the legacy
  cluster updater was removed; RISK-011's citation is stale and should be re-pointed or closed).
- **Gap 1 — agent-death mid-apply is unrecoverable (F-05).** No persisted operation journal;
  `ops.MarkAllInterrupted()` is a literal `return 0`. A process kill between retag and health-gate
  leaves Docker in an unknown state with no reconciliation and no automatic rollback. **This is the
  single largest gap in the day-2 surface.**
- **Gap 2 — no compatibility gate (F-07) and no disk preflight (F-20).** A validly-signed but
  runtime-incompatible release is only caught reactively (if it happens to be *unhealthy*); a healthy
  but misbehaving release is undefined. There is no free-space check before a multi-hundred-MB pull.
- **Concurrency:** the apply lock is in-process only (`ops.go:204`, 409 on conflict) — correct for a
  single agent, but two agent instances against one host would not mutually exclude.

---

## 10. Backup & restore risks

**Strong:** offline CLI one-shots; atomic publish (temp→fsync→rename); layered corruption detection
(gzip/tar/AES-GCM/sha256) that runs **before** any `/data` mutation; extra/missing-referenced files
rejected; RISK-005 interrupted-restore boot guard present, wired (`main.go:173`), and thoroughly tested.

**Gaps (all MEDIUM, all in F-18):**
1. **No cross-version compat gate** — only `schema_version` is enforced; `culvert_version` is
   printed, never compared. A downgrade restore or a data-shape drift that ships without bumping
   `backupSchemaVersion` restores silently.
2. **Encrypted cluster-CA DR trap** — when `CULVERT_CLUSTER_CA_ENCRYPT` is on, the encrypted
   `cluster-ca.key` is backed up but its KEK is **excluded by design**; restore validates the cert
   alone and passes, then boot fails closed on a fresh host with no KEK. Silent until boot.
3. **Silent state omission** — the static allowlist omits `idp_profiles.json` (SSO config),
   `revocations.json` (active session revocations), and `fileprofiles.json` with no warning; a new
   durable file added in a future release is silently un-backed-up until someone edits
   `defaultBackupArtifacts`. Intent for these three is unverifiable from code/docs — **confirm.**
4. **No required-file presence check** — an empty/partial backup passes validation and, in full-restore
   mode, can overwrite a populated `/data` with one lacking admin users / cluster CA → lockout
   (recoverable only via the `.bak`).

---

## 11. Top ten customer-impact risks (ranked)

1. **F-01 — Fresh appliance runs open (allow + no auth).** An operator who exposes 8080 before
   completing hardening runs an open proxy; only an advisory log warns. *Customer impact: data
   exfiltration / open relay on day 0.*
2. **F-05 — Agent-death mid-apply leaves Docker unreconciled.** A killed upgrade can strand the
   appliance with no automatic recovery. *Customer impact: outage requiring manual Docker surgery.*
3. **F-03/F-04 — Corrupt crown-jewel store = data loss / security regression.** Lost admin+TOTP
   enrollment or revalidated revoked node certs, then overwritten. *Customer impact: admin lockout;
   a deprovisioned node rejoins the cluster.*
4. **F-02 — Lost CA passphrase silently disables inspection.** A `.env` loss on reboot turns the SWG
   into a plain tunnel. *Customer impact: DLP/threat scanning silently off (now at least alerted).*
5. **F-09 — Upstream-pool bypass to direct egress.** Silently defeats a parent-proxy/DLP boundary.
   *Customer impact: compliance-boundary bypass, no alert.*
6. **F-25 — DP cert renewal brick.** A CP outage spanning the renewal window bricks the DP at expiry.
   *Customer impact: node hard-down, revoke+re-enroll to recover.*
7. **F-24 — Unmounted volume → silent fresh start.** A volume-mount mistake comes up empty and open
   instead of refusing. *Customer impact: silent loss of all config + open posture.*
8. **F-10 — Scanner-error fail-open.** ClamAV crash / plain-HTTP read error forwards content unscanned.
   *Customer impact: malware/DLP bypass window, uncounted.*
9. **F-08 — Degraded DP stays "ready."** LB keeps routing to a DP running stale policy. *Customer
   impact: new blocks not enforced fleet-wide, no ejection.*
10. **F-14 — Remote OOM via scan buffering.** N concurrent large/compressed downloads OOM-kill the
    proxy (connlimit default-off, no global cap). *Customer impact: remotely-triggerable restart loop.*

---

## 12. Evidence references (anchor set)

All findings above carry inline `file:line:symbol`. The auditor **hand-verified** the following at
HEAD (independent of the agent sweeps): F-01 (`rewrite_default_action_startup.go:23-25` + `proxy.go:16`
+ config default empty + compose no flag); F-03/F-04 (load-and-continue pattern in
`auth_startup.go`/`cluster_startup.go` + overwrite-on-save); F-05 (`ops.go:468 MarkAllInterrupted`
returns 0; `update_cluster.go`/`triggerAutoRollback` absent from the tree); F-09 (zero non-test callers
of upstream `CB.RecordFailure/Success`; `detectportal.firefox.com` at `upstream.go:302`; `Next()`→direct
at `:296`); F-12 (`applyConfigBackup` no return type, discards `.Save()`); F-13 (`go SaveAdminSettings()`
`admin_settings.go:437`); CHAOS-01 **fixed** (`armVersionPersistence` wired `main.go:1106`); CHAOS-24
**fixed** (`revocationSyncLoop` wired `controlplane_client.go:140` — stale in the 07-07 review);
F-14 (connlimit `enabled=false` default, no global ceiling); F-23 (fatal set + `restart: unless-stopped`).

---

## 13. Governance observations (traceability defects found during the audit)

- **CHAOS-ID collision.** The 2026-07-07 and 2026-07-10 reviews **both** define CHAOS-22…CHAOS-27 with
  **different meanings** (e.g. CHAOS-22 = "dead circuit breaker" in 07-07 vs "refresh-loop panic" in
  07-10; CHAOS-24 = "revocation not propagated" vs "catalog freshness skew"). The CHAOS series is not a
  stable registry — cross-referencing an ID requires naming the review date. *Recommendation: renumber
  the 07-10 additions to CHAOS-44+ and keep a single append-only ledger.*
- **RISK-011 stale citation.** Its cited symbol (`update_cluster.go:804-852 triggerAutoRollback`) was
  removed with the legacy updater; the concern it names is resolved in the successor
  (`inline_rollback.go`). Re-point to the *new* residual (F-05, agent-death reconciliation) or close.
- **Register/review drift.** CHAOS-24 (revocation sync) is listed OPEN in the 07-07 review but is wired
  at HEAD (`controlplane_client.go:140`). Validating-at-HEAD, not trusting the register, is essential —
  this audit found two "open" findings already closed and confirmed twelve still open.

---

## 14. Prioritized implementation backlog

Every item points at a concrete code path, test target, or workflow. Scoped small and separable.

### P0 — data corruption, security bypass, unrecoverable appliance, unsafe upgrade
- **P0-1 (F-01):** Make the fresh-boot default posture safe *or* loud. Minimum: surface
  "passthrough + no-auth" as a **degraded `/ready` state + a persistent admin banner + a
  `security_posture_open` alert** (mirror the CHAOS-06 CA-visibility pattern). Do **not** silently
  serve open on the advisory log alone. Target: `rewrite_default_action_startup.go`, `healthcheck.go`.
- **P0-2 (F-05):** Persist a minimal **operation journal** for the maintenance agent (op id + phase +
  target/prior digest, `AtomicWrite`) and make `MarkAllInterrupted()` real: on agent restart, detect an
  in-flight apply, reconcile Docker (running digest vs journal), and either resume or roll back.
  Target: `cmd/culvert-maint/internal/ops/ops.go:468`, `handlers_upgrade_apply.go`.
- **P0-3 (F-03/F-04):** ~~Quarantine-don't-overwrite~~ **SHIPPED 2026-07-12** (`state_corruption.go`):
  present-but-corrupt `ui_users.json`/`cluster.json` is renamed to `.corrupt.<unixnano>` before any
  save can overwrite it, with a `state_file_corrupt` alert (deferred until the webhook store loads)
  and a report-only `/readyz` row. **Remainder:** the refuse-to-boot / locked-admin fail-closed
  posture (`readVersionFloor` pattern) is still open — boot currently proceeds with an empty store.

### P1 — prolonged outage, silent policy failure, broken restore, misleading health
- **P1-1 (F-08/F-25):** Add readiness gates for sustained CP-poll failure and imminent node-cert
  expiry (`handleReady` reads `dpControlPlanePollFailing` + `checkDPCertExpiry`); hot-reload the DP
  gRPC client after `renewDPCert` (mirror `cdr_health.go:254`). Target: `healthcheck.go`,
  `dp_enrollment.go:407`, `controlplane_client.go`.
- **P1-2 (F-12/F-13):** Make `applyConfigBackup` return per-store `Save()` errors and surface a
  partial-apply warning + alert; convert `go SaveAdminSettings()` to synchronous with the error
  returned to the mutating handler. Target: `configversion.go:274`, `admin_settings.go:437`.
- **P1-3 (F-24/F-19):** A boot-time **"expected-state" assertion**: if `/data` is a mount and both
  `ui_users.json` and `cluster.json` are absent while a mount-present sentinel says otherwise, refuse
  to silently fresh-start; promote the RO writability probe from advisory to a fail-closed startup gate
  (or a loud degraded readiness state). Target: `persistent_admin_state_startup.go:38`, `diagnostics.go:81`.
- **P1-4 (F-18):** Restore: warn/refuse on `culvert_version` skew (at least downgrade); add a
  required-Tier-1-presence check; surface the encrypted-CA KEK-custody requirement in the restore
  summary; add `idp_profiles.json`/`revocations.json` to the backup allowlist (or document the
  exclusion). Target: `restore.go:345,415`, `backup.go:57`.
- **P1-5 (F-09/F-10):** Add `fail_mode: open|closed` to the upstream pool + a pool-empty alert; wire
  the circuit breaker into the transport path (or delete it); make the health-probe URL configurable;
  add `scan.on_error: block|allow` + `culvert_scan_errors_total`; align the plain-HTTP scan-error path
  with the inspect path. Target: `internal/upstream/upstream.go:291,302`, `internal/secscan/secscan.go`,
  `proxy_http.go:161`.

### P2 — operational friction, incomplete diagnostics, manual recovery gaps
- **P2-1 (F-20):** Free-space preflight before `docker pull` in the agent apply path.
- **P2-2 (F-14):** A global scan-buffer semaphore; reconsider a generous default connlimit.
- **P2-3 (F-15/F-17):** Budget the early shutdown phase (race `GracefulStop` vs timer → `Stop()`);
  honor a second SIGTERM; unify env-vs-config secret handling (both loud or both alert-and-fallback).
- **P2-4 (F-27/CHAOS-20):** Export threat-feed staleness + sync-failure to Prometheus.
- **P2-5 (DEBT-009):** Effective-config precedence/source diagnostics endpoint.

### P3 — hardening & usability
- **P3-1 (F-22):** Skew tolerance on the runtime catalog-freshness watchdog (mirror the load-time
  `catalogClockSkew`); an NTP/clock-drift health hint (TOTP-lockout is the sharpest consequence).
- **P3-2 (F-16):** A `/data` directory lock (advisory `flock`) to prevent two-instance LWW corruption.
- **P3-3 (F-30):** Align `category_groups` corrupt-load posture with the fail-closed sibling stores.
- **P3-4:** Boot-time orphan `*.tmp.*` sweep (crash-leftover hygiene); CHAOS-13/14 jitter + gRPC
  keepalives; renumber the CHAOS ledger (governance §13).

---

## 15. Independent three-perspective review

**(1) Appliance reliability engineer.** The write layer and restore guard are genuinely strong; the
availability killers are F-05 (agent-death), F-14 (OOM), F-15 (shutdown hang), and F-23 (crash loop).
The most under-appreciated is F-24: an unmounted volume should never be indistinguishable from a first
boot on an appliance — that is the classic "customer restored the VM without the data disk" incident.
Ranks P0-2, P1-3 highest.

**(2) Security architect.** F-01 (default-open) and F-04 (revoked-cert revalidation) are the ones that
turn an operational event into a security bypass. F-02/F-09/F-10 are fail-opens that erode the product's
core value (a SWG that silently stops inspecting is worse than no SWG, because the operator believes
it's on). Insists P0-1 and P0-3 are non-negotiable before any "appliance" claim, and that F-01's
advisory-log-only signal is itself the defect.

**(3) Customer support / field engineer.** Everything that "reports success but didn't persist"
(F-12/F-13) or "looks ready but isn't" (F-08) generates the worst support tickets — the customer's
dashboard disagrees with reality. The lost-passphrase downgrade (F-02) and the KEK-custody DR trap
(F-18) are the top "why did my appliance stop working after a reboot/restore" calls. Wants the
observability gaps (§8) closed first because they convert silent failures into diagnosable ones.

**Resolved disagreement / unresolved tradeoff.** The reliability and security reviewers disagreed on
F-01's fix: security wants fail-**closed** by default (refuse to serve until configured); reliability
warns that a fail-closed default breaks the onboarding UX the passthrough default exists to serve, and
risks a worse outcome (operator disables auth entirely to get traffic flowing). **Resolution adopted in
P0-1:** keep passthrough available for onboarding but make it *loud and un-missable* (degraded readiness
+ banner + alert), not silent — this satisfies the security requirement (no silent open posture) without
forcing the fail-closed onboarding cliff. **Unresolved tradeoff (recorded):** whether an
internet-exposed first boot should hard-refuse to bind the proxy port until setup completes is a product
decision, not a code defect — flagged for the maintainer.

---

## 16. What could not be verified (honesty about limits)

- No behavior was executed: SIGKILL-mid-write, real ENOSPC/EROFS, registry-network fault during
  `docker pull`, and actual clock steps were **not injected** — all "actual" claims are static code
  reads, cross-validated across six independent agents and the CHAOS reviews.
- Whether `idp_profiles.json`/`revocations.json`/`fileprofiles.json` omission from backups is
  **intentional** is unverifiable from code/docs (F-18 item 3) — confirm with the maintainer.
- Whether gRPC actually re-dials via `failover()` on an idle GOAWAY (vs silently reusing a broken conn)
  is gRPC-internal timing; the load-bearing fact for F-25 is that the code provides **no** explicit
  post-renewal reconnect.
- `docker pull` digest verification relies on Docker's own content-addressing; no additional in-Go
  re-hash was found (F-21).

---

*End of audit. Companion documents: `DAY2-OPERATIONS-READINESS.md` (operator acceptance criteria),
`FAILURE-INJECTION-TEST-PLAN.md` (deterministic tests for the highest-value scenarios).*
