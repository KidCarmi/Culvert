# Culvert Customer Operations Lifecycle Review

**Lens:** Customer Success Engineering / Enterprise Platform Engineering /
Technical Account Management / Product Operations / Professional Services.

**Scope:** the complete operational lifecycle of a Culvert customer — first
contact → retirement. **Not** a security/release/R2/CI review; those are accepted
and referenced only where they touch the customer experience.

Grounded in the actual repo. Capabilities that exist are cited; missing ones are
**[GAP]**; structural/model facts are **[STRUCTURAL]**.

---

## 0. The main question, answered first

> **If a customer buys Culvert today and stays five years, what does the journey
> look like — and is every stage clean, supportable, scalable, low-friction?**

**The *administrator* journey is surprisingly strong. The *commercial* and
*support* journeys have foundational gaps.** Three facts from the repo dominate
this review:

1. **[STRUCTURAL] Culvert is software, not an appliance.** It ships as **Docker
   Compose + a systemd host agent** (`packaging/culvert-maint`, `packaging/systemd`,
   `scripts/install.sh`) — there is **no ISO/OVA** (the "OVA" hits in the tree are
   false positives — `apprOVAl`/`remOVAl`). So the customer's **Linux host, Docker
   engine, OS patching, and networking are all in the support surface.** The
   prompt's "ISO/OVA → first boot → wizard" assumes a form factor Culvert does not
   have. This is the **single largest source of onboarding + support friction.**
2. **[GAP] There is no licensing, entitlement, activation, customer-registration,
   or tenant system** (confirmed: zero `licens*`/`entitlement*`/`activation` in
   `static/index.html` or the runtime; `enrollment.go` is *cluster-node* join, not
   customer licensing). The entire **commercial wrapper** — purchase, license
   issuance, renewal, support-tier enforcement, EOL signaling — **does not exist in
   the product.** Sales/Purchase/Renewal/EOL stages have no product hooks today.
3. **[GAP] There is no vendor telemetry and no downloadable support bundle**
   (confirmed prior review; `diagnostics.go` produces an in-product *health
   verdict* `OperatorContract`, ok/warn/fail with actionable hints — a great
   foundation — but not an exportable logs+config+state bundle). So **support is
   blind and manual.**

**The good news:** the *technical* building blocks for most lifecycle stages
**already exist and are solid** — guided install script, HA fencing lease, backup
/restore with validation+analyzer+offline commit, 50-version config rollback,
full SSO (LDAP/OIDC/SAML/multi-IdP) + TOTP + RBAC, key-at-rest + CA rotation,
digest-pinned updates, and an actionable diagnostics verdict. Culvert is **not**
missing runtime capability; it is missing the **commercial and customer-success
connective tissue** around it.

**Verdict:** a customer who buys today and is a competent Linux/Docker shop will
have a **workable but DIY** five years — clean on HA/backup/updates/config,
**friction-heavy on install, support, and the commercial lifecycle.** To be
**low-friction at enterprise scale**, redesign the *operational workflow* (not the
architecture) around five additive things: **(A) an appliance/turnkey form factor
or a hardened guided installer, (B) a support-bundle export, (C) a first-run setup
wizard with preflight validation, (D) licensing + EOL signaling, (E) opt-in
telemetry.** None increases architectural complexity; all reduce operational
complexity.

---

## Customer lifecycle — the 13 stages (grounded, with who/manual/auto/fail/recovery/future)

### 1. Sales / Pre-Sales

| Aspect | State |
|---|---|
| Product evaluation / trial / PoC | **[GAP] no time-boxed trial or license-gated eval** (no licensing). Today "eval" = `scripts/install.sh` off the public image — good for a technical buyer, no guardrails for a managed PoC. |
| Licensing / sizing / HW requirements | **[GAP] no license; [GAP] no published sizing guide** (Docker resource asks exist in compose, but no "N Mbps / M users → X cores/RAM" table). |
| Security docs / architecture review | ✅ **strong**: `docs/architecture.md`, `docs/deployment-guide.md`, `docs/operator/*`, security-reviews, SBOM/provenance. A security buyer's diligence is well-served. |

- **Who:** SE/Sales Eng + customer security team. **Manual:** everything (spin up compose, hand-configure). **Auto:** install script only. **Can fail:** eval drifts into an unsupported prod deploy (no license boundary). **Future:** time-boxed signed eval license + a one-command PoC bundle with sample policy + a sizing calculator.

### 2. Purchase

| Aspect | State |
|---|---|
| License creation / customer registration / tenant | **[GAP] none — [STRUCTURAL]** self-hosted, no vendor tenant. |
| Download experience | ✅ public image (GHCR) + install script; **[GAP]** no versioned "download center" with release selection UX. |
| Release selection | ⚠️ implicit — the customer points `CULVERT_RELEASE_CATALOG_URL` at `stable`; no guided "choose your supported version." |

- **Future:** a **lightweight offline license** = a signed entitlement file the customer drops in (`/data/license.json`), verified with the *existing* signing primitives (reuse the ed25519/keyless verification pattern — **no new crypto**, just a new artifact type). It carries entitlement + support tier + expiry + EOL date and drives in-product renewal/EOL banners. This is the smallest commercial hook and it unlocks stages 2/12/13.

### 3. Installation

**[STRUCTURAL] No ISO/OVA/first-boot.** Reality today: customer provisions a Linux
host + Docker, runs `scripts/install.sh` (seeds pinned image, wires the
`culvert-maint` agent, health-validates — `install-lifecycle-e2e.yml` covers this).

| Checklist item | Today |
|---|---|
| Deploy | `docker compose up` via install script | ✅ works |
| First boot | container starts; `/healthz`+`/readyz` (`healthcheck.go`) | ✅ |
| Initial wizard | **[GAP] web setup gate only** (`IsConfigured`/`defaultAuthOutcome`, bootstrap token flow `bootstrap.go`) — no guided TUI/first-run wizard for network/TLS/DNS/time |
| Network / TLS / DNS | manual (compose env, UI-TLS `internal/uitls`) | ⚠️ hand-configured |
| Time sync | **[GAP] not validated** — yet clock skew breaks catalog freshness (5-min tolerance) and TOTP | ❌ silent failure risk |
| Admin creation | web setup + bcrypt (`auth.go`) | ✅ |
| Licensing | **[GAP]** | — |
| Health validation | `diagnostics.go` `OperatorContract` (ok/warn/fail, actionable) | ✅ **strong foundation** |

> **Should the installer detect problems automatically? YES — and it half does.**
> `diagnostics.go` already computes an actionable health verdict. The **[GAP]** is a
> **preflight**: before/at first boot, validate host clock/NTP, Docker version,
> rootful/no-userns (the maint-agent wiring already checks some of this per
> `release-management-agent.md`), disk, ports, DNS resolution, and TLS cert
> validity — and **refuse or loudly warn** rather than boot into a subtly-broken
> state. This is the highest-leverage, lowest-complexity onboarding win.

### 4. Initial Configuration (first-day)

| Should be… | Recommendation |
|---|---|
| **Automatic** | admin RBAC defaults, default-deny policy (already the model), TLS on the UI, audit ring, config-version snapshots, backup schedule prompt |
| **Optional** | SSO/IdP (LDAP/OIDC/SAML — all exist), SSL inspection + CA, threat feeds, clustering/HA, bandwidth/QoS |
| **Impossible to misconfigure** | open-mode admin UI must stay gated (already true — `IsConfigured`); CA passphrase required for inspect (already enforced); **[GAP]** make "no backup passphrase configured" a first-day blocking warning, not a silent skip |

- **Future:** a **guided setup wizard** (web) that sequences: admin → time/NTP → TLS/DNS → auth mode/IdP → first policy → backup → readiness check. Reuse `OperatorContract` as the "you're ready" gate.

### 5. Production Readiness

**This mostly EXISTS** — `diagnostics.go`'s `OperatorContract` is a production-
readiness verdict engine. Turn it into an explicit checklist (see Deliverable 7).
**[GAP]:** add checks for NTP/clock, backup-configured+tested, TLS-not-self-signed,
license-valid, catalog-reachable+fresh, HA-quorum (if clustered).

### 6. Daily Operations

| Task | State | Automate? |
|---|---|---|
| Monitoring / health | `/healthz`, `/readyz`, `OperatorContract`, Prometheus `metrics.go`, SSE events | ✅ mostly; **[GAP]** ship a reference Grafana dashboard + alert rules |
| Backups | `cli` service backup (`docker-compose-backup-restore.md`) | ⚠️ **manual/cron-your-own** → should be a scheduled default |
| Updates | operator-confirmed dispatch (Release panel) | ⚠️ manual per update |
| Logs | rotating file + JSON + syslog/SIEM (`logger.go`, `syslog.go`) | ✅ good |
| Certificates | CA rotation loop, UI-TLS, OCSP; key-at-rest | ✅ ; **[GAP]** expiry alerting for the UI/customer certs |
| Policy management | full policy engine + UI + config versioning/rollback | ✅ **strong** |
| Performance | Prometheus histograms, per-rule counters | ✅ |
| Troubleshooting / support bundle | `OperatorContract` verdict | ⚠️ **[GAP] no exportable support bundle** |

> **How much should be automated? The 80/20: backups (scheduled by default),
> cert-expiry alerts, and health→alert wiring.** Everything else is already
> self-service in the UI.

### 7. Updates (the customer's experience)

| Step | Today | Should be |
|---|---|---|
| Discovery | CP pulls catalog; **[GAP] refresh unwired in prod (RB-3)** → discovery only on restart/manual | periodic auto-discovery (wire the refresher) |
| Approval | operator confirms | ✅ keep (with opt-in auto-apply for critical) |
| Scheduling | **[GAP] none** — apply is now-or-never | maintenance-window scheduling |
| Execution | agent pulls digest, restarts, verifies (`handlers_upgrade_apply.go`) | ✅ strong, digest-verified |
| Validation | hard RepoDigest verify + health gate | ✅ |
| Rollback | inline auto-rollback on failure + manual `rollbacks` with anchor digest | ✅ mechanism; **[GAP]** one-click guided rollback UX |
| Failure recovery | fail-closed; proxy stays up | ✅ |
| Notification | in-UI availability | **[GAP]** email/webhook "update available/critical" |

> **How should customers experience updates?** Discover automatically, be
> *notified* (esp. critical), *schedule* into a window, apply with one click, see a
> clear validation result, and roll back in one click if needed. Today the *engine*
> is excellent; the *experience* (discovery/scheduling/notification) is thin.

### 8. Support

| Aspect | State |
|---|---|
| Request support / logs / diagnostics | logs exist; `OperatorContract` verdict exists | ⚠️ |
| **Support bundle (safe export)** | **[GAP] the single biggest support gap** | ❌ |
| Air-gap export | config export exists (`apiConfigExport`); no *diagnostic* bundle | ⚠️ |
| Remote troubleshooting | **[GAP]** no vendor remote access (correct for a security product — keep offline) | — |
| Telemetry (optional) | **[GAP] none** | ❌ |

> **How do support engineers diagnose fast? Today: slowly and blind.** They ask
> the customer for logs by hand. **The fix is one feature: a `culvert support-bundle`
> export** — a signed, redacted archive of `OperatorContract` + version/digest +
> config-version summary (not secrets) + recent audit + update history + health
> timeline, generated with one command/click, safe to email or hand over air-gapped.
> This extends `diagnostics.go` (which already assembles most of it read-only) and
> is the highest-ROI customer-ops feature in the whole review.

### 9. Expansion

| Task | State |
|---|---|
| Add appliances / scale horizontally | ✅ token enrollment (`enrollment.go`), CP/DP, node groups (label selectors) |
| Add HA | ✅ **strong** — etcd fencing lease (`ha-lease-failover.md`), auto-promote/standby |
| Rolling upgrade of a cluster | ✅ `update_cluster.go` (canary→soak→error-budget) |
| Upgrade HW / change networking / move DC | ⚠️ backup/restore + re-enroll; **[GAP]** no documented "migrate a node" runbook |
| Expand licenses | **[GAP]** no license = no seat/throughput enforcement |

- Expansion is **technically well-supported**; the gaps are **documentation** (migration runbooks) and **licensing** (entitlement growth).

### 10. Disaster Recovery

| Scenario | State |
|---|---|
| Node/disk failure | ✅ HA failover (lease) + restore from backup |
| Restore from backup | ✅ **strong** — validation → analyzer → **offline commit** (`D1.3b`, `docker-compose-backup-restore.md`) |
| Lost certificates / CA | ⚠️ CA rotation exists; **[GAP]** "lost CA/passphrase" recovery runbook (key-at-rest `key-at-rest.md` helps) |
| Lost administrator | ⚠️ **[GAP]** no documented break-glass admin-reset runbook (lockout.go handles brute-force, not recovery) |
| Lost database/config | ✅ config export/import + 50-version rollback + backup restore |
| Site migration | ⚠️ backup→restore works; **[GAP]** end-to-end migration runbook |

> DR *primitives* are strong (backup/restore/HA); the **[GAP] is runbooks** for the
> scary human cases: lost admin, lost CA passphrase, full site rebuild.

### 11. Security Incidents

| Scenario | Recovery today |
|---|---|
| Compromised administrator | rotate creds, revoke sessions (session revocation exists), audit review | ⚠️ needs a runbook |
| Compromised appliance | isolate, restore from known-good backup, re-enroll | ⚠️ runbook |
| Expired certificates | CA rotation / re-issue | ⚠️ **[GAP] proactive expiry alerting** |
| Failed update / emergency hotfix / rollback | fail-closed + inline rollback + forward-supersede | ✅ engine strong; **[GAP]** notification + one-click |

- Primitives exist; the **[GAP] is the incident-response runbook + proactive alerting** (cert expiry, failed update, session anomalies).

### 12. Renewal

**[GAP] entirely external today** — no license, no maintenance/version-support
signal, no LTS designation, no upgrade-planning surface in-product. **Future
(minimal):** the offline license file (§2) carries `expires_at` + `support_tier`
+ `eol_at`; the UI shows renewal/EOL banners; the catalog carries per-release
`supported_until`/LTS flags (additive metadata) so "am I on a supported version?"
is answerable in-product.

### 13. End of Life

| Task | State |
|---|---|
| Export config / policies | ✅ `apiConfigExport` (curated `configBackup`) |
| Migration | ⚠️ export exists; **[GAP]** documented decommission runbook |
| Secure wipe | **[GAP]** no guided secure-wipe of `/data` (CA keys, sessions, KEK material) |
| Decommission appliance | **[GAP]** runbook |
| Audit trail | ✅ audit ring + config versions; **[GAP]** exportable final audit archive |

- **Future:** a `culvert decommission` flow: export config+audit → secure-wipe `/data` (keys/KEK) → confirm. Low complexity, high trust value for a security buyer.

---

## Deliverables

### 1. Customer Lifecycle Diagram

```
                         ┌─────────────────────────── 5-YEAR JOURNEY ───────────────────────────┐
 PRE-SALES → PURCHASE → INSTALL → INITIAL CONFIG → PROD-READY → ── DAILY OPS ──►  RENEWAL → EOL
   eval/PoC   license*   compose+   wizard*+          readiness    monitor/backup/   license*   export+
   sizing*    download   agent      preflight*        verdict      update/policy      /EOL*     wipe*+
   sec-docs✅  select     health✅   (impossible-to-   (OperatorContract✅)             banners*  audit
                          ✅         misconfig)                │
                                                              ├── EXPANSION ✅ (enroll/HA/cluster)
                                                              ├── DR ✅ primitives / ⚠️ runbooks
                                                              └── INCIDENTS ✅ engine / ⚠️ runbooks+alerts
   ✅ exists   * = [GAP] commercial/UX connective tissue to build   ⚠️ = primitive exists, runbook/alert missing
```

### 2. Customer (buyer/org) Journey

Evaluate (DIY compose, no guardrails) → Buy (no license hook) → Provision a Linux
host + Docker → Install (script, good) → Configure (manual, no wizard) → Run
(strong: HA/backup/policy/updates) → Support (blind, manual) → Renew (external) →
EOL (manual export/wipe). **Clean in the middle, friction at both ends.**

### 3. Administrator Journey

Install script → web setup gate → configure policy/auth/TLS (rich UI) → daily:
health verdict, config-versioned changes, operator-confirmed updates, backups
(manual) → HA/cluster expansion (token enroll) → DR (backup/restore) → **the admin
experience is the strongest part of the product** and mostly self-service. Top
admin gaps: **scheduled backups, cert-expiry alerts, update scheduling/notification,
one-click rollback, and a support-bundle button.**

### 4. Support Engineer Journey

Today: ticket → ask customer for logs/version by hand → guess → slow. Target: ticket
→ customer clicks **"Generate support bundle"** → signed, redacted archive
(`OperatorContract` + version/digest + config-version summary + recent audit +
update history) → SE reads it → root-cause in minutes. **One feature
(support-bundle export) transforms this stage.** Remote access stays *off* by
design (security product) — the bundle is the channel.

### 5. Product Manager touchpoints

Per the release-ops review: define supported versions / LTS / EOL dates (→ catalog
metadata + license), approve releases, own the renewal/EOL calendar. **PM never
touches a customer directly and never edits customer state** — PM sets *policy*
(what's supported, what's EOL) that the product surfaces to every customer via
catalog metadata + license banners.

### 6. Installation checklist (operator-facing)

- [ ] Host: supported Linux, rootful Docker, no userns-remap (maint-agent needs it)
- [ ] **NTP/clock synced** (breaks catalog freshness + TOTP if not) — *preflight must check*
- [ ] Ports/DNS: UI + proxy reachable; outbound to catalog origin + GHCR resolvable
- [ ] Run `scripts/install.sh`; confirm `/healthz` + `/readyz` green
- [ ] Create admin (web setup); enable TOTP
- [ ] Set CA passphrase (if SSL inspect) + **backup passphrase** (don't skip)
- [ ] Configure TLS cert (not self-signed for prod)
- [ ] Point `CULVERT_RELEASE_CATALOG_URL` at the supported ring; confirm `available:true`
- [ ] Drop in license file (when licensing ships)
- [ ] Run the readiness verdict → all `ok`

### 7. Production Readiness checklist (map to `OperatorContract`)

Extend `diagnostics.go` checks so the verdict is `ok` only when: admin+2FA set ·
TLS not self-signed · **NTP synced** · **backup configured AND a test-restore
passed** · audit/log sink configured (SIEM optional) · catalog reachable+fresh+
verified · CA/keys healthy + **cert-expiry > 30d** · **HA quorum healthy (if
clustered)** · **license valid (when it exists)** · default-deny policy active.
Ship this as the literal "Are we production-ready?" screen.

### 8. Daily operations checklist

- [ ] Health verdict `ok` (or triage warn/fail with the supplied `OperatorAction`)
- [ ] Backup ran + is restorable (scheduled, alert on miss)
- [ ] No cert within 30d of expiry
- [ ] Catalog fresh; note any "update available" (apply in-window; apply criticals promptly)
- [ ] Review audit ring for unexpected admin actions
- [ ] Cluster (if any): quorum + all nodes reporting

### 9. Support runbook

1. Reproduce the state: customer generates a **support bundle** (target feature) or exports config + `OperatorContract` + logs.
2. Triage from the bundle: version/digest, health verdict + failing checks, recent config-version diffs, update history, audit anomalies.
3. Known-issue match → fix or workaround → guided config change (config-versioned, so trivially reversible).
4. If update-related: check catalog `available/verify_mode/version/expires_at`, running digest vs offered, refresh outcome.
5. If unrecoverable: restore from a known-good backup (offline commit) or roll config back a version.
6. Escalate with the bundle attached; never request remote access.

### 10. Disaster Recovery runbook

- **Node/disk loss:** HA lease fails over to standby (auto); rebuild the lost node, re-enroll, restore `/data` from backup, rejoin.
- **Full site loss:** provision host → install → **offline restore commit** (`compose down` → `cli --confirm` → `up`) from the latest backup → verify readiness verdict → re-point clients.
- **Lost admin:** *(build this runbook — [GAP])* documented break-glass: host-level reset of the admin record + forced re-setup, audited.
- **Lost CA passphrase:** *(build — [GAP])* re-key CA via rotation, re-issue leafs; document data loss boundary (inspect history).
- **Lost DB/config:** restore backup, or roll forward from config-version snapshots + export.
- Every path ends with the readiness verdict `ok` and a fresh backup.

### 11. Customer onboarding improvements (ranked, low→high effort, all reduce friction)

1. **Support-bundle export** (extends `diagnostics.go`) — transforms support. *Low effort, highest ROI.*
2. **First-run wizard + preflight** (reuse `OperatorContract` as the gate; validate NTP/Docker/ports/DNS/TLS) — kills day-one misconfig.
3. **Scheduled backups + cert-expiry alerts by default** — removes silent DR risk.
4. **Update discovery + notification + scheduling** (wire the refresher; add email/webhook + maintenance windows).
5. **Reference observability pack** (Grafana dashboard + alert rules shipped with the product).
6. **Offline license file + EOL/renewal banners** — the commercial hook.
7. **Turnkey form factor** (OVA/ISO, or a certified cloud image) — the big one for "appliance" positioning.

### 12. Biggest operational pain points

1. **Form factor: DIY container, not an appliance** — customer's host/Docker/OS in the support surface; steepest onboarding friction.
2. **No support-bundle export** — support is blind and manual.
3. **No first-run wizard/preflight** — day-one misconfiguration (esp. clock/TLS) fails silently.
4. **No licensing/entitlement/EOL signaling** — no clean purchase/renewal/EOL loop.
5. **Backups + cert expiry are manual/opt-in** — latent DR and outage risk.
6. **Update experience thin** (discovery/scheduling/notification) despite a strong engine.
7. **Missing human-crisis runbooks** (lost admin, lost CA, site rebuild, decommission).

### 13. Features that should exist BEFORE Enterprise GA

- **Support-bundle export** (signed, redacted, air-gap-friendly).
- **First-run wizard + install preflight** (NTP/Docker/ports/DNS/TLS validation).
- **Scheduled backups + backup-tested readiness check + cert-expiry alerting.**
- **Update notification (esp. critical) + maintenance-window scheduling + one-click rollback UX.**
- **Offline license file + EOL/`supported_until` metadata + in-UI banners.**
- **Lifecycle runbooks:** lost admin, lost CA passphrase, site rebuild, decommission/secure-wipe.
- **A turnkey deployment option** (OVA/ISO or certified cloud marketplace image) — or, if deferred, a *hardened* installer that makes the DIY path near-appliance in reliability.

### 14. Features that can wait until after MVP

- Multi-tenant/managed-service control plane (structurally not the model — likely never).
- Vendor remote-access tooling (keep it off by design; the support bundle replaces it).
- Percentage/phased rollout UX, multi-ring beta/dev for customers.
- Self-service license portal / automated provisioning (manual license issuance is fine at first).
- Fancy fleet analytics beyond the opt-in health beacon.

---

## Product review — friction map & the guiding principle

**Every friction point above resolves to *connective tissue*, not architecture.**
The runtime is capable; the customer experience is thin at the edges (onboarding,
support, commercial). The two highest-leverage, lowest-complexity moves are:

1. **Turn `diagnostics.go` from a screen into two products:** a **preflight/first-run
   gate** (front of the lifecycle) and a **support-bundle export** (support stage).
   Same read-only engine, two customer-facing surfaces — the best complexity-to-value
   ratio in the whole review.
2. **Add the smallest commercial hook — a signed offline license file** — reusing
   existing verification patterns, which unlocks purchase/renewal/EOL with **no new
   architecture.**

**Do NOT** add architectural complexity for these: no multi-tenant control plane,
no vendor remote access, no phone-home-by-default. The pull-based, self-hosted,
privacy-preserving model is a *selling point* to security buyers — keep it, and
make the human lifecycle around it turnkey.

**Bottom line for the five-year journey:** a capable customer will succeed today;
an *average* enterprise will feel DIY friction at install, support, and renewal.
Ship the seven onboarding improvements (Deliverable 11) — especially the
support-bundle, the first-run wizard/preflight, and a turnkey form factor — and the
same architecture becomes a low-friction, supportable, five-year enterprise
lifecycle without adding a single new architectural moving part.
