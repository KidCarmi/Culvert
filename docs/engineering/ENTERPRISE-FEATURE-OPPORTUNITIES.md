# Enterprise Feature Opportunities

Capabilities exposed *naturally* by attempting a real enterprise implementation of Culvert. Each is justified by a specific deployment step that blocked or degraded, not by competitor parity. For each: the exposing step, the customer problem, current workaround + its quality, security/operational value, implementation leverage (does the primitive already exist?), complexity, architectural fit, timing (before-MVP / first-enterprise-customer / later), and acceptance criteria.

Timing definitions:
- **Before MVP** — the product is not credibly deployable/operable without it.
- **First enterprise customer** — needed before the first real, supported enterprise engagement.
- **Later** — valuable, not gating.

Cross-references are to the [Gap Register](ENTERPRISE-IMPLEMENTATION-GAP-REGISTER.md).

> **Independent review status:** each opportunity below was re-reviewed for (a) solving a real deployment problem, (b) no existing capability already solving it, (c) correct scope, (d) no unnecessary architecture. Results in the "Review" line per item.

---

## FO-1 — GUI/API backup & restore (surface the existing agent primitives)

- **Exposing step:** Backup configuration / restore validation (steps 41–42). GAP-BAK-01.
- **Customer problem:** A no-SSH admin cannot back up or recover — the only path is `docker compose --profile cli` on the host. This also violates the project's own GUI-parity rule.
- **Current workaround:** Host CLI / retained SSH. **Quality: poor** for a no-SSH model.
- **Security value:** Medium — self-service, audited backups without handing operators host shell.
- **Operational value:** High — backup/restore is a day-1 requirement.
- **Implementation leverage:** **Very high.** The maintenance agent *already implements* `POST /v1/backups`, `GET /v1/backups`, `POST /v1/restores/dryrun`, `POST /v1/restores/commit` over its UDS. This is wiring admin routes to an existing engine, not building backup.
- **Complexity:** Medium.
- **Architectural fit:** Strong — mirrors the existing Release Management → agent dispatch pattern; keeps restore-commit offline-gated.
- **Timing:** **First enterprise customer.**
- **Acceptance criteria:** An admin takes an encrypted backup and runs a restore dry-run from the GUI with no host shell; commit still enforces the offline gate; actions are audited. **Scope note:** backup/restore rides the CP-local agent (`localAgentKey = "local"`), so in a CP/DP cluster this covers **CP node config/state**, not DP-local data — state this explicitly so it is not mistaken for a whole-cluster backup.
- **Review:** Real problem (GAP-BAK-01, verified); routes `/v1/backups`, `/v1/restores/dryrun`, `/v1/restores/commit` confirmed present (`cmd/culvert-maint/internal/server/server.go:280-283`) so "wire existing primitives" is accurate; no new architecture. **Endorsed** (independent reviewer: by the project's own GUI-parity rule this arguably reads *before-MVP*, not just first-customer).

## FO-2 — Support bundle endpoint

- **Exposing step:** Diagnostics & support (step 40). GAP-MON-01.
- **Customer problem:** No single redacted artifact for a support ticket; engineers stitch ≥4 API calls + host access for the system log.
- **Current workaround:** Manual API stitching + `--backup`. **Quality: poor** as GUI self-service.
- **Security value:** Medium — a *redacted* bundle is safer than ad-hoc log sharing.
- **Operational value:** High — every support interaction needs it.
- **Implementation leverage:** **High** — aggregates existing sources (`/api/diagnostics`, `/api/audit?source=file`, `/api/config/export`, version info, recent logs) with existing redaction.
- **Complexity:** Medium.
- **Architectural fit:** Strong — a read-only aggregator handler.
- **Timing:** **First enterprise customer.**
- **Acceptance criteria:** `GET /api/support-bundle` (admin) streams a redacted tar.gz; a test asserts no secrets present.
- **Review:** Real, no existing single artifact, correctly scoped to aggregation+redaction. **Endorsed.**

## FO-3 — Monitor-only policy enforcement mode

> **Naming caveat (independent review):** do **not** call this "shadow" mode — `shadow` already denotes the C2 metadata-RBAC log-only mode (`CULVERT_C2_ENFORCE=false`). Use `Monitor` / `monitor-only` to avoid a support/telemetry collision.

- **Exposing step:** Policy rollout / pilot (steps 28, 47). GAP-POL-01.
- **Customer problem:** No observe-only mode — a blocking rule always blocks, so there is no safe window to see what a new deny policy *would* block.
- **Current workaround:** Author rules as `Allow`+log, then flip to deny. **Quality: marginal** — laborious, error-prone.
- **Security value:** High — enables confident, staged enforcement instead of "flip and hope."
- **Operational value:** High — a top enterprise rollout requirement.
- **Implementation leverage:** Medium — the evaluation path exists; add a `Monitor` action (or policy-level `enforcement_mode`) that logs the would-be decision + a `would_block` metric but allows the request.
- **Complexity:** Medium.
- **Architectural fit:** Strong — a new action value + a branch in `proxy.go` + a metric.
- **Timing:** **First enterprise customer.**
- **Acceptance criteria:** In monitor mode a would-block request is allowed and logged with `would_block=true`; a metric counts would-blocks; test covers it.
- **Review:** Real (GAP-POL-01, verified); not solved by `LogTraffic` or default-action; scope is minimal. **Endorsed.**

## FO-4 — Setup token (fix trust-on-first-use)

- **Exposing step:** Initial administrator access (step 15). GAP-APP-04.
- **Customer problem:** Anyone reaching :9090 during the boot window claims admin.
- **Current workaround:** Firewall :9090 until setup. **Quality: procedural, not enforced.**
- **Security value:** High — closes an admin-takeover window with a small change.
- **Operational value:** Low-Medium.
- **Implementation leverage:** High — print a random token to the container/console log; require it in `apiSetupComplete`.
- **Complexity:** Small.
- **Architectural fit:** Strong.
- **Timing:** **First enterprise customer.**
- **Acceptance criteria:** With the feature on, setup rejects a request lacking the console-printed token; tests cover reject + accept.
- **Review:** Real security gap; no existing control; minimal scope. **Endorsed.**

## FO-5 — In-band administrator break-glass / recovery mode

- **Exposing step:** Break-glass recovery (step 24). GAP-IAM-01.
- **Customer problem:** The only recovery from a lost sole-admin password is a host CLI flag — impossible under strict no-SSH.
- **Current workaround:** Multi-admin + retained host-exec. **Quality: acceptable if enforced; not enforced/documented by the product.**
- **Security value:** High (availability of privileged access) — but must not create a network-reachable reset surface.
- **Operational value:** High.
- **Implementation leverage:** Medium — smallest safe version: (a) a startup guard/warning when only one admin exists; (b) a console-gated recovery action on appliance builds. Avoid any unauthenticated network reset endpoint.
- **Complexity:** Medium (guard) → Large (console recovery, needs the appliance from FO-9).
- **Architectural fit:** Moderate — the console variant depends on an appliance form factor.
- **Timing:** **First enterprise customer** (the multi-admin guard + documented runbook); **Later** for full console recovery.
- **Acceptance criteria:** A single-admin deployment surfaces a warning; a documented, tested no-SSH recovery exists for appliance builds; no unauthenticated reset path is added.
- **Review:** Real (verified); the *documented runbook + multi-admin guard* is the correctly-scoped near-term slice — full console recovery is deliberately deferred to avoid over-building before the appliance decision. **Endorsed (phased).**

## FO-6 — Air-gapped update: wire `RepoRewrite` and/or offline bundle

- **Exposing step:** Air-gapped update (steps 21, 43). GAP-UPD-01.
- **Customer problem:** The official signed catalog cannot target an internal registry (the `RepoRewrite` seam is unwired), and there is no offline update bundle.
- **Current workaround:** Self-sign a private catalog + mirror images. **Quality: poor** — heavy, undocumented.
- **Security value:** High — keeps air-gapped customers on the signed supply chain instead of improvising `docker save`/`load`.
- **Operational value:** High for air-gapped customers, none for connected ones.
- **Implementation leverage:** **High for the rewrite** — the `RepoRewrite{From→To}` logic is implemented and tested; it only needs a config surface (`CULVERT_RELEASE_REPO_REWRITE` + validation that `To == ProxyRepo`). The offline bundle is larger.
- **Complexity:** Medium (rewrite wiring) → Large (offline bundle).
- **Architectural fit:** Strong for the rewrite (fills an intentionally-left seam).
- **Timing:** **First enterprise customer** *if air-gapped* (rewrite wiring); **Later** for the full offline bundle.
- **Acceptance criteria:** An operator points the official catalog at an internal registry via config and dispatch succeeds against the same digest; verified in a network-isolated test.
- **Review:** Real (verified unwired); the rewrite-wiring slice is minimal and high-leverage; full offline bundle correctly deferred. **Endorsed (phased).**

## FO-7 — Durable, algorithm-flexible CA import + rotation opt-out

- **Exposing step:** CA import / rotation (steps 31–32). GAP-PKI-01/02/03.
- **Customer problem:** GUI-imported inspection CA is non-persistent, ECDSA-only, and clobbered by auto-rotation.
- **Current workaround:** On-disk EC bundle via host + external expiry monitoring. **Quality: poor.**
- **Security value:** High — avoids silent trust regression on restart.
- **Operational value:** High for internal-PKI customers.
- **Implementation leverage:** Medium — persist the uploaded CA (`SaveCA` on `target=mitm`), accept RSA signing keys, and disable auto-rotation for imported CAs (alert instead).
- **Complexity:** Medium.
- **Architectural fit:** Strong — all three are localized to `internal/ca` + the upload handler.
- **Timing:** **First enterprise customer** *if internal-PKI inspection is in scope.*
- **Acceptance criteria:** An imported (RSA or EC) CA survives restart, signs leaves, and is never silently auto-replaced; tests cover each.
- **Review:** Real (PKI-01 adversarially confirmed); scope localized; note the intentional "forward-only" comment must be revisited deliberately. **Endorsed.**

## FO-8 — Independent CA-expiry watchdog

- **Exposing step:** Certificate expiry (step 31). GAP-PKI-05.
- **Customer problem:** `cert_expiry` fires only on rotation; the documented startup watchdog doesn't exist.
- **Current workaround:** Poll `/api/ca/status` externally. **Quality: acceptable with external monitoring.**
- **Security/Operational value:** Medium — closes a doc/impl drift.
- **Implementation leverage:** High — a startup + periodic ≤30-day check firing `cert_expiry`.
- **Complexity:** Small.
- **Architectural fit:** Strong.
- **Timing:** **Later** (external monitoring suffices short-term).
- **Acceptance criteria:** A CA ≤30 days out fires `cert_expiry` at startup independent of rotation; fix the doc.
- **Review:** Real (drift verified); trivial scope; correctly ranked Later. **Endorsed.**

## FO-9 — Signed appliance image (OVA) + first-boot console

- **Exposing step:** Appliance installation / first boot (steps 12–14). GAP-APP-01/02.
- **Customer problem:** No ISO/OVA; no in-product L3/DNS/NTP/hostname config; forces a Docker-on-VM model.
- **Current workaround:** Golden VM / Compose on a hardened host. **Quality: acceptable for Docker-comfortable customers; not for appliance-mandated procurement.**
- **Security value:** Medium — signed provenance for the appliance.
- **Operational value:** High *if* the customer's model requires an appliance.
- **Implementation leverage:** Low — a new build pipeline + console.
- **Complexity:** XL.
- **Architectural fit:** New surface; only pursue if the appliance form factor is a real requirement.
- **Timing:** **Later** unless contractually required — otherwise **document Compose-on-VM as the supported model** and downgrade the gap.
- **Acceptance criteria:** A signed OVA boots to a first-boot console, runs offline, passes `/ready` smoke; provenance attached to releases.
- **Review:** Real gap, but the *cheapest correct action first* is documenting Compose-on-VM as supported; the OVA is genuinely large and should not be built speculatively. **Endorsed as conditional/Later — explicitly not before-MVP.**

## FO-10 — Scheduled backup

- **Exposing step:** Backup configuration (step 41). GAP-BAK-02.
- **Customer problem:** No automated backup; RPO depends on operator cron.
- **Current workaround:** External cron + off-host sync. **Quality: acceptable if owned.**
- **Operational value:** High.
- **Implementation leverage:** Medium — **not** merely "extends FO-1." The maintenance agent has **no scheduler primitive** (no timer/cron/retention loop under `cmd/culvert-maint`), so this adds a net-new timer + retention loop, not just wiring.
- **Complexity:** Medium.
- **Architectural fit:** Moderate (new scheduling loop).
- **Timing:** **Later** (downgraded on independent review). The workaround — external cron / host systemd timer invoking the FO-1 backup — fully covers RPO once FO-1 exists; ship FO-1 first, then reassess demand for in-product scheduling.
- **Acceptance criteria:** An operator sets a nightly encrypted backup + retention from the GUI; backups appear on schedule.
- **Review:** Real; workaround acceptable if owned; **downgraded to Later** — the "extends FO-1" framing overstated leverage (no scheduler primitive exists). Ship FO-1 first.

## FO-11 — Admin SSO (IdP-group → admin RBAC)

- **Exposing step:** Administrator roles (steps 23, 26). GAP-IAM-02.
- **Customer problem:** Admin accounts are a separate local store outside the IdP lifecycle; no central MFA/conditional access on admin login.
- **Current workaround:** Small manual roster + TOTP. **Quality: acceptable for few operators; not for IdP-mandated shops.**
- **Security value:** High for centralized privileged-access governance.
- **Operational value:** Medium.
- **Implementation leverage:** Medium — reuse the existing OIDC/SAML engine for an admin-side callback + a group→role map; keep local accounts as break-glass.
- **Complexity:** Large.
- **Architectural fit:** Moderate — must not entangle admin identity with the proxy session.
- **Timing:** **First enterprise customer** *if IdP-mandated*; otherwise **Later**.
- **Acceptance criteria:** An admin logs in via the corporate IdP and gets a mapped role; local break-glass still works.
- **Review:** Real; reuses existing IdP code; keep break-glass local. **Endorsed (conditional).**

---

## Prioritisation summary

| Timing | Opportunities |
|---|---|
| **First enterprise customer** | FO-1 (backup/restore GUI), FO-2 (support bundle), FO-3 (monitor-only), FO-4 (setup token), FO-5 (recovery guard + runbook), FO-6 (repo-rewrite wiring, if air-gapped), FO-7 (CA import durability, if internal-PKI) |
| **Later** | FO-8 (expiry watchdog), FO-10 (scheduled backup — after FO-1, no scheduler primitive today), FO-9 (appliance/OVA — conditional; **document Compose-on-VM first, do not build the OVA speculatively**), FO-11 (admin SSO — conditional), FO-6/FO-5 full variants |

The four highest-leverage, lowest-risk items — **FO-1, FO-2, FO-3, FO-4** — each reuse an existing engine or add a small, localized change, and each closes a verified gap that a first enterprise customer will hit in week one. None introduces new architecture. Recommend sequencing these first. (Independent review confirmed all four gaps are truly absent in code and endorsed this sequencing; it downgraded FO-10 to Later — the maintenance agent has no scheduler primitive, so external cron suffices — and cautioned that the FO-9 OVA is genuinely XL and should not be built before it is contractually required.)
