# Production-Qualification UX — Current-State Visual Report

**Scope:** MCP Gateway admin surface (the nine `mcp-*` views) and the activity
surfaces they depend on.
**Method:** live screenshots of the real `newAdminUIHandler()` middleware chain
driven by headless Chromium (playwright-go), plus code/DOM/API inventory derived
from the merged tree.
**Baseline:** PR #1027 merged; PR-1…PR-11 complete; V1 connectivity = Model A
(`local-client`) only; Production qualification-locked; Management MCP
non-mutating. This pass changed **no** production behavior.

> Every claim below cites a **screenshot** (path under
> `docs/design/mcp/ux-audit-assets/current/`), a **DOM selector**, a **source
> file/function**, or a **Playwright/ledger result**. Nothing here is taste-only.

---

## 1. Executive summary

The MCP gateway is, functionally, **remarkably complete**: nine dedicated views,
24 admin API routes (`registerMCPRoutes`, `ui_mcp.go:127-153`), a rich backend
domain model (rollout mode ladder, hard-failure taxonomy, evaluated-vs-effective
resolution, CP→DP signed distribution with per-DP ack state, durable decision
events, credential power ceilings, an evidence-gated Production lock). The data
an operator needs almost all **exists** and is exposed through the API.

The problem is entirely at the **presentation and workflow layer**:

1. **Eight of nine MCP views render server responses as a raw JSON dump inside a
   `<pre>`** (`mcpShow`, `index.html:5490`; only `mcp-approvals` builds
   structured rows, only `mcp-settings` uses a textarea). The **first** MCP
   screen an operator sees — *MCP Overview* — is a `Refresh` button above a JSON
   blob (`admin-dark/mcp-overview.png`). This is a developer console, not an
   operator product.
2. **The evaluated-vs-effective distinction is present in the data but invisible
   in the UI.** A Shadow-mode policy `DENY` that was executed anyway appears as a
   row `{"action":"DENY", … "execution_state":"shadow_recorded"}` with no visual
   difference from a real block (`admin-dark/mcp-decisions-shadow.png`). The task's
   hard rule — *"the UI must never make a Shadow-executed DENY appear to have been
   an ALLOW"* — is only satisfied by asking the operator to read raw JSON.
3. **Critical state is buried.** Emergency kill-switch active is `"killed": true`
   on line 5 of a JSON object (`admin-dark/mcp-rollout-killswitch.png`);
   durability-degraded is a nested `"severity":"high"`
   (`admin-dark/mcp-health-durability.png`); a min-version-incompatible fleet is
   `distribution_state:"distribution_degraded"` in a blob
   (`admin-dark/mcp-health-dpincompat.png`). No banner, chip, or "needs
   attention" surface exists.
4. **Blast radius before promotion does not exist in the GUI.** Scope editing
   (`PUT /api/mcp/rollout/scope`), publication creation
   (`POST /api/mcp/publications`), and publication approval
   (`POST /api/mcp/publication-decision`) have **no UI control at all** — reachable
   only by direct API call (see §5, §7). Mode transition offers a capability + a
   target-mode dropdown and a button, with no scope-delta / affected-subjects /
   newly-executable-operations preview (`admin-dark/mcp-rollout-*.png`, Mode
   Transition panel).
5. **Stale-data has no indicator.** Every panel prints whatever the last fetch
   returned; there is no "as-of" timestamp, no auto-refresh, and `mcp-rollout` is
   not even auto-loaded (absent from the load table `index.html:5677-5684`) — all
   six of its panels are blank until the operator clicks each `Refresh`.

The **good news** for the qualification program: the Production lock is real and
un-bypassable at the data layer (`production_locked:true` is hard-coded because
the build ships no qualification issuer, `mcp_rollout.go:141`;
`checkProductionQualification` fails closed, `transition.go:106`), and the RBAC /
error / redaction behavior is correct server-side. So the required work is a
**presentation + workflow layer over an already-correct engine** — not a rewrite,
and not new production behavior. This report enumerates exactly what that layer
must add.

Bottom line: **Culvert MCP is safe but not yet *operable* for qualification.** An
operator cannot currently answer "what is at risk, what is executing only because
of Shadow, what is the blast radius, and what is the safest next action" without
reading and mentally parsing JSON. Those are the Production-Qualification UX
blockers in §13.

---

## 2. Screenshot contact sheet

49 screenshots, all captured against the real handler chain. Full ledger:
`ux-audit-assets/current/_ledger.json`. Directory layout:
`current/<role>-<theme>/[responsive/<width>px/]<view>[-<scenario>].png`.

### Current-state baseline — admin / dark / 1920 (real, unseeded, disabled-default)
| View | File |
|---|---|
| MCP Overview | `admin-dark/mcp-overview.png` |
| MCP Servers & Tools | `admin-dark/mcp-servers.png` |
| MCP Decisions & Explain | `admin-dark/mcp-decisions.png` |
| MCP Policies & Simulator | `admin-dark/mcp-policies.png` |
| MCP Approvals | `admin-dark/mcp-approvals.png` |
| MCP Health & Durability | `admin-dark/mcp-health.png` |
| MCP Rollout & Execution | `admin-dark/mcp-rollout.png` |
| Management MCP Access | `admin-dark/mcp-management.png` |
| MCP Listener Settings | `admin-dark/mcp-settings.png` |
| Dashboard / Traffic / Audit | `admin-dark/dashboard.png`, `livefeed.png`, `audit.png` |

### Operational-posture scenarios — admin / dark / 1920 (synthetic fixtures)
| Scenario (task #) | View | File |
|---|---|---|
| Healthy install (1) | overview/health/rollout | `admin-dark/mcp-{overview,health,rollout}-healthy.png` |
| Observe mode (3) | rollout | `admin-dark/mcp-rollout-observe.png` |
| Shadow + overrides (4) | rollout, decisions | `admin-dark/mcp-rollout-shadow.png`, `mcp-decisions-shadow.png` |
| Canary mixed (5) | rollout, decisions | `admin-dark/mcp-rollout-canary.png`, `mcp-decisions-canary.png` |
| Hard auth failure (6) | decisions/explain | `admin-dark/mcp-decisions-hardfail.png` |
| Unknown/drifted tool (7) | servers | `admin-dark/mcp-servers-unknowntool.png` |
| Request DLP block (8) | decisions/explain | `admin-dark/mcp-decisions-dlpblock.png` |
| Response DLP redaction (9) | decisions/explain | `admin-dark/mcp-decisions-dlpredact.png` |
| Partial CP→DP ack (10) | health | `admin-dark/mcp-health-partialack.png` |
| DP incompatible / min-version (11) | health | `admin-dark/mcp-health-dpincompat.png` |
| Durability-degraded (12) | health, overview | `admin-dark/mcp-health-durability.png`, `mcp-overview-durability.png` |
| Emergency kill switch (13) | rollout | `admin-dark/mcp-rollout-killswitch.png` |
| Rollback available (14) | health | `admin-dark/mcp-health-rollback.png` |
| Production locked / missing evidence (15) | rollout | `admin-dark/mcp-rollout-prodlocked.png` |
| Loading/API-failure/stale (18) | overview | `admin-dark/mcp-overview-apifail.png` |
| Operational approvals (detail) | approvals | `admin-dark/mcp-approvals-approvals.png` |

### RBAC — dark / 1920
| Role | Files |
|---|---|
| Operator (16 contrast) | `operator-dark/mcp-{overview,rollout}-healthy.png`, `mcp-settings.png` |
| Viewer (16 permission-denied) | `viewer-dark/mcp-{overview,rollout}-healthy.png`, `mcp-settings-viewer-denied.png` |

### Themes & resolutions
| Set | Files |
|---|---|
| Light theme (primary + investigation) | `admin-light/mcp-overview-healthy.png`, `mcp-decisions-shadow.png`, `mcp-rollout-healthy.png`, `dashboard.png`, `livefeed.png` |
| 1440×900 | `admin-dark/responsive/1440px/mcp-{overview,rollout}-healthy.png` |
| 1280×800 | `admin-dark/responsive/1280px/mcp-{overview,rollout}-healthy.png` |

---

## 3. Actual screen inventory (Phase 1)

Derived from `static/index.html`, `uiRoutes` (`ui_routes_meta.go:847-915`), the
`registerMCPRoutes` handlers (`ui_mcp.go`, `ui_mcp_rollout.go`), and the
Playwright run. "PW E2E" = a dedicated browser test exists **before** this audit.

| data-view | Nav label | Min role | Primary operator goal | APIs consumed | Mutations reachable in UI | PW E2E (pre-audit) | Loading | Empty | Error | Perm-denied | Stale | Destructive confirm | Deep-link | Investigation pivot | Operational usefulness today |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| mcp-overview | MCP Overview | viewer | See gateway posture at a glance | `GET /api/mcp/overview` | none | **none** | "Loading…" (`mcpGet`) | "No results." | "Error (n): body" | "Permission denied." | **none** | n/a | hash only | **none** | Low — raw JSON, no posture (`mcp-overview.png`) |
| mcp-servers | MCP Servers & Tools | viewer | Inventory servers/tools; spot drift/quarantine | `GET /api/mcp/servers`, `/api/mcp/tools` | none | **none** | yes | "No results." | yes | yes | none | n/a | hash | none (IDs are plain text) | Low — JSON list (`mcp-servers-unknowntool.png`) |
| mcp-decisions | MCP Decisions & Explain | viewer | Search decisions, explain one | `GET /api/mcp/decisions`, `/api/mcp/decision-explain` | none | **none** | yes | "No results." | yes | yes | none | n/a | hash | **none** — event_id typed by hand | Medium data / Low form (`mcp-decisions-shadow.png`) |
| mcp-policies | MCP Policies & Simulator | viewer (sim: operator) | View policy; validate/simulate/compare | `GET /api/mcp/policy`; `POST /api/mcp/policy-simulate` | validate/simulate/compare | **none** | yes | — | yes | yes | none | n/a | hash | none | Medium — JSON policy + JSON sim (`mcp-policies.png`) |
| mcp-approvals | MCP Approvals | viewer (decide: admin) | Four-eyes operational approvals | `GET /api/mcp/approvals`; `POST /api/mcp/approval-decision` | approve / reject | **none** | yes | "No approvals." | yes | yes | none | `window.confirm` on destructive (`index.html:5607`) | none | none | Medium — only structured view (`mcp-approvals-approvals.png`) |
| mcp-health | MCP Health & Durability | viewer (rollback: admin) | Runtime + durability + distribution | `GET /api/mcp/health`, `/api/mcp/distribution`; `POST /api/mcp/rollback` | rollback request | **none** | yes | — | yes / 409 | yes | none | none | hash | none | Low — two JSON dumps (`mcp-health-durability.png`) |
| mcp-rollout | MCP Rollout & Execution | viewer (mutate: admin) | Mode/scope/evidence; transition; emergency | `GET rollout, executions, upstream-health, rollout/evidence`; `POST transition, emergency, rehearse-rollback` | transition, emergency disable/clear, rehearse rollback | **none** | **not auto-loaded** (blank until click) | — | yes / 403 / 409 | yes | none | **none** on emergency disable | hash | none | Low — six JSON panels (`mcp-rollout-killswitch.png`) |
| mcp-management | Management MCP Access | viewer | Mgmt access posture + tool catalog | `GET /api/mcp/management-access` | none | **none** | yes | — | yes | yes | none | n/a | hash | none | Low — JSON (`mcp-management.png`) |
| mcp-settings | MCP Listener Settings | **admin** | Node-local gateway/mgmt config | `GET/PUT /api/mcp/config` | save config | **none** | custom | — | "Permission denied." | hidden from nav | none | none | hash | none | Medium — editable textarea (`mcp-settings.png`) |

Routes with **no GUI entry point** (API-only; a GUI-parity gap — see §11):
`POST /api/mcp/publications` (create publication request), `POST /api/mcp/publication-decision`
(approve/reject/publish), `PUT /api/mcp/rollout/scope` (edit scope / blast radius),
`GET /api/mcp/tools` (loaded only via the servers panel, no metadata row).
Source: agent inventory of `ui_mcp.go` + `static/index.html` `data-click` handlers.

**MCP surfaces the task asked about, mapped to what actually exists** (they are
*panels inside* the nine views, not separate screens):

| Task concept | Where it actually lives | Evidence |
|---|---|---|
| Overview | `mcp-overview` view | `mcp-overview.png` |
| Inventory | `mcp-servers` view (servers + tools) | `mcp-servers-unknowntool.png` |
| Decisions & explanations | `mcp-decisions` view | `mcp-decisions-shadow.png` |
| Policies & simulation | `mcp-policies` view | `mcp-policies.png` |
| Approvals | `mcp-approvals` view (operational) + **API-only** publications | `mcp-approvals-approvals.png` |
| Health & durability | `mcp-health` view | `mcp-health-durability.png` |
| Management MCP access | `mcp-management` view | `mcp-management.png` |
| Listener settings | `mcp-settings` view (textarea) | `mcp-settings.png` |
| CP/DP distribution | **panel inside** `mcp-health` (Distribution & Rollback) + inside `mcp-rollout` | `mcp-health-partialack.png` |
| Rollback | **panel inside** `mcp-health`; `POST /api/mcp/rollback` | `mcp-health-rollback.png` |
| Rollout modes & scope | `mcp-rollout` view (mode via dropdown; **scope has no editor**) | `mcp-rollout-*.png` |
| Shadow / Canary / Executions | **panels inside** `mcp-rollout` + rows in `mcp-decisions` | `mcp-rollout-shadow.png`, `mcp-decisions-canary.png` |
| Hard failures | a `metrics.hard_blocks` counter + a `reason_code` on a decision row | `mcp-rollout-killswitch.png`, `mcp-decisions-hardfail.png` |
| Emergency controls | **panel inside** `mcp-rollout` (disable/clear/rehearse) | `mcp-rollout-killswitch.png` |
| Production qualification status | **panel inside** `mcp-rollout` + `GET /api/mcp/rollout/evidence` | `mcp-rollout-prodlocked.png` |

Not every planned panel is a separate screen: the MCP surface is **9 views, many
of which stack several JSON panels**, not the ~15 screens the plan language
implies.

---

## 4. Actual navigation map

`static/index.html:551-677` — a flat `<nav>` of `.nav-section` headings +
`.nav-item[data-view]` rows. Seven sections:

```
Overview  ─ Dashboard
Monitor   ─ Traffic · Audit Log · Decryption Exclusions · Decryption Health · Policy Tester
MCP Gateway (data-min-role=viewer)         ◀── the whole MCP surface, one dedicated block
          ─ MCP Overview
          ─ MCP Servers & Tools
          ─ MCP Decisions & Explain
          ─ MCP Policies & Simulator
          ─ MCP Approvals
          ─ MCP Health & Durability
          ─ MCP Rollout & Execution
          ─ Management MCP Access
          ─ MCP Listener Settings (data-min-role=admin)
Policies  ─ Access Rules · Authentication Rules · Blocklist · Content & Scanning · File Control · CDR
Objects   ─ URL Categories · Category Groups · Decryption Profiles · Header Rewrite · Identity Providers
Platform  ─ Certificates · CA Management · Cluster · Upstream Proxies · PAC File · Releases · Diagnostics · Support · Settings
Administration (admin) ─ Administrators · Governance
```

Observations:
- The MCP Gateway group is well-placed (high IA, after Monitor). Good.
- But the nine items are **nine sibling destinations with no hierarchy or state**
  — an operator investigating one call has to leave the view they are in and
  reopen a sibling with the context (tenant, event id) **retyped by hand**
  (`#mcp-dec-tenant`, `#mcp-dec-event` are free-text inputs, `index.html:3450`).
  There is no persistent context, no drawer, no cross-view pivot.
- Nav-level RBAC works: the viewer capture (`viewer-dark/mcp-settings-viewer-denied.png`)
  shows the VIEWER badge and **no** "MCP Listener Settings" item (admin-only,
  `data-min-role="admin"`, `index.html:600`), so the click found no target and
  the SPA stayed on Dashboard — a correct client-side denial, backed server-side
  (`requireRole`, and the ledger's `C2-enforce: DENIED … required="admin"` lines).

---

## 5. Actual MCP workflow map

The intended day-2 flow — *understand posture → find the interesting call →
understand why → see related context → act safely → confirm* — maps onto today's
UI as a series of **disconnected, manually-primed JSON reads**:

```
MCP Overview            → JSON blob (posture as text). No links out.                 [mcp-overview.png]
   │  (operator manually opens a sibling view)
MCP Decisions           → type tenant → Search → JSON array of decision rows          [mcp-decisions-shadow.png]
   │  (operator copies an event_id by hand)
MCP Decisions/Explain   → paste event_id → Explain → JSON explanation object          (same view, 2nd <pre>)
   │  (no link to the tool, server, policy rule, snapshot, or credential profile)
MCP Servers & Tools     → retype tenant → Load → JSON list (fingerprint as text)      [mcp-servers-unknowntool.png]
MCP Rollout             → click 4 Refresh buttons → 4 JSON panels                     [mcp-rollout-killswitch.png]
   │  Mode Transition: pick capability + to-mode → Request (no blast-radius preview)
   │  Emergency: red "Emergency disable" (no confirm dialog)
MCP Health              → Refresh + Refresh Distribution → 2 JSON panels; rollback needs a hash typed in  [mcp-health-rollback.png]
```

Every arrow above is a **manual context switch that loses state**. The evidence
chain the task wants —
`identity → server/tool → inspection → policy → rollout mode → approval →
durable event → credential profile → upstream outcome → response DLP → snapshot`
— is *present as fields* inside the `decision-explain` object
(`ExplanationView`, `decisions.go:71-119`; see `mcp-decisions-dlpblock.png`) but
can only be reconstructed by reading one long JSON object and then hand-navigating
to other views to see the referenced tool/server/policy. It cannot be *followed*.

---

## 6. Playwright coverage map

**Before this audit: zero of the nine MCP views had any browser E2E test**
(agent grep of `*e2e_test.go` for `mcp` → 0 hits). The MCP Gateway is the single
largest nav group and was entirely uncovered. There was also **no screenshot /
visual harness anywhere** in the repo (`docs/ci/ui-e2e-playwright-plan.md` §8
lists trace capture as future work).

This audit adds an advisory, build-tagged (`//go:build uie2e`) screenshot harness
that covers all nine MCP views + the three activity views across roles / themes /
resolutions / 15 synthetic postures. It is **not** a merge gate (matches the
existing advisory-tier convention).

| data-view | Pre-audit E2E | This audit's screenshot coverage |
|---|---|---|
| mcp-overview | ❌ | current, healthy, durability, apifail; light; 1440/1280; operator/viewer |
| mcp-servers | ❌ | current, unknowntool |
| mcp-decisions | ❌ | current, shadow, canary, hardfail, dlpblock, dlpredact; light |
| mcp-policies | ❌ | current |
| mcp-approvals | ❌ | current, operational-approvals (structured rows) |
| mcp-health | ❌ | current, healthy, partialack, dpincompat, durability, rollback |
| mcp-rollout | ❌ | current, healthy, observe, shadow, canary, killswitch, prodlocked; light; 1440/1280; operator/viewer |
| mcp-management | ❌ | current |
| mcp-settings | ❌ | current (admin); viewer-denied |

Harness: `ux_audit_screens_e2e_test.go`, `ux_audit_run_e2e_test.go`,
`ux_audit_fixtures_e2e_test.go`, `ux_audit_fixtures_data_e2e_test.go`.

---

## 7. Browser console / API failures observed

Full ledger: `ux-audit-assets/current/_ledger.json` (48 rows; each row lists
`console_errors`, `page_errors`, `request_failures`, `http_4xx_5xx`).

- **Uncaught page exceptions: 0.** **Failed requests (network): 0.** The SPA does
  not throw on any MCP view.
- **Console errors: 333, all one benign harness artifact.** Every page logs
  `Failed to load resource: 503 (Service Unavailable)` + `SyntaxError: … "CA not
  initialised" is not valid JSON`. This is the SPA global posture-strip calling
  `GET /api/ca-cert` (`dashboard`, `setPosture`), which returns 503 because the
  hermetic test harness never initialises the CA singleton. It is **identical on
  every page, MCP or not, and is a test-environment artifact — not an MCP UI
  defect.** (It does, however, incidentally show the posture strip has no graceful
  handling of a non-JSON error body — a minor P2, §12.)
- **HTTP 4xx/5xx: 167 events**, dominated by the same `/api/ca-cert` 503, plus the
  **intended** `403`s in the viewer-denied capture (real `requireRole` denials,
  logged as `C2-enforce: DENIED … required="admin"`) and the **intended** `503`s
  in the `apifail` scenario (`mcp-overview-apifail.png`, fixture `failAll:503`).

Net: no real client-side errors on the MCP surface; the observer machinery works
and would have caught genuine exceptions.

---

## 8. Strengths (keep these)

1. **The backend model is right.** Evaluated-vs-effective is a first-class split
   (`rollout.Resolution.EvaluatedAction`/`EffectiveAction`/`ShadowOverride`,
   `resolve.go:96-105`; `ExecOutput`, `execute.go:49-60`); the Production lock is
   evidence-gated and ships no issuer (`transition.go:106`, `mcp_rollout.go:141`);
   CP→DP distribution distinguishes desired/active/fleet with per-DP ack states
   (`cpdp/ack.go:8-20`, `publication.DistributionCounts`). The UI just has to
   *show* it.
2. **RBAC is correct and layered.** Client `data-min-role` gating
   (`applySession`, `index.html:5870`) + server `requireRole` + C2 metadata
   enforcement. Viewer capture proves it (`viewer-dark/mcp-settings-viewer-denied.png`).
3. **Redaction discipline.** No raw token/secret/argument is exposed anywhere;
   `decision-explain` carries `credential_profile_ref` + `power_ceiling`, never
   material (`decisions.go:71-119`). This is a genuine strength to preserve as the
   UI gets richer.
4. **The panel prose is good.** The `mcp-rollout` panel descriptions explain
   Shadow/Canary/hard-fail/Production-lock semantics clearly
   (`mcp-rollout-killswitch.png`). The problem is the *data* under them, not the
   copy.
5. **Consistent, clean Culvert shell.** Sidebar IA, topbar, LIVE pill, role badge,
   dark/light theming all work and look calm and readable
   (`admin-light/mcp-overview-healthy.png`). The visual foundation to build on is
   already there.
6. **Approvals is the proof-of-concept.** `mcp-approvals` already renders
   structured rows with per-row Approve/Reject and a destructive confirm
   (`mcp-approvals-approvals.png`, `index.html:5578-5610`) — evidence the team can
   build structured MCP UI in the existing stack.

---

## 9. Usability defects (evidence-backed)

| # | Defect | Evidence |
|---|---|---|
| D1 | Overview is a JSON dump, not a posture — no capability cards, no needs-attention, no next action | `mcp-overview.png`; `mcpShow` `index.html:5490` |
| D2 | Every read view (except approvals) dumps raw JSON into `<pre>` | all `mcp-*.png`; `mcpShow` |
| D3 | `mcp-rollout` shows the same rollout JSON in ≥2 panels (Overview panel + Evidence panel both print `status()`), doubling scroll and confusion | `mcp-rollout-killswitch.png` (identical blob twice) |
| D4 | `mcp-rollout` is not auto-loaded; all six panels blank until the operator clicks each `Refresh` | absent from `index.html:5677-5684`; `mcp-rollout.png` (current, empty) |
| D5 | Decisions requires the operator to hand-type a tenant, then hand-copy an `event_id` into a second box to explain a row | `#mcp-dec-tenant`, `#mcp-dec-event` `index.html:3450`; `mcp-decisions-shadow.png` |
| D6 | Fingerprints, hashes, revisions are long opaque strings with no truncation/copy/tooltip | `mcp-servers-unknowntool.png` (`fp-…`), `mcp-rollout-killswitch.png` (hashes) |
| D7 | No timestamps/"as-of" on any panel; nothing tells the operator how old the reading is | all `mcp-*.png` |
| D8 | Health durability is a flat 25-field JSON object; the one field that matters (`severity`) is line 3 of a nested object | `mcp-health-durability.png` |

---

## 10. Dangerous ambiguity (this is where qualification is at risk)

| # | Ambiguity | Why it is dangerous | Evidence |
|---|---|---|---|
| A1 | **Shadow DENY looks like a block, not an execution.** `{"action":"DENY", "execution_state":"shadow_recorded"}` has no visual marker that the call *was executed anyway* | Violates the task's explicit rule; an operator reviewing Shadow can wrongly believe a risky call was blocked when it ran | `mcp-decisions-shadow.png` (`evt_9f1a` DENY + shadow_recorded; `evt_9f2f` `credential_power_exceeded` DENY + shadow_recorded) |
| A2 | **Effective action is never labeled.** The UI shows the policy `action` but not the `EffectiveAction`/`ShadowOverride`/hard-failure override that actually governed execution | Operator cannot tell "policy-evaluated" from "what happened" | data exists (`resolve.go:96-105`) but unshown; `mcp-decisions-*.png` |
| A3 | **Kill-switch active is invisible.** `"killed": true` is one line in a JSON object; no banner, no red state on the view or nav | Operator may not realise admission is globally stopped | `mcp-rollout-killswitch.png` |
| A4 | **Desired vs active vs fleet-effective are three JSON fields, not three states.** `mode` vs `desired` vs `distribution_state` are printed but never contrasted | Operator cannot see "I set canary but the fleet hasn't converged / a DP rejected it" | `mcp-rollout-canary.png` (`distribution_state:"partially_acknowledged"` buried), `mcp-health-dpincompat.png` (`distribution_degraded`) |
| A5 | **Blast radius is absent before promotion.** Mode Transition = capability + to-mode dropdown + button; no affected tenants/agents/servers/tools/#subjects/#DPs/newly-executable-ops preview | Promotion is a blind action | `mcp-rollout-killswitch.png` Mode Transition panel; **`PUT /api/mcp/rollout/scope` has no UI at all** |
| A6 | **Stale vs live is undetectable.** No stale indicator; `mcp-rollout` panels can silently show data from minutes ago (or nothing) | Operator may act on stale posture | D4, D7 above |
| A7 | **Partial/rejected fleet reads as "fine".** `distribution_state:"distribution_degraded"` / `"partially_acknowledged"` is a string in a blob; the incompatible-DP subset (`Incompatible` count, `distribution.go:178`) isn't surfaced at all in the DTO the UI receives | Operator can't see a min-version-incompatible node holding an old policy | `mcp-health-partialack.png`, `mcp-health-dpincompat.png` |

---

## 11. Missing investigation pivots

The entities the task wants to pivot between all exist as **plain-text fields**;
**none is a link**. From a decision/explain object you cannot click through to any
of:

| Entity | Present as (field) | Pivotable today? |
|---|---|---|
| Principal / Agent / Client / Tenant | `principal_id`, `agent_id`, `client_id`, `tenant` | ❌ text only |
| Server / ServerID | `server_id` | ❌ (retype tenant in mcp-servers) |
| Tool + fingerprint | `tool_name`, `tool_fingerprint` | ❌ text only |
| Policy rule + decisive condition | `matched_rule_id`, `decisive_condition_id` | ❌ (no MCP-policy rule view at all) |
| Credential profile + power ceiling | `credential_profile_ref`, `credential_power_ceiling` | ❌ (no credential-profile view exists) |
| Destination | `destination_class` | ❌ |
| Snapshot + revisions | `policy_snapshot_hash`, `*_revision`, `epoch` | ❌ text |
| DP / node | (only aggregate `distribution_state`) | ❌ (no per-node view) |
| Approval / allowance | `decision_event_id` on approvals | ❌ |
| Related decisions / executions | — | ❌ (no "related calls" query in UI) |

There is also **no view for MCP policy rules themselves** (only `mcp-policies`
shows policy *metadata* + a simulator), **no credential-profile view**, and **no
per-DP node view** — so several pivots have no destination even if links existed.

---

## 12. Inconsistent terminology & inaccessible controls

**Terminology drift (operator-facing):**
- "Decisions & Explain" (view) vs `execution_state` vs `EffectiveAction`
  (backend) vs `disposition` (runtime) — three vocabularies for "what happened".
- `distribution_state` uses eight internal tokens
  (`local_only`, `pending_distribution`, `partially_acknowledged`,
  `fully_acknowledged`, `distribution_degraded`, `rollback_pending`,
  `rolled_back`, `rejected_by_all`) shown verbatim to the operator
  (`mcp-health-*.png`) with no plain-language mapping.
- `reason_code` shows raw enum tokens (`rollout_out_of_scope`,
  `credential_power_exceeded`, `sender_constraint_required`) with no human label
  (`mcp-decisions-hardfail.png`).

**Inaccessible / missing controls (GUI-parity gaps):**
- **Scope editing** — `PUT /api/mcp/rollout/scope` exists but has **no UI**. An
  admin cannot define/narrow blast radius from the GUI at all. This directly
  violates the repo's GUI-parity rule (CLAUDE.md "Every new CLI flag or config
  option MUST have a corresponding … UI panel").
- **Publications** — `POST /api/mcp/publications` and
  `POST /api/mcp/publication-decision` (four-eyes publish) have **no UI control**;
  `mcp-approvals` filters to `kind=="operational"` only, so publication approvals
  are invisible.
- Minor: posture strip does not handle a non-JSON error body gracefully (§7).

---

## 13. Production-Qualification UX blockers (summary)

The full backlog is in `PRODUCTION-QUALIFICATION-UX-BACKLOG.md`. The blockers
(anything that prevents an operator from *safely qualifying* Production):

- **PQ-B1 — Evaluated vs effective is invisible (A1, A2).** A Shadow-executed
  DENY must be visually unambiguous. Today it is raw JSON.
- **PQ-B2 — No blast-radius / scope preview before promotion (A5).** Promotion and
  scope-widening are blind; scope editing has no GUI.
- **PQ-B3 — No stale-data indication (A6, D7).** Operators may act on old posture.
- **PQ-B4 — Critical state (kill switch, durability-degraded, incompatible DP) is
  buried in JSON (A3, A4, A7).** No posture surface, no needs-attention list.
- **PQ-B5 — No coherent evidence chain / investigation pivots (§5, §11).** The
  decision→…→snapshot chain can't be followed without retyping context.
- **PQ-B6 — Emergency disable has no confirmation and no local-vs-fleet framing
  (A3).** A destructive, fleet-affecting control is a bare red button.
- **PQ-B7 — Production qualification evidence is shown as targets in JSON, with no
  real-vs-synthetic distinction surfaced to the operator (`origin` field exists
  but is unlabeled).** Risk that "locked" is understood but "what's missing" is not
  (`mcp-rollout-prodlocked.png`; `evidence.go:34-43`).

None of these is a backend gap — every one is a presentation/workflow layer over
data that already exists and is already correct. That is the good news, and the
subject of the Target IA (`…-UX-TARGET.md`) and wireframes (`…-UX-WIREFRAMES.md`).
