# Production-Qualification UX — Prioritized Backlog

Classification: **PQ-BLOCKER** (prevents safe Production qualification) ·
**P0** (must be fixed before enabling Production; may land *during* the
qualification program) · **P1** (important post-GA operator improvement, not a
release blocker) · **P2** (polish).

Every item lists: current screenshot · operator risk · proposed target behavior ·
affected views · backend/API impact · Playwright test required · effort (S/M/L) ·
dependency · **production-behavior change? (No = presentation/workflow only)**.

All PQ-BLOCKER and P0 items below are **presentation/workflow only** — none
changes MCP admission, policy, distribution, or the Production lock. The lock
stays un-bypassable (`transition.go:106`, `mcp_rollout.go:141`).

---

## PQ-BLOCKER

### PQB-1 — Make evaluated-vs-effective visually unambiguous
- **Screenshot:** `admin-dark/mcp-decisions-shadow.png` (DENY + `shadow_recorded`, no marker).
- **Operator risk:** a Shadow-executed policy DENY looks like a block; operator believes a risky call was stopped when it ran. Violates the task's explicit rule.
- **Target:** Investigations table renders **two chips per row — Evaluated → Effective** — with a distinct `exec (shadow) ⚠` state; drawer WHY shows `shadow_override`, effective action, and any hard-failure override. Data exists (`Resolution.EvaluatedAction/EffectiveAction/ShadowOverride`, `resolve.go:96-105`; `ExecOutput`, `execute.go:49-60`; `DecisionView.execution_state`).
- **Affected views:** `mcp-decisions`, `mcp-overview` (recent activity), `mcp-rollout` (shadow panel).
- **Backend/API:** none — fields already returned. (Optional: add `effective_action`/`shadow_override` to `DecisionView` if not already projected — verify against `decisions.go`.)
- **Playwright:** a Shadow DENY row shows two chips and never a lone ALLOW; drawer shows override.
- **Effort:** M · **Dep:** shared Activity row/drawer (P0-6) · **Prod change:** No.

### PQB-2 — Blast-radius preview before promotion / scope widening + a scope editor
- **Screenshot:** `admin-dark/mcp-rollout-killswitch.png` (Mode Transition = dropdown + button, no preview); **no scope UI exists** for `PUT /api/mcp/rollout/scope`.
- **Operator risk:** promotion and scope-widening are blind; can't see affected subjects/DPs/newly-executable ops/credential-power/rollback target.
- **Target:** a **blast-radius preview** modal before the four-eyes step (affected tenants/agents/clients/serverIDs/tool-fps/op-classes/environments/percent/exclusions · #subjects · #DPs · newly executable ops · credential-power delta · rollback target) + a **GUI scope editor** for `PUT /api/mcp/rollout/scope`. Derivable from `ScopeSpec` (`scope.go:98-121`) + `DistributionCounts`.
- **Affected views:** `mcp-rollout`.
- **Backend/API:** likely a small **read-only preview endpoint** (compute counts for a candidate scope) — additive, non-mutating; or compute client-side from existing scope + inventory. Scope editor uses the existing `PUT` route (no new mutation semantics).
- **Playwright:** promote shows preview listing affected subjects/DPs + rollback target before four-eyes; scope editor round-trips via the existing PUT.
- **Effort:** L · **Dep:** state-triplet chip (P0-3) · **Prod change:** No (preview is read-only; scope editor exposes an existing API in the GUI, honoring GUI-parity).

### PQB-3 — Stale-data indication everywhere
- **Screenshot:** all `mcp-*.png` (no timestamps); `mcp-rollout.png` (panels blank until clicked).
- **Operator risk:** operator acts on stale/old posture with no signal.
- **Target:** per-panel **as-of** stamp; amber past a staleness threshold; fleet-effective state always carries "as-of"; auto-load `mcp-rollout`.
- **Affected views:** all nine `mcp-*`.
- **Backend/API:** none (client timestamp of last successful fetch); optionally surface server `time_unix_nano` where present.
- **Playwright:** as-of stamp present; advancing the clock past threshold turns it amber.
- **Effort:** S · **Dep:** none · **Prod change:** No.

### PQB-4 — Posture surface + needs-attention (surface buried critical state)
- **Screenshot:** `mcp-overview.png` (JSON), `mcp-rollout-killswitch.png` (`killed:true` buried), `mcp-health-durability.png` (`severity` buried), `mcp-health-dpincompat.png` (`distribution_degraded` buried).
- **Operator risk:** kill-switch active / durability-degraded / incompatible DP invisible at a glance.
- **Target:** Command Center **posture strip** + **needs-attention** list (shared primitive) surfacing kill switch, durability severity, incompatible DPs, pending approvals, stale snapshot, failing evidence gates.
- **Affected views:** `mcp-overview` (Command Center); posture strip reused as context header on others.
- **Backend/API:** none — composes existing `overview`/`health`/`rollout`/`distribution` reads.
- **Playwright:** seeded hard-fail/kill-switch/incompatible-DP each appear in needs-attention/posture with the right severity.
- **Effort:** M · **Dep:** none · **Prod change:** No.

### PQB-5 — Investigation pivots + evidence chain (persistent context)
- **Screenshot:** `mcp-decisions-dlpblock.png` (explain object; every entity is plain text), current-state §5/§11.
- **Operator risk:** the decision→server/tool→policy→snapshot→credential chain can't be followed; context is retyped by hand between views.
- **Target:** entity **pivot chips** (principal/agent/client/tenant/server/tool-fp/rule/credential-profile/snapshot/DP) that open drawers without leaving the view; drawer *Evidence* section renders the ordered chain; "related calls" query. Fields exist in `ExplanationView` (`decisions.go:71-119`).
- **Affected views:** `mcp-decisions`, `mcp-servers`, `mcp-rollout`, `mcp-health`; new drawers.
- **Backend/API:** mostly none; may add a "related decisions by fingerprint/principal" filter param to `GET /api/mcp/decisions` (additive).
- **Playwright:** a pivot chip opens the tool drawer without navigation; drawer shows all evidence stages present in the fixture; no raw secret/token appears.
- **Effort:** L · **Dep:** Activity drawer (P0-6) · **Prod change:** No.

### PQB-6 — Emergency disable needs confirmation + local-vs-fleet framing
- **Screenshot:** `admin-dark/mcp-rollout-killswitch.png` (bare red "Emergency disable", no confirm).
- **Operator risk:** a fleet-relevant, admission-stopping control is one misclick; no framing of effect/reversibility.
- **Target:** standardized dangerous-action dialog with immediate local effect · expected fleet convergence · reversibility · evidence · **typed confirm**. Reuse `ui_dialogs` typed-confirm.
- **Affected views:** `mcp-rollout` (emergency), and all destructive MCP actions.
- **Backend/API:** none.
- **Playwright:** emergency disable requires typed confirmation; dialog states local-only + reversibility.
- **Effort:** S · **Dep:** dangerous-action standard (P0-4) · **Prod change:** No.

### PQB-7 — Production qualification: real-vs-synthetic evidence + gate checklist
- **Screenshot:** `admin-dark/mcp-rollout-prodlocked.png` (evidence JSON, duplicated; no origin distinction).
- **Operator risk:** a qualification program could appear complete on synthetic/injected-clock evidence.
- **Target:** gate **checklist** with state/target/current + an **origin badge** (`real`/`synthetic ⚠ does not qualify`) from `EvidenceOrigin` (`evidence.go:34-43`); keep the locked banner (no issuer).
- **Affected views:** `mcp-rollout` (qualification panel).
- **Backend/API:** none — `origin` already in `GET /api/mcp/rollout/evidence`.
- **Playwright:** synthetic-origin evidence is badged non-qualifying; no control transitions to Production (server 403, `ui_mcp_rollout.go:72`).
- **Effort:** M · **Dep:** none · **Prod change:** No.

---

## P0 — before enabling Production (implementable during the program)

### P0-1 — Replace raw-JSON reads with structured panels (overview, health, management, servers)
- **Screenshot:** `mcp-overview.png`, `mcp-health-*.png`, `mcp-management.png`, `mcp-servers-*.png`.
- **Risk:** operators parse JSON to read posture; slow, error-prone.
- **Target:** structured cards/tables/meters; durability as labeled meters (not 25-field JSON).
- **Affected:** `mcp-overview`, `mcp-health`, `mcp-management`, `mcp-servers`. **API:** none.
- **Playwright:** each renders structured elements (not a single `<pre>`). **Effort:** L · **Dep:** none · **Prod:** No.

### P0-2 — DP acknowledgement matrix + per-node view (fleet visibility)
- **Screenshot:** `mcp-health-partialack.png`, `mcp-health-dpincompat.png`.
- **Risk:** can't see which DP rejected/incompatible/lagging.
- **Target:** node×capability ack matrix with state + reject reason (`AckState`, `distribution.go`; `Incompatible` subset).
- **Affected:** `mcp-health`. **API:** may need a per-node ack read (the current `mcpDistributionStatus` DTO omits per-DP counts — additive read).
- **Playwright:** incompatible DP shows `snapshot_min_version_unmet`. **Effort:** M · **Dep:** state triplet · **Prod:** No (may add a read endpoint).

### P0-3 — State-triplet chip (desired / active / fleet-effective)
- **Screenshot:** `mcp-rollout-canary.png` (three JSON fields).
- **Risk:** operator can't distinguish "set" from "converged".
- **Target:** one chip component; used on Command Center, Rollout, Health. **API:** none.
- **Playwright:** active≠fleet renders a pending/rejected/incompatible qualifier. **Effort:** M · **Dep:** none · **Prod:** No.

### P0-4 — Dangerous-action dialog standard
- **Screenshot:** `mcp-rollout-killswitch.png` (bare buttons); `mcp-approvals-approvals.png` (only `window.confirm` today).
- **Target:** one dialog for quarantine/revoke/demote/rollback/promote/scope-widen with the five disclosures + typed-confirm for high-risk. Reuse `ui_dialogs`.
- **Affected:** all MCP mutations. **API:** none.
- **Playwright:** each destructive action routes through the dialog; typed-confirm gates high-risk. **Effort:** M · **Dep:** none · **Prod:** No.

### P0-5 — GUI for publications (create + four-eyes decide)
- **Screenshot:** none (no UI exists); `POST /api/mcp/publications`, `POST /api/mcp/publication-decision`.
- **Risk:** GUI-parity gap; publication approvals invisible (`mcp-approvals` filters to operational only).
- **Target:** publication list + create + approve/reject in Approvals & Allowances.
- **Affected:** `mcp-approvals`. **API:** existing routes (no new semantics).
- **Playwright:** publication approvals appear and can be decided (admin). **Effort:** M · **Dep:** P0-4 · **Prod:** No (exposes existing API — GUI-parity).

### P0-6 — Shared Activity row + detail drawer
- **Screenshot:** `mcp-decisions-shadow.png` (JSON).
- **Target:** the reusable row + six-section drawer (Header/Why/Context/Execution/Evidence/Actions).
- **Affected:** `mcp-decisions`, `mcp-overview`, `mcp-rollout`. **API:** none.
- **Playwright:** drawer renders all six sections from a fixture event. **Effort:** L · **Dep:** none · **Prod:** No.

### P0-7 — Human labels for reason codes / distribution states / dispositions
- **Screenshot:** `mcp-decisions-hardfail.png` (`sender_constraint_required`), `mcp-health-dpincompat.png` (`distribution_degraded`).
- **Target:** a client-side label map (enum token → operator phrase) with the raw token available on hover/expand. **API:** none.
- **Playwright:** a known reason token renders its human label + keeps the raw token accessible. **Effort:** S · **Dep:** none · **Prod:** No.

### P0-8 — Deep-linkable view + selection state (without breaking selectors)
- **Screenshot:** all (hash-only routing today).
- **Target:** encode tenant/filters/selected-event in the URL so an investigation is shareable/bookmarkable; keep existing `data-view` + element ids intact.
- **Affected:** all MCP views. **API:** none.
- **Playwright:** a deep link restores the filtered/selected state; existing selectors still resolve. **Effort:** M · **Dep:** none · **Prod:** No.

---

## P1 — post-GA operator improvements

- **P1-1 — Structured policy simulate/compare diff** (not JSON). Screenshot `mcp-policies.png`. `mcp-policies`. API none. PW: diff renders allow/deny deltas. M · No.
- **P1-2 — Credential-profile & MCP policy-rule views** (pivot destinations that don't exist yet). §11. New read views over existing data. M/L · No.
- **P1-3 — Related-activity graph** (entity → related decisions/executions) beyond simple filters. L · No.
- **P1-4 — Fingerprint/hash affordances** (truncate + copy + tooltip everywhere). Screenshots `mcp-servers-unknowntool.png`. S · No.
- **P1-5 — Config form for `mcp-settings`** (enum selects + validation, replacing the raw textarea). Screenshot `mcp-settings.png`. `mcp-settings`. API none. M · No.
- **P1-6 — Auto-refresh / live posture** on Command Center via the existing SSE pattern (reuse `/api/events` infra; MCP-scoped events optional/future). M · possibly additive event.

---

## P2 — polish

- **P2-1 — Posture strip handles non-JSON error bodies gracefully** (the `/api/ca-cert` 503 SyntaxError seen in every ledger row — a real-world resilience gap even though it's a harness artifact here). Ledger `_ledger.json`. S · No.
- **P2-2 — Skeleton loaders** instead of "Loading…" text (`mcpGet`, `index.html:5491`). S · No.
- **P2-3 — De-duplicate `mcp-rollout` panels** (rollout JSON printed twice, `mcp-rollout-killswitch.png`). S · No.
- **P2-4 — Consistent empty-state copy** across MCP views (some say "No results.", some blank). S · No.
- **P2-5 — Accessibility pass** on the new chips/drawers (focus, aria, keyboard) — reuse the `ui_dialogs` focus-stack patterns. M · No.
- **P2-6 — Visual-system cleanup:** align MCP chips/cards to `docs/design/DESIGN-SYSTEM.md` tokens so the MCP surface matches the rest of Culvert. S/M · No.

---

## Rollup

| Priority | Items | All presentation/workflow-only? |
|---|---|---|
| PQ-BLOCKER | 7 | Yes |
| P0 | 8 | Yes |
| P1 | 6 | Yes |
| P2 | 6 | Yes |

No item requires a change to MCP admission, policy evaluation, distribution
trust, or the Production lock. Two items (PQB-2 scope editor, P0-5 publications)
*expose existing mutating APIs in the GUI* — which is the repo's GUI-parity
requirement, not new behavior. A handful (P0-2, PQB-2 preview, PQB-5 related)
may add **read-only** endpoints. The sequencing is in
`PRODUCTION-QUALIFICATION-UX-IMPLEMENTATION-SLICES.md`.
