# Production-Qualification UX — Target Information Architecture

**Design intent (read this first).** The target is **not** a SOC, SIEM, or
incident-response console, and **not** a clone of any vendor. The reference point
is only a *product-interaction mindset*: strong information hierarchy, excellent
drill-down, logs told as a coherent activity story, persistent context while
moving between entities, fast pivots, clear "why", actions next to context, and
progressive disclosure from summary to technical evidence.

The visual and product identity stays **Culvert**: clean, minimal, calm,
spacious, direct, readable by a security administrator or platform engineer who is
**not** a SOC analyst — no alert walls, no severity-color soup, no threat maps, no
investigation jargon. Color reinforces status; it is never the only signal.

> Target one-liner: **Cortex-XDR-quality information *flow*, expressed through
> Culvert's existing clean UX.** A user can understand a tool call, why Culvert
> treated it that way, what related context matters, and what safe action to take
> — without being a SOC analyst.

This document keeps the existing single-binary / CSP-nonce / server-side-RBAC /
Playwright-Go / no-Node constraints. It reuses the existing APIs where adequate
and preserves stable `data-view` names and element selectors that tests depend on
(new state is additive). It defines the **desired** IA; the migration is in
`…-UX-IMPLEMENTATION-SLICES.md`, and none of it unlocks Production or adds a
connector / DMZ / Management mutation / qualification issuer.

The design rests on **four shared primitives** reused by every workspace:

1. **Posture strip** — a compact, one-line status band (capability modes, hard
   failures, distribution health, durability, Production lock, needs-attention
   count). Reused verbatim on Command Center and as a context header elsewhere.
2. **State triplet chip** — a single component that renders **desired / locally
   active / fleet-effective** for any mode or config value, with a "pending",
   "partial", "rejected", or "stale" qualifier. This is the antidote to today's
   three-JSON-fields problem.
3. **Activity row + Activity detail drawer** — a concise decision/execution row
   (result · action · principal · server/tool · evaluated→effective · reason ·
   time) that opens a right-side drawer with the full evidence chain and
   context-relevant actions. Progressive disclosure: summary first, technical
   evidence on expand.
4. **Entity pivot chip** — any principal/agent/client/tenant/server/tool/rule/
   credential-profile/snapshot/DP rendered as a chip that opens that entity's
   drawer *without leaving the current view* (persistent context).

Every action obeys the **safe-action hierarchy** (investigate → simulate → narrow
scope → quarantine tool → quarantine server → revoke allowance → revoke credential
profile → demote mode → emergency disable → rollback snapshot) and every action
communicates **immediate local effect · expected fleet convergence · reversibility
· impact · evidence created**.

---

## The ten workspaces

They map onto the existing nav (they do **not** require 10 new nav sections — see
each "Realised as"). The nine `mcp-*` data-views are preserved; workspaces are
*groupings and behaviors*, not necessarily new routes.

---

### 1. Command Center
**Realised as:** upgraded `mcp-overview` (same `data-view`).

- **Operator question:** *Do I need to act right now, and on what?*
- **Primary objects:** capabilities (gateway, management), hard-failure queue,
  distribution/DP health, durability, Production-qualification progress.
- **Key metrics:** active mode per capability; open hard failures; DPs converged /
  total; durability severity; pending approvals; Production lock state;
  needs-attention count.
- **Main "table":** the **Needs-attention list** — a ranked, deduped list of
  actionable items (hard-failure spike, degraded durability, incompatible DP,
  kill switch active, stale snapshot, pending approvals, evidence gate failing),
  each a one-line summary + a pivot into the relevant detail.
- **Filters:** capability (gateway/management); severity (needs-attention only vs
  all).
- **Pivots:** each attention item → its Activity/entity detail; each capability
  card → Rollout & Exposure.
- **Detail drawer:** capability card expands to runtime + durability + current
  mode triplet + recent critical changes.
- **Permitted actions:** navigate/inspect only (no mutation on the landing
  surface); "investigate" is the primary action.
- **RBAC:** viewer read; no mutation here.
- **Dangerous-action confirmation:** n/a (read-only).
- **Empty/loading/error/stale:** empty = "MCP gateway disabled — nothing to
  attend to" with an enable pointer (to `mcp-settings`); loading = skeleton cards
  (not "Loading…" text); error = inline card-level error with retry, never a bare
  JSON body; **stale = an "as-of HH:MM:SS · refresh" affordance on the posture
  strip** with amber styling past a threshold.
- **Playwright acceptance:** posture strip renders all capability modes; a seeded
  hard failure appears in needs-attention; kill-switch-active shows a red posture
  segment; disabled-default shows the empty state; stale badge appears when the
  clock advances past threshold.

### 2. Investigations
**Operator question:** *What happened, why, and what related activity matters?*
**Realised as:** upgraded `mcp-decisions` + the shared Activity detail drawer.

- **Primary objects:** decisions and executions (the durable event stream).
- **Key metrics:** count by result; count executed-in-shadow (override); count
  hard-blocked; DLP interventions.
- **Main table columns:** Time · Result · **Evaluated → Effective action** (two
  chips, always both) · Principal/Agent · Server/Tool · Reason (human label) ·
  Duration. (Backed by `DecisionView`, `decisions.go:41-58`.)
- **Filters:** tenant, principal, agent, client, server, tool fingerprint, action,
  reason, operation class, time range, "shadow-override only", "hard-fail only".
- **Pivots:** every column value is an entity pivot chip; a row opens the Activity
  detail drawer (§ shared primitive 3).
- **Detail drawer sections (progressive disclosure):** *Header* (result, action,
  server/tool, time, mode) → *Why* (evaluated action, effective action, reason
  code + human label, matched rule, decisive condition, hard-failure/Shadow
  override) → *Context* (tenant/principal/agent/client/server identity/tool
  fingerprint/environment/destination) → *Execution* (approval/allowance,
  credential-profile ref + power ceiling, upstream outcome, latency, request/response
  inspection state) → *Evidence* (snapshot hash, policy/catalog/config/credential
  revisions, durable event id, DP/node, **related activity**) → *Actions*
  (context-relevant, safe subset). All fields exist in `ExplanationView`
  (`decisions.go:71-119`).
- **Permitted actions:** inspect related calls, simulate policy (→ Policy &
  Simulation), quarantine tool/server, revoke allowance, demote mode, rollback
  snapshot — each scoped to what the decision implicates.
- **RBAC:** viewer reads; mutating actions gated (operator/admin) with server
  `requireRole` backstop.
- **Dangerous-action confirmation:** standardized dialog (see §Dangerous-action
  standard) for quarantine/revoke/demote/rollback.
- **Empty/loading/error/stale:** empty = "No decisions for this filter"; loading =
  row skeletons; error = inline; **stale = as-of stamp per result set**.
- **Playwright acceptance:** a Shadow-executed DENY row shows **two distinct
  chips** (Evaluated: DENY / Effective: executed-in-shadow) and never a single
  ALLOW; opening a row shows the six drawer sections; a pivot chip opens the tool
  drawer without navigating away; DLP-block row shows the finding classes and
  `dlp_disposition` from the fixture.

### 3. MCP Assets
**Operator question:** *What servers and tools exist, and which are risky?*
**Realised as:** upgraded `mcp-servers` (servers + tools), plus a Tool entity
drawer.

- **Primary objects:** servers (`ServerView`), tools (`ToolView`,
  `inventory.go:30-54`).
- **Key metrics:** servers enabled/verified; tools usable / review-required /
  quarantined / drifted; destination-class distribution.
- **Main table columns (tools):** Server · Tool · Disposition (chip) ·
  Destination class · Fingerprint (truncated + copy) · Revision.
- **Filters:** tenant, server, disposition, destination class, "drifted only",
  "quarantined only".
- **Pivots:** server → server drawer; tool → tool drawer; from a tool drawer →
  *related decisions* (Investigations pre-filtered by fingerprint).
- **Detail drawer:** tool identity, fingerprint, eligibility/disposition, drift
  history, destination class, credential-profile binding, recent decisions.
- **Permitted actions:** quarantine tool, quarantine server, (from drawer) view
  related decisions, simulate a call.
- **RBAC:** viewer reads; quarantine operator/admin.
- **Dangerous-action confirmation:** standardized (quarantine is reversible but
  fleet-affecting).
- **Empty/loading/error/stale:** empty = "No servers registered for <tenant>";
  requires a tenant — default to the operator's last tenant, not a blank box.
- **Playwright acceptance:** a `review_required`/`quarantined` tool shows the
  correct disposition chip and destination class; tool drawer pivots to
  Investigations filtered by that fingerprint.

### 4. Policy & Simulation
**Operator question:** *What is the policy, and what would a change do — safely?*
**Realised as:** `mcp-policies` (metadata + simulator) + a real MCP policy-rule
list.

- **Primary objects:** active policy snapshot, rules, simulation candidates.
- **Key metrics:** revision, rule count, default action, snapshot hash.
- **Main table columns:** rule id · match summary · action · operation/risk class
  · obligations.
- **Filters:** capability; action; risk class.
- **Pivots:** rule → decisions matched by that rule (Investigations); simulate →
  diff view.
- **Detail drawer:** rule detail; simulate/compare result as a **structured diff**
  (allow→deny deltas), not raw JSON.
- **Permitted actions:** validate, simulate, compare (non-publishing, as today);
  propose a change → publication (four-eyes) via Approvals & Allowances.
- **RBAC:** viewer read; simulate operator; publish admin (four-eyes).
- **Dangerous-action confirmation:** publication requires the standardized dialog
  + shows the scope/blast-radius the change implies.
- **Empty/loading/error/stale:** empty = "No policy published (default deny)";
  stale = snapshot-hash + as-of.
- **Playwright acceptance:** simulate renders a structured allow/deny diff; a rule
  pivots to Investigations; publish is admin-gated.

### 5. Rollout & Exposure
**Operator question:** *What mode is really in effect, where, and what would
widening it expose?*
**Realised as:** upgraded `mcp-rollout`.

- **Primary objects:** capability rollout state, scope spec, DP acknowledgement
  matrix, evidence windows.
- **Key metrics:** desired/active/fleet-effective mode (triplet chip); scope size
  (#subjects); DPs converged/total; incompatible DPs; evidence gates met.
- **Main table:** the **Ladder** — Disabled → Observe → Shadow → Canary →
  Production, each rung showing the triplet state and (for Production) the lock.
- **Filters:** capability (gateway/management).
- **Pivots:** DP row → node detail (Health & Distribution); scope subject → entity
  drawer.
- **Detail drawer / preview:** **Blast-radius preview** before any promotion or
  scope widening — exact tenants/agents/clients/serverIDs/tool fingerprints/
  operation classes/environments/percentage buckets/exclusions, **credential-power
  implications**, **#affected subjects**, **#affected DPs**, **newly executable
  operations**, and the **rollback target**. (All derivable from `ScopeSpec`,
  `scope.go:98-121`, and `DistributionCounts`.)
- **Permitted actions:** promote (one rung, four-eyes), demote, edit/narrow scope
  (**new GUI for `PUT /api/mcp/rollout/scope`**), rehearse rollback, rollback,
  emergency disable/clear.
- **RBAC:** viewer read; all mutations admin (four-eyes on promote).
- **Dangerous-action confirmation:** promotion and scope-widening use the
  standardized dialog **with the blast-radius preview embedded and a typed
  confirmation** for scope-widening/emergency (reuse `ui_dialogs` typed-confirm).
- **Empty/loading/error/stale:** empty = disabled ladder; **stale = triplet chip
  shows "fleet state as-of …"**; error = per-panel inline.
- **Playwright acceptance:** promote shows a blast-radius preview listing affected
  subjects/DPs and the rollback target before the four-eyes step; Production rung
  shows locked + "evidence required"; a `partially_acknowledged` fleet renders the
  triplet as active≠fleet with a pending qualifier; kill-switch shows the ladder in
  a stopped state.

### 6. Approvals & Allowances
**Operator question:** *What is waiting on a human, and what exactly am I
approving?*
**Realised as:** upgraded `mcp-approvals` (operational **and** publication kinds).

- **Primary objects:** operational approvals + publication approvals
  (`ApprovalView`, `approvals.go:12-40`).
- **Key metrics:** pending count by kind; expiring soon.
- **Main table columns:** id · kind · requester · action · server/tool · operation
  · risk · credential power · created/expiry.
- **Filters:** tenant, kind, state, risk.
- **Pivots:** approval → the decision that triggered it (`decision_event_id` →
  Investigations); resource/server → entity drawer.
- **Detail drawer:** the full request, the **credential-power implication**, the
  proposed revision diff (for publications), and who requested it.
- **Permitted actions:** approve, reject (four-eyes; self-approval blocked
  server-side, `approval_self_approval`).
- **RBAC:** viewer read; decide admin.
- **Dangerous-action confirmation:** standardized dialog; publication approval
  shows the scope/blast-radius it will publish.
- **Empty/loading/error/stale:** empty = "No pending approvals".
- **Playwright acceptance:** a pending row shows Approve/Reject; approving fires
  the four-eyes decision; publication approvals appear (not just operational);
  pivot to the triggering decision works.

### 7. Health & Distribution
**Operator question:** *Is the fleet converged and durable — and where is it not?*
**Realised as:** upgraded `mcp-health` (durability) + a real **DP acknowledgement
matrix** and per-node view.

- **Primary objects:** capability runtime/durability health; per-DP ack state.
- **Key metrics:** runtime state; durability severity; DPs applied/rejected/
  incompatible/unavailable (`DistributionCounts`, `distribution.go:42-49`).
- **Main table:** **DP ack matrix** — node × capability → ack state
  (`received/rejected/validated/applied/rolled_back`), content hash, epoch,
  DP version, health, **reject reason** (the field that distinguishes an
  *incompatible* node from a merely lagging one, `distribution.go:178`).
- **Filters:** capability, ack state, "incompatible only".
- **Pivots:** node → node detail; hash → snapshot; back to Rollout.
- **Detail drawer:** durability sub-panel (critical/denial/severity, quotas,
  recovery) rendered as labeled meters, not a 25-field JSON object; node detail
  (applied vs desired hash, version, last-seen epoch).
- **Permitted actions:** rollback (admin), rehearse rollback.
- **RBAC:** viewer read; rollback admin.
- **Dangerous-action confirmation:** rollback uses the standardized dialog with the
  rollback target hash pre-filled (not hand-typed).
- **Empty/loading/error/stale:** empty = "local-only (no CP→DP distribution)";
  **stale = ack matrix as-of; a node not seen recently is flagged, not silently
  omitted**.
- **Playwright acceptance:** durability-degraded shows a high-severity meter, not a
  buried field; an incompatible DP shows its `snapshot_min_version_unmet` reason;
  rollback pre-fills the target hash.

### 8. Evidence & Audit
**Operator question:** *Can I reconstruct exactly what governed this call, and
prove it later?*
**Realised as:** the Activity detail drawer's *Evidence* section + links into the
existing `audit` log; a coherent read-only evidence chain.

- **Primary objects:** durable event ids, snapshot/revisions, credential-profile
  refs, config-change audit entries.
- **Key metrics:** n/a (evidence is per-item, not a dashboard).
- **Main view:** the evidence chain for one decision, rendered as an ordered,
  linkable sequence:
  `identity → server/tool → inspection → policy (rule + decisive condition) →
  rollout mode → approval/allowance → durable event → credential profile →
  upstream outcome → response DLP → snapshot & revisions`.
- **Filters:** by event id, correlation id, tenant, time.
- **Pivots:** each node in the chain is an entity pivot chip.
- **Detail drawer:** each stage expandable to its safe technical fields (ids,
  hashes, revisions, DLP classes, destination status).
- **Permitted actions:** copy safe evidence (hashes/ids); export via existing
  redacted paths only.
- **RBAC:** viewer read.
- **Dangerous-action confirmation:** n/a.
- **Empty/loading/error/stale:** empty = "no durable evidence for this id".
- **Playwright acceptance:** the chain renders all stages present in the fixture
  event; no raw token/secret/argument appears anywhere (redaction assertion).

### 9. Production Qualification
**Operator question:** *What evidence is still missing before Production can be
qualified — and is that evidence real?*
**Realised as:** upgraded Production-Qualification panel in `mcp-rollout`.

- **Primary objects:** qualification gate categories + evidence windows
  (`EvidenceSummary`, `evidence.go`).
- **Key metrics:** GO/NO-GO per gate; Shadow window (≥14d), Canary window (≥7d),
  soak (≥24h); open critical/high defects; rollback-rehearsed; durability proof;
  supply-chain evidence; **evidence origin (real vs synthetic)**.
- **Main table:** gate checklist — each gate with state, threshold, current value,
  and **a real-vs-synthetic origin badge** (`EvidenceOrigin`,
  `evidence.go:34-43`) so synthetic/injected-clock evidence can never *look*
  qualifying.
- **Filters:** capability.
- **Pivots:** a failing gate → the data that would satisfy it (e.g. open defects →
  Investigations; durability → Health).
- **Detail drawer:** per-gate detail + the receipt status (locked; no issuer in
  build).
- **Permitted actions:** rehearse rollback; **no "qualify" action exists** (by
  design — no issuer). The panel is read + evidence-gathering only.
- **RBAC:** viewer read; rehearse admin.
- **Dangerous-action confirmation:** n/a (no promotion to Production is possible).
- **Empty/loading/error/stale:** locked banner always present until an issuer
  exists; windows show progress vs target.
- **Playwright acceptance:** panel shows `production_locked:true` with a clear
  "qualification required" state; synthetic-origin evidence is badged as
  non-qualifying; no control can transition to Production (server returns 403,
  `ui_mcp_rollout.go:72`).

### 10. Administration
**Operator question:** *How is the listener configured, and who can do what?*
**Realised as:** `mcp-settings` (listener config) + `mcp-management` (Management
access posture) + existing `users`/`governance`.

- **Primary objects:** node-local gateway/management config; management tool
  catalog + access posture; RBAC.
- **Key metrics:** listener enabled/bound; mutation enabled (management stays
  non-mutating); default min-role.
- **Main view:** a **form** over `MCPConfig` (`config.go:53-88`) — not a raw
  textarea — with enum selects (`client_cert_mode`, `unknown_tool_default_action`,
  `default_min_role`, `tenant_scope_mode`) and validation; the read-only
  management tool catalog as a table (14 tools, scopes, roles, classes).
- **Filters:** n/a.
- **Pivots:** management tool → its scope/role.
- **Detail drawer:** config field help; per-tool scope detail.
- **Permitted actions:** save config (admin, node-local, non-distributed).
- **RBAC:** config admin; management catalog viewer.
- **Dangerous-action confirmation:** save shows a diff (config-versioned).
- **Empty/loading/error/stale:** defaults shown when unset.
- **Playwright acceptance:** viewer cannot see `mcp-settings` (already verified,
  `viewer-dark/mcp-settings-viewer-denied.png`); config form validates enums;
  management shows `mutation_enabled:false`.

---

## Cross-cutting standards

### State triplet (desired / active / fleet-effective)
Every mode/config value renders as one chip with up to three states and a
qualifier. Never three separate JSON fields. Fleet-effective always carries an
**as-of** stamp and, when active≠fleet, an explicit "pending N DPs" / "rejected by
N" / "incompatible: N" qualifier (data from `DistributionCounts`).

### Dangerous-action standard
One dialog component for all destructive/fleet-affecting actions (reuse the
existing typed-confirm from `ui_dialogs`). It always shows: **immediate local
effect**, **expected fleet convergence**, **reversibility**, **impact / blast
radius**, **evidence created**. Scope-widening, emergency disable, and rollback
additionally require a typed confirmation.

### Loading / empty / error / stale
Standard set everywhere: skeletons (not "Loading…" text); explicit, actionable
empty states; inline card/panel errors with retry (never a raw error body in a
`<pre>`); a per-panel **as-of** stamp that turns amber past a staleness threshold.

### Redaction (unchanged, load-bearing)
No raw token/secret/argument/output. Fingerprints/hashes shown truncated with
copy. This is already correct server-side (`decisions.go`, `mcpscrub.go`) and must
survive every enrichment.
