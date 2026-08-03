# Production-Qualification UX — Wireframes

Low-fidelity ASCII sketches for the five core surfaces + one end-to-end
drill-down. These express **information flow and hierarchy**, not pixels. They
stay recognizably Culvert: sidebar + topbar shell, calm spacing, status **chips**
(not color blocks), one dominant primary action, tables with expandable detail,
side drawers for context, restrained color. They add **no** new production
behavior and preserve existing `data-view` names.

Legend: `[ btn ]` button · `‹chip›` status/entity chip · `▸`/`▾` expander ·
`�WHY` drawer section · `«as-of»` freshness stamp · `⧉` copy · `→` pivot link.

---

## A. MCP Command Center  (`data-view="mcp-overview"`)

Replaces the JSON dump (`ux-audit-assets/current/admin-dark/mcp-overview.png`)
with a posture-first landing surface.

```
┌ Culvert ───────────────────────────────────────────────────────────────────────── LIVE ‹admin› ┐
│ MCP Command Center                                        MCP gateway posture · «as-of 13:52:45» │
├──────────────────────────────────────────────────────────────────────────────────────────────── │
│ POSTURE  ‹Gateway: Canary›  ‹Mgmt: Observe›  ‹Hard fails: 3 ⚠›  ‹Fleet: 4/5 DPs›                 │
│          ‹Durability: OK›   ‹Snapshot: fresh›  ‹Production: LOCKED›   ‹Needs attention: 4›        │
├────────────────────────────────────────────┬───────────────────────────────────────────────────┤
│  CAPABILITY CARDS                           │  NEEDS ATTENTION (4)                    [ dismiss ] │
│  ┌ Gateway ───────────────┐                 │  ⚠ 1 DP incompatible (min-version) → Health         │
│  │ Mode  ‹Canary›         │                 │  ⚠ Hard-fail spike: auth_identity ×3 → Investigate  │
│  │ desired Canary         │                 │  • 2 approvals pending (1 destructive) → Approvals  │
│  │ active  Canary         │                 │  • Evidence gate: Canary window 3d/7d → Qualify     │
│  │ fleet   ‹4/5 pending›  │  ‹stopped: no›  │                                                     │
│  │ sessions 7 · in-flt 3  │                 │  RECENT CRITICAL CHANGES                             │
│  └────────────────────────┘                 │  13:41 mode Shadow→Canary (four-eyes: a.smith)      │
│  ┌ Management ────────────┐                 │  13:12 scope widened +srv-k8s (a.smith)             │
│  │ Mode  ‹Observe›  fleet ‹ok›  mutation:off│  12:58 rollback rehearsed (gateway)                 │
│  └────────────────────────┘                 │                                                     │
├────────────────────────────────────────────┴───────────────────────────────────────────────────┤
│  RECENT ACTIVITY  (last 10)                                                     [ open Investigations →] │
│  13:52  ‹DENY→exec(shadow)⚠›  svc-agent-billing  srv-github/create_issue   out_of_scope   → drawer│
│  13:52  ‹ALLOW→executed›      u-jdoe             srv-github/list_issues     ok             → drawer│
│  13:51  ‹DENY→blocked›        svc-agent-x        srv-unknown/exfil          hard: server_trust    │
└──────────────────────────────────────────────────────────────────────────────────────────────── ┘
```

Answers, in seconds: capabilities enabled? mode? degraded? hard failures? DPs
synced? approvals pending? Production locked? something to do now? — the exact
question set from the brief. No charts, no threat map, no alert wall.

---

## B. Investigation workbench  (`data-view="mcp-decisions"` + Activity drawer)

Replaces two hand-primed JSON `<pre>`s
(`ux-audit-assets/current/admin-dark/mcp-decisions-shadow.png`) with a filtered
activity table + a right-side evidence drawer. **Evaluated and Effective are
always two chips.**

```
┌ MCP Investigations ─────────────────────────────────────────────── «as-of 13:52:45» [ ↻ ] ┐
│ tenant[acme-prod] principal[ ] server[ ] tool[ ] action[all] reason[all]  ☑ shadow-override │
├─────────────────────────────────────────────────────────────────────────────────────────── ┤
│ Time   Result            Eval → Effective        Principal/Agent   Server/Tool         Reason        │
│ 13:52  ‹block?⚠›  DENY → exec (shadow)   svc-agent-billing·a42  srv-github/create_issue  out_of_scope │◀ selected
│ 13:52  ‹ok›       ALLOW → executed        u-jdoe·a42            srv-github/list_issues    observe_only │
│ 13:52  ‹block›    DENY → exec (shadow)    svc-agent-deploy·a7   srv-k8s/delete_pod        cred_power_exceeded│
└────────────────────────────────────────────────────────────────────┬────────────────────── ┘
                                                                       │  DECISION evt_9f1a          [×]
   Persistent table on the left; drawer on the right keeps context.    │  ── HEADER ──────────────── │
                                                                       │  ‹DENY› evaluated · ‹EXECUTED│
                                                                       │  IN SHADOW ⚠› effective       │
                                                                       │  srv-github/create_issue      │
                                                                       │  13:52:03 · mode Shadow        │
                                                                       │  ▾ WHY                         │
                                                                       │   policy action: DENY          │
                                                                       │   effective: allow (shadow)    │
                                                                       │   shadow_override: yes ⚠       │
                                                                       │   reason: out_of_scope          │
                                                                       │   rule → rule-write-guard       │
                                                                       │   decisive cond → cond-scope    │
                                                                       │  ▸ CONTEXT  (tenant→ agent→ …)  │
                                                                       │  ▸ EXECUTION (cred-profile→ …)  │
                                                                       │  ▸ EVIDENCE  (snapshot⧉ revs…)  │
                                                                       │  ── ACTIONS ───────────────── │
                                                                       │  [ related calls → ]           │
                                                                       │  [ simulate policy → ]         │
                                                                       │  [ quarantine tool ] [ demote ]│
                                                                       └────────────────────────────── ┘
```

The one non-negotiable: the row for a Shadow-executed DENY reads
`DENY → exec (shadow) ⚠` — it can **never** collapse to a plain `ALLOW`. This is
the fix for the current ambiguity in `mcp-decisions-shadow.png`.

---

## C. Rollout & Exposure  (`data-view="mcp-rollout"`)

Replaces six stacked JSON panels
(`ux-audit-assets/current/admin-dark/mcp-rollout-killswitch.png`) with a mode
ladder, the state triplet, a DP ack matrix, and a **blast-radius preview gate**
before promotion.

```
┌ MCP Rollout & Exposure · Gateway ───────────────────────────────── «fleet as-of 13:52» [ ↻ ] ┐
│ LADDER   Disabled ──○ Observe ──○ Shadow ──● Canary ──◌ Production(LOCKED 🔒)                    │
│ STATE    desired ‹Canary›   active ‹Canary›   fleet ‹4/5 · 1 incompatible⚠›                      │
│ SCOPE    3 tenants · 2 servers · 12 tool-fps · ops[read,write] · 25% (bucket:principal)          │
│                                                          [ edit scope ]  [ simulate ]            │
├──────────────────────────────────────────────────────────────────────────────────────────────── ┤
│ DP ACKNOWLEDGEMENT MATRIX                                                                         │
│  node        cap      state       hash        epoch  ver  reason                                  │
│  dp-us-1    gateway  ‹applied›    …009988      8      1    —                                       │
│  dp-us-2    gateway  ‹applied›    …009988      8      1    —                                       │
│  dp-eu-1    gateway  ‹rejected⚠›  —            8      —    snapshot_min_version_unmet  → node      │
├──────────────────────────────────────────────────────────────────────────────────────────────── ┤
│ PROMOTE  Canary → Production        [ Preview blast radius ]   (four-eyes required)               │
│ EMERGENCY   [ Emergency disable ]  [ Clear ]  [ Rehearse rollback ]   local-only · narrows only   │
└──────────────────────────────────────────────────────────────────────────────────────────────── ┘

   ── Blast-radius preview (modal, shown BEFORE the four-eyes step) ─────────────────────────────
   │ Promote Gateway: Canary → Production                                             [locked 🔒] │
   │ Newly executable: write, destructive on 2 servers / 12 tools                                 │
   │ Affected: 3 tenants · ~180 principals · 2 servers · 12 tool fingerprints · 4 DPs             │
   │ Credential power raised to: ‹destructive› on srv-k8s                                          │
   │ Rollback target: snapshot …998877 (epoch 7)                                                   │
   │ Evidence: Shadow 14d ✓ · Canary 3d/7d ✗ · soak 24h ✗ · defects 0 ✓ · rehearsed ✓             │
   │ Production is LOCKED — no issuer in this build. This preview is informational.   [ close ]    │
   └──────────────────────────────────────────────────────────────────────────────────────────────
```

The kill-switch state is now a ladder-level "stopped" chip + a red posture segment
on Command Center — not `"killed": true` on line 5 of JSON.

---

## D. Production Qualification  (panel in `data-view="mcp-rollout"`)

Replaces the duplicated evidence JSON
(`ux-audit-assets/current/admin-dark/mcp-rollout-prodlocked.png`) with a gate
checklist that distinguishes **real vs synthetic** evidence.

```
┌ Production Qualification · Gateway ──────────────────────────────────────────────────────── ┐
│ STATUS   ‹PRODUCTION LOCKED 🔒›   qualification required · no issuer in this build           │
├──────────────────────────────────────────────────────────────────────────────────────────── ┤
│ GATE                         STATE     TARGET   CURRENT     ORIGIN                            │
│ Shadow window                ‹GO›      ≥14d     14d         ‹real›                            │
│ Canary window                ‹NO-GO›   ≥7d      3d          ‹real›                            │
│ Soak window                  ‹NO-GO›   ≥24h     6h          ‹synthetic ⚠ does not qualify›    │
│ Open critical/high defects   ‹GO›      0        0           ‹real›                            │
│ Rollback rehearsal           ‹GO›      done     done        ‹real›                            │
│ Durability proof             ‹GO›      normal   normal      ‹real›                            │
│ Supply-chain evidence        ‹GO›      signed   signed      ‹real›                            │
│ Privacy/support/ops ready    ‹NO-GO›   —        pending     —                                 │
├──────────────────────────────────────────────────────────────────────────────────────────── ┤
│ RECEIPT   none (issuer absent)         [ Rehearse rollback ]     (no "qualify" action exists) │
└──────────────────────────────────────────────────────────────────────────────────────────── ┘
```

Synthetic/injected-clock evidence is badged `synthetic ⚠ does not qualify`
(`EvidenceOrigin`, `evidence.go:34-43`) so a program can never appear complete on
fake evidence — directly answering PQ-B7.

---

## E. Emergency response  (drawer/modal from `mcp-rollout` + Investigations)

One surface for the safe-action hierarchy, each action framed by local effect vs
fleet convergence.

```
┌ Emergency response · Gateway ──────────────────────────────────────────────────────── ┐
│ Pick the least-drastic action that resolves the risk:                                  │
│                                                                                        │
│  [ Stop admission ]      local now · narrows only · reversible · fleet: node-local     │
│  [ Demote mode ]         Canary→Shadow · four-eyes · fleet: converges on ack           │
│  [ Quarantine tool ]     one tool · reversible · fleet: on next snapshot               │
│  [ Quarantine server ]   all its tools · reversible                                    │
│  [ Revoke allowance ]    one allowance · immediate                                     │
│  [ Revoke cred profile ] raises ceiling to none · high impact                          │
│  [ Rollback snapshot ]   target …998877 · four-eyes · fleet: re-distributes            │
│                                                                                        │
│  Selected: Stop admission                                                              │
│   Immediate local effect : new admissions stop on THIS node                            │
│   Expected fleet          : node-local only (no CP round-trip)                         │
│   Reversibility           : [ Clear ] restores admission                               │
│   Evidence created        : audit mcp.rollout.emergency.disable                        │
│   Type DISABLE to confirm : [__________]                    [ Cancel ]  [ Confirm ]     │
└──────────────────────────────────────────────────────────────────────────────────── ┘
```

---

## Drill-down path (end-to-end)

`Command Center → Hard Failure → Investigation → Tool entity → Related decisions →
Quarantine → Signed rollout status` — with context persisting the whole way:

```
1. COMMAND CENTER   needs-attention: "Hard-fail spike: auth_identity ×3"  → click
2. INVESTIGATIONS   table pre-filtered reason=auth_identity; select evt_hf01
                    drawer WHY: hard-failure class = auth_identity (sender_constraint_required)
3. DRAWER ▸ CONTEXT tool chip  srv-github/create_issue  → click (drawer stays, context kept)
4. TOOL ENTITY      fingerprint fp-…, disposition, drift, destination_class
                    [ related decisions → ]  (pre-filtered by fingerprint)
5. RELATED DECISIONS several DENY→blocked rows for this tool; decide it must be stopped
6. ACTION           [ quarantine tool ]  → dangerous-action dialog:
                    local: tool unusable now · fleet: on next snapshot · reversible · audit written
7. ROLLOUT STATUS   Rollout & Exposure shows scope/snapshot re-signed + DP ack matrix converging
                    (state triplet: active updated, fleet ‹pending 1/4›)  «as-of …»
```

At no step does the operator retype a tenant or copy an event id by hand (the two
manual context losses in today's flow, §5 of the current-state report). Every hop
is a pivot chip; the drawer keeps the thread.
