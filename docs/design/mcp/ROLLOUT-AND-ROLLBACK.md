# MCP Rollout, Rollback and Emergency Procedures

Purpose: this document defines the mode ladder that governs how the Culvert MCP Security Gateway and
Culvert Management MCP Server move from no traffic to production enforcement, who authorizes each
promotion, what stays hard-blocked at every stage regardless of mode, and how a bad rollout is undone —
by config-snapshot rollback, emergency disable, server quarantine, or credential revoke. It operationalizes
[BLUEPRINT.md](BLUEPRINT.md) §21 ("Rollout, Rollback and Production Readiness") and feeds
[GO-NO-GO-CHECKLIST.md](GO-NO-GO-CHECKLIST.md) and [PR0-REVIEW-CHECKLIST.md](PR0-REVIEW-CHECKLIST.md).
Threat IDs are defined in [THREAT-MODEL.md](THREAT-MODEL.md); requirement IDs are defined in
[SECURITY-REQUIREMENTS.md](SECURITY-REQUIREMENTS.md). Per doctrine, the two MCP capabilities — the
Culvert Management MCP Server and the MCP Security Gateway — keep **separate** rollout tracks, separate
kill switches, and separate quarantine/rollback state; nothing below merges their enforcement engines or
trust boundaries.

**Status: PR-0 design artifact (Proposed).** Nothing described here is implemented. No listener, mode
switch, rollback mechanism, or runbook below exists in the repository today. Duration figures (shadow
≥14 days, canary ≥7 days, soak ≥24 hours) and the rollback-time figure are **design targets**, never
measured results, until a PR-11 / Production Qualification evidence pack says otherwise. Claim legend:
**[FACT]** (verified by repository read, traced to [VERIFIED-REPOSITORY-CONTEXT.md](VERIFIED-REPOSITORY-CONTEXT.md)),
**[INFER]** (architectural inference), **[REC]** (recommendation), **[EXT]** (externally unverified).

---

## 1 · Mode Ladder

Five modes, strictly ordered. A capability may only be promoted one stage at a time; it may be demoted
(rolled back) by any number of stages at once, including straight to Disabled. Each stage below mirrors
[BLUEPRINT.md](BLUEPRINT.md) §21's stage table, expanded with the evidence and authority columns needed
to actually operate a promotion decision.

### 1.1 Disabled

| Field | Detail |
|---|---|
| Enforcement | No listener bound, no traffic accepted. Both `/mcp/management` and `/mcp/gateway/{server-id}` are absent from the mux — not merely denying, **not registered**. |
| Entry criteria | Default state. Also the landing state of any rollback (§3). |
| Exit criteria | PR-0 design package approved (this package); the ADR promoted to [`docs/adr/0024`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) (done 2026-07-24, `Status: Proposed`) and **ratified to Accepted by ARB + Security Architecture**; **D-1 protocol baseline externally verified + approved**; **build/test baseline run + recorded**; lab environment ready. |
| Evidence required | PR-0 review sign-off ([PR0-REVIEW-CHECKLIST.md](PR0-REVIEW-CHECKLIST.md)); **ADR-0024 Accepted** (currently `Proposed`); recorded build/test baseline. |
| Owner | Staff / Principal Engineer (architecture); Product Lead (scope). |
| Approval authority | Architecture Review Board (ADR); Executive Sponsor / GM (scope). |

### 1.2 Observe

| Field | Detail |
|---|---|
| Enforcement | Listener bound in a test/lab environment only, or bound in production with no real upstream execution (calls are parsed, identified, and logged; no tool call reaches an enterprise system). Every decision is `MONITOR`; nothing is blocked, nothing is approved for real effect. |
| Entry criteria | Protocol kernel (PR-1), registry/catalog (PR-2), identity/auth validation (PR-3), and bounded runtime (PR-5) merged and green on required CI gates. |
| Exit criteria | Server/tool inventory validated against a known test fleet; telemetry (events, metrics) validated end to end — an event emitted must be observable in the configured sink. |
| Evidence required | Inventory completeness check; telemetry smoke test; **[REC]** a fixed malicious/non-compliant test-server suite exercised with zero real-system side effects. |
| Owner | Engineering (protocol/runtime owners). |
| Approval authority | Engineering lead sign-off; no external board required (no real traffic is enforced or mutated yet). |

### 1.3 Shadow

| Field | Detail |
|---|---|
| Enforcement | Real traffic passes through the gateway/management listener. Policy evaluates and **reports** every decision (`ALLOW`/`DENY`/etc. all logged with reason code), but only the fixed **Hard Failures** list in §2 actually blocks a call — everything else is allow-and-record, even a policy-computed `DENY`. |
| Entry criteria | Decision parity demonstrated (shadow policy decisions match a manual/reference evaluation on a fixed corpus); durable event pipeline (PR-8) live with zero measured loss for critical event classes in the lab. |
| Exit criteria | False-positive rate (shadow `DENY`/`QUARANTINE` decisions that a human reviewer overturns) within target, over a **design-target minimum window of ≥14 days** of continuous shadow traffic — not measured until a real rollout runs; this is a duration floor, not evidence that 14 days is sufficient by itself. |
| Evidence required | False-positive review log; event-durability proof under load; on-call rotation staffed (§3 rollback rehearsal must have run at least once before exit). |
| Owner | Product Security (policy correctness); SRE/Engineering (event durability). |
| Approval authority | Security Architecture (false-positive rate + threat-model closure); joint sign-off with Engineering before Canary entry. |

### 1.4 Canary

| Field | Detail |
|---|---|
| Enforcement | Full enforcement (all nine policy actions active, not just hard failures) for a small, explicitly scoped, **read-first** slice — a named subset of servers/tools/principals, chosen to exclude destructive/write tool calls where practical. |
| Entry criteria | Rollback rehearsed at least once end to end (§3) with a recorded rollback time; on-call roster active with a named primary; canary scope explicitly enumerated and approved (not "everything at 1%"). |
| Exit criteria | SLOs met over a **design-target minimum window of ≥7 days** (design target, not yet measured) and no critical/high defects open against the canary scope. |
| Evidence required | SLO dashboard for the canary window; defect log (zero open critical/high); rollback rehearsal record with timing. |
| Owner | SRE (SLOs, rollback rehearsal); Engineering (defect triage). |
| Approval authority | Operations Readiness + Security Architecture joint sign-off. |

### 1.5 Production

| Field | Detail |
|---|---|
| Enforcement | Full enforcement for an approved scope (which may still be narrower than "all servers/all tools" — scope expansion beyond the approved set is itself a re-entry into Canary for the newly added scope). |
| Entry criteria | Security and operations sign-off; full Production Readiness Evidence pack (§5) complete; Joint Go/No-Go Board approval per [BLUEPRINT.md](BLUEPRINT.md) §24. |
| Exit criteria | N/A (steady state) — subject to continuous monitoring; a regression can demote the capability per §3 at any time. |
| Evidence required | Continuous monitoring and periodic review (recorded cadence: **[REC]** at minimum monthly SLO + threat-model re-review while the product is young). |
| Owner | Engineering + Product + SRE. |
| Approval authority | Joint Go/No-Go Board (per [BLUEPRINT.md](BLUEPRINT.md) §24 Approval RACI). |

A **soak** requirement of **≥24 hours (design target)** of stable, defect-free operation applies at every
promotion boundary above Observe — i.e. before promoting Shadow→Canary or Canary→Production, the source
stage must show at least 24 continuous hours immediately preceding the promotion decision with no open
critical/high defect and no unexplained SLO excursion. This is a minimum floor layered under the longer
Shadow (≥14d) and Canary (≥7d) windows, not a substitute for them.

> **Risk phrasing (evidence caveat):** the false-positive, SLO, and rollback-timing figures above are
> design targets pending a real PR-11 rollout. Low for the read-only Phase 1 investigation, but the
> current repository test baseline remains unverified in this session — this document does not claim any
> of these targets have been measured.

---

## 2 · Hard Rule: Failures Blocked Even in Shadow

Shadow mode's entire premise is "report, don't block" — with one fixed exception list. These seven
failure classes are **hard-blocked in Shadow, Canary, and Production alike**; they are never
policy-overridable and never downgraded to `MONITOR` by any mode. Each maps to a requirement ID in
[SECURITY-REQUIREMENTS.md](SECURITY-REQUIREMENTS.md):

| Hard Failure | Requirement IDs | Why it cannot wait for a policy decision |
|---|---|---|
| Invalid or expired token; wrong audience or resource | [MCP-AUTH-002](SECURITY-REQUIREMENTS.md), [MCP-AUTH-003](SECURITY-REQUIREMENTS.md) | Authentication is a precondition to evaluating policy at all — there is no principal to evaluate a rule against. Closes [MCP-T-003](THREAT-MODEL.md) (wrong audience), [MCP-T-004](THREAT-MODEL.md) (wrong resource). |
| Unregistered server or failed TLS identity | [MCP-SERVER-001](SECURITY-REQUIREMENTS.md), [MCP-SERVER-002](SECURITY-REQUIREMENTS.md) | An unregistered destination or a server that fails identity verification has no fingerprint/registry entry to evaluate a tool-level policy against, and forwarding to it is itself the compromise. Closes [MCP-T-020](THREAT-MODEL.md) (malicious server), [MCP-T-016](THREAT-MODEL.md) (server identity change), [MCP-T-036](THREAT-MODEL.md) (SSRF). |
| Credential scope mismatch or unavailable secret for a dangerous action | [MCP-CRED-002](SECURITY-REQUIREMENTS.md), [MCP-CRED-006](SECURITY-REQUIREMENTS.md) | A dangerous action executed with the wrong scope, or executed at all when the broker cannot supply a valid scoped credential, cannot be undone by a later shadow finding. Closes [MCP-T-022](THREAT-MODEL.md)/[025](THREAT-MODEL.md) (over-privileged/scope-mismatch), [MCP-T-024](THREAT-MODEL.md) (broker/cache compromise). |
| Payload or stream limits that threaten availability | [MCP-PROTO-006/008](SECURITY-REQUIREMENTS.md) (parse-time, PR-1) + [MCP-OPS-002](SECURITY-REQUIREMENTS.md) (listener/runtime, PR-5) | An unbounded payload/stream is a resource-exhaustion event for the gateway process itself — it must fail closed regardless of what policy would have decided about the tool call's content. Closes [MCP-T-040](THREAT-MODEL.md) (oversized payloads), [MCP-T-042](THREAT-MODEL.md) (SSE exhaustion), [MCP-T-043](THREAT-MODEL.md) (slow-client), [MCP-T-044](THREAT-MODEL.md) (queue saturation/event loss). |
| Explicit destination to private or blocked network | [MCP-INSP-004](SECURITY-REQUIREMENTS.md) | An SSRF-shaped destination is an attack on Culvert's own network position, not a business decision policy is meant to arbitrate. Closes [MCP-T-036](THREAT-MODEL.md) (SSRF), [MCP-T-030](THREAT-MODEL.md) (private-network access). |
| Unknown tool when upstream execution may be destructive | [MCP-TOOL-006](SECURITY-REQUIREMENTS.md) | The product's core trust principle — an unknown tool must never auto-allow — is a red line, not a tunable; this is the one place shadow mode functionally behaves like production. Closes [MCP-T-017](THREAT-MODEL.md) (unknown-tool auto-allow, Critical). |
| Management mutation without valid approval and publication workflow | [MCP-MGMT-001](SECURITY-REQUIREMENTS.md) | The Management MCP Server has no shadow concept for mutation: mutation is simply not exposed until plan→validate→approve→apply exists, in every mode including Shadow. Closes [MCP-T-034](THREAT-MODEL.md) (management privilege escalation, Critical). |

These seven map directly onto [BLUEPRINT.md](BLUEPRINT.md) §21's "Hard Failures Blocked Even in Shadow"
list; the requirement-ID mapping above is this document's addition, not a renumbering of the source list.

---

## 3 · Mode Transitions

| Transition | Authorized by | Evidence gate |
|---|---|---|
| Disabled → Observe | Engineering lead | PR-0 approved + ADR Accepted (§1.1 exit criteria). |
| Observe → Shadow | Engineering lead + Product Security | Inventory/telemetry validation (§1.2 exit criteria). |
| Shadow → Canary | Security Architecture + Engineering (joint) | False-positive rate + ≥14d shadow window + ≥24h soak + rollback rehearsed (§1.3 exit criteria). |
| Canary → Production | Joint Go/No-Go Board | Full [Production Readiness Evidence](#5--production-readiness-evidence) pack (§5) + ≥7d canary window + ≥24h soak + [BLUEPRINT.md](BLUEPRINT.md) §24 Go/No-Go Checklist all-GO. |
| Any stage → Disabled (rollback/demotion) | On-call incident commander (immediate); ratified after the fact by Engineering lead | Incident record; no pre-approval required — see §4 (rollback is fast-path by design). |
| Scope expansion within Production | Joint Go/No-Go Board (treated as a new Canary for the added scope) | Same evidence bar as Canary entry, scoped to the delta. |

Every promotion decision is recorded against [GO-NO-GO-CHECKLIST.md](GO-NO-GO-CHECKLIST.md)'s per-domain
GO/NO-GO gates and the Approval RACI in [BLUEPRINT.md](BLUEPRINT.md) §24. [PR0-REVIEW-CHECKLIST.md](PR0-REVIEW-CHECKLIST.md)
governs sign-off on this document and its PR-0 siblings themselves, not runtime promotions — it is the
gate for the design package, not the gate for a live mode change.

The Management MCP Server and the MCP Security Gateway are promoted **independently**: a Canary approval
for the gateway confers no standing for the management server's mode, and vice versa. Each keeps its own
mode-ladder state, its own rollback trigger, and its own Go/No-Go Board sign-off.

---

## 4 · Rollback

Four independent, non-exclusive rollback mechanisms — pick the narrowest one that resolves the incident:

### 4.1 Snapshot rollback (policy/config)

Design intent: policy and catalog publication is versioned and CP→DP distributed as an immutable,
epoch-fenced snapshot — see [CP-DP-HA-MODEL.md](CP-DP-HA-MODEL.md) for the MCP-specific snapshot,
fencing, and acknowledgement model. Rollback restores the immediately-prior published revision atomically;
it is not a diff-and-reapply, it is a swap to a known-good, previously-active snapshot. This closes
[MCP-HA-002](SECURITY-REQUIREMENTS.md): *"The DP MUST retain the previous snapshot and support atomic
rollback within the rollback SLO target."*

Prior art in this repository — cited as an existing pattern to build from, **not** as an existing MCP
capability:

- **[FACT]** `internal/configver` numbered-snapshot store with `DefaultMax=50` retained versions
  (`configversion.go` capture/apply/diff at lines 43-577) is the SWG's own config-version rollback
  mechanism today, for the unrelated `configBackup`/`AdminSettings`/`ConfigSnapshot` surfaces declared in
  the `config_surfaces.go` registry. It demonstrates a working numbered-snapshot, atomic-swap,
  bounded-retention pattern already shipping in this codebase.
- **[FACT]** CP→DP `ConfigSnapshot` today (`controlplane_snapshot.go:22-112`) carries `Version`/`Epoch`/
  `PolicyVersion` but **no** `catalog_revision`/`credential_revision`/`minimum_dp_version`/`content_hash`/
  `signature` fields, and has **no snapshot signing** (mTLS + epoch fencing only) — an MCP snapshot
  extension is new design, not a reuse of an existing signed-snapshot capability.
- **[FACT]** The epoch-fencing pattern (`internal/halease`, `ha_fencing.go dpObserveEpoch:122-150` rejecting
  stale epochs, `ha_lease.go WriteAllowed:251-261`) is the closest existing "reject a stale publication"
  primitive; MCP-HA-001/002 are designed to reuse this fencing shape for MCP catalog/policy publication,
  per [CP-DP-HA-MODEL.md](CP-DP-HA-MODEL.md).

Rollback is **atomic** (the DP either serves the prior snapshot in full or continues serving its current
one — no partial-field rollback) and targeted to complete within the **rollback SLO — a design target,
not yet measured** ([BLUEPRINT.md](BLUEPRINT.md) §22 cites a product target of "< 5 minutes" for policy
rollback specifically; this document treats that figure as the same class of unmeasured design target).

### 4.2 Emergency disable

A single kill action that stops a capability from accepting further traffic without requiring a snapshot
rollback — equivalent to demoting straight to Disabled (§1.1) for the affected capability only. Scoped
independently to the Management MCP Server and the MCP Security Gateway; killing one must not affect the
other's listener. See [OPERATIONS-AND-SUPPORT.md](OPERATIONS-AND-SUPPORT.md) for the on-call runbook.

### 4.3 Server quarantine

Narrower than emergency disable: removes a single registered MCP server (or a single tool fingerprint on
that server) from the reachable set — new/changed calls to that server/tool are denied — while the rest of
the gateway keeps operating normally for every other registered server. This is the same quarantine
primitive [MCP-TOOL-006](SECURITY-REQUIREMENTS.md) requires for unknown tools, applied operator-initiated
to a known server/tool that has become suspect (drifted fingerprint, identity change, abuse signal). See
[OPERATIONS-AND-SUPPORT.md](OPERATIONS-AND-SUPPORT.md) for the quarantine runbook.

### 4.4 Credential revoke

Narrowest: revokes/rotates a single scoped upstream credential (or credential profile) the broker holds,
without disabling the listener or quarantining the server — used when the incident is "this credential's
scope/exposure is the problem," not "this server/tool is malicious." See
[OPERATIONS-AND-SUPPORT.md](OPERATIONS-AND-SUPPORT.md) for the revoke runbook.

---

## 5 · Emergency Procedures

The three operator-initiated actions below are the emergency toolkit; each is documented as a runbook in
[OPERATIONS-AND-SUPPORT.md](OPERATIONS-AND-SUPPORT.md) (on-call ownership, paging, and step-by-step
execution live there — this document defines what the action means and when to reach for it, not how to
execute it):

| Action | When to use | Blast radius | Runbook |
|---|---|---|---|
| Emergency disable | Systemic issue with the listener/runtime itself (resource exhaustion, auth bypass suspected, unexplained mass allow) | One capability's entire traffic (gateway **or** management, never both by one action) | [OPERATIONS-AND-SUPPORT.md](OPERATIONS-AND-SUPPORT.md) |
| Server quarantine | A specific registered server or tool fingerprint is suspect | Just that server/tool; rest of the fleet unaffected | [OPERATIONS-AND-SUPPORT.md](OPERATIONS-AND-SUPPORT.md) |
| Credential revoke | A specific credential/profile's scope or exposure is the problem | Just that credential's future issuance; already-brokered short-lived grants expire per broker TTL | [OPERATIONS-AND-SUPPORT.md](OPERATIONS-AND-SUPPORT.md) |

All three are **fast-path, on-call-executable actions** — per §3, they do not require pre-approval from
the Joint Go/No-Go Board; the Board ratifies after the fact and decides re-entry criteria back up the mode
ladder.

---

## 6 · Production Readiness Evidence

This is the evidence pack §1.5 (Production entry) requires in full, mirroring
[BLUEPRINT.md](BLUEPRINT.md) §21's Production Readiness Evidence table. It feeds a **separate Production
Qualification gate** (§7) — it is not itself a rollout mode.

| Domain | Required Evidence |
|---|---|
| Security | Approved threat model ([THREAT-MODEL.md](THREAT-MODEL.md)), closed critical risks, and passed negative tests. |
| Reliability | Load/soak/chaos evidence, restart recovery proof, and bounded-resource proof. |
| Compatibility | Supported-version matrix ([PROTOCOL-COMPATIBILITY.md](PROTOCOL-COMPATIBILITY.md)) and a malicious/non-compliant server test suite. |
| Operations | Dashboards, alerts, runbooks ([OPERATIONS-AND-SUPPORT.md](OPERATIONS-AND-SUPPORT.md)), on-call roster, and a rehearsed rollback. |
| Privacy | Data inventory, retention policy, redaction proof, and access controls. |
| Support | Known limitations, troubleshooting guide, upgrade/downgrade procedure, and customer-communication plan. |
| Release | Signed artifacts, SBOM, provenance, change approval, and source SHA (per [SUPPLY-CHAIN-SECURITY.md](SUPPLY-CHAIN-SECURITY.md)). |
| Connectivity | **V1 scope: Model A (`local-client`) only** — validated local-client deployment model with documented data flows and failure semantics (per [ON-PREM-CONNECTIVITY.md](ON-PREM-CONNECTIVITY.md)), plus evidence that the shipped config surface **rejects** `outbound-connector`/`dmz-endpoint`. Model B (connector) evidence belongs to **PR-C** and Model C (DMZ) evidence to the **Future DMZ Architecture & Production-Readiness Gate**; both are post-GA and **MUST NOT** gate V1 sign-off. |

---

## 7 · Implementation-Sequence Correction

Per the shared PR-0 editorial correction (see [BLUEPRINT.md](BLUEPRINT.md) §23 and
[IMPLEMENTATION-SLICES.md](IMPLEMENTATION-SLICES.md)): the rollout modes defined in this document map onto
**PR-11 — Shadow / Canary** (modes, scope controls, dashboards, and rollout guardrails), which is followed
by a **separate Production Qualification gate** (full evidence pack per §6 + Joint Go/No-Go Board
sign-off). There is **no PR-12**. The source DOCX's separate connectivity slice is folded across PR-5
(runtime/listener) and PR-10 (CP/DP); any reinstatement of a distinct connectivity or PR-12 slice is a
tracked open decision in [OPEN-DECISIONS.md](OPEN-DECISIONS.md), not part of this rollout model.

Sequence, for reference: PR-0 (this design baseline) → PR-1 Protocol kernel → PR-2 Registry & catalog →
PR-3 Identity principal → PR-4 Credential broker → PR-5 Observe runtime → PR-6 Policy engine →
PR-7 Inspection → PR-8 Durable decision events → PR-9 API & GUI → PR-10 CP/DP & HA →
**PR-11 Shadow & canary (this document's mode ladder)** → **Production Qualification (this document's §6
evidence pack + Board sign-off)**.
