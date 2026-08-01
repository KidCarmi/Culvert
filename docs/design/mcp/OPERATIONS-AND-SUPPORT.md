# MCP Operations and Support Model

**Status: PR-0 design artifact (Proposed)**

This document defines the operational and support model for the Culvert MCP subsystem: service-level
objectives, capacity dimensions, dashboards/alerts/on-call ownership, operational runbooks, the support
and incident-severity model, and known limitations. It covers **both** capabilities separately wherever
their operational posture differs — Capability A (Culvert Management MCP Server) and Capability B (MCP
Security Gateway) — per the doctrine in [`README.md`](README.md) and [`PRODUCT-SCOPE.md`](PRODUCT-SCOPE.md):
one platform, shared Control Plane services, separate enforcement engines and trust boundaries.

> **Every SLO, capacity, and timing number in this document is an unverified DESIGN TARGET, not a
> measured result.** None of them has been produced by a load test, a staging deployment, or production
> telemetry — no MCP listener exists in the repository today (see
> [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md)). Each number below is labeled
> **[TARGET]**. Repository facts are labeled **[FACT]** with `path · symbol · lines`; architectural
> inferences are **[INFER]**; human decisions are **[REC]**; anything needing a non-repository source is
> **[EXT]**. See the legend in [`README.md`](README.md).

> **PR-5 update.** An MCP listener runtime now EXISTS in the repository — `internal/mcp/runtime` — but is
> **DISABLED BY DEFAULT** and **observe-only** (no policy/credential/upstream; decision-point methods return
> a deterministic `observe_only` rejection). It exposes a typed, low-cardinality per-listener health/counter
> surface (`HealthSnapshot` — phase, accepted/rejected conns, requests total/rejected, kernel-terminal vs
> observe-only, active sessions, queued/in-flight, timeouts, auth + host/origin failures, admission rejects,
> shutdown cancels, observe drops) that a later slice will wire to the `MCP-OPS-003` metrics/dashboards
> surface. The SLO/capacity numbers below remain **unverified DESIGN TARGETS** — PR-5 ships the runtime and
> its load/slowloris/queue-saturation + MCP-off benchmarks, not a production availability measurement.

---

## 1 · SLOs as design targets

These targets are carried over verbatim from [`BLUEPRINT.md`](BLUEPRINT.md) §20 ("SLOs, Capacity and
Operations"), which itself states they "are not performance claims until verified in staging and
production-like environments." They apply to the Gateway (Capability B) request path unless noted.

| Metric | Target (design target, unverified) | Note | Requirement ID(s) |
|---|---|---|---|
| Gateway availability | **[TARGET]** 99.95% | For the scope operating in enforcement mode. | MCP-OPS-001 |
| Policy evaluation p99 | **[TARGET]** < 1 ms | Excludes external inspection calls. | MCP-OPS-001, MCP-POLICY-001..007 |
| Added latency p50 | **[TARGET]** < 5 ms | Gateway-local path. | MCP-OPS-001 |
| Added latency p95 | **[TARGET]** < 10 ms | Without external inspection services. | MCP-OPS-001 |
| Added latency p99 | **[TARGET]** < 25 ms | Under approved load. | MCP-OPS-001 |
| Policy rollback | **[TARGET]** < 5 minutes | Operational objective; faster is preferred. | MCP-OPS-002, MCP-CPDP-001..003 |
| Attribution completeness | **[TARGET]** > 99.9% | Calls with principal + agent + server + tool. | MCP-EVENT-002, MCP-ID-001..007 |
| Lost auth/deny/config events | **[TARGET]** 0 | Durability requirement — no silent drop of a decision or a config-apply event. | MCP-EVENT-002, MCP-EVENT-001..006 |
| MCP-off overhead | **[TARGET]** Zero or measurably negligible | No SWG regression while MCP is disabled. | MCP-OPS-004 |
| Shadow duration | **[TARGET]** ≥ 14 days | Or equivalent evidence, per [`README.md`](README.md) rollout stages. | MCP-OPS-002 |
| Canary enforcement | **[TARGET]** ≥ 7 days | No Sev-1/2 product defect. | MCP-OPS-002 |
| Soak test | **[TARGET]** ≥ 24 hours | Realistic streams and event pipeline. | MCP-OPS-002, MCP-HA-002 |

Additional mapping called out explicitly by this document's brief:

- **MCP-OPS-001** (gateway performance/availability SLOs) is the umbrella requirement for the top five
  rows above — availability and the four latency percentiles.
- **MCP-EVENT-002** (durable, non-lossy decision events) is the umbrella requirement for "Attribution
  completeness" and "Lost auth/deny/config events" — see [`EVENT-MODEL.md`](EVENT-MODEL.md) for the event
  schema and loss-policy design.
- **MCP-HA-002** (Data Plane fail-static / soak resilience under Control Plane unavailability) is the
  umbrella requirement for the soak-test target and for the Data Plane lag/split runbook (§5 below) — see
  [`CP-DP-HA-MODEL.md`](CP-DP-HA-MODEL.md).

**[INFER]** None of these targets can be claimed for Capability A (Management MCP) today. Management MCP
is read-only-default, tenant-scoped, and explicitly has no production-mutation surface until a
plan→validate→approve→apply workflow exists (see [`PRODUCT-SCOPE.md`](PRODUCT-SCOPE.md)); its own SLOs
(if any) are an **[OPEN-DECISIONS.md]**-tracked follow-up, not defined in this PR-0 package.

---

## 2 · Capacity dimensions

Carried from [`BLUEPRINT.md`](BLUEPRINT.md) §20 ("Capacity Dimensions"). Each is a **dimension to
provision and load-test against**, not yet a validated number:

- Concurrent MCP connections and SSE streams per Data Plane.
- Tool calls per second, by risk class.
- Maximum registered servers, tools, policies, and tenants.
- Payload sizes and schema complexity.
- Credential fetch/cache rate.
- Event throughput, queue depth, export latency, and spool size.
- Per-agent, per-tool, and per-credential rate limits.

**[INFER]** These dimensions are analogous in kind — but not in number or implementation — to existing
SWG capacity controls that are bounded today: `internal/sse` (`DefaultMaxClients=256`, evict-on-slow),
`internal/syslog` (`queueCap=2048`, drop-on-full → drops counter), and `ruleMetrics` cardinality capping
(`maxRuleMetrics=200`, `metrics.go:24`) — all per [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md).
The MCP event pipeline and connection pools are **net-new** and must define their own bounds; reusing the
SWG numbers verbatim would be a guess, not a target — actual MCP capacity numbers are **[OPEN-DECISIONS.md]**.

---

## 3 · Dashboards, alerts, paging, and on-call ownership

### 3.1 Metrics surface (requirement MCP-OPS-003)

**[FACT]** Culvert's existing Prometheus exposition lives at `handleMetrics` (`metrics.go:431`) under the
`culvert_*` namespace, with a lock-free latency histogram (`newHistogram`, `metrics.go:348-408`) and
cardinality-capped per-rule counters (`ruleMetrics`, `maxRuleMetrics=200`, `metrics.go:24`) — the pattern
that caps a naturally unbounded label set (rule names) to a fixed budget, folding overflow into an
`_other_` bucket.

**[INFER]** MCP-OPS-003 requires that new MCP metrics follow this same repository-established pattern
rather than introducing a second metrics convention:

- Metric names stay in the `culvert_*` namespace (e.g. `culvert_mcp_gateway_decision_total`,
  `culvert_mcp_policy_eval_seconds`, `culvert_mcp_event_export_lag_seconds`), appended to the same
  `mcpWritePrometheus`-style exposition path alongside the existing `handleMetrics` writer — a new
  exporter/port/format is out of scope.
- Any label with attacker- or tenant-controllable cardinality (server ID, tool name, tenant ID, agent ID)
  MUST be cardinality-capped the same way `ruleMetrics` is capped today (fixed bound + `_other_` overflow),
  not left open-ended.
- Capability A and Capability B metrics are **namespaced separately** (e.g. `culvert_mcp_mgmt_*` vs.
  `culvert_mcp_gateway_*`) so a dashboard or alert can never silently blend the two trust boundaries.

### 3.2 Dashboards (design intent, **[REC]**)

| Dashboard | Audience | Key panels |
|---|---|---|
| Gateway health | SRE / on-call | Availability, added-latency percentiles vs. targets in §1, policy-eval p99, connection/SSE stream counts vs. capacity in §2. |
| Policy & decisions | Sec / Product Sec | Decisions by action (of the nine policy actions), reason-code distribution, rollback events, shadow-vs-enforce parity. |
| Credential broker | IAM/PAM | Fetch/cache rate, scope-mismatch denials, revocation events, credential-leak alerts. |
| Event pipeline | SRE / Sec | Queue depth, export lag, spool size, loss-policy activations (target: zero lost auth/deny/config events). |
| CP/DP & HA | SRE / Cluster | Epoch/fencing state, stale-snapshot rejections, split-brain indicators, soak status. |
| Management MCP | Sec / Support | Read/write mix, RBAC denials, redaction hits, data-overexposure signals (MCP-T-035). |

### 3.3 Alerts and paging (design intent, **[REC]**)

| Alert | Trigger condition | Severity | Pages |
|---|---|---|---|
| SLO burn — availability/latency | Error budget burn rate exceeds a fast/slow multi-window threshold against §1 targets. | Sev-2 | On-call SRE |
| Lost auth/deny/config event | Any observed drop of a durable decision or config-apply event (target is zero). | Sev-1 | On-call SRE + Sec |
| Event pipeline saturation | Queue depth / spool size approaching capacity bound (§2). | Sev-2 (Sev-1 if evidence loss risk) | On-call SRE |
| `critical-durability-degraded` | An **authenticated** critical decision event failed to commit in this durability domain. | **Sev-1** — critical operations in that domain are failing closed. | On-call SRE / Reliability |
| `denial-lane-degraded` | Coalesced denial aggregates cannot commit, or `P-DEN` reached its quota. | **Sev-3** — nothing authenticated is blocked; usually an authentication flood, and the coalescer working as designed. | Security (not a storage page) |
| Credential-leak signal | Secret pattern detected in an inspected payload, or a credential-cache compromise indicator. | Sev-1 | On-call Sec |
| CP/DP split-brain or stale snapshot | Fencing epoch conflict or snapshot age beyond bound. | Sev-1 | On-call SRE + Cluster owner |
| Server compromise / drift | Registered-server identity change, tool schema/description drift, or unknown-tool auto-allow attempt. | Sev-1 | On-call Sec |
| Management MCP overexposure | RBAC/redaction bypass indicator on the Management surface. | Sev-1 | On-call Sec |

### 3.4 On-call ownership (**[REC]**, mirrors the Blueprint's RACI in §21/§22 evidence rows)

| Domain | Primary owner | Secondary |
|---|---|---|
| Gateway availability & latency | SRE / Network | Engineering |
| Policy engine & decisions | Product Security | Engineering |
| Credential broker | IAM/PAM | Product Security |
| Event pipeline durability | SRE | Engineering |
| CP/DP & HA | SRE / Cluster | Engineering |
| Management MCP | Product Security | Support |
| Customer-facing incidents | Support | Product |

---

## 4 · Runbooks

Carried from [`BLUEPRINT.md`](BLUEPRINT.md) §20 ("Operational Runbooks"), expanded with trigger and owner
columns. Every runbook's emergency-disable and rollback steps are governed by, and must stay consistent
with, [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md) — this document does not redefine the
rollout-stage machine or the emergency-disable procedure; it only maps operational triggers to it.

| Runbook | Trigger | Primary actions | Owner |
|---|---|---|---|
| Server compromise (MCP-T-020, MCP-T-021) | Registry/identity-change alert, or external compromise report for a registered/approved MCP server. | Disable registry entry, revoke associated credentials, quarantine affected tools, search decision events for prior calls to the server. Escalate to emergency disable in [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md) if enforcement scope is affected. | Product Security |
| Credential leak (MCP-T-023, MCP-T-024) | Secret-pattern hit in inspected payload/event, or credential-cache compromise indicator. | Revoke/rotate the credential, block the credential profile, identify all calls and resources reached with it via decision events. | IAM/PAM |
| Policy regression | Post-deploy anomaly in decision distribution, false-positive/negative spike, or SLO burn tied to a policy change. | Pause rollout stage advance, compare current vs. prior policy snapshot/revision, roll back per [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md), export affected decisions for review. | Product Security / Engineering |
| Data Plane lag / split (MCP-T-047..050) | Fencing-epoch conflict, stale-snapshot detection, or DP/CP heartbeat loss. | Fence the stale Control Plane, block partial config apply, route traffic to a healthy DP, recover from the last known-good snapshot. | SRE / Cluster |
| **Durability degradation (MCP-T-075, MCP-T-044)** | `critical-durability-degraded` **or** `denial-lane-degraded` alert, scoped to one node × capability. | See §5.8a — the two states have **different owners and different actions**: `critical-durability-degraded` is an **SRE / Reliability** storage page; `denial-lane-degraded` is a **Security** signal that an authentication flood is in progress. | SRE / Reliability (+ Security for the denial lane) |
| Event pipeline saturation (MCP-T-042..044) | Queue-depth/spool-size alert from §3.3. | Apply the configured loss policy and alert. **Reclamation is deterministic and already specified — it is not an operator judgement call:** the runtime frees `exported P-DEN → exported P-ORD → unexported P-DEN → unexported P-ORD → exported P-CRIT`, and **never** reclaims an unexported `P-CRIT` record while any lower-priority record remains ([EVENT-MODEL.md](EVENT-MODEL.md) §4b.4). The operator action is therefore to **add capacity, drain the export path, or reduce ingress** — *not* to choose which evidence to drop. If reclamation cannot free space without discarding unexported critical records, the domain enters `critical-durability-degraded` and §5.8a applies. *(The former remedy, "scale or spool", was circular: the spool was the thing that was full.)* | SRE |
| Protocol incompatibility | Compatibility-matrix failure or adapter error for a client/server version. | Use the adapter/compatibility status surface, disable the unsupported capability safely (fail closed, not open), notify affected tenants. | Engineering |
| Connector outage (MCP-T-051, MCP-T-052) | Outbound connector or DMZ endpoint health-check failure. | Maintain local enforcement where possible, fail according to the documented connectivity failure mode, alert, and prevent unsafe Management-MCP mutations during the outage. | SRE / Network |

---

## 5 · Support ownership and incident model

### 5.1 Support ownership

| Function | Owner |
|---|---|
| Tier-1 customer support (triage, known-issue matching) | Support |
| Tier-2 escalation (product/security judgment calls) | Product Security / Engineering |
| Tier-3 (code-level defect, hotfix) | Engineering |
| Customer-facing security incident communication | Support + Product Security (joint) |
| Upgrade/downgrade guidance | Support, with Engineering sign-off on compatibility |

### 5.2 Incident severity

| Severity | Definition (MCP context) | Example |
|---|---|---|
| Sev-1 | Data/credential exposure, lost durable event, active server compromise, or enforcement bypass. | Credential leaked to an agent; auth/deny event dropped; unknown-tool auto-allow fired. |
| Sev-2 | SLO breach without confirmed data exposure, or a policy regression causing incorrect (but logged) decisions. | Added-latency p99 breach; false-positive block spike. |
| Sev-3 | Degraded but bounded — capacity warning, non-critical drift alert, cosmetic dashboard issue. | Event-export lag approaching but not exceeding spool bound. |

### 5.3 Customer escalation

- Sev-1: immediate notification per customer contract, joint Support + Product Security communication,
  interim mitigation offered (e.g. emergency disable per [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md)).
- Sev-2: notification within the contracted SLA window; root-cause update once triaged.
- Sev-3: standard support-ticket channel; no proactive customer paging.

### 5.4 Upgrade, downgrade, and rollback (customer-facing)

- Version compatibility (client/server/protocol) is governed by [`PROTOCOL-COMPATIBILITY.md`](PROTOCOL-COMPATIBILITY.md);
  support must consult its version matrix before advising a customer to upgrade or downgrade.
- Config/policy rollback follows [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md); the < 5 minute
  policy-rollback target (§1) is the operational objective support communicates to customers during a
  Sev-1/Sev-2 policy regression.
- A downgrade that removes MCP enforcement must not silently re-widen access — the "MCP-off overhead ≈
  zero" target (§1) exists precisely so that disabling MCP is a safe, fully-reversible action, not a
  partial state.

### 5.5 Compatibility incidents

Handled per the "Protocol incompatibility" runbook (§4): fail closed on an unsupported capability rather
than falling back to unauthenticated/unpolicied behavior. Escalate to Engineering for an adapter fix or a
documented non-support decision in [`PROTOCOL-COMPATIBILITY.md`](PROTOCOL-COMPATIBILITY.md).

### 5.6 Credential incidents

Handled per the "Credential leak" runbook (§4) and the credential-broker model in
[`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md). Because Culvert's design principle is that
raw credentials are never delivered to the agent (Capability B) and never exposed in Management MCP
(Capability A), a credential incident is always treated as a broker- or storage-layer compromise, not an
agent-side leak — the investigation starts at the broker/cache, not the client.

### 5.7 Server compromise

Handled per the "Server compromise" runbook (§4). A **confirmed** compromise of a previously-approved
server is a distinct residual risk (R-3 in [`THREAT-MODEL.md`](THREAT-MODEL.md) §12, MCP-T-021) accepted
with drift, destination, and output controls as compensating layers — support/on-call should expect that
detection may be delayed until a drift or output-anomaly signal fires, not instantaneous.

### 5.8 Event-pipeline saturation

Handled per the "Event pipeline saturation" runbook (§4). Support-facing framing: a saturation incident
risks the "lost auth/deny/config events = 0" target (§1); it is never treated as a purely capacity/
performance ticket — Sec is looped in whenever the loss policy is invoked, even if no loss has yet
occurred.

### 5.8a Durability degradation — `critical-durability-degraded` / `denial-lane-degraded`

**These two states are NOT the same incident and MUST NOT share a response.** Treating a denial-lane
alert as a storage page wastes an on-call rotation on an attack; treating a critical-durability page as
"just noisy denials" leaves critical operations failing closed. The distinguishing question is
**whose event failed to commit**: an **authenticated** critical event, or an **attacker-mintable** denial
aggregate.

| | `critical-durability-degraded` | `denial-lane-degraded` |
|---|---|---|
| **Means** | An authenticated critical decision event could not be durably committed in this domain | Coalesced denial aggregates could not commit, or `P-DEN` hit its quota |
| **Blast radius** | Critical operations **in that one durability domain** fail closed (`node × capability × partition`) | **Nothing authenticated is blocked** — anywhere |
| **Owner** | **SRE / Reliability** | **Security** |
| **Severity** | Sev-1 | Sev-3 |
| **Usually caused by** | Real storage failure: `ENOSPC` (including a co-tenant filling a shared volume), `fsync` errors, an unavailable encryption key | An authentication flood; the coalescer and quota are containing it |

**Procedure — `critical-durability-degraded`:**

1. **Read the scope off the alert.** It names one node/DP runtime, one capability and one partition. Other
   nodes, the other capability and other tenants are **unaffected by design** — do not widen the incident
   on assumption. Confirm rather than assume: check whether the paired capability is still `normal`.
2. **Restore durable commitment in that domain.** Free space (respecting the reclamation order — the
   runtime will not discard unexported critical records for you), repair the volume, or restore the
   encryption key.
3. **Do not restart to clear the state.** Restart is **not** a recovery path: the state and its scope are
   restart-persistent by design (`MCP-OPS-005`), and a restart on ambiguous metadata deliberately resolves
   to the **narrow local degraded state**, not to `normal`. If you find yourself restarting to clear it,
   the underlying durability fault is still present.
4. **Let the bounded probe clear it.** Once all four exit criteria hold (storage writable; `P-CRIT` reserve
   above the recovery watermark; recovery marker committed **and read back**; pending critical records
   within the safe bound), the state exits within one
   `mcp_{gateway,mgmt}_durability_recovery_probe_interval`. **A state that does not clear within one
   interval after the criteria hold is a bug — escalate it as one**, do not work around it.
5. **There is no bypass to reach for.** V1 has no emergency policy, no break-glass flag and no
   configuration that permits a critical operation to run without a durable event. Recovery means
   restoring durability. If the business impact of failing closed is unacceptable in a specific incident,
   that is an **incident-command decision to take the capability out of service**, not a control to
   disable.

**Procedure — `denial-lane-degraded`:**

1. **Do not page storage.** By construction this state blocks nothing authenticated, cannot enter
   `critical-durability-degraded`, and cannot consume the `P-CRIT` reserve.
2. **Treat it as attack telemetry.** Read the aggregate counts and first/last-seen per
   `capability/listener × normalized source bucket × denial reason`. Volume is intentionally coalesced —
   the **count**, not the record count, is the signal.
3. **Respond at the network/identity layer** (block or rate-limit the source, investigate the targeted
   principal) — not by enlarging the denial quota, which only buys the attacker more durable footprint.
4. **Escalate to Sev-1 only if** `critical-durability-degraded` **also** appears. That combination means a
   real storage fault is present as well; the denial flood did not cause it, and the two are handled
   separately.

**Fleet-wide action is a human decision, never an automatic one.** No lost event — of any class — escalates
beyond its durability domain automatically. If an incident genuinely warrants fleet-wide action, that is an
authorized incident-response decision taken through this runbook and recorded as such
([`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md) emergency procedures).

### 5.9 CP/DP drift

Handled per the "Data Plane lag / split" runbook (§4) and [`CP-DP-HA-MODEL.md`](CP-DP-HA-MODEL.md). A
Data Plane fenced off or running on a last-known-good snapshot is a degraded-but-safe state (fail-static),
not an outage in itself — support should communicate "policy may be stale, not permissive" rather than
"the gateway is down."

### 5.10 Privacy incidents

Any indication of Management-MCP data overexposure (MCP-T-035) or a Gateway exfiltration/secret-leakage
event (MCP-T-026..028) is routed jointly to Sec and Privacy/Legal per
[`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) (MCP-PRIVACY-001..003) and treated with the same
urgency as a Sev-1 security incident regardless of confirmed exfiltration volume.

---

## 6 · Known limitations

These are **product-level, accepted limitations**, not defects to be silently worked around by operations
or support — each has an owner and an acceptance condition recorded in
[`THREAT-MODEL.md`](THREAT-MODEL.md) §12 ("Residual risk ownership"), linked below.

| Limitation | Threat ID(s) | Residual risk row | Operational implication |
|---|---|---|---|
| stdio / localhost / direct-egress bypass of the Gateway | MCP-T-054, MCP-T-055, MCP-T-056 | [R-1](THREAT-MODEL.md#12-residual-risk-ownership) | An agent using a local stdio transport or a direct-egress path never traverses `/mcp/gateway/{server-id}` — support must be able to explain that Culvert governs traffic it can see, not every possible local integration path, until the endpoint-bridge roadmap item ([`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) D-8) ships. |
| Pattern-based inspection is best-effort | MCP-T-026, MCP-T-027, MCP-T-038 | [R-2](THREAT-MODEL.md#12-residual-risk-ownership) | Secret/injection detection in tool args and responses cannot catch every case; defense-in-depth (approvals, redaction, monitoring) is the accepted compensating control — an incident is not automatically a product defect. |
| An approved server can be compromised after approval | MCP-T-021 | [R-3](THREAT-MODEL.md#12-residual-risk-ownership) | See §5.7 — drift/destination/output controls are the detection layer, not prevention; on-call should expect a lag between compromise and detection. |
| Human approval flows are subject to social engineering | MCP-T-032, MCP-T-033 | [R-4](THREAT-MODEL.md#12-residual-risk-ownership) | Explicit, auditable approval UX is the accepted mitigation; support cannot treat every approved-then-regretted action as a system failure. |
| Cloud AI vendor data handling is outside Culvert's control | MCP-T-053 | [R-5](THREAT-MODEL.md#12-residual-risk-ownership) | Customer contract + allowlist + DLP-before-egress is the accepted per-deployment mitigation; escalate data-residency questions to Privacy/Legal, not Engineering. |

**[FACT]** No MCP listener, JSON-RPC endpoint, or SSE stream exists in the current repository
(`VERIFIED-REPOSITORY-CONTEXT.md`: "NO existing MCP/JSON-RPC listener in inspected paths"). All limitations
above describe the **designed** V1 posture for when Capability A/B ship, not a currently-operating system.

---

## 7 · Support lifecycle

| Stage | What support does | Gate to next stage |
|---|---|---|
| Disabled | No customer-facing support surface; internal-only. | PR-0 approved (this package). |
| Observe | Internal/lab support only; no customer traffic. | Protocol kernel, auth, bounded runtime validated. |
| Shadow | Support is briefed on the feature but it is not customer-enforcing; issues are triaged as internal findings. | Decision parity and event durability confirmed (§1 shadow-duration target). |
| Canary | Support handles a small, read-first customer scope; runbooks (§4) rehearsed at least once. | SLO met (§1) and no critical defect during the canary window. |
| Production | Full support lifecycle (§5) active: severity model, escalation, upgrade/downgrade guidance. | Security and operations sign-off per [`BLUEPRINT.md`](BLUEPRINT.md) §21 Production Readiness Evidence. |
| End-of-life / deprecation | Support communicates a deprecation timeline and a rollback/downgrade path before removing any enforcement scope. | **[OPEN-DECISIONS.md]** — no EOL policy defined yet in this PR-0 package. |

This mirrors the rollout stage machine in [`README.md`](README.md) / [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md);
support readiness at each stage is a **gate**, not a parallel track — support must not be asked to run a
customer-facing incident process for a stage that has not yet met its entry criteria.

---

## 8 · Tests-not-run risk

None of the SLOs, capacity numbers, dashboards, alert thresholds, or runbooks in this document have been
exercised against a running MCP implementation — there is no MCP code to test yet (§0 disclaimer, and
[`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md)). Per this package's standing
methodology note:

> Low for the read-only Phase 1 investigation, but the current repository test baseline remains unverified
> in this session.

This risk phrasing applies with equal force here: the operations and support model above is a **design
baseline for future validation** (load tests, chaos tests, soak tests, a rehearsed rollback drill, and a
real support-ticket dry run), not evidence that any target has been met. Closure of this risk is tracked
in [`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md) and the Production Readiness Evidence table in
[`BLUEPRINT.md`](BLUEPRINT.md) §21.

---

## Cross-references

- [`BLUEPRINT.md`](BLUEPRINT.md) §20–§22 — source SLO/capacity/runbook table, rollout stages, business metrics.
- [`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md) — rollout stage machine, rollback mechanics, emergency disable.
- [`THREAT-MODEL.md`](THREAT-MODEL.md) §12 — residual risk ownership referenced in §6 above.
- [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) — MCP-OPS-001..004, MCP-EVENT-001..006, MCP-HA-001..002 and other requirement IDs referenced above.
- [`EVENT-MODEL.md`](EVENT-MODEL.md) — durable decision event schema and loss policy underlying §1's event targets.
- [`CP-DP-HA-MODEL.md`](CP-DP-HA-MODEL.md) — snapshot/fencing model underlying §4's Data Plane lag/split runbook.
- [`OPEN-DECISIONS.md`](OPEN-DECISIONS.md) — open items referenced above (endpoint bridge D-8, MCP-specific capacity numbers, EOL policy).
- [`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md) — blocking conditions for promoting these targets to Production.
