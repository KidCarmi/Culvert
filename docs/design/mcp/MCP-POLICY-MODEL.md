# MCP Policy Model

> **PR-11 status (guarded execution / Shadow / Canary) — IMPLEMENTED, disabled by default.** The mode
> ladder, immutable revisioned scope, central hard-failure classifier, bounded Model-A upstream client,
> guarded execution (commit-before-side-effect, DLP-before-egress, credential containment, no client-token
> passthrough), and signed CP→DP rollout distribution now ship in `internal/mcp/{rollout,upstreamclient,execution}`
> and the `package main` composition. **Observe is non-executing; Shadow/Canary execute only inside an exact
> approved scope for Model A (local-client); Production remains qualification-locked** (no config/env/CLI/API
> bypass; no in-binary issuer). `outbound-connector`/`dmz-endpoint`, endpoint bridge, transparent discovery,
> and Management mutation remain excluded. Duration targets (14d/7d/24h) are measurable machinery, not
> completed evidence; Production Qualification is the separate gate. There is no PR-12 in this
> package's slice sequence — see [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md) (not to be
> confused with the unrelated fix CLAUDE.md separately labels "PR-12").


Defines the MCP Security Gateway policy engine: inputs, the nine decision actions, obligations, reason
codes, and the policy lifecycle. **Status: PR-0 design artifact (Proposed).** This is a **separate**
policy schema from the SWG `PolicyRule` — per [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md),
the SWG rule (`policy.go:91-188`, four actions `:19-27`) is a network-destination selector and **MUST NOT**
be extended with MCP fields, and the SWG evaluator (which does DNS/disk I/O during a decision,
`policy.go:1387`) **MUST NOT** be reused because MCP evaluation must be I/O-free.

> **Implementation status (PR-6) — IMPLEMENTED (dormant).** This model is realized by `internal/mcp/policy`
> (engine, immutable `DecisionInput` tuple, immutable capability-local compiled `Snapshot`, strict parser,
> deterministic order-independent hash, bounded lock-free store, `Decision` + sanitized `ExplainTrace`) and
> `internal/mcp/policy/simulate` (single/corpus/blast-radius/shadow over the SAME evaluator). The engine is a
> pure, **I/O-free** function of `(snapshot, input)` — no network/fs/db/DNS/env/**clock**/secret/logging on the
> eval path (explicit `EvalTime`, never `time.Now()`; enforced by an AST import-allowlist test) — exactly the
> separation this section mandates from the SWG rule. It is a **separate** Go type set from SWG `PolicyRule` and
> calls no SWG evaluator. Decision-only in this slice: wired into the PR-5 runtime as an optional provider, an
> ALLOW-class decision returns `execution_state: not_implemented` (no upstream/credential/broker call). The
> approval-UX lifecycle (`MCP-POLICY-007`) and the policy-bundle publication API/GUI + signed CP→DP distribution
> are later slices (PR-9/PR-10). See [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md) PR-6.

Legend: **[FACT]** repo-verified · **[INFER]** · **[REC]** · **[EXT]**.

---

## 1. Policy input (the decision tuple)

A single deterministic function `evaluate(input) → decision` over these inputs (mirrors BLUEPRINT §11):

| Group | Fields |
|---|---|
| Principal | subject, type (human/workload), tenant, groups, assurance |
| Agent | agent ID, owner, version, managed status, risk |
| Client | OAuth client, application ID, deployment, trust |
| Tenant | tenant ID (bound + enforced — MCP-ID-007) |
| Server | registry ID, owner, environment, TLS/workload identity |
| Tool identity | name + canonical input/output/description hashes ([`TOOL-DISCOVERY-AND-DRIFT.md`](TOOL-DISCOVERY-AND-DRIFT.md)) |
| Tool risk | intent, input surface, destination breadth, credential power, reversibility |
| Method / operation | **protocol method** (admitted per [`MCP-OPERATION-REGISTRY.md`](MCP-OPERATION-REGISTRY.md)), **operation class** (read / write / destructive / discovery / control), **operation namespace** (tool name for Gateway tools; mgmt-operation for Management — **tool name is ONE operand type, not the universal authorization key**), **normalized operand identity** (the policy-visible operand extracted per the registry's resource/destination-extraction column). #928 |
| Arguments | extracted, inspected, resource-bearing fields ([`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md)) |
| Resource | repository, project, database, tenant, record scope |
| Destination | scheme/host/IP class (SSRF policy — MCP-INSP-004) |
| Credential profile | selected profile ID (metadata only) |
| Environment / Time | environment tag, schedule/time window |
| Session / assurance | session ID, assurance level |
| Revisions | catalog revision, policy revision (stamped on the decision) |

**MCP-POLICY-002 [REC]:** evaluation **MUST** be a pure function — **no network or other I/O**. All inputs
(including resolved destination class and tool fingerprint) are materialized **before** evaluation. This is
the explicit contrast to the SWG evaluator. **[FACT]** SWG `Evaluate` performs DNS/disk during a decision.

## 2. Decision actions (the nine)

Every decision returns exactly one action plus obligations, a reason code, matched-rule ID, revision
context, remediation and an event classification (MCP-POLICY-003, MCP-POLICY-005).

| Action | When | Required obligations |
|---|---|---|
| `ALLOW` | Approved action, controlled risk. | Logging, rate limit, destination scope. |
| `DENY` | Explicit rule or hard security failure. | Reason + remediation. |
| `MONITOR` | Learning / low-confidence classification. | Full telemetry, no block. |
| `QUARANTINE` | New or changed tool/server/identity. | Review required; **no execution**. |
| `REQUIRE_CONFIRMATION` | Initiating user must confirm. | Display exact action, resource, impact. |
| `REQUIRE_APPROVAL` | High-risk / production action. | Approver role, expiry, ticket/reference. |
| `ALLOW_ONCE` | Point exception. | One call, strict scope, short TTL. |
| `ALLOW_FOR_SESSION` | Time/scope-limited series. | Session ID, max calls, revoke. |
| `ALLOW_WITH_REDACTION` | Allowed after removing a sensitive field. | Redaction evidence, transformed hash. |

**Hard rules:**
- **MCP-POLICY-001:** default-deny when no rule matches (Zero Trust). **[FACT]** SWG precedent exists
  (`policy.go:1142`, `proxy.go:543-556`) but the MCP engine implements its own.
- **MCP-TOOL-006 / MCP-TOOL-004:** an unknown tool or a privilege expansion **MUST** resolve to
  `QUARANTINE` and **MUST NOT** auto-`ALLOW` (threat MCP-T-017 Critical).
- **MCP-POLICY-004:** upstream credential selection happens **only after** an ALLOW-class decision
  (prevents confused deputy, MCP-T-046).
- **MCP-POLICY-006:** destructive tools default to `REQUIRE_APPROVAL` or `DENY` (MCP-T-029).

## 3. Every output carries

| Field | Meaning |
|---|---|
| reason code | Machine-readable, from §5 taxonomy. |
| matched rule | Stable rule ID (SWG precedent: `proxy.go:470` stamps a rule ULID). |
| obligations | From §2. |
| revision context | `policy_revision` + `catalog_revision` (SWG lacks per-decision revision today — net-new). |
| remediation | Human-actionable next step. |
| event classification | Maps to [`EVENT-MODEL.md`](EVENT-MODEL.md) category + criticality. |

**MCP-POLICY-003 [REC]:** no `ALLOW`/`DENY` without a reason code + revision context (BLUEPRINT §06
"explain every decision").

## 4. Policy lifecycle

```
Draft → Validate → Simulate → Review → Approve
→ Publish Snapshot → Observe/Shadow → Canary → Production
→ Monitor → Roll Back / Retire
```

- **Draft / Validate / Simulate:** authored via Management MCP (read/draft only, no activation —
  MCP-MGMT-001) or the admin API; the **simulator** computes blast radius before publication (BLUEPRINT §15).
- **Review / Approve:** four-eyes (TB-5); RBAC-gated (`requireRole`, `ui_rbac.go:46-53` precedent).
- **Publish Snapshot:** immutable, signed CP→DP snapshot ([`CP-DP-HA-MODEL.md`](CP-DP-HA-MODEL.md));
  policy_revision increments.
- **Observe/Shadow → Canary → Production:** staged rollout ([`ROLLOUT-AND-ROLLBACK.md`](ROLLOUT-AND-ROLLBACK.md)),
  the same `Disabled → Observe → Shadow → Canary → Production` ladder that document defines
  (`internal/mcp/rollout.Mode`); hard failures block even in Shadow.
- **Roll Back / Retire:** atomic rollback to the previous snapshot (MCP-HA-002).

## 5. Reason-code taxonomy

Prefixes (BLUEPRINT Appendix C); codes are stable identifiers used in decision events and the GUI.

| Prefix | Meaning | Example codes |
|---|---|---|
| `MCP.AUTH` | Authentication & identity | `INVALID_TOKEN`, `WRONG_AUDIENCE`, `WRONG_RESOURCE`, `IDENTITY_AMBIGUOUS`, `REPLAY_SUSPECTED` |
| `MCP.SERVER` | Registry, TLS, server state | `UNREGISTERED`, `DISABLED`, `IDENTITY_CHANGED` |
| `MCP.TOOL` | Tool catalog & drift | `UNKNOWN`, `SCHEMA_CHANGED`, `PRIVILEGE_EXPANSION`, `SEMANTIC_DRIFT` |
| `MCP.POLICY` | Rule evaluation | `NO_MATCH_DEFAULT_DENY`, `RESOURCE_SCOPE`, `TIME_WINDOW`, `APPROVAL_REQUIRED` |
| `MCP.CREDENTIAL` | Broker & scope | `UNAVAILABLE`, `SCOPE_MISMATCH`, `EXPIRED` |
| `MCP.INSPECTION` | Input/output controls | `SECRET_FOUND`, `SSRF_BLOCKED`, `SCHEMA_INVALID`, `ORIGIN_REJECTED` |
| `MCP.RATE` | Quota & abuse | `AGENT_LIMIT`, `TOOL_LIMIT`, `CREDENTIAL_LIMIT` |
| `MCP.SYSTEM` | Runtime & HA | `SNAPSHOT_INVALID`, `EVENT_BACKPRESSURE`, `DEGRADED_MODE` |
| `MCP.MANAGEMENT` | Management MCP | `TOOL_NOT_EXPOSED`, `MUTATION_NOT_APPROVED`, `TENANT_SCOPE` |

Reason codes map to threats: e.g. `WRONG_AUDIENCE`→MCP-T-003, `WRONG_RESOURCE`→MCP-T-004,
`REPLAY_SUSPECTED`→MCP-T-002, `PRIVILEGE_EXPANSION`→MCP-T-019, `SSRF_BLOCKED`→MCP-T-036,
`ORIGIN_REJECTED`→MCP-T-031, `SNAPSHOT_INVALID`→MCP-T-047.

## 6. Worked example (from BLUEPRINT §11)

```
Decision: DENY
Matched:
  ✓ Managed agent   ✓ Approved server   ✓ User in Developers
  ✗ Tool schema changed after approval
  ✗ Repository scope includes production
Blocking rule: MCP-PROD-WRITE-14
Reason code: MCP.TOOL.SCHEMA_CHANGED
policy_revision: 82   catalog_revision: 37
Remediation: review drift or request temporary approval
```

## 7. Policy example (declarative sketch)

```yaml
rule: MCP-GITHUB-DEV-WRITE
when:
  method: tools/call            # admitted per MCP-OPERATION-REGISTRY.md (not the raw version set)
  operation.class: write        # read/write/destructive/discovery/control — matched, not assumed
  operation.namespace: tool     # tool name is ONE operand type, not the universal key
  principal.group: developers
  agent.managed: true
  server.id: github-prod
  tool.name: repository.write_file
  tool.risk: [medium, high]
  resource.repository: KidCarmi/Culvert
  resource.branch: feature/*
require:
  tool.fingerprint_status: approved
  credential.profile: github-prod-writer
  input.secret_detection: clean
action: ALLOW
else_if:
  resource.branch: main
action: REQUIRE_APPROVAL   # reason: MCP.POLICY.APPROVAL_REQUIRED
```

**Method/operation is a first-class match key (#928).** A rule matches only when the admitted `method` and a
**representable** operand are present. **Default-deny (`MCP-POLICY-001`) is meaningful only after the method
and operand have been represented and routed to the named decision point** — "no rule matched" over an
operand the tuple cannot express is a modelling failure wearing a security outcome's clothes, not honest
default-deny. For **rejected** V1 method classes (`resources/*` incl. `resources/read`, `prompts/*`,
`completion/*`, server-originated `sampling`/`elicitation`/`roots`, `tasks/*`), **admission precedes policy**
and **no policy exception can re-admit them** ([`MCP-OPERATION-REGISTRY.md`](MCP-OPERATION-REGISTRY.md),
`MCP-PROTO-016`); they never reach this evaluator.

## 8. Management vs Gateway policy separation

The Management MCP (Capability A) and the Gateway (Capability B) use **separate policy namespaces and
decision actions** ([`RECOMMENDED-ARCHITECTURE.md`](RECOMMENDED-ARCHITECTURE.md)). Management decisions use
the `MCP.MANAGEMENT` reason space and default read-only (MCP-MGMT-001); they never share a rule set with
business-tool authorization. A single generic "policy for everything" is explicitly rejected (BLUEPRINT §03).
