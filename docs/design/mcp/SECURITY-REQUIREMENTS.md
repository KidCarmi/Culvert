# MCP Security Gateway — Security Requirements

Canonical **requirement-ID registry** for the PR-0 package. IDs are stable and referenced by
[`THREAT-MODEL.md`](THREAT-MODEL.md), [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md),
[`ABUSE-CASES.md`](ABUSE-CASES.md) and [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md).

**All requirements are `Status: Proposed`** (PR-0 is design-only; nothing is implemented). Normative
keywords **MUST / MUST NOT / SHOULD / MAY** are used deliberately. "Gate" names the slice or CI gate that
must be green before the requirement is considered satisfied. Every requirement carries: statement,
rationale, threat IDs, control owner, implementation owner, verification method, evidence required.

Column key per table: **ID · Normative statement · Rationale · Threats · Owner (Control / Impl) ·
Verification · Evidence · Gate**. Status is `Proposed` for all rows unless noted.

> **Decision provenance (2026-07-24).** Options for five families are now fixed by
> [`docs/adr/0023`](../../adr/0023-mcp-agent-security-gateway-trust-boundary.md): **MCP-AUTH** (D-2 —
> resource-server + reframed MCP-AUTH-006 sender-constraint/DPoP-proof replay), **MCP-EVENT** (D-5 —
> durable spool + per-action fail-closed matrix), **MCP-CONNECT** (D-8 — Model A only V1; connector
> post-V1), **MCP-CONNECT-003 / MCP-INSP-008** (D-9 — DMZ default-off; host-allowlist + Origin-per-protocol
> on every listener), **MCP-MGMT** (D-13 — read-only + draft/validate/simulate; mutation excluded). The
> requirement **IDs and statements are unchanged** except MCP-AUTH-006, whose framing is corrected below.

---

## MCP-AUTH — Authentication & token validation

| ID | Normative statement | Rationale | Threats | Owner (Control/Impl) | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-AUTH-001 | The gateway **MUST** validate the client bearer token on every tool call and **MUST NOT** accept a token in a query string. | Prevent unauthenticated/URL-leaked tokens. | MCP-T-001 | Sec / Eng | Negative auth matrix | Test logs: rejected missing/invalid/query-string tokens | PR-3 |
| MCP-AUTH-002 | The token audience **MUST** identify Culvert (the MCP resource); tokens for other audiences **MUST** be rejected. | No confused-audience acceptance. Repo today binds audience to OIDC `client_id` only (`auth_oidc_flow.go:523`) — insufficient. | MCP-T-003 | Sec / Eng | Wrong-audience negative tests | Rejections for foreign `aud` | PR-3 |
| MCP-AUTH-003 | The gateway **MUST** validate the resource indicator (RFC 8707) binding the token to the target MCP server; unbound tokens **MUST** be denied for write/high-risk. | Prevent token reuse across resources. **Not present today** (0 matches). | MCP-T-004 | Sec / Eng | Resource-binding negative tests | Denials for mismatched resource | PR-3 |
| MCP-AUTH-004 | Tokens **MUST** be short-TTL and expiry **MUST** be enforced. | Bound the stolen-token window. Repo enforces exp (`auth_oidc_flow.go:653-659`). | MCP-T-001 | Sec / Eng | Expiry tests | Expired-token rejection | PR-3 |
| MCP-AUTH-005 | The client token **MUST NOT** be forwarded unchanged upstream (no passthrough). | Isolate agent token from upstream privilege. Precedent only (`proxy.go:46-73`); net MCP impl required. | MCP-T-005 | Sec / Eng | Upstream-capture test | Upstream request carries no client token | PR-4 |
| MCP-AUTH-006 | The gateway **MUST** implement anti-replay / token-abuse defense as a layered posture — TLS every request, short TTL, audience/resource restriction, issuer/sig/exp/tenant/scope validation, introspection/revocation where applicable, client/session correlation + rate limits + anomaly signals, and **sender-constrained tokens (mTLS or DPoP) for high-risk or externally reachable profiles**. It **MUST NOT** be defined as one-time-use rejection of an access-token `jti` (reuse of a still-valid token is not itself replay). **When DPoP is used, replay detection applies to the per-request DPoP proof** (proof `jti`, method, URI, `iat`, `ath`, server nonce), never the underlying access token. | **Net-new; NOT VERIFIED as present** — reusable path has no access-token replay defense (VRC §6). Reframed by [`ADR-0023 §D-2`](../../adr/0023-mcp-agent-security-gateway-trust-boundary.md) items 7–9. | MCP-T-002 | Sec / Eng | Replay/DPoP-proof test suite + anomaly/rate-limit tests | Replayed DPoP proof rejected; sender-constraint enforced on high-risk profiles; stolen-token abuse rate-limited/flagged | PR-3 |
| MCP-AUTH-007 | Session/token binding **MUST** prevent cross-user session confusion. | One caller's session cannot serve another's identity. | MCP-T-008 | Sec / Eng | Cross-session tests | No identity bleed across concurrent sessions | PR-3 |
| MCP-AUTH-008 | Management MCP and Gateway MCP **MUST** use separate OAuth client registrations and scopes. | Separate authorization planes. | MCP-T-034 | Sec / IAM | Config/scope review + tests | Distinct clients/scopes enforced | PR-3 |

## MCP-ID — Identity, principals & delegation

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-ID-001 | The identity model **MUST** represent human, workload, agent, client, tenant, server, tool and resource as distinct principals. | Flat `Identity` (`identity.go:9-27`) is human-only. | MCP-T-006,007 | IAM / Eng | Model review + unit tests | Principal types populated end-to-end | PR-3 |
| MCP-ID-002 | Agent identity **MUST** be attributed (agent ID, owner, managed status) and **MUST NOT** be inferred from IP alone. | Prevent agent impersonation. | MCP-T-006 | IAM / Eng | Attribution tests | Agent fields on decision events | PR-3 |
| MCP-ID-003 | Workload identity **MUST** be validated (service identity/attestation) where no human session exists. | Automation without a human. | MCP-T-007 | IAM / Eng | Workload-auth tests | Attested workload accepted; spoof rejected | PR-3 |
| MCP-ID-004 | The delegation chain (human→agent→client→server→tool→resource) **MUST** be recorded without storing secrets. | Attribution + non-repudiation. | MCP-T-045 | IAM / Eng | Event schema tests | Chain present, no secrets | PR-8 |
| MCP-ID-005 | Missing or ambiguous identity **MUST** produce DENY for write/high-risk operations. | Fail closed on ambiguity. | MCP-T-006,007 | Sec / Eng | Ambiguous-identity tests | DENY + reason code | PR-6 |
| MCP-ID-006 | Assurance level **SHOULD** be carried and **MAY** gate step-up for sensitive operations. | Risk-proportionate auth. | MCP-T-008 | IAM / Eng | Step-up tests | Assurance influences decision | PR-6 |
| MCP-ID-007 | Tenant identity **MUST** be bound and enforced on every call; cross-tenant access **MUST** be denied. | Prevent cross-tenant confusion. | MCP-T-009,010 | IAM / Eng | Tenant-escape tests | Cross-tenant denials | PR-3 |

## MCP-SERVER — Server registry & TLS identity

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-SERVER-001 | Only registered servers on the allowlist **MUST** be reachable; unregistered destinations **MUST** be denied. | No open destination. | MCP-T-020,036 | Sec / Eng | Allowlist tests | Unregistered denied | PR-2 |
| MCP-SERVER-002 | Server TLS/workload identity **MUST** be verified and pinned to the registry entry. | Detect malicious/spoofed servers. | MCP-T-016,020 | Sec / Eng | TLS-identity tests | Identity mismatch → disable | PR-2 |
| MCP-SERVER-003 | A server identity change **MUST** disable the server until re-verified. | Rug-pull at server level. | MCP-T-016,021 | Sec / Eng | Identity-change tests | Auto-disable on change | PR-2 |

## MCP-TOOL — Tool catalog, fingerprint & drift

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-TOOL-001 | Every tool **MUST** be fingerprinted (server ID + name + canonical input/output/description hashes + credential profile + destination class). | Stable identity for drift detection. | MCP-T-011 | Sec / Eng | Canonicalization tests | Deterministic fingerprint | PR-2 |
| MCP-TOOL-002 | Duplicate/shadowing tool names **MUST** be detected and disambiguated by fingerprint. | Prevent tool shadowing. | MCP-T-012 | Sec / Eng | Shadowing tests | Collisions flagged | PR-2 |
| MCP-TOOL-003 | Schema/description drift **MUST** be classified (no-change / safe-narrowing / expansion / semantic / identity / unknown). | Distinguish safe from dangerous change. | MCP-T-013,014 | Sec / Eng | Drift-class tests | Correct class per fixture | PR-2 |
| MCP-TOOL-004 | Privilege expansion and rug-pull **MUST** move the tool to QUARANTINE and **MUST NOT** auto-allow. | Core trust principle. | MCP-T-015,019 | Sec / Eng | Expansion tests | Quarantine + no allow | PR-6 |
| MCP-TOOL-005 | Semantic/description drift **MUST** trigger risk re-score and review. | Behavior claim changes. | MCP-T-014 | Sec / Eng | Semantic-drift tests | Re-score recorded | PR-2 |
| MCP-TOOL-006 | An unknown tool **MUST** be quarantined and **MUST NOT** receive automatic allow. | Red line. | MCP-T-017 | Sec / Eng | Unknown-tool tests | Quarantine + reason code | PR-6 |

## MCP-POLICY — Policy engine & decisions

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-POLICY-001 | Policy evaluation **MUST** default-deny when no rule matches. | Zero Trust. | MCP-T-017,018 | Sec / Eng | Default-deny tests | No-match → DENY | PR-6 |
| MCP-POLICY-002 | Policy evaluation **MUST** be deterministic and **MUST NOT** perform network or other I/O. | SWG eval does DNS/disk (`policy.go:1387`) — must not be reused. | MCP-T-018 | Sec / Eng | Determinism + no-I/O tests | Pure-function proof | PR-6 |
| MCP-POLICY-003 | Every decision **MUST** carry a machine-readable reason code, matched-rule ID and revision context (policy/catalog). | Explainability; repo lacks reason-code enum + per-decision revision. | MCP-T-019 | Sec / Eng | Reason-code tests | Reason+rule+revisions on every decision | PR-6 |
| MCP-POLICY-004 | Upstream credential selection **MUST** occur only after a policy ALLOW-class decision. | Prevent confused deputy. | MCP-T-046 | Sec / Eng | Ordering tests | No credential before decision | PR-6 |
| MCP-POLICY-005 | The nine decision actions **MUST** be supported with obligations (see [`MCP-POLICY-MODEL.md`](MCP-POLICY-MODEL.md)). | Rich enforcement. SWG has 4 verbs only. | MCP-T-018 | Sec / Eng | Action-matrix tests | Each action + obligation exercised | PR-6 |
| MCP-POLICY-006 | Destructive tools **MUST** require REQUIRE_APPROVAL or DENY by default. | Control critical operations. | MCP-T-029 | Sec / Eng | Destructive-tool tests | Approval/deny enforced | PR-6 |
| MCP-POLICY-007 | Human approval UX **MUST** display exact action, resource, impact and credential. | Meaningful HITL. | MCP-T-032,033,039 | Product Sec / Eng | UX review + tests | Approval dialog completeness | PR-9 |

## MCP-CRED — Credential broker

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-CRED-001 | Agents **MUST NOT** receive upstream/production credentials. | Primary differentiation. | MCP-T-005 | IAM/PAM / Eng | Credential-flow tests | No secret to agent | PR-4 |
| MCP-CRED-002 | Credentials **MUST** be scoped by environment/server/tool/resource; over-privileged credentials **MUST** be rejectable by policy. | Least privilege. | MCP-T-022,025,046 | IAM/PAM / Eng | Scope-mismatch tests | Over-broad rejected | PR-4 |
| MCP-CRED-003 | Credentials **MUST** be short-lived, rotatable without downtime and immediately revocable. | Limit exposure. | MCP-T-022 | IAM/PAM / Eng | Rotation/revoke tests | Revoke takes effect | PR-4 |
| MCP-CRED-004 | Secrets **MUST NOT** appear in logs, metrics, traces, errors or decision events. | No secret leakage. | MCP-T-023,028 | IAM/PAM / Sec | Secret-scan tests | gitleaks + event redaction | PR-4 |
| MCP-CRED-005 | The credential cache **MUST** be bounded and encrypted at rest. | Cache compromise containment. Prior art: `internal/secret`. | MCP-T-024 | IAM/PAM / Eng | Cache tests | Bounded + encrypted | PR-4 |
| MCP-CRED-006 | Broker failure **MUST** fail closed for write/high-risk; fail-open **MAY** be allowed only with a valid cached credential and explicit policy for read-only low-risk. | Safe failure semantics. | MCP-T-024 | IAM/PAM / Eng | Broker-failure tests | Fail-closed proven | PR-4 |

## MCP-INSP — Inspection, DLP & SSRF

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-INSP-001 | Input **MUST** be schema/size/depth/field-count bounded. | Bound hostile payloads. | MCP-T-040,029 | Sec / Eng | Fuzz + limit tests | Oversized rejected | PR-7 |
| MCP-INSP-002 | Output **MUST** be size/type/schema bounded with a truncation policy. | Bound hostile responses. | MCP-T-027,021 | Sec / Eng | Output-limit tests | Truncation enforced | PR-7 |
| MCP-INSP-003 | Secret/PII patterns **MUST** be detected and redacted or blocked by classification. | DLP. Prior art: `internal/redaction`. | MCP-T-026,027,028 | Sec/Privacy / Eng | Synthetic-secret corpus | Redaction/block evidence | PR-7 |
| MCP-INSP-004 | Outbound destinations **MUST** be checked (scheme/host/IP range) against a private/link-local/metadata policy. | SSRF. Prior art: `internal/ssrf` peer-IP recheck (`ssrf.go:126-139`). | MCP-T-036,030 | Sec / Eng | Private-IP matrix | Private denied | PR-7 |
| MCP-INSP-005 | DNS resolution **MUST** be pinned across resolve→connect (rebinding TOCTOU guard). | Prevent rebinding. Prior art: dialer `Control`. | MCP-T-037,030 | Sec / Eng | DNS-rebinding lab | Rebinding blocked | PR-7 |
| MCP-INSP-006 | Redirects **MUST** be limited and re-checked per hop; a shared MCP redirect guard **SHOULD** replace per-client copies. | Redirect abuse. | MCP-T-041 | Sec / Eng | Redirect-chain tests | Hop cap + re-check | PR-7 |
| MCP-INSP-007 | Output content that attempts to influence the agent **MUST** be labeled/reported (not silently trusted). | Injection defense (best-effort). | MCP-T-038,039 | Sec / Eng | Injection corpus | Labels emitted | PR-7 |
| MCP-INSP-008 | The inbound MCP/SSE listener **MUST** validate Origin/Host to prevent DNS-rebinding against the local server: **host validation + configured-host allowlisting are mandatory on every HTTP MCP listener**, and the listener **MUST** bind only to explicitly configured interfaces (never default to unrestricted public ingress). Origin validation follows the supported MCP protocol baseline — validate `Origin` on incoming Streamable HTTP and reject a **present-but-invalid** Origin with the protocol-required response; do **not** require every non-browser client to always send `Origin` unless the selected protocol version mandates it ([`ADR-0023 §D-9`](../../adr/0023-mcp-agent-security-gateway-trust-boundary.md) items 3–5). | **Missing today** (`isSafeRedirectURL` captive-portal-only). | MCP-T-031,055,052 | Sec / Eng | Inbound-rebinding tests + host-allowlist fail-closed + bind-interface tests | Bad Origin/Host rejected; empty allowlist fails closed; no default public bind | PR-1 |

## MCP-EVENT — Durable decision events

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-EVENT-001 | Decision events **MUST** use bounded queues with backpressure and disk spool or durable export. | Audit ring (`MaxRing=500`) is not production evidence. | MCP-T-044 | SRE/Sec / Eng | Durability tests | Spool/export under load | PR-8 |
| MCP-EVENT-002 | Loss of authentication/deny/configuration/high-risk events **MUST NOT** occur silently; otherwise the system **MUST** fail closed or enter a defined degraded mode and alert. | Critical-event durability. | MCP-T-044 | SRE/Sec / Eng | Saturation tests | Zero critical loss or fail-closed | PR-8 |
| MCP-EVENT-003 | Events **MUST NOT** store raw tokens, upstream secrets, private keys, complete raw arguments or complete raw outputs by default. | Privacy defaults. | MCP-T-028,023 | Sec/Privacy / Eng | Redaction tests | Only hashes/labels stored | PR-8 |
| MCP-EVENT-004 | Events **MUST** carry replay IDs / correlation IDs for reconstruction. | Investigation + dedup. | MCP-T-044,045 | Sec / Eng | Replay-id tests | IDs present + unique | PR-8 |
| MCP-EVENT-005 | Events **MUST** carry integrity fields (event ID, timestamp, DP ID, snapshot hash) and **SHOULD** be tamper-evident. | Non-repudiation. | MCP-T-045 | Sec / Eng | Integrity tests | Tamper detected | PR-8 |
| MCP-EVENT-006 | Event export **MUST** be authorized and tenant-separated. | Prevent cross-tenant export. | MCP-T-035,045 | Sec/Privacy / Eng | Export-authz tests | Cross-tenant export denied | PR-8 |

## MCP-CPDP / MCP-HA — Control Plane, Data Plane & HA

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-CPDP-001 | The CP→DP snapshot **MUST** carry configuration_epoch, config/policy/catalog/credential revisions, minimum_dp_version and content_hash+signature. | Repo snapshot lacks catalog/credential rev, min_dp_version, hash, signature. | MCP-T-047,050 | Eng / SRE | Snapshot-schema tests | Fields present + verified | PR-10 |
| MCP-CPDP-002 | The DP **MUST** validate signature, schema, caps, revisions and minimum version, and reject partial/corrupt snapshots whole. | No partial apply. | MCP-T-047 | Eng / SRE | Corrupt-snapshot tests | Whole-reject proven | PR-10 |
| MCP-CPDP-003 | Mixed-version CP/DP behavior **MUST** be defined; a DP below minimum_dp_version **MUST NOT** apply. | Prevent mixed-version misbehavior. | MCP-T-050 | Eng / SRE | Mixed-version tests | Version gate enforced | PR-10 |
| MCP-HA-001 | Stale Control-Plane publications **MUST** be fenced by epoch; the DP **MUST** keep the last valid snapshot and never depend on a CP round-trip per call. | Prior art: `halease`, `dpObserveEpoch`, fail-static. | MCP-T-047,048,049 | Eng / SRE | Stale-epoch tests | Stale rejected; last-good served | PR-10 |
| MCP-HA-002 | The DP **MUST** retain the previous snapshot and support atomic rollback within the rollback SLO target. | Recover without partial state. | MCP-T-048 | Eng / SRE | Rollback tests | Atomic rollback proven | PR-10 |

## MCP-CONNECT — On-prem connectivity

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-CONNECT-001 | An outbound connector **MUST** be customer-initiated with no unsolicited inbound port and mTLS connector identity. | No inbound exposure. | MCP-T-051 | Net/Sec / Eng | Connector tests | No inbound port; mTLS verified | PR-11 |
| MCP-CONNECT-002 | Connector certificates **MUST** rotate and reconnect **MUST** be bounded with a defined degraded mode. | Availability + key hygiene. | MCP-T-051 | Net/Sec / Eng | Rollover/failover tests | Rotation without outage | PR-11 |
| MCP-CONNECT-003 | A DMZ endpoint **MUST** enforce OAuth, WAF, Origin/Host validation, rate limits and internal mTLS, with explicit risk acceptance. | Hardened routable endpoint. | MCP-T-052 | Net/Sec / Eng | DMZ abuse tests | Controls enforced | PR-11 |
| MCP-CONNECT-004 | Every connector/DMZ session **MUST** be tenant-bound. | Prevent tenant-binding failure. | MCP-T-010,053 | Net/Sec / Eng | Tenant-binding tests | Session bound to tenant | PR-11 |

## MCP-MGMT — Management MCP

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-MGMT-001 | Management MCP **MUST** default to read-only; mutation **MUST NOT** be exposed until plan→validate→approve→apply controls exist. | Contain privilege. | MCP-T-034 | Sec / Eng | Mutation-negative tests | No mutation tool exposed | PR-9 |
| MCP-MGMT-002 | Management tools **MUST** be tenant-scoped and RBAC-gated per tool. | Least privilege. | MCP-T-034 | Sec / Eng | Tool-level RBAC tests | Unauthorized denied | PR-9 |
| MCP-MGMT-003 | Raw secret access, arbitrary command execution and unrestricted log/trace export **MUST NOT** be exposed as management tools. | Hard prohibitions. | MCP-T-034,035 | Sec / Eng | Prohibited-capability tests | Not exposed | PR-9 |
| MCP-MGMT-004 | Management output **MUST** be bounded and redacted. | Prevent overexposure. | MCP-T-035 | Sec/Privacy / Eng | Output-bound tests | Redacted, bounded | PR-9 |

## MCP-PRIVACY — Data residency & privacy

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-PRIVACY-001 | Only policy-approved content **MUST** cross the AI connectivity path; DLP/redaction/destination controls **MUST** run before egress. | Data-residency truth. | MCP-T-053,035 | Privacy/Legal / Eng | Egress-gate tests | DLP-before-egress proven | PR-11 |
| MCP-PRIVACY-002 | Tenant data **MUST** be isolated across all surfaces (events, exports, catalog). | Cross-tenant privacy. | MCP-T-009 | Privacy / Eng | Isolation tests | No cross-tenant read | PR-8 |
| MCP-PRIVACY-003 | Every deployment **MUST** have a documented data-flow diagram, retention model, privacy review and customer-owned allowlist. | Accountable data handling. | MCP-T-053 | Privacy/Legal | Review artifact | Signed privacy review | Prod-Qual |

## MCP-SUPPLY — Supply chain

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-SUPPLY-001 | Dependencies **MUST** be pinned and minimal; new runtime deps **SHOULD** be avoided (single-binary, zero-runtime-dep posture). | Footprint control. | — | Sec/Release | go.mod review + go-licenses | Pinned; license-clean | PR-1 |
| MCP-SUPPLY-002 | CI actions **MUST** be pinned to immutable SHAs with least-privilege tokens. | Build-chain integrity. Prior art present. | — | Release | Workflow review | SHA-pinned actions | PR-1 |
| MCP-SUPPLY-003 | Every artifact **MUST** ship a signed SBOM and signed provenance; consumers **MUST** verify before deploy. | Supply-chain assurance. Prior art: cosign+SLSA+syft. | — | Release | Signature/provenance verify | Verified SBOM+provenance | Prod-Qual |
| MCP-SUPPLY-004 | A vulnerability-remediation SLA, emergency-revoke and customer-notification procedure **MUST** exist. | Response readiness. | — | Sec/Release | Runbook review | Documented SLA + revoke | Prod-Qual |

## MCP-OPS — Operations & bounds

| ID | Statement | Rationale | Threats | Owner | Verification | Evidence | Gate |
|---|---|---|---|---|---|---|---|
| MCP-OPS-001 | MCP disabled **MUST** cause no measurable SWG regression. | Protect the existing product. | — | SRE / Eng | MCP-off benchmark | Overhead ≈ zero | PR-5 |
| MCP-OPS-002 | Connections, SSE streams, payloads, queues, concurrency and event buffers **MUST** be bounded with per-entity rate limits. | Resource-exhaustion defense. | MCP-T-040,042,043,044 | SRE / Eng | Load/soak/slowloris/queue tests | Bounds hold under load | PR-5 |
| MCP-OPS-003 | Dashboards, alerts and runbooks **MUST** exist for the runbook set in [`OPERATIONS-AND-SUPPORT.md`](OPERATIONS-AND-SUPPORT.md). | Operability. | MCP-T-044,051 | SRE | Ops review | Runbooks + alerts | Prod-Qual |
| MCP-OPS-004 | V1 coverage limits (stdio/localhost/direct-egress bypass) **MUST** be documented as known limitations. | Honest coverage. | MCP-T-054,055,056 | Product/Sec | Doc review | Documented limitation | PR-0 |

---

## Summary

**Total requirements: 75** across 15 namespaces (MCP-AUTH 8, ID 7, SERVER 3, TOOL 6, POLICY 7, CRED 6,
INSP 8, EVENT 6, CPDP 3, HA 2, CONNECT 4, MGMT 4, PRIVACY 3, SUPPLY 4, OPS 4). All `Status: Proposed`.
Every requirement maps to ≥1
threat ID (except supply-chain/ops posture requirements that are cross-cutting), a verification method, an
evidence expectation and a release gate. Uniqueness and threat-coverage are validated in
[`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md) and the Phase 5 consistency checks.
