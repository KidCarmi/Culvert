# MCP Abuse Cases

Attacker-centric cases. Each has: ID, attacker, preconditions, attack path, affected assets, expected
control, expected event, expected policy result, test requirement, owner, severity, closure condition.
IDs are `MCP-AC-###`. Threat/requirement IDs reference [`THREAT-MODEL.md`](THREAT-MODEL.md) and
[`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md). **Status: PR-0 design artifact (Proposed).**
Every case is a **negative test** the implementation must pass; none is claimed to pass today.

Asset IDs (A-*) are from [`THREAT-MODEL.md`](THREAT-MODEL.md) §1. Expected event = [`EVENT-MODEL.md`](EVENT-MODEL.md)
category + reason code from [`MCP-POLICY-MODEL.md`](MCP-POLICY-MODEL.md) §5. Closure = the case is closed
when its test passes with the expected control, event and policy result.

---

### MCP-AC-001 — Foreign-audience token accepted
- **Attacker:** external, holds a token minted for another service.
- **Preconditions:** valid-looking bearer token, wrong `aud`.
- **Path:** present token to `/mcp/gateway/{id}` (threat MCP-T-003).
- **Affected assets:** A-2, A-1.
- **Expected control:** MCP-AUTH-002 audience validation.
- **Expected event:** decision/DENY, `MCP.AUTH.WRONG_AUDIENCE`.
- **Expected policy result:** DENY (hard fail, blocked even in Shadow).
- **Test:** wrong-audience negative test.
- **Owner:** IAM/Sec. **Severity:** High. **Closure:** foreign `aud` always denied.

### MCP-AC-002 — Token replay
- **Attacker:** captured a valid access token.
- **Preconditions:** token not yet expired/revoked.
- **Path:** replay the same token on a second call (MCP-T-002).
- **Affected assets:** A-2.
- **Expected control:** MCP-AUTH-006 replay protection (**net-new; NOT VERIFIED as present** — VRC §6).
- **Expected event:** decision/DENY, `MCP.AUTH.REPLAY_SUSPECTED`.
- **Expected policy result:** DENY or step-up.
- **Test:** replay negative matrix.
- **Owner:** IAM/Sec. **Severity:** High. **Closure:** replayed token rejected/flagged.

### MCP-AC-003 — Token in query string
- **Attacker:** any caller.
- **Preconditions:** none.
- **Path:** place bearer token in the URL query (MCP-T-001).
- **Affected assets:** A-2.
- **Expected control:** MCP-AUTH-001 (no query-string tokens).
- **Expected event:** decision/DENY, `MCP.AUTH.INVALID_TOKEN`.
- **Expected policy result:** DENY.
- **Test:** query-string-token test. **Owner:** IAM/Sec. **Severity:** Medium. **Closure:** always rejected.

### MCP-AC-004 — Token passthrough to upstream
- **Attacker:** compromised agent.
- **Preconditions:** an allowed tool call.
- **Path:** attempt to have the client token forwarded to the upstream server (MCP-T-005).
- **Affected assets:** A-2, A-1.
- **Expected control:** MCP-AUTH-005 + MCP-CRED-001 (broker-selected credential only).
- **Expected event:** execution event shows a broker credential profile, not the client token.
- **Expected policy result:** upstream call uses scoped credential; client token never leaves Culvert.
- **Test:** upstream-capture test asserting no client token upstream.
- **Owner:** IAM/Sec. **Severity:** Critical. **Closure:** upstream never sees the client token.

### MCP-AC-005 — Agent receives a production credential
- **Attacker:** compromised/curious agent.
- **Preconditions:** allowed tool call requiring an upstream credential.
- **Path:** attempt to read the credential from the response/side channel (MCP-T-005,023).
- **Affected assets:** A-1.
- **Expected control:** MCP-CRED-001 (agent never holds secrets), MCP-EVENT-003 (never stored).
- **Expected event:** no secret in any event; `credential_profile` id only.
- **Expected policy result:** ALLOW with credential attached only to the upstream leg.
- **Test:** credential-flow + secret-scan tests.
- **Owner:** IAM/PAM. **Severity:** Critical. **Closure:** no path yields the secret to the agent.

### MCP-AC-006 — Over-privileged credential requested
- **Attacker:** agent requesting a broad-scope action.
- **Preconditions:** a credential profile broader than the action.
- **Path:** invoke a low-risk tool but trigger a tenant-admin credential (MCP-T-022,025).
- **Affected assets:** A-1.
- **Expected control:** MCP-CRED-002 scope match; policy may reject.
- **Expected event:** decision/DENY, `MCP.CREDENTIAL.SCOPE_MISMATCH` + security event.
- **Expected policy result:** DENY.
- **Test:** scope-mismatch test. **Owner:** IAM/PAM. **Severity:** High. **Closure:** over-broad denied.

### MCP-AC-007 — Unknown tool auto-allowed
- **Attacker:** malicious/updated server exposing a new tool.
- **Preconditions:** server registered; new tool appears.
- **Path:** call the new tool expecting default allow (MCP-T-017).
- **Affected assets:** A-4, A-9.
- **Expected control:** MCP-TOOL-006 quarantine; MCP-POLICY-001 default-deny.
- **Expected event:** decision/QUARANTINE, `MCP.TOOL.UNKNOWN`.
- **Expected policy result:** QUARANTINE (no execution).
- **Test:** unknown-tool test. **Owner:** Sec/Eng. **Severity:** Critical. **Closure:** never auto-allowed.

### MCP-AC-008 — Tool schema drift (rug pull)
- **Attacker:** approved server changes a tool's schema post-approval.
- **Preconditions:** tool previously approved.
- **Path:** add a field enabling admin/delete (MCP-T-013,015,019).
- **Affected assets:** A-4.
- **Expected control:** MCP-TOOL-003,004 drift classify → QUARANTINE.
- **Expected event:** decision/QUARANTINE, `MCP.TOOL.PRIVILEGE_EXPANSION`/`SCHEMA_CHANGED`.
- **Expected policy result:** QUARANTINE.
- **Test:** drift + privilege-expansion fixtures. **Owner:** Sec/Eng. **Severity:** High. **Closure:** expansion never auto-allowed.

### MCP-AC-009 — Server identity change
- **Attacker:** MITM / server re-binding.
- **Preconditions:** registered server; TLS identity changes.
- **Path:** present a new TLS identity for an approved endpoint (MCP-T-016).
- **Affected assets:** A-5.
- **Expected control:** MCP-SERVER-002,003 (disable until re-verified).
- **Expected event:** decision/DENY, `MCP.SERVER.IDENTITY_CHANGED`.
- **Expected policy result:** DENY + server disabled.
- **Test:** identity-change test. **Owner:** Sec/Eng. **Severity:** High. **Closure:** disabled until re-verified.

### MCP-AC-010 — SSRF via tool argument
- **Attacker:** agent supplying an internal URL.
- **Preconditions:** a tool that fetches URLs.
- **Path:** target a private/link-local/metadata address (MCP-T-036,030).
- **Affected assets:** A-9, internal network.
- **Expected control:** MCP-INSP-004 destination policy (reuses `internal/ssrf` `Control`).
- **Expected event:** decision/DENY, `MCP.INSPECTION.SSRF_BLOCKED`.
- **Expected policy result:** DENY (hard fail even in Shadow).
- **Test:** private-IP matrix. **Owner:** Sec/Eng. **Severity:** High. **Closure:** private targets denied.

### MCP-AC-011 — DNS rebinding
- **Attacker:** controls a domain that re-resolves after the policy check.
- **Preconditions:** a URL-fetching tool.
- **Path:** pass a hostname that resolves public at check, private at connect (MCP-T-037).
- **Affected assets:** internal network.
- **Expected control:** MCP-INSP-005 resolve→connect pinning.
- **Expected event:** decision/DENY, `MCP.INSPECTION.SSRF_BLOCKED`.
- **Expected policy result:** DENY.
- **Test:** DNS-rebinding lab. **Owner:** Sec/Eng. **Severity:** High. **Closure:** rebinding blocked.

### MCP-AC-012 — Inbound Origin/Host rebinding against the listener
- **Attacker:** malicious web page targeting a local MCP/SSE listener.
- **Preconditions:** a local/desktop MCP client (Model A).
- **Path:** browser-driven request with a forged Host/Origin (MCP-T-031,055).
- **Affected assets:** A-11, A-9.
- **Expected control:** MCP-INSP-008 inbound Origin/Host validation (**missing today**).
- **Expected event:** decision/DENY, `MCP.INSPECTION.ORIGIN_REJECTED`.
- **Expected policy result:** DENY.
- **Test:** inbound-rebinding test. **Owner:** Sec/Eng. **Severity:** High. **Closure:** bad Origin/Host rejected.

### MCP-AC-013 — Secret exfiltration through a tool
- **Attacker:** agent embedding a secret to send outward.
- **Preconditions:** a tool with an external destination.
- **Path:** place a synthetic secret (raw + encoded) in arguments/output (MCP-T-026,027,028).
- **Affected assets:** A-9, A-1.
- **Expected control:** MCP-INSP-003 DLP; MCP-EVENT-003 no-store.
- **Expected event:** decision/DENY or ALLOW_WITH_REDACTION, `MCP.INSPECTION.SECRET_FOUND`.
- **Expected policy result:** block or redact.
- **Test:** synthetic-secret corpus (encoded variants). **Owner:** Sec/Privacy. **Severity:** High. **Closure:** secrets blocked/redacted, never stored raw.

### MCP-AC-014 — Approval phishing / ambiguity
- **Attacker:** crafts a call whose approval dialog is misleading.
- **Preconditions:** a REQUIRE_APPROVAL tool.
- **Path:** obscure the true resource/impact to gain human approval (MCP-T-032,033).
- **Affected assets:** A-8.
- **Expected control:** MCP-POLICY-007 (dialog shows exact action/resource/impact/credential).
- **Expected event:** approval event with full context.
- **Expected policy result:** REQUIRE_APPROVAL with complete disclosure.
- **Test:** approval-UX completeness test. **Owner:** Product Sec. **Severity:** Medium. **Closure:** dialog always complete.

### MCP-AC-015 — SSE / queue exhaustion
- **Attacker:** floods streams/payloads/events.
- **Preconditions:** reachable listener.
- **Path:** open many slow SSE streams / oversized payloads (MCP-T-042,043,040,044).
- **Affected assets:** availability, A-6.
- **Expected control:** MCP-OPS-002 bounds; MCP-EVENT-002 critical-event durability.
- **Expected event:** `MCP.SYSTEM.EVENT_BACKPRESSURE` / `DEGRADED_MODE`; no critical-event loss.
- **Expected policy result:** bounded; fail-closed for critical classes.
- **Test:** load/soak/slowloris/queue-saturation. **Owner:** SRE/Sec. **Severity:** High/Critical. **Closure:** bounds hold; no critical loss.

### MCP-AC-016 — Critical decision-event loss
- **Attacker:** induces pipeline saturation to erase a deny event.
- **Preconditions:** high event volume.
- **Path:** saturate the pipeline during a high-risk deny (MCP-T-044,045).
- **Affected assets:** A-6.
- **Expected control:** MCP-EVENT-001,002 (mandatory local encrypted spool + backpressure; for critical write/destructive/config/credential classes: **fail closed AND** degraded mode + alert + loss counter).
- **Expected event:** the deny event survives; if durability is lost, the triggering critical operation fails closed **and** the system enters degraded mode + alerts.
- **Expected policy result:** no silent loss of auth/deny/config/high-risk events; degraded mode is not an alternative to fail-closed for critical classes.
- **Test:** event-durability-under-saturation. **Owner:** SRE/Sec. **Severity:** Critical. **Closure:** zero critical loss demonstrated.

### MCP-AC-017 — Stale / corrupt snapshot applied
- **Attacker:** fenced-out CP or corrupted transport.
- **Preconditions:** CP/DP sync active.
- **Path:** deliver a stale-epoch or partial/corrupt snapshot (MCP-T-047,050).
- **Affected assets:** A-7, A-3.
- **Expected control:** MCP-HA-001 epoch fence; MCP-CPDP-002 whole-reject.
- **Expected event:** `MCP.SYSTEM.SNAPSHOT_INVALID`.
- **Expected policy result:** reject; keep last valid snapshot.
- **Test:** stale-epoch + corrupt-snapshot + mixed-version. **Owner:** Eng/SRE. **Severity:** High. **Closure:** stale/corrupt rejected; last-good served.

### MCP-AC-018 — Management MCP mutation attempt
- **Attacker:** AI client on `/mcp/management`.
- **Preconditions:** read-only default posture.
- **Path:** invoke a mutation/prohibited capability (MCP-T-034,035).
- **Affected assets:** A-11, A-3.
- **Expected control:** MCP-MGMT-001,003 (no mutation/prohibited tools exposed).
- **Expected event:** `MCP.MANAGEMENT.MUTATION_NOT_APPROVED`/`TOOL_NOT_EXPOSED`.
- **Expected policy result:** DENY.
- **Test:** mutation-negative + prohibited-capability tests. **Owner:** Sec/Eng. **Severity:** Critical. **Closure:** no mutation reachable in V1.

### MCP-AC-019 — Cross-tenant access
- **Attacker:** tenant A principal targeting tenant B data.
- **Preconditions:** multi-tenant deployment.
- **Path:** manipulate tenant scope on a call/export (MCP-T-009,010).
- **Affected assets:** A-10, A-9.
- **Expected control:** MCP-ID-007 tenant binding; MCP-PRIVACY-002 isolation.
- **Expected event:** `MCP.MANAGEMENT.TENANT_SCOPE` / decision DENY.
- **Expected policy result:** DENY.
- **Test:** tenant-escape tests. **Owner:** IAM/Sec. **Severity:** Critical. **Closure:** no cross-tenant read.

### MCP-AC-020 — Connector / DMZ compromise
- **Attacker:** hijacks the outbound connector or DMZ endpoint.
- **Preconditions:** Model B/C deployment.
- **Path:** impersonate connector identity / replay tunnel / abuse DMZ (MCP-T-051,052).
- **Affected assets:** A-12, A-9.
- **Expected control:** MCP-CONNECT-001,002,003 + MCP-INSP-008.
- **Expected event:** connectivity event; DENY on identity/tenant failure.
- **Expected policy result:** DENY; tenant-bound.
- **Test:** impersonation + tunnel-replay + rollover + DMZ-abuse. **Owner:** Net/Sec. **Severity:** High. **Closure:** impersonation/replay blocked; tenant binding holds.

### MCP-AC-021 — Parser differential via duplicate JSON keys
- **Attacker:** client sending a crafted JSON-RPC envelope with duplicate/ambiguous keys.
- **Preconditions:** reachable protocol kernel (PR-1 harness or later listener).
- **Path:** send `{"method":"safe", ... ,"method":"dangerous"}` so the validator and a downstream reader disagree (MCP-T-058).
- **Affected assets:** A-3, A-9.
- **Expected control:** MCP-PROTO-001 strict single-parse decode; duplicate-key reject/canonicalize.
- **Expected event:** decision/DENY, `MCP.PROTOCOL.MALFORMED`.
- **Expected policy result:** DENY (message rejected before downstream stages).
- **Test:** parser-differential + duplicate-key fixtures. **Owner:** Sec/Eng. **Severity:** High. **Closure:** validated message == forwarded message, always.

### MCP-AC-022 — Response mis-correlation / request-ID confusion
- **Attacker:** client replaying/forging response or notification IDs.
- **Preconditions:** an active session with outstanding requests.
- **Path:** send a response whose `id` matches no outstanding request, or a duplicate/null/oversized id (MCP-T-060,071).
- **Affected assets:** A-9, A-3.
- **Expected control:** MCP-PROTO-003 bounded per-session ID table + type/edge validation.
- **Expected event:** decision/DENY, `MCP.PROTOCOL.ID_MISCORRELATION`.
- **Expected policy result:** rejected/ignored; no cross-correlation.
- **Test:** ID-correlation + int/string/null edge tests. **Owner:** Sec/Eng. **Severity:** High. **Closure:** uncorrelated responses rejected; table bounded.

### MCP-AC-023 — Depth/size bomb (parse-time exhaustion)
- **Attacker:** client sending a deeply nested / huge-field / long-string envelope.
- **Preconditions:** reachable protocol kernel.
- **Path:** send a payload exceeding depth/field/string/size bounds to exhaust CPU/memory at parse time (MCP-T-063,073).
- **Affected assets:** availability.
- **Expected control:** MCP-PROTO-006 structural limits + MCP-PROTO-008 per-session resource budget.
- **Expected event:** `MCP.PROTOCOL.LIMIT_EXCEEDED`.
- **Expected policy result:** rejected with bounded cleanup; session budget enforced.
- **Test:** limit + fuzz + resource-budget assertions. **Owner:** SRE/Sec. **Severity:** High. **Closure:** over-limit rejected; budget holds.

### MCP-AC-024 — Protocol-version downgrade
- **Attacker:** client negotiating an unknown or weaker protocol version.
- **Preconditions:** version negotiation at session establishment.
- **Path:** offer a version outside the allowlist expecting best-effort/downgrade acceptance (MCP-T-066,067).
- **Affected assets:** A-3, security invariants.
- **Expected control:** MCP-PROTO-010 version allowlist; reject unknown; no silent downgrade.
- **Expected event:** decision/DENY, `MCP.PROTOCOL.VERSION_REJECTED`.
- **Expected policy result:** explicit negotiation failure (not a narrowed-security connection).
- **Test:** version-conformance/downgrade fixtures (**D-1-gated**). **Owner:** Sec/Eng. **Severity:** High. **Closure:** unknown/downgrade rejected; only allowlisted versions accepted.

### MCP-AC-025 — Version-adapter differential
- **Attacker:** sends equivalent inputs across two supported versions to obtain divergent normalized messages.
- **Preconditions:** ≥2 versions in the allowlist with adapters.
- **Path:** exploit an adapter that normalizes the same intent differently so downstream policy differs by version (MCP-T-068).
- **Affected assets:** A-3.
- **Expected control:** MCP-PROTO-011 adapter equivalence to one internal representation.
- **Expected event:** n/a (equivalence proven in test); divergence → `MCP.PROTOCOL.ADAPTER_DIVERGENCE`.
- **Expected policy result:** identical normalized message regardless of version.
- **Test:** adapter-equivalence fixtures (**D-1-gated**). **Owner:** Sec/Eng. **Severity:** High. **Closure:** no cross-adapter differential.

### MCP-AC-026 — Mid-session identity rebind / protocol-state confusion
- **Attacker:** attempts to re-bind a session to a different identity mid-flight or drive out-of-order lifecycle.
- **Preconditions:** an established session.
- **Path:** inject a lifecycle/auth message to swap the bound principal or reorder establishment (MCP-T-069).
- **Affected assets:** A-2, A-10.
- **Expected control:** split by layer — **MCP-ID-008 (PR-3)** owns *resolved-identity binding: one identity per session, no mid-flight rebind* (PR-1 cannot provide it: `MCP-PROTO-012`'s session context is deliberately opaque and identity-free); **MCP-PROTO-012 (PR-1)** owns only *lifecycle ordering / no out-of-order establishment* on that opaque context.
- **Expected event:** decision/DENY — `MCP.IDENTITY.REBIND_DENIED` (identity rebind, PR-3) or `MCP.PROTOCOL.STATE_VIOLATION` (out-of-order lifecycle, PR-1).
- **Expected policy result:** DENY; session not rebound.
- **Test:** identity-binding + no-rebind + cross-session tests (MCP-ID-008, PR-3) for the rebind path; protocol-lifecycle + reconnect tests (MCP-PROTO-012, PR-1) for ordering. **Owner:** IAM/Eng (identity) + Sec/Eng (lifecycle). **Severity:** High. **Closure:** one resolved identity for the session lifetime (PR-3); valid lifecycle ordering (PR-1).

### MCP-AC-027 — Hostile input crash / panic
- **Attacker:** fuzzing the kernel to trigger a panic or uncontrolled allocation.
- **Preconditions:** reachable protocol kernel.
- **Path:** feed adversarial bytes to parser/framing/adapter/cancellation paths (MCP-T-074).
- **Affected assets:** availability.
- **Expected control:** MCP-PROTO-009 crash-resistance; MCP-PROTO-013 bounded error + cleanup.
- **Expected event:** `MCP.PROTOCOL.MALFORMED` (bounded error), never a crash.
- **Expected policy result:** bounded error; process stays up.
- **Test:** fuzz (panic/crash detection) + race. **Owner:** Sec/Eng. **Severity:** High. **Closure:** no panic/crash on the corpus.

---

## Coverage

27 abuse cases spanning all Critical/High threat classes, including the seven PR-1 protocol-kernel cases
(MCP-AC-021..027, added by the remediation — `PR1-READINESS-REMEDIATION.md`, finding H-1). Each maps to
≥1 requirement and a named test; the consolidated chain is in
[`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md). Residual-only cases
(stdio/localhost/direct-egress bypass) are covered as documented limitations (MCP-OPS-004) rather than
abuse cases, per [`THREAT-MODEL.md`](THREAT-MODEL.md) §12 R-1.
