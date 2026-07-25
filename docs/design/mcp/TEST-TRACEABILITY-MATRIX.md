# MCP Test Traceability Matrix

`Threat → Security requirement → Control → Test → Evidence → Owner → Gate` for every Critical/High threat
and the full test taxonomy. **Status: PR-0 design artifact (Proposed).** No test below exists today; each
is a build target. Per [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md), the MCP-specific
suites (malicious-server, OAuth-negative, DNS-rebinding lab, inbound Origin/Host, SSE-exhaustion,
mixed-version/stale-epoch/corrupt-snapshot, MCP-off overhead) are **missing**; the reusable harnesses
(race, gosec, govulncheck, gitleaks, benchgate, fuzz-nightly) exist ([`CI-GATES.md`](CI-GATES.md)).

> Test-baseline caveat: **Low for the read-only Phase 1 investigation, but the current repository test
> baseline remains unverified in this session** — no build or test was executed while authoring PR-0. Per
> [`ADR-0024` PR-1 entry gate](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md), the repository
> build/test baseline **MUST** be run and recorded before any PR-1 code change begins.
>
> **ID provenance (accurate history):**
> - **Decision closure (D-2/D-5/D-8/D-9/D-13, 2026-07-24)** reframed the replay row (MCP-T-002 / MCP-AUTH-006
>   per [`ADR-0024 §D-2`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md)) and made the
>   connectivity/events/dual-surface rows decision-backed — it **did not renumber or remove** any
>   previously existing ID.
> - **PR-1 remediation** ADDED threats **MCP-T-057..074** (18) and the requirement family
>   **MCP-PROTO-001..014** (14 — `MCP-PROTO-014` came in the follow-up).
> - **Follow-up remediation** ADDED **MCP-INSP-009** (PR-5 listener) and **MCP-ID-008** (PR-3 identity), and
>   `MCP-PROTO-014` (UTF-8/protocol-token handling).
> - **Independently recomputed totals:** **74 threats**; **91 requirements** (MCP-PROTO **14**, MCP-INSP
>   **9**, MCP-ID **8**; the other families unchanged). No ID was removed; no duplicates/orphans.

IDs: threats `MCP-T-*` ([`THREAT-MODEL.md`](THREAT-MODEL.md)); requirements `MCP-*-*`
([`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md)); abuse cases `MCP-AC-*` ([`ABUSE-CASES.md`](ABUSE-CASES.md)).
Gate = slice/CI gate that must be green.

---

## 1. Core traceability (Critical/High threats)

| Threat | Requirement | Control | Test (type) | Evidence | Owner | Gate |
|---|---|---|---|---|---|---|
| MCP-T-001 token theft | MCP-AUTH-001,004 | Token validation + short TTL | Auth negative matrix (unit/integration) | Rejections logged | IAM/Sec | PR-3 |
| MCP-T-002 token replay | MCP-AUTH-006 | Sender-constraint (mTLS/DPoP-proof) + short-TTL/aud/resource + correlation/rate-limit/anomaly — **not** access-token one-time-use ([`ADR-0024 §D-2`](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md)) | DPoP-proof replay + anomaly/rate-limit matrix (integration) | Replayed DPoP proof rejected; sender-constraint enforced on high-risk profiles | IAM/Sec | PR-3 |
| MCP-T-003 wrong audience | MCP-AUTH-002 | Audience validation | Wrong-audience (negative) | Foreign `aud` denied | IAM/Sec | PR-3 |
| MCP-T-004 wrong resource | MCP-AUTH-003 | RFC 8707 resource binding | Wrong-resource (negative) | Mismatch denied | IAM/Sec | PR-3 |
| MCP-T-005 token passthrough | MCP-AUTH-005, MCP-CRED-001 | No passthrough + broker | Upstream-capture (integration) | No client token upstream | IAM/Sec | PR-4 |
| MCP-T-006 agent impersonation | MCP-ID-002 | Agent attribution | Attribution (unit) | Agent fields present | IAM/Sec | PR-3 |
| MCP-T-007 workload impersonation | MCP-ID-003 | Workload attestation | Workload-auth (integration) | Spoof rejected | IAM/Sec | PR-3 |
| MCP-T-008 cross-user session | MCP-AUTH-007, MCP-ID-006 | Session binding | Cross-session (integration) | No identity bleed | IAM/Sec | PR-3 |
| MCP-T-009, MCP-T-010 cross-tenant / tenant-binding failure | MCP-ID-007, MCP-PRIVACY-002 | Tenant binding + isolation | Tenant-escape (integration) | Cross-tenant denied | IAM/Sec | PR-3 |
| MCP-T-011 tool poisoning | MCP-TOOL-001,004 | Fingerprint + quarantine | Malicious-server fixture | Poisoned tool quarantined | Sec/Eng | PR-2 |
| MCP-T-012 tool shadowing | MCP-TOOL-002 | Disambiguate by fingerprint | Shadowing (unit) | Collision flagged | Sec/Eng | PR-2 |
| MCP-T-013/014 schema/desc drift | MCP-TOOL-003 | Drift classification | Canonicalization + drift fixtures | Correct class | Sec/Eng | PR-2 |
| MCP-T-015 rug pull | MCP-TOOL-004 | Quarantine on expansion | Rug-pull fixture | No auto-allow | Sec/Eng | PR-6 |
| MCP-T-016 server identity change | MCP-SERVER-003 | Disable until re-verified | Identity-change (integration) | Auto-disable | Sec/Eng | PR-2 |
| MCP-T-017 unknown-tool auto-allow | MCP-TOOL-006, MCP-POLICY-001 | Quarantine + default-deny | Unknown-tool (integration) | No auto-allow | Sec/Eng | PR-6 |
| MCP-T-018 policy bypass | MCP-POLICY-001,002 | Default-deny + no-I/O | Determinism + property tests | Pure eval proof | Sec/Eng | PR-6 |
| MCP-T-019 privilege expansion | MCP-TOOL-004, MCP-POLICY-003 | Quarantine + reason code | Privilege-expansion fixture | Quarantined | Sec/Eng | PR-6 |
| MCP-T-046 confused deputy | MCP-POLICY-004 | Credential after decision | Ordering (unit) | No cred pre-decision | Sec/Eng | PR-6 |
| MCP-T-022 over-privileged cred | MCP-CRED-002 | Scope match | Scope-mismatch (integration) | Over-broad denied | IAM/PAM | PR-4 |
| MCP-T-025 scope mismatch not rejected | MCP-CRED-002 | Scope match → deny + security event | Scope-mismatch (integration) | Mismatch denied + security event | IAM/PAM | PR-4 |
| MCP-T-023 credential leakage | MCP-CRED-004, MCP-EVENT-003 | No secret in logs/events | Secret-scan + event-redaction | gitleaks clean | IAM/PAM | PR-4 |
| MCP-T-024 cache compromise | MCP-CRED-005,006 | Bounded encrypted cache + fail-closed | Broker-failure (integration) | Fail-closed proven | IAM/PAM | PR-4 |
| MCP-T-026, MCP-T-027 exfiltration (input/output) | MCP-INSP-001,002,003 | Bounds + DLP | Synthetic-secret corpus | Blocked/redacted | Sec/Privacy | PR-7 |
| MCP-T-028 secret in events | MCP-EVENT-003, MCP-CRED-004 | No-store + redaction | Event secret-scan | No secret stored | Sec/Privacy | PR-8 |
| MCP-T-036 SSRF | MCP-INSP-004 | Destination policy (ssrf Control) | Private-IP matrix | Private denied | Sec/Eng | PR-7 |
| MCP-T-030 private-network access | MCP-INSP-004,005 | Destination policy + DNS pin | Private-IP matrix + DNS-rebinding lab | Private/rebind denied | Sec/Eng | PR-7 |
| MCP-T-037 DNS rebinding | MCP-INSP-005 | resolve→connect pin | DNS-rebinding lab | Rebinding blocked | Sec/Eng | PR-7 |
| MCP-T-041 redirect abuse | MCP-INSP-006 | Redirect cap + re-check | Redirect-chain | Hop cap enforced | Sec/Eng | PR-7 |
| MCP-T-031 inbound rebinding (validation primitive) | MCP-INSP-008 | Pure Origin/Host accept/reject decision + fail-closed empty allowlist | Primitive unit tests (no socket) | Bad Origin/Host rejected; empty allowlist fails closed | Sec/Eng | PR-1 |
| MCP-T-031 inbound rebinding (listener E2E) | MCP-INSP-009 | Listener binds configured interfaces + host allowlist at accept + invokes the primitive | E2E rebinding against a live listener | No default public bind; E2E rebinding rejected | SRE/Eng | PR-5 |
| MCP-T-058 parser differential | MCP-PROTO-001 | Strict single-parse decode; duplicate-key reject/canonical | Parser-differential + duplicate-key + malformed corpus | Validated == forwarded message | Sec/Eng | PR-1 |
| MCP-T-060 request-ID mis-correlation | MCP-PROTO-003 | Bounded per-session ID table + type/edge validation | ID-correlation + int/string/null edge tests | Mis-correlated response rejected; table bounded | Sec/Eng | PR-1 |
| MCP-T-063 parse-time exhaustion (size/depth/field/string) | MCP-PROTO-006, MCP-PROTO-008 | Structural bounds + per-session resource budget | Limit + fuzz + resource-budget assertions | Oversized/deep rejected; budget holds | SRE/Sec | PR-1 |
| MCP-T-066 version-negotiation confusion | MCP-PROTO-010 | Version allowlist; reject unknown; record negotiated version | Version-conformance fixtures (**D-1-gated**) | Unknown version rejected; version recorded | Sec/Eng | PR-1 (fixtures gated on D-1) |
| MCP-T-067 protocol downgrade | MCP-PROTO-010 | No silent downgrade; explicit negotiation failure | Downgrade fixtures (**D-1-gated**) | Weaker-semantics negotiation rejected | Sec/Eng | PR-1 (fixtures gated on D-1) |
| MCP-T-068 version-adapter differential | MCP-PROTO-011 | Adapter equivalence to one internal representation | Adapter-equivalence fixtures (**D-1-gated**) | No cross-adapter differential | Sec/Eng | PR-1 (fixtures gated on D-1) |
| MCP-T-069 protocol-state confusion (lifecycle) | MCP-PROTO-012 | Immutable opaque session context; lifecycle validated; cancel/reconnect handled (no identity) | Protocol-lifecycle + cancellation-race + reconnect tests | Opaque context; races handled; reconnect re-validated | Sec/Eng | PR-1 |
| MCP-T-069 identity rebind | MCP-ID-008 | One resolved identity bound per session; mid-session rebind denied | Identity-binding + no-rebind + cross-session tests | No mid-session identity rebind | IAM/Eng | PR-3 |
| MCP-T-074 hostile-input crash/panic | MCP-PROTO-009, MCP-PROTO-013 | Crash-resistant parse/adapter; bounded error + cleanup | Fuzz (panic/crash detection) + race | No panic/crash on corpus; bounded error | Sec/Eng | PR-1 |
| MCP-T-057/065 UTF-8 / protocol-token handling | MCP-PROTO-014 | Reject invalid UTF-8; **exact** method-token comparison; reject non-ASCII method names (pending D-1); opaque identifiers not globally normalized by the kernel | Invalid-UTF-8 rejection + exact-comparison + non-ASCII-method-rejection (D-1-gated) + no-global-normalization fixtures | Invalid UTF-8 rejected; method tokens compared exactly; non-ASCII methods rejected; opaque IDs untouched by kernel normalization | Sec/Eng | PR-1 |

### 1a. Requirement-specific coverage (completeness — do not rely on the "Unit | all" row)

These requirements were previously reachable only via family/range shorthand or the catch-all "Unit | all"
row; the follow-up remediation (finding 6) gives each an explicit Threat → Requirement → Test → Evidence →
Owner → Gate chain.

| Threat | Requirement | Control | Test (type) | Evidence | Owner | Gate |
|---|---|---|---|---|---|---|
| MCP-T-034 mgmt escalation (auth plane separation) | MCP-AUTH-008 | Separate OAuth client registrations + disjoint scopes for Mgmt vs Gateway | Config/scope review + separate-client negative tests | Distinct clients/scopes enforced; cross-plane token rejected | IAM/Sec | PR-3 |
| MCP-T-044/045 event reconstruction | MCP-EVENT-004 | Replay/correlation IDs on every event | Replay-id tests (uniqueness + correlation) | `event_id`/`correlation_id` present + unique | Sec/Eng | PR-8 |
| MCP-T-035/045 cross-tenant export | MCP-EVENT-006 | Export authorization + tenant separation | Export-authz + tenant-separation tests | Cross-tenant export denied; export RBAC-gated | Sec/Privacy | PR-8 |
| MCP-T-010 connector/DMZ tenant binding | MCP-CONNECT-004 | Tenant-bound connector/DMZ session | Tenant-binding tests | Session bound to tenant; cross-tenant denied | Net/Sec | PR-C (connector) / Future DMZ gate |
| MCP-T-020 malicious server | MCP-SERVER-001,002 | Allowlist + TLS pin | Non-compliant/malicious fixtures | Unregistered denied | Sec/Eng | PR-2 |
| MCP-T-021 compromised server | MCP-SERVER-003, MCP-INSP-002 | Drift + output inspection | Compromised-server fixture | Contained | Sec/Eng | PR-7 |
| MCP-T-029 destructive calls | MCP-POLICY-006 | Approval/deny default | Destructive-tool (integration) | Approval enforced | Sec/Eng | PR-6 |
| MCP-T-038/039 injection/elicitation | MCP-INSP-007 | Label/report | Injection corpus | Labels emitted | Sec/Eng | PR-7 |
| MCP-T-040 oversized payloads | MCP-PROTO-006 (parse-time, PR-1), MCP-OPS-002 (runtime under load, PR-5) | Structural bounds at the kernel + listener bounds under load | Fuzz + limit tests (PR-1); load/soak (PR-5) | Oversized rejected at parse; bounds hold under load | SRE/Sec | PR-1 (parse) / PR-5 (runtime) |
| MCP-T-042/043 SSE exhaustion/slow | MCP-OPS-002 | Stream bounds + rate limit | Load/soak/slowloris | Bounds hold | SRE/Sec | PR-5 |
| MCP-T-044 queue saturation/loss | MCP-EVENT-001,002 | Backpressure + fail-closed | Queue-saturation + durability | Zero critical loss | SRE/Sec | PR-8 |
| MCP-T-045 audit tampering | MCP-EVENT-005 | Integrity fields | Tamper-evidence (unit) | Tamper detected | Sec | PR-8 |
| MCP-T-047 stale snapshot | MCP-HA-001, MCP-CPDP-002 | Epoch fence + whole-reject | Stale-epoch + corrupt-snapshot | Rejected; last-good served | Eng/SRE | PR-10 |
| MCP-T-048 split-brain | MCP-HA-001,002 | Fence + rollback | HA/failover tests | No split-brain | Eng/SRE | PR-10 |
| MCP-T-049 stale CP publication | MCP-HA-001 | Epoch fence rejects fenced-out CP | Stale-epoch + no-live-holder tests | Stale CP rejected; last-good served | Eng/SRE | PR-10 |
| MCP-T-050 mixed-version | MCP-CPDP-003 | minimum_dp_version gate | Mixed-version tests | Version gate holds | Eng/SRE | PR-10 |
| MCP-T-034 mgmt escalation | MCP-MGMT-001,002,003 | Read-only + tool RBAC | Mutation-negative + tenant-escape | No mutation reachable | Sec/Eng | PR-9 |
| MCP-T-035 mgmt overexposure | MCP-MGMT-004, MCP-PRIVACY-001 | Bounded redacted output | Output-bound tests | Redacted | Sec/Privacy | PR-9 |
| MCP-T-051 connector compromise | MCP-CONNECT-001,002 | mTLS identity + rotation | Impersonation + rollover + replay | Impersonation blocked | Net/Sec | **PR-C** (post-V1 connector slice) |
| MCP-T-052 DMZ abuse | MCP-CONNECT-003, MCP-INSP-009 | OAuth/WAF/Origin/rate + listener-side host allowlist | DMZ-abuse tests | Controls enforced | Net/Sec | **Future DMZ Architecture & Production-Readiness Gate** |
| MCP-T-010 tenant-binding failure (connector/DMZ session) | MCP-CONNECT-004, MCP-ID-007 | Tenant-bound connector/DMZ session | Tenant-binding tests | Session bound to tenant; cross-tenant denied | Net/Sec | **PR-C** (connector) / Future DMZ gate |
| MCP-T-053 data residency | MCP-PRIVACY-001,003 | DLP-before-egress | Egress-gate tests | DLP proven | Privacy/Legal | PR-11 |
| MCP-T-054 stdio bypass | MCP-OPS-004 (Origin/Host does **not** control stdio) | Documented V1 limitation; endpoint-bridge roadmap (D-7) | Doc review | Limitation documented | Product/Sec | PR-0 (doc) / D-7 roadmap |
| MCP-T-055 localhost bypass | MCP-OPS-004 + MCP-INSP-008 (primitive, PR-1) + MCP-INSP-009 (listener, PR-5) where HTTP-listener traffic is involved | Documented limit + Origin/Host validation on the local HTTP listener | Doc review + primitive tests (PR-1) + listener E2E rebinding (PR-5) | Limitation documented; bad Origin/Host rejected | Product/Sec | PR-0 (doc) / PR-1 (primitive) / PR-5 (listener) |
| MCP-T-056 direct-egress bypass | MCP-OPS-004 (in-product limitation); a customer network-egress policy is a **compensating external control, not an MCP requirement ID** (Origin/Host does **not** control arbitrary direct egress) | Documented V1 limitation | Doc review | Limitation documented | Net/Sec | PR-0 (doc) |

## 2. Full test taxonomy → requirement coverage

| Test category | Primary requirements | Present today? | Gate |
|---|---|---|---|
| Unit | (harness only — **NOT** requirement-specific proof; see §1 and §1a for per-requirement chains) | Harness exists (`go test -race`) | PR-1+ |
| Integration | all runtime | Harness exists | PR-1+ |
| Compatibility (protocol conformance) | MCP-PROTO-010,011 | **Missing** — `[EXT]`/`[D-1]` version fixtures; content gated on D-1 closure; must become a **blocking PR-1** gate ([`CI-GATES.md`](CI-GATES.md)) | PR-1 (D-1-gated) |
| Malformed JSON-RPC / parser-differential / classification / batch | MCP-PROTO-001,002,003,004,005,007,013 | **Missing** — malformed + duplicate-key + framing + batch-policy corpus | PR-1 |
| Protocol structural limits (size/depth/field/string/number) | MCP-PROTO-006,007,008 | **Missing** — limit + resource-budget assertions | PR-1 |
| Version negotiation / downgrade / adapter equivalence | MCP-PROTO-010,011 | **Missing** — D-1-gated fixtures | PR-1 (D-1-gated) |
| Protocol-state / cancellation / duplicate-completion | MCP-PROTO-012 | **Missing** — protocol-state machine tests | PR-1 |
| Malicious MCP server fixtures | MCP-SERVER-*, MCP-TOOL-* | **Missing** | PR-2 |
| Non-compliant server fixtures | MCP-SERVER-*, protocol | **Missing** | PR-2 |
| Fuzzing (protocol kernel: parser/framing/adapter/cancellation) | MCP-PROTO-009 (+006,008) | `fuzz-nightly.yml` exists but is **advisory/nightly — not a merge gate**; a **new bounded blocking PR-1 fuzz gate** is required ([`CI-GATES.md`](CI-GATES.md)) | PR-1 |
| Race | concurrency invariants | `-race` gate exists | PR-1+ |
| Property tests | MCP-POLICY-002 (determinism) | **Missing** | PR-6 |
| Authentication negative matrix | MCP-AUTH-001..004 | **Missing** | PR-3 |
| Authorization negative matrix | MCP-POLICY-*, MCP-MGMT-* | **Missing** | PR-6/PR-9 |
| Replay | MCP-AUTH-006 | **Missing** | PR-3 |
| Wrong audience / wrong resource | MCP-AUTH-002,003 | **Missing** | PR-3 |
| SSRF (private-IP matrix) | MCP-INSP-004 | ssrf unit tests exist; MCP matrix **missing** | PR-7 |
| DNS rebinding lab | MCP-INSP-005 | **Missing** | PR-7 |
| Redirect chains | MCP-INSP-006 | per-client tests exist; shared MCP **missing** | PR-7 |
| Origin/Host validation primitive (no listener) | MCP-INSP-008 | **Missing** | PR-1 |
| Listener bind + host-allowlist + E2E rebinding enforcement | MCP-INSP-009 | **Missing** | PR-5 |
| Tool canonicalization | MCP-TOOL-001 | **Missing** | PR-2 |
| Tool drift / privilege expansion | MCP-TOOL-003,004 | **Missing** | PR-2/PR-6 |
| Streaming / cancellation / reconnect | MCP-PROTO-012 (protocol-state, PR-1); MCP-OPS-002 (stream bounds under load, PR-5) | **Missing** | PR-1 (state) / PR-5 (load) |
| Load / soak | MCP-OPS-002 | nightly load harness exists (not gate) | PR-5 |
| Slow clients / queue saturation | MCP-OPS-002, MCP-EVENT-001 | **Missing** | PR-5/PR-8 |
| Event durability | MCP-EVENT-001,002 | **Missing** | PR-8 |
| Restart / failover | MCP-HA-001,002 | HA harness (proxy) exists; MCP **missing** | PR-10 |
| Mixed versions / stale epoch / corrupt snapshot | MCP-CPDP-002,003, MCP-HA-001 | **Missing** for MCP | PR-10 |
| Rollback | MCP-HA-002 | configver tests exist; MCP **missing** | PR-10 |
| SWG regression | MCP-OPS-001 | benchgate harness exists | PR-5 |
| MCP-disabled overhead | MCP-OPS-001 | **Missing** (specific assertion) | PR-5 |
| Secret logging | MCP-CRED-004, MCP-EVENT-003 | gitleaks exists; event-scan **missing** | PR-4/PR-8 |
| Privacy | MCP-PRIVACY-001,002,003 | **Missing** | PR-8/PR-11 |
| Supply-chain verification | MCP-SUPPLY-003 | cosign/SLSA/SBOM exist | Prod-Qual |

## 3. Coverage assertions (validated in Phase 5)

- Every Critical/High threat in [`THREAT-MODEL.md`](THREAT-MODEL.md) §11 appears in §1 with a requirement,
  test, evidence expectation, owner and gate.
- Every requirement in [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) is reachable from a §1 or §2
  row (test coverage).
- Every abuse case `MCP-AC-*` maps to a §1 row via its threat/requirement IDs.
- Missing suites are labeled **Missing** here and in [`CI-GATES.md`](CI-GATES.md); none is claimed present.
