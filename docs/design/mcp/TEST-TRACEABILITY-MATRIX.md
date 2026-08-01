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
> - **First PR-1 readiness remediation** allocated threats **MCP-T-057..074** (18) and the requirement
>   family **MCP-PROTO-001..013** (13).
> - **Follow-up remediation** allocated **MCP-PROTO-014** (UTF-8/protocol-token handling), **MCP-INSP-009**
>   (PR-5 listener), and **MCP-ID-008** (PR-3 identity) — three new requirement IDs. *(`MCP-PROTO-014` is
>   counted here once, in the follow-up; it is not part of the first-remediation `001..013` block.)*
> - **[#927](https://github.com/KidCarmi/Culvert/issues/927) remediation** allocated **MCP-CFG-001**
>   (config-surface anti-drift governance) — one new requirement ID, no new threat.
> - **[#926](https://github.com/KidCarmi/Culvert/issues/926) remediation** allocated **MCP-T-075**
>   (unauthenticated denial-event flood → durability-lockout DoS) and the requirement IDs
>   **MCP-EVENT-007** (isolated denial lane) and **MCP-OPS-005** (restart-persistent, bounded, scoped
>   degraded-state machine) — one new threat, two new requirements.
> - **Final totals (independently recomputed against the live registries, not carried forward):**
>   **78 threats**; **97 requirements** (MCP-PROTO **17**, MCP-INSP **9**, MCP-ID **8**, MCP-EVENT **7**,
>   MCP-OPS **5**, MCP-CFG **1**; the other families unchanged). No ID was removed; no duplicates; no
>   orphans. The RPR-1 remediation for [#925](https://github.com/KidCarmi/Culvert/issues/925) and
>   [#928](https://github.com/KidCarmi/Culvert/issues/928) added `MCP-PROTO-015`/`MCP-PROTO-016` (two
>   requirements) and `MCP-T-076`/`MCP-T-077` (two threats). The RPR-4 remediation for
>   [#929](https://github.com/KidCarmi/Culvert/issues/929) added `MCP-PROTO-017` (legacy-transport
>   exclusion + no-pre-negotiation-held-stream) and `MCP-T-078` (security-rejection-path legacy fallback +
>   retained unauthenticated stream) — one requirement, one threat. *(The previously published "**91 requirements**" was stale: it predated `MCP-CFG-001`, which
>   #927 added without updating this line. Recounting from the registry rather than incrementing the
>   published figure is what surfaced that — the same class of drift these matrices exist to catch.)*

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
| MCP-T-004 wrong resource | MCP-AUTH-003 | RFC 8707 `resource` requested; resulting `aud`/introspection audience validated | Wrong-resource (negative) over JWT **and** opaque tokens; `aud`-less token denied on **every** operation class (read/low-risk as well as write/high-risk); outbound `resource` parameter asserted | Mismatch **or absent audience** denied on all operation classes | IAM/Sec | PR-3 |
| MCP-T-005 token passthrough | MCP-AUTH-005, MCP-CRED-001 | No passthrough + broker | Upstream-capture (integration) | No client token upstream | IAM/Sec | PR-4 |
| MCP-T-006 agent impersonation | MCP-ID-002 | Agent attribution | Attribution (unit) | Agent fields present | IAM/Sec | PR-3 |
| MCP-T-007 workload impersonation | MCP-ID-003 | Workload attestation | Workload-auth (integration) | Spoof rejected | IAM/Sec | PR-3 |
| MCP-T-008 cross-user session | **MCP-ID-008**, MCP-AUTH-007, MCP-ID-006 | One resolved identity bound per session; **no mid-flight rebind** (MCP-ID-008) — `MCP-ID-006` assurance/step-up is contributory, not the enforcing control | Cross-session (integration) **+ identity-rebind negative test** (mid-session identity change denied) | No identity bleed; rebind attempt denied | IAM/Sec | PR-3 |
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
| MCP-T-031 inbound rebinding (listener E2E) | MCP-INSP-009 | Listener binds configured interfaces at accept; host allowlist evaluated and the primitive invoked **per request / per H2 stream after header parsing, never once per connection**; **each capability's allowlist is independent** | E2E rebinding against a live listener, **per listener**, plus **cross-capability allowlist isolation** (a host approved on one listener is still rejected by the other), plus **per-request revalidation over a reused connection** (keep-alive and H2 multiplexing) | No default public bind; E2E rebinding rejected | SRE/Eng | PR-5 |
| MCP-T-058 parser differential | MCP-PROTO-001 | Strict single-parse decode; duplicate-key reject/canonical | Parser-differential + duplicate-key + malformed corpus | Validated == forwarded message | Sec/Eng | PR-1 |
| MCP-T-060 request-ID mis-correlation | MCP-PROTO-003 | Bounded per-session ID table + type/edge validation; **correlation is response-only** (notifications carry no top-level `id`) | ID-correlation + int/string/null edge tests, **plus: a valid no-`id` notification is accepted, a notification bearing an `id` is rejected, and a cancellation naming another session's request `id` in params does not take effect** | Mis-correlated response rejected; table bounded | Sec/Eng | PR-1 |
| MCP-T-063 parse-time exhaustion (size/depth/field/string) | MCP-PROTO-006, MCP-PROTO-008 | Structural bounds + per-session resource budget | Limit + fuzz + resource-budget assertions, **plus cross-capability limit isolation** (change one capability's bound, assert the paired capability's is unchanged) | Oversized/deep rejected; budget holds; **a Management change never widens the Gateway bound (and vice versa)** | SRE/Sec | PR-1 |
| MCP-T-066 version-negotiation confusion | MCP-PROTO-010 | Version allowlist; reject unknown; record negotiated version | Version-conformance fixtures (**D-1-gated**) | Unknown version rejected; version recorded | Sec/Eng | PR-1 (fixtures gated on D-1) |
| MCP-T-067 protocol downgrade | MCP-PROTO-010 | No silent downgrade; explicit negotiation failure | Downgrade fixtures (**D-1-gated**) | Weaker-semantics negotiation rejected | Sec/Eng | PR-1 (fixtures gated on D-1) |
| MCP-T-068 version-adapter differential | MCP-PROTO-011 | Adapter equivalence to one internal representation | Adapter-equivalence fixtures (**D-1-gated**) | No cross-adapter differential | Sec/Eng | PR-1 (fixtures gated on D-1) |
| MCP-T-069 protocol-state confusion (lifecycle) | MCP-PROTO-012 | Immutable opaque session context; lifecycle validated; cancel/reconnect handled (no identity) | Protocol-lifecycle + cancellation-race + reconnect tests | Opaque context; races handled; reconnect re-validated | Sec/Eng | PR-1 |
| MCP-T-069 identity rebind | MCP-ID-008 | One resolved identity bound per session; mid-session rebind denied | Identity-binding + no-rebind + cross-session tests | No mid-session identity rebind | IAM/Eng | PR-3 |
| MCP-T-074 hostile-input crash/panic | MCP-PROTO-009, MCP-PROTO-013 | Crash-resistant parse/adapter; bounded error + cleanup | Fuzz (panic/crash detection) + race | No panic/crash on corpus; bounded error | Sec/Eng | PR-1 |
| MCP-T-057/065 UTF-8 / protocol-token handling | MCP-PROTO-014 | Reject invalid UTF-8; **exact** method-token comparison; reject non-ASCII method names (pending D-1); opaque identifiers not globally normalized by the kernel | Invalid-UTF-8 rejection + exact-comparison + non-ASCII-method-rejection (D-1-gated) + no-global-normalization fixtures | Invalid UTF-8 rejected; method tokens compared exactly; non-ASCII methods rejected; opaque IDs untouched by kernel normalization | Sec/Eng | PR-1 |
| MCP-T-076 reverse-channel / requestor-direction state confusion | MCP-PROTO-015, MCP-PROTO-003, MCP-PROTO-013 | Peer-role kernel; requestor-scoped `(session, direction, id)` correlation; direction-scoped cancellation; no cross-direction state release | Opposite-direction-cancel-rejected + same-id-both-directions + initialize-not-cancellable + late-cancel-tolerated + upstream-corpus-same-kernel fixtures | Correlation direction-scoped; other direction's state never released; one kernel over both legs | Sec/Eng | PR-1 |
| MCP-T-077 admitted-but-unpoliced method dispatch | MCP-PROTO-016, MCP-POLICY-001 | Culvert-reviewed admitted-method registry; forward/reverse parity; registry-absent rejected; representable operand before default-deny | Forward/reverse-parity (predicate-28) + resources/read-rejected + registry-absent-rejected + no-config-re-admission + advertisement-matches-registry fixtures | Every admitted method owned once; absent rejected; no unpoliced dispatch | Sec/Eng | PR-1 (parity) / PR-6 (enforcement) |

### 1b. RPR-1 protocol-direction & method-registry blocking fixtures (#925 + #928)

The eighteen fixtures below are **blocking**: the registry/parity and protocol-state fixtures at **PR-1**,
and the two business-policy-enforcement fixtures (#15, #16) at **PR-6** — without weakening the PR-1
registry gate. Mirrored in [`CI-GATES.md`](CI-GATES.md); the parity fixtures are executable now as
`predicates/predicate-28.py`.

| # | Blocking fixture | Requirement | Gate |
|---|---|---|---|
| 1 | Same-session **opposite-direction** cancellation is rejected and the owning entry is retained | MCP-PROTO-015 | PR-1 |
| 2 | The same `id` is outstanding **concurrently in both directions** with no cross-correlation | MCP-PROTO-015 | PR-1 |
| 3 | Cancellation of `initialize` is rejected | MCP-PROTO-015 | PR-1 |
| 4 | A **late** post-response cancellation is tolerated, not a duplicate-completion fault | MCP-PROTO-012, MCP-PROTO-015 | PR-1 |
| 5 | **Wrong-requestor** cancellation (right direction, wrong owner) is rejected | MCP-PROTO-015 | PR-1 |
| 6 | Server-originated `sampling`/`elicitation`/`roots` request is rejected (no wire response where the class forbids) | MCP-PROTO-016, MCP-PROTO-013 | PR-1 |
| 7 | `tasks/*` (incl. `tasks/cancel`) is rejected under capability admission | MCP-PROTO-016 | PR-1 |
| 8 | Hostile **upstream-leg** corpus runs through the **same** kernel — identical classification and bounds on both legs | MCP-PROTO-015 | PR-1 |
| 9 | Every admitted method resolves to **one** decision point **or** is kernel-terminal | MCP-PROTO-016 | PR-1 |
| 10 | A registry row with **neither** owner fails the build | MCP-PROTO-016 | PR-1 |
| 11 | A registry row with **both** owners fails the build | MCP-PROTO-016 | PR-1 |
| 12 | **No** dispatch path exists for a method absent from the registry (reverse parity) | MCP-PROTO-016 | PR-1 |
| 13 | A spec-valid but **registry-absent** method is rejected | MCP-PROTO-016 | PR-1 |
| 14 | `resources/read` is **explicitly rejected** (never admitted-and-unpoliced) | MCP-PROTO-016 | PR-1 |
| 15 | Each admitted **business** method reaches default-deny with a **representable** operand | MCP-POLICY-001, MCP-PROTO-016 | PR-6 |
| 16 | Credential scope and audit category resolve for every admitted business method | MCP-CRED-002 | PR-6 |
| 17 | Arbitrary config **cannot** re-admit an unsupported method (no `allow_unknown_methods`) | MCP-PROTO-016, MCP-CFG-001 | PR-1 |
| 18 | Capability advertisement **exactly matches** the admitted registry | MCP-PROTO-016 | PR-1 |

### 1c. RPR-4 transport-fallback blocking fixtures (#929)

Structural / terminal-status / zero-stream properties block at **PR-1** (primitive) or **PR-5** (listener).
Fixtures whose expected values depend on the **final selected version set** are **`D-1 BLOCKED`** and MUST
NOT be marked green until D-1 closes. Mirrored in [`CI-GATES.md`](CI-GATES.md) and enumerated with sources in
[`TRANSPORT-FALLBACK-EVIDENCE.md`](TRANSPORT-FALLBACK-EVIDENCE.md) §9. Threat: `MCP-T-078`; requirement:
`MCP-PROTO-017` (+ `MCP-INSP-009`/`MCP-OPS-002` for the listener assertions).

| # | Blocking fixture | Requirement | Gate |
|---|---|---|---|
| 19 | Legacy `2024-11-05` endpoint negative — no route/config pair can emit an `endpoint` event | MCP-PROTO-017 | PR-1 |
| 20 | GET without a valid negotiated session/context → terminal **405**, no `text/event-stream`, zero allocation | MCP-PROTO-017, MCP-INSP-009 | PR-1 (primitive) / PR-5 (listener) |
| 21 | Invalid/unsupported `MCP-Protocol-Version` → **400**; observed SDK follow-on; terminal GET **405**; zero retention | MCP-PROTO-017 | PR-1 / PR-5 |
| 22 | Missing `MCP-Session-Id` → **400**; observed SDK behavior; no retained stream | MCP-PROTO-017 | PR-1 / PR-5 |
| 23 | Terminated session → **404**; SDK reinitialize; terminal GET **405**; zero retention | MCP-PROTO-017 | PR-1 / PR-5 |
| 24 | DELETE termination unsupported → **405**; zero retention | MCP-PROTO-017 | PR-1 / PR-5 |
| 25 | Initialize **counter-offer** at HTTP **200**; compatible client continues; incompatible client disconnects; no legacy probe | MCP-PROTO-010, MCP-PROTO-017 | PR-1 / PR-5 — **D-1 BLOCKED** (version set) |
| 26 | Sessionless absent-`MCP-Protocol-Version` — the exact D-1 ruling asserted; no silent `2025-03-26` admission | MCP-PROTO-017, MCP-PROTO-010 | PR-1 — **D-1 BLOCKED** |
| 27 | Official-SDK unsupported-version full sequence terminates deterministically; zero retained streams | MCP-PROTO-017 | PR-5 — **D-1 BLOCKED** (version set) |
| 28 | Catch-any-failure client — every failure branch terminates; no held stream | MCP-PROTO-017 | PR-5 |
| 29 | Load: **N** rejected clients ⇒ **zero** retained pre-negotiation streams | MCP-OPS-002, MCP-PROTO-017 | PR-5 |
| 30 | Protocol-era separation — 2025 initialize/session fixtures cannot run on a 2026-era handler, and 2026 stateless/discovery fixtures cannot silently fall into 2025 legacy SSE probing | MCP-PROTO-017, MCP-PROTO-016 | PR-1 / PR-5 |

The **PR-1 gate proves structural / terminal / zero-stream properties only**; it does **not** claim the PR-5
runtime listener assertions (load, N-client zero-retention) are implemented, and it does **not** claim any
`D-1 BLOCKED` fixture is green.

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
| MCP-T-044 queue saturation/loss | MCP-EVENT-001,002 | Backpressure + **commit-before-side-effect per class** + fail-closed + **domain-scoped degradation** (denial events routed to the isolated denial lane, MCP-EVENT-007 — never a lockout) | Queue-saturation **and a spool-commit-failure case distinct from saturation** (`ENOSPC` / `fsync` error / encryption-key failure), **run on both the Management and Gateway legs**, incl. a **Management-originated** denial-event loss; **each critical class asserts the absence of EVERY irreversible action downstream of that flow's commit gate — not only the action the class is NAMED after** — write/destructive: no upstream call **and no broker-side materialization** (DFD-5 gates both); configuration publication: no new revision, nothing signed or pushed, every DP on the prior epoch; credential: broker state unchanged (nothing minted, rotated or revoked) **and no upstream call**; state-affecting Management: no state change **and no new revision, nothing signed or pushed, every DP on the prior epoch** — DFD-3 publishes a signed snapshot, so a state-change-only assertion passes a handler that publishes anyway (**stub only at PR-8 — no V1 Management mutation exists per ADR-0024 §D-13; the real-path assertion is owned by the future Management-mutation gate**) | Zero critical loss; **for every critical class, EVERY irreversible action downstream of that flow's commit gate is proven not to have happened** — not only the eponymous one, and not merely that an error was returned or degraded mode entered; commit failure after admission fails closed identically to saturation; **a Management-originated denial-event loss does NOT block a subsequent allowed Gateway write/high-risk operation** — containment is per durability domain, and a cross-capability block is a FAILING result (`MCP-T-075`); **the configuration-publication case is re-run against the real signed publication path at PR-10, since that path does not exist at PR-8** | SRE/Sec | PR-8 **+ mandatory PR-10 re-run (publication path)** **+ mandatory re-run at the Future Management-Mutation Gate (D-13) for the `state-affecting Management` class — PR-8 can only stub it** |
| **MCP-T-075 unauthenticated denial-event flood → durability-lockout DoS** | MCP-EVENT-007, MCP-EVENT-001, MCP-EVENT-002, MCP-OPS-005, MCP-OPS-002 | Separate denial lane (pre-queue admission control + attacker-rate-independent coalescing + own quota, no access to the `P-CRIT` reserve); three logically separate spool partitions with reserved critical capacity and a deterministic reclamation order; degraded state **scoped to one durability domain**, restart-persistent, bounded on exit; **no emergency-policy bypass** | The **nine blocking `MCP-T-075` containment tests** ([CI-GATES.md](CI-GATES.md)): headline attacker test, coalescing, reserved partition, local-scope containment, **preserved fail-closed guarantee** (queue saturation **and** post-admission commit failure), recovery termination, restart persistence, storage reclamation, counter integrity | Authenticated allowed critical work in another tenant/listener/capability succeeds throughout a saturated denial lane; `N` denials ⇒ O(1) durable records with correct count and first/last-seen; critical event commits from reserve under denial saturation; degradation provably confined to `node × capability × partition`; **fail-closed still holds in both failure modes**; state exits within one probe interval and survives restart; unexported critical records outlive all denial/ordinary records; denial-loss and critical-commit-failure counters distinct | SRE/Sec | PR-8 |
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
| MCP-T-006,007 principal typing | MCP-ID-001 | Distinct human/workload/agent/client/tenant/server/tool/resource principals | Principal-model unit tests (each type populated end-to-end) | Principal types populated on decision events | IAM/Eng | PR-3 |
| MCP-T-045 delegation chain | MCP-ID-004 | Record human→agent→client→server→tool→resource chain without secrets | Event-schema tests (chain present, no secrets) | Delegation chain present; no secrets | IAM/Eng | PR-8 |
| MCP-T-006,007 ambiguous identity | MCP-ID-005 | Missing/ambiguous identity → DENY for write/high-risk | Ambiguous-identity tests | DENY + reason code on ambiguity | Sec/Eng | PR-6 |
| MCP-T-022 credential lifetime | MCP-CRED-003 | Short-lived, rotatable-without-downtime, immediately revocable credentials | Rotation/revoke tests | Revoke takes effect; rotation without outage | IAM/PAM | PR-4 |
| MCP-T-047,050 snapshot fields | MCP-CPDP-001 | Snapshot carries epoch + config/policy/catalog/credential revisions + minimum_dp_version + content_hash+signature | Snapshot-schema tests | All fields present + verified | Eng/SRE | PR-10 |
| MCP-T-018 nine-action model | MCP-POLICY-005 | Nine decision actions + obligations supported | Action-matrix tests (each action + obligation exercised) | Each action/obligation exercised | Sec/Eng | PR-6 |
| MCP-T-032,033,039 approval UX | MCP-POLICY-007 | Approval dialog shows exact action/resource/impact/credential | Approval-UX completeness tests | Dialog completeness proven | Product Sec/Eng | PR-9 |
| MCP-T-014 semantic drift | MCP-TOOL-005 | Semantic/description drift triggers risk re-score + review | Semantic-drift tests | Re-score recorded | Sec/Eng | PR-2 |
| MCP-T-044,051 operability | MCP-OPS-003 | Dashboards, alerts and runbooks for every incident class | Ops review (runbooks + alerts present) | Runbooks + alerts exist | SRE | Prod-Qual |
| MCP-T-078 transport-rejection legacy fallback | MCP-PROTO-017 (+ MCP-INSP-009, MCP-OPS-002 listener) | Legacy `2024-11-05` exclusion + no-pre-negotiation-stream: terminal `405` on GET-without-context, `200` counter-offer preferred, every `4xx` follow-on GET is `405` with zero retention | Legacy-endpoint-negative + GET→`405`-zero-stream + `400`/`404`/`405`-terminal-zero-retention + N-rejected-zero-streams (PR-5) + counter-offer + era-separation fixtures ([`TRANSPORT-FALLBACK-EVIDENCE.md`](TRANSPORT-FALLBACK-EVIDENCE.md) §9) | No legacy endpoint; zero pre-negotiation streams; `2025-03-26` not silently admitted (D-1) | Sec/Eng | PR-1 (exclusion/terminal) / PR-5 (held-stream/load); version-set fixtures **D-1 BLOCKED** |

**Cross-cutting / posture requirements (no threat ID — supply-chain/build posture; still with explicit
test, evidence, owner and gate, per the completeness rule — a fake threat is NOT invented for these):**

| Requirement | Type | Control | Verification / test | Evidence | Owner | Gate |
|---|---|---|---|---|---|---|
| MCP-SUPPLY-001 | cross-cutting supply-chain posture | Dependencies pinned + minimal; new runtime deps avoided (single-binary posture) | `go.mod` review + `go-licenses` on the first MCP dependency change | Pinned; license-clean | Sec/Release | PR-1 |
| MCP-SUPPLY-002 | cross-cutting build posture | CI actions pinned to immutable SHAs with least-privilege tokens | Workflow review (no floating action tags) on the first MCP workflow change | SHA-pinned actions | Release | PR-1 |
| MCP-SUPPLY-004 | cross-cutting response posture | Vulnerability-remediation SLA + emergency-revoke + customer-notification procedure | Runbook review | Documented SLA + revoke + notification procedure | Sec/Release | Prod-Qual |

## 2. Full test taxonomy → requirement coverage

| Test category | Primary requirements | Present today? | Gate |
|---|---|---|---|
| Unit | (harness only — **NOT** requirement-specific proof; see §1 and §1a for per-requirement chains) | Harness exists (`go test -race`) | PR-1+ |
| Integration | all runtime | Harness exists | PR-1+ |
| Compatibility (protocol conformance) | MCP-PROTO-010,011 | **Missing** — `[EXT]`/`[D-1]` version fixtures; content gated on D-1 closure; must become a **blocking PR-1** gate ([`CI-GATES.md`](CI-GATES.md)) | PR-1 (D-1-gated) |
| Malformed JSON-RPC / parser-differential / classification / batch | MCP-PROTO-001,002,003,004,005,007,013 | **Missing** — malformed + duplicate-key + framing corpus, plus **deterministic** batch-policy cases (max batch size, per-element bounds, bounded amplification, unsupported-batch explicit rejection) and **deterministic** pathological-number cases (overflow, precision, encodings) — deterministic, not fuzz-delegated | PR-1 |
| Protocol structural limits (size/depth/field/string/number) | MCP-PROTO-006,007,008 | **Missing** — limit + resource-budget assertions | PR-1 |
| Version negotiation / downgrade / adapter equivalence | MCP-PROTO-010,011 | **Missing** — D-1-gated fixtures | PR-1 (D-1-gated) |
| Protocol-state / cancellation / duplicate-completion | MCP-PROTO-012 | **Missing** — protocol-state machine tests | PR-1 |
| Malicious MCP server fixtures | MCP-SERVER-*, MCP-TOOL-* | **Present (PR-2)** | PR-2 |
| Non-compliant server fixtures | MCP-SERVER-*, protocol | **Present (PR-2)** | PR-2 |
| Fuzzing (protocol kernel: parser/framing/adapter/cancellation) | MCP-PROTO-009 (+006,008) | `fuzz-nightly.yml` exists but is **advisory/nightly — not a merge gate**; a **new bounded blocking PR-1 fuzz gate** is required ([`CI-GATES.md`](CI-GATES.md)) | PR-1 |
| Race | concurrency invariants | `-race` gate exists | PR-1+ |
| Config-surface matrix **parse validity + anti-vacuity** — valid GFM table (header == delimiter == every data-row width) with **every delimiter cell ≥ 3 hyphens**, **non-empty** parse, expected row count, no duplicate field IDs; **summary integrity** (every declared label exactly once, no duplicate member inside a row, forward parity plus reverse parity bound either to the class it enumerates exhaustively or to an explicit pinned name list for a bounded subset); and **two complete, unique censuses** (value kind *and* registry class — every token claimed exactly once incl. zero-valued `pinned-identity`/`RC-X`, no unknown tokens, plus row and sensitive-kind totals); **zero parsed rows is an unconditional failure**. Executable now as `predicates/predicate-26.py` with **22** seeded controls (delimiter cells of one/two hyphens and malformed alignment, 16-vs-17 delimiter, zero-row parse, dropped bounded-summary member, duplicate summary member, duplicate summary row, registry-class census omitted/wrong/duplicated/`RC-X`-nonzero, deleted value-kind claim, falsified zero-valued claim, falsified row total, RC-1 summary disagreement, `RC-0` row in the `RC-2` summary, missing summary member, `provider-ref → RC-6`, duplicate field, unknown value kind, live `RC-X` row) and 3 negative controls. | **MCP-CFG-001** | `predicate-26.py` **runs in the required Fast PR Gate** (`Gate · MCP design predicates`) for PRs touching the MCP design surface; a failure blocks the aggregate. This gates the **design matrix** only — the runtime `configSurfaces` parity below remains unenforced until PR-1. | PR-1 |
| Config-surface anti-drift parity (MCP) — both omission cases (new field in a known type **and** an entirely new/nested type), redaction parity for `Sensitive` rows, **value-kind vocabulary + `sensitive-kind ⇒ RC-1|RC-2` invariant evaluated over REGISTRY ENTRIES, plus bidirectional registry↔matrix field-ID parity, with two seeded failure cases: `provider-ref → RC-6`, and a sensitive field registered with no matrix row**, capture/apply parity for every DP-affecting field (the **four** `RC-5` fields **and** DP-affecting `RC-7` rows such as `snapshot_sync_enabled` / `snapshot_min_dp_version`, which are covered by the every-DP-affecting-field rule rather than by `RC-5` membership), nested cap parity, wire-wipe ⇔ `omitempty`, GUI parity, `count(RC-X) == 0` | **MCP-CFG-001** | Existing `config_surfaces_test.go` covers **only** the three hard-coded non-MCP types at one level of reflection — **MCP coverage is Missing**; extension strategy is `D-15` | PR-1 |
| Property tests | MCP-POLICY-002 (determinism) | **Missing** | PR-6 |
| Authentication negative matrix | MCP-AUTH-001..004 | **Present (PR-3)** — `internal/mcp/authn` JWT + opaque negative-auth matrix (alg=none/confusion/bad-sig/unknown-kid/wrong-issuer/missing-or-wrong-audience/expired/not-yet-valid/excessive-TTL/missing subject-client-tenant-scope) | PR-3 |
| Authorization negative matrix | MCP-POLICY-*, MCP-MGMT-* | **Missing** | PR-6/PR-9 |
| Replay | MCP-AUTH-006 | **Present (PR-3)** — `internal/mcp/senderconstraint` DPoP proof-`jti` replay cache: a repeated proof is rejected, a fresh proof for the same still-valid access token succeeds, per-capability partitions cannot exhaust one another, and a full cache fails closed | PR-3 |
| Wrong audience / wrong resource | MCP-AUTH-002,003 | **Present (PR-3)** — `internal/mcp/authn` canonical-resource audience validation over JWT **and** opaque tokens; foreign `aud`, `client_id`-as-audience, upstream-server-as-audience, cross-capability resource, and absent audience all denied | PR-3 |
| No client-token passthrough | MCP-AUTH-005, MCP-CRED-001 | **Present (PR-4)** — `internal/mcp/credentials/broker` consumes only the PR-3 `identity.ResolvedContext`; the provider request carries only the one-way correlation digest (no `RawSecret`/`ForwardToken`/`AuthorizationHeader` accessor exists) | PR-4 |
| Credential scope / power validation | MCP-CRED-002 | **Present (PR-4)** — profile scope + provider-effective-scope subset/power-ceiling checks reject cross-tenant/server/tool/resource and over-privileged material; a read-only credential is rejected for a write op | PR-4 |
| Credential rotation / revocation | MCP-CRED-003 | **Present (PR-4)** — validate-before-publish rotation state machine with bounded grace; immediate tombstone-and-cache-invalidate revocation (idempotent; racing materialization/rotation cannot revive a revoked version) | PR-4 |
| Secret containment (broker) | MCP-CRED-004 | **Present (PR-4)** — opaque `secret.Sealed` handles only; scoped zeroize-on-success/error/panic callback; sanitized `SafeResult`; canary-proof provider-error sanitization; canary scans over errors/metadata/cache/snapshots. Event-redaction leg stays PR-8 | PR-4 (broker) / PR-8 (events) |
| Encrypted bounded credential cache | MCP-CRED-005 | **Present (PR-4)** — bounded, partitioned, TTL, deterministic-eviction, stampede-coalesced cache holding only encrypted envelopes (no plaintext) | PR-4 |
| Broker fail-closed semantics | MCP-CRED-006 | **Present (PR-4)** — high-risk always fails closed (no stale fallback); low-risk cached fallback only under explicit profile policy with a valid, fresh, non-revoked entry; gate failure leaves provider/cache untouched | PR-4 |
| SSRF (private-IP matrix) | MCP-INSP-004 | ssrf unit tests exist; MCP matrix **missing** | PR-7 |
| DNS rebinding lab | MCP-INSP-005 | **Missing** | PR-7 |
| Redirect chains | MCP-INSP-006 | per-client tests exist; shared MCP **missing** | PR-7 |
| Origin/Host validation primitive (no listener) | MCP-INSP-008 | **Missing** | PR-1 |
| Listener bind + host-allowlist + E2E rebinding enforcement | MCP-INSP-009 | **Missing** | PR-5 |
| Tool canonicalization | MCP-TOOL-001 | **Present (PR-2)** | PR-2 |
| Tool drift / privilege expansion | MCP-TOOL-003,004 | **Present (PR-2 classify); enforcement PR-6** | PR-2/PR-6 |
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
- Every requirement in [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) is reachable from a §1 or §1a
  row (or the labeled cross-cutting/posture block in §1a) with an explicit test/evidence/owner/gate — **all
  97 requirements, 0 unreachable** (independently recomputed with exact/comma/range expansion, excluding the
  generic "Unit | all" and "Integration" harness rows, which are **not** counted as requirement-specific
  proof).
- Every abuse case `MCP-AC-*` maps to a §1 row via its threat/requirement IDs.
- Missing suites are labeled **Missing** here and in [`CI-GATES.md`](CI-GATES.md); none is claimed present.
