# MCP Protocol Compatibility

This document defines what MCP transports, protocol versions and wire-lifecycle behaviors Culvert's
protocol kernel intends to support in V1, what it explicitly does not support, and how it must behave
when it encounters something outside that support envelope (default deny / disable safely, never a
silent widening of trust). It applies to **both** MCP capabilities in this package — the Culvert
Management MCP Server and the MCP Security Gateway — since both terminate MCP wire traffic through the
same protocol kernel component even though their listeners, scopes and policy schemas stay separate (see
[`README.md`](README.md) and [`BLUEPRINT.md`](BLUEPRINT.md) §06/§09 for the shared-vs-separate doctrine).

**Status: PR-0 design artifact (Proposed).** Nothing described here is implemented. No MCP listener, no
JSON-RPC parser, and no protocol-version adapter exists in the repository today (`VERIFIED-REPOSITORY-CONTEXT.md`
— NO existing MCP/JSON-RPC listener in inspected paths).

**Claim legend**: **[FACT]** repository-verified · **[INFER]** architectural inference · **[REC]**
recommendation · **[EXT]** externally unverified — needs a non-repository source (the MCP specification)
before implementation. Per the PR-0 brief, **every concrete MCP protocol-version number, transport wire
name, or JSON-RPC/Streamable-HTTP/SSE lifecycle detail in this document is marked `[EXT]` and MUST be
verified against the authoritative MCP specification before PR-1 implementation begins.** This document
never asserts that a given protocol version is "current" — that is an external fact, not a repository
fact, and it can change between when this is written and when PR-1 starts.

---

## 1. Supported MCP Transports

| Transport | V1 intent | Rationale | Status |
|---|---|---|---|
| Remote Streamable HTTP | **In scope for V1.** `[EXT]` — the exact wire name, request/response framing and capability-negotiation fields of "Streamable HTTP" are defined by the MCP specification, not this repository. | Matches `BLUEPRINT.md` §06/§07 ("Honest coverage — V1 covers remote MCP routed through Culvert") and the doctrine that both capabilities are reached over a Culvert-owned listener (`/mcp/management`, `/mcp/gateway/{server-id}`). | Proposed |
| stdio | **Explicitly deferred**, not V1. `[EXT]` for the transport's wire semantics. | A local/stdio transport has no network hop for Culvert to interpose on — it structurally cannot be inspected by a network-terminating gateway without a local bridge component. | Deferred — see [OPEN-DECISIONS.md](OPEN-DECISIONS.md) |
| Local/"localhost" HTTP | **Explicitly deferred**, not V1. `[EXT]`. | Same reasoning — a loopback-only server bypasses the remote listener entirely (see MCP-T-055 below). | Deferred |
| Any other transport (e.g. future MCP transports not yet standardized) | **Not supported.** `[EXT]` — future transports are, by definition, outside current repository or specification knowledge. | V1 non-goal: "Do not support every MCP transport, extension and protocol version on day one" (`BLUEPRINT.md` §06). | Out of scope |

`MCP-OPS-004` requires these V1 coverage limits (stdio/localhost/direct-egress bypass) to be documented as
a known limitation, not silently assumed away — this table, together with §8 below, is that documentation.

**Bypass threats these limits create** (documented, not mitigated by V1): MCP-T-054 (stdio bypass),
MCP-T-055 (localhost bypass), MCP-T-056 (direct egress bypass). See [`THREAT-MODEL.md`](THREAT-MODEL.md)
for the residual-risk owner and [`ON-PREM-CONNECTIVITY.md`](ON-PREM-CONNECTIVITY.md) for the roadmap item
(a local Desktop/Endpoint Bridge) that would close these gaps outside V1.

---

## 2. Supported Protocol Versions and Version Negotiation Policy

`[EXT]` **The set of MCP protocol versions that exist, their identifiers, and the negotiation handshake
by which a client and server agree on one are defined entirely by the external MCP specification.** This
repository has no prior implementation to draw from (VERIFIED EVIDENCE: NO existing MCP/JSON-RPC listener
in inspected paths), so no protocol-version number is stated here as fact, and none should be read as
"the current version" — that must be re-verified against the specification at PR-1 implementation time,
not assumed from this document.

Design intent, independent of the specific version identifiers:

- The protocol kernel **MUST** know, at any given time, an explicit **allowlist of supported protocol
  versions** (a finite, reviewed set — never "accept anything that looks like a version string").
- Version negotiation **MUST** be a bounded, deterministic step of the connection lifecycle (evaluated
  once at session establishment, not re-negotiated mid-session in a way that can silently escalate
  capability).
- A version outside the allowlist **MUST** be rejected at negotiation time with a defined error, not
  passed through to later protocol-kernel stages "best-effort."
- The negotiation outcome (the version actually agreed) **MUST** be attached to the session/decision
  context so downstream policy and event logging can record which version handled a given call — this
  supports MCP-T-050 (mixed-version) analysis and `MCP-CPDP-003` (mixed CP/DP version).

This is intent, not a spec citation — the concrete version strings, the negotiation message shape, and
whether negotiation is a distinct step versus part of the initial handshake are all `[EXT]`.

---

## 3. JSON-RPC Lifecycle

`[EXT]` **The JSON-RPC 2.0 message shapes (request/response/notification), the `id` correlation rules, and
the standard/custom error-code semantics are external specification facts**, not verified in this
repository. What follows is what Culvert's protocol kernel must do to those messages, independent of the
exact external rules:

| Lifecycle element | Culvert protocol-kernel intent | External fact status |
|---|---|---|
| Request | Bounded parse (size/depth/field-count — see `MCP-PROTO-006`; strict single-parse decode `MCP-PROTO-001`); the kernel decodes the envelope only — it **MUST NOT** decide business policy on it (that is the Policy Engine's job, per `BLUEPRINT.md` §09 "Must Not: Decide business policy or contain business rules"). | `[EXT]` exact JSON-RPC request shape |
| Response | Bounded encode (size/type/schema, truncation policy — `MCP-INSP-002`); responses from an upstream/approved server pass through the Inspection Pipeline before being returned to the agent. | `[EXT]` exact response shape |
| Notification | Treated as a one-way message with no correlatable response; the kernel **MUST** apply the same size/rate bounds as a request (a notification flood is still an availability threat — MCP-T-042/043/044). | `[EXT]` whether/how notifications differ structurally from requests |
| `id` correlation | The kernel **MUST** track outstanding request `id`s per session within a bounded table (never unbounded — an attacker sending many uncorrelated/duplicate `id`s is a queue-saturation vector, MCP-T-044) and **MUST** reject or ignore a response/notification whose `id` cannot be correlated to an outstanding request from the same session. | `[EXT]` exact `id` uniqueness/reuse rules in the spec |
| Errors | The kernel **MUST** map internal failures (parse error, oversized payload, policy DENY, upstream failure) to a defined, bounded set of JSON-RPC error responses — **MUST NOT** leak internal state (stack traces, upstream credentials, file paths) in an error message (this is the same posture as `MCP-CRED-004`/`MCP-EVENT-003` applied to the wire layer). | `[EXT]` the standard JSON-RPC error-code table and whether MCP reserves additional codes |

Determinism note: bounding and validating the JSON-RPC envelope is a protocol-kernel responsibility and is
independent of `MCP-POLICY-002`'s no-I/O determinism requirement on the Policy Engine — the kernel may do
bounded parsing work, but it still **MUST NOT** perform network or disk I/O as part of deciding whether a
message is well-formed (that would reintroduce the same class of problem `MCP-POLICY-002` calls out in the
existing SWG `Evaluate` path, `policy.go:1083-1143`/`:1387`, which is explicitly **not** to be reused here).

---

## 4. Streamable HTTP + SSE Lifecycle

`[EXT]` **The exact Streamable HTTP connection-establishment sequence, SSE event framing (event/data/id
fields), and keep-alive/heartbeat convention are external specification facts.** Culvert's obligations at
this layer, independent of those specifics:

- **Connect**: the inbound HTTP request that establishes the Streamable HTTP/SSE channel **MUST** pass
  Origin/Host validation before the channel is established — the `MCP-INSP-008` Origin/Host validation
  **primitive** (a pure decision, PR-1) is a hard precondition on connect, not a post-hoc check; the
  **listener that invokes it at connect and binds only configured interfaces is `MCP-INSP-009` at PR-5**
  (PR-1 ships no listener). This closes a gap the repository does not have a general
  answer for today: `isSafeRedirectURL` (`proxy_portal.go:152`) is captive-portal-only and does not cover
  an inbound MCP/SSE listener (VERIFIED EVIDENCE). Relevant threats: MCP-T-031 (inbound DNS-rebinding vs
  MCP/SSE listener), MCP-T-055 (localhost bypass), MCP-T-052 (DMZ abuse).
- **Event framing**: `[EXT]` for the wire-level SSE event shape. The kernel's obligation is bound
  enforcement regardless of the exact framing: `MCP-OPS-002` requires connections, SSE streams, payloads,
  queues, concurrency and event buffers to be bounded with per-entity rate limits. A slow or hostile
  client/server on this channel maps to MCP-T-043 (slow-client) and MCP-T-042 (SSE exhaustion); an
  unbounded event buffer maps to MCP-T-044 (queue saturation/event-loss, Critical).
- **Keep-alive**: `[EXT]` for the exact heartbeat mechanism the spec defines (e.g. comment pings vs.
  typed events). Design intent: keep-alive **MUST** be bounded (a maximum idle interval before the kernel
  closes the channel) and **MUST NOT** be relied upon as the sole liveness signal for billing/quota
  purposes — a channel that stops sending keep-alives **MUST** be treated as dead after a bounded timeout,
  not held open indefinitely (this mirrors the existing raw-tunnel idle-bound posture in the SWG data path,
  `CLAUDE.md` "Relay pattern" — read-deadline-armed idle bounding — cited here as **prior-art precedent
  only**, not as a claim that the MCP kernel reuses that code).

`MCP-INSP-008` (inbound Origin/Host) and the protocol-kernel bounds `MCP-PROTO-005/006/008` are **PR-1**
requirements; `MCP-OPS-002` (deployed-listener stream/connection/rate bounds under load) is a **PR-5**
requirement that depends on the Observe Runtime (see [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md),
finding H-4). This section states the design intent those requirements bind the protocol kernel to, not an
implementation.

---

## 5. Session Handling, Cancellation, Reconnect

These are described as **intended Culvert semantics**; where a behavior is dictated by the MCP
specification itself rather than by Culvert's own design choice, it is marked `[EXT]`.

| Behavior | Intended semantics | External-fact status |
|---|---|---|
| Session establishment | A session is created only after version negotiation (§2) and Origin/Host validation (§4) succeed, and only after identity resolution (`MCP-ID` family — see [`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md)) attaches a principal to it. A session with ambiguous/missing identity **MUST NOT** be granted write/high-risk capability (`MCP-ID-005`). | Culvert design choice — not spec-mandated |
| Session identity binding | One session serves exactly one resolved identity for its lifetime; a session **MUST NOT** be re-bound to a different identity mid-flight (this is the protocol-layer analog of `MCP-AUTH-007` cross-user session confusion, MCP-T-008). | Culvert design choice |
| Cancellation | `[EXT]` whether/how the MCP spec defines an explicit cancellation notification for an in-flight tool call. Intended Culvert behavior regardless: a cancellation **MUST** free the corresponding entry in the bounded `id`-correlation table (§3) promptly, and **MUST NOT** be usable to bypass an already-issued QUARANTINE/DENY decision (cancel-and-retry is not a policy-evaluation bypass). | Mixed — cancellation existing in the spec is `[EXT]`; how Culvert accounts for it is design intent |
| Reconnect | `[EXT]` for any spec-defined resumption/session-id-reuse mechanism (e.g. replaying missed SSE events by last-event-id). Intended Culvert posture: a reconnect **MUST** re-run Origin/Host validation and **MUST** re-verify the bearer token has not expired (no implicit session-lifetime extension via reconnect) — a reconnect is not a trust carry-over, it is a new connect that happens to resume application-level session state. | Mixed |
| Idle/timeout | A session with no activity for a bounded interval **MUST** be closed by the kernel (ties to `MCP-OPS-002` bounding and to the queue-saturation concern in MCP-T-044). | Culvert design choice on the specific bound; the notion that MCP sessions can idle is `[EXT]` |

---

## 6. Authentication Expectations at the Protocol Layer

Protocol-layer authentication is a thin, mechanical enforcement point — the substantive identity/token
model lives in [`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md). This section states only
what the protocol kernel must enforce on every inbound call, independent of transport-version specifics:

- **Bearer token only, never in a query string.** `MCP-AUTH-001`: "The gateway MUST validate the client
  bearer token on every tool call and MUST NOT accept a token in a query string." A token that arrives in
  the query string **MUST** be rejected outright by the kernel before it reaches any handler — a
  query-string token is logged, cached and proxied by ordinary infrastructure (access logs, referrer
  headers, browser history) and is not a credential-handling posture Culvert accepts at any layer.
- **Audience binding.** `MCP-AUTH-002`: the token audience must identify Culvert as the resource; a token
  minted for a different audience is rejected. The existing SWG OIDC flow binds audience to the OIDC
  `client_id` only (`auth_oidc_flow.go:523`, VERIFIED EVIDENCE) — that is **insufficient** for MCP and is
  explicitly not reused as the MCP audience model (`BLUEPRINT.md` §06 non-goal: "Do not reuse the existing
  SWG OIDC proxy flow as a generic MCP authentication model").
- **Resource-indicator binding.** `MCP-AUTH-003`: Culvert's clients request the **canonical
  Culvert-controlled MCP resource URI** via the RFC 8707 `resource` parameter (`[EXT]` RFC 8707 is an
  external IETF specification, not a Culvert repository fact) — **never** the upstream business MCP server
  (ADR-0024 §D-2) — and the gateway validates the **resulting** audience restriction from standard token
  metadata (`aud` for JWTs, introspection for opaque tokens) rather than a bespoke in-token claim. An
  unbound (`aud`-less) token is denied for **every** operation class — read/low-risk included — since it
  cannot be shown to target Culvert at all. VERIFIED EVIDENCE: RFC 8707 has zero
  matches in the current repository — this is a **net-new** control, not an extension of anything that
  exists today.
- **No passthrough at the protocol layer.** The protocol kernel never forwards the client's bearer token
  unchanged to an upstream MCP server; credential selection is a separate, later step gated on a policy
  ALLOW-class decision (`MCP-POLICY-004`, `MCP-CRED-001`) and is out of the protocol kernel's
  responsibility entirely — see [`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md) for the
  credential broker design.

`[EXT]` note: whether the MCP specification itself defines a mandatory bearer-token auth scheme, an
alternative scheme, or leaves authentication entirely to the deployer is an external specification
question. The three requirements above (`MCP-AUTH-001/002/003`) are Culvert's own security posture applied
at this layer regardless of what the base spec mandates as a minimum.

---

## 7. Unsupported Capabilities

Explicit non-support list for V1 (documented per the "Honest coverage" principle in `BLUEPRINT.md` §06,
and per `MCP-OPS-004`):

| Capability | V1 status | Downgrade-safely policy |
|---|---|---|
| stdio transport | Not supported | Connection attempt over stdio is not reachable through the Culvert listener at all — there is nothing to downgrade; it is simply out of the network path Culvert can see (see §1). |
| Localhost-only MCP servers | Not supported | Same — Culvert cannot interpose on a server the agent reaches directly over loopback (MCP-T-055). |
| Direct egress bypassing the gateway | Not supported/not preventable by the gateway alone | Documented network-architecture assumption, not a protocol-kernel feature (MCP-T-056). |
| Protocol versions outside the allowlist (§2) | Not supported | The kernel **MUST** reject the negotiation, not attempt best-effort interpretation of an unrecognized version. Rejecting is the downgrade-safe behavior — silently treating an unknown version as the closest known one would be an implicit trust decision made by the wire layer, which `BLUEPRINT.md` §09 explicitly forbids ("Must Not: Decide business policy"). |
| MCP extensions/experimental capabilities not reviewed by Culvert | Not supported | An unreviewed capability bit in a handshake **MUST NOT** be honored implicitly; the kernel advertises only the capability set it has actually implemented and bounded. |
| Every MCP transport/extension/version on day one | Explicit V1 non-goal (`BLUEPRINT.md` §06) | N/A — scoping decision, not a runtime fallback. |

"Downgrade-safely" here means: when the kernel cannot support something a client/server requests, the
**safe** outcome is an explicit rejection or a reduced, still-fully-validated capability set — never a
silent attempt to proceed with an unverified assumption about what the peer meant.

---

## 8. Adapter Policy

- **Version adapters live in the protocol kernel component**, not in the Policy Engine, Identity
  Resolver, Credential Broker or Inspection Pipeline (`BLUEPRINT.md` §09 component-responsibility table:
  "MCP Listener / Protocol Kernel — Termination, framing, version adapters, lifecycle and bounds" /
  "Must Not: Decide business policy or contain business rules"). This keeps the version-compatibility
  concern isolated: a new supported version is a protocol-kernel change, and it does not require touching
  policy/identity/credential/inspection logic, which stay version-agnostic against the adapter's
  normalized internal representation.
- **Suggested package boundary** (design intent, `[INFER]` from `BLUEPRINT.md` §09's package-boundary
  sketch: `internal/mcp/protocol`): each supported version gets its own adapter that translates the
  wire-specific message shape into one internal, version-agnostic representation consumed by every
  downstream stage. Downstream code never branches on protocol version.
- **Unknown or newer versions**: default **deny** — an unrecognized version is rejected at negotiation
  (§2), never passed through to an adapter on a "best guess" basis. This is the direct application of the
  repository-wide default-deny posture (`CLAUDE.md` "Default deny", precedent: `policy.go:1142`,
  `proxy.go:543-556` — cited as **prior-art posture only**, not as MCP-reused code) to the protocol layer.
- **Disabling a version safely**: if a previously supported version is later found to have a
  security-relevant flaw, the adapter for that version **MUST** be removable/disable-able from the
  allowlist (§2) as a config change, and disabling it **MUST** fail closed for any session still
  attempting to negotiate it — not fail open to a lower/older adapter implicitly. This mirrors
  `MCP-CPDP-003`'s mixed-version discipline (a DP below minimum version must not apply) applied to
  client-to-kernel version compatibility instead of CP-to-DP.
- Mixed protocol versions across concurrent sessions are an expected, supported condition (the allowlist
  in §2 can contain more than one entry); mixed versions across **CP/DP** config sync is the distinct
  concern tracked as MCP-T-050 and `MCP-CPDP-003` — the two "mixed version" concepts are not the same
  thing and must not be conflated in tests or documentation.

---

## 9. Downgrade Policy

- The protocol kernel **never auto-negotiates down** to a version or capability set the client did not
  explicitly request and the kernel did not explicitly advertise as supported. There is no implicit
  "try the newest, fall back silently" loop that could mask an integrity failure as a version mismatch.
- If a session cannot be established under any mutually acceptable version (§2) or any mutually acceptable
  capability set, the correct behavior is an **explicit negotiation failure**, not a silent narrowing of
  security properties (e.g. dropping Origin/Host validation, or dropping bearer-token audience checks) to
  "make the connection work."
- Any degraded/disable-safely mode (§7, §8) reduces **functionality**, never reduces **security
  invariants** — `MCP-AUTH-001/002/003`, `MCP-INSP-008`, and default-deny (§8) apply identically regardless
  of which supported version or capability subset a given session negotiated.
- `[EXT]` note: whether the base MCP specification itself defines a standard version-downgrade or
  capability-negotiation failure mode is an external fact to verify before PR-1; the policy above is
  Culvert's own floor regardless of what the spec allows as a minimum.

---

## 10. Compatibility-Test Requirements

Per the PR-0 brief's CI evidence, **these fixtures do not exist today** — VERIFIED EVIDENCE lists, among
the items "MISSING for MCP": malicious-MCP-server tests, OAuth-negative matrix, DNS-rebinding lab, inbound
Origin/Host tests, SSE-exhaustion, mixed-version/stale-epoch/corrupt-snapshot MCP gates, and MCP-off
overhead regression. None of these MCP-specific **fixtures/gates** exist in the current CI pipeline
(`pr-fast-gate.yml`/`pr-deep-gate.yml`/`ci.yml`). (`codeql.yml` **does** already analyze `internal/mcp/**`
via its `internal/**` PR path filter, but is non-blocking — see [`CI-GATES.md`](CI-GATES.md), finding M-1;
that is CodeQL SAST, not the MCP compatibility/fuzz fixtures listed here.) This section states what PR-1 and
later slices must add, and is intentionally a **requirements list**, not a claim that any of it exists.

| Fixture class | Purpose | Threats exercised | Requirement(s) | Gate |
|---|---|---|---|---|
| Protocol-version conformance fixtures | Prove the kernel negotiates every allowlisted version, rejects every non-allowlisted version, refuses silent downgrade, and that version adapters are equivalent. | MCP-T-066,067,068 (version negotiation/downgrade/adapter differential); MCP-T-050 (mixed CP/DP version, distinct) | `MCP-PROTO-010,011` | PR-1 (**fixtures + greenness gated on D-1**) |
| Malformed/non-compliant JSON-RPC fixtures | Prove the kernel bounds and rejects malformed envelopes without a crash, panic, or unbounded resource use, and that parsing is non-differential. | MCP-T-057,058,063,073,074 (malformed/differential/exhaustion/crash) | `MCP-PROTO-001,006,009,013` | PR-1 |
| Malicious/non-compliant MCP **server** fixtures | Prove the kernel and downstream tool-discovery layer do not trust a hostile server's self-reported tool list, schema, or identity claims. | MCP-T-011..017 (tool poisoning, shadowing, schema drift, description drift, rug pull, server identity change, unknown-tool auto-allow) | `MCP-TOOL-001..006`, `MCP-SERVER-001..003` | PR-2 |
| Origin/Host validation primitive fixtures | Prove the pure Origin/Host accept/reject decision + empty-allowlist fail-closed (no socket, no listener). | MCP-T-031, MCP-T-055 | `MCP-INSP-008` | PR-1 |
| Inbound listener rebinding E2E fixtures | Prove the running listener binds only configured interfaces and rejects a bad Origin/Host at connect (§4). | MCP-T-031 (inbound DNS-rebinding vs MCP/SSE listener), MCP-T-055 (localhost bypass), MCP-T-052 (DMZ abuse) | `MCP-INSP-009` | PR-5 |
| SSE-exhaustion / slow-client / queue-saturation load fixtures | Prove connection/stream/queue bounds hold under adversarial load. | MCP-T-042 (SSE exhaustion), MCP-T-043 (slow-client), MCP-T-044 (queue saturation/event-loss) | `MCP-OPS-002` | PR-5 |
| OAuth-negative matrix | Prove missing/invalid/query-string/wrong-audience/wrong-resource/replayed tokens are all rejected. | MCP-T-001..005 | `MCP-AUTH-001..006` | PR-3 |
| Mixed-version CP/DP fixtures | Prove a DP below minimum_dp_version does not apply a snapshot, distinct from client-protocol-version mixing. | MCP-T-050, MCP-T-047 | `MCP-CPDP-003` | PR-10 |
| MCP-off overhead regression | Prove MCP disabled causes no measurable SWG regression. | — (availability/product-integrity concern) | `MCP-OPS-001` | PR-5 |

Full threat→requirement→control→test→evidence→owner→gate traceability for every row above is the
responsibility of [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md) — this section only
identifies the protocol-compatibility-specific fixture classes that matrix must account for. Per the
brief's required risk phrasing: the current absence of these fixtures is a real gap, and while the
associated risk is judged **"Low for the read-only Phase 1 investigation, the current repository test
baseline remains unverified in this session"** — this is never stated as zero or none.

---

## Cross-references

- [`README.md`](README.md) — package index and the shared-vs-separate doctrine for the two MCP
  capabilities.
- [`BLUEPRINT.md`](BLUEPRINT.md) — §06 (principles/non-goals), §07 (V1 scope), §09 (component
  responsibilities and trust boundaries), §23 (PR-1 Protocol Kernel slice).
- [`VERIFIED-REPOSITORY-CONTEXT.md`](VERIFIED-REPOSITORY-CONTEXT.md) — repository evidence cited throughout
  (no existing MCP listener, `auth_oidc_flow.go:523` audience binding, `isSafeRedirectURL`
  captive-portal-only scope, CI gate composition).
- [`THREAT-MODEL.md`](THREAT-MODEL.md) — canonical definitions for every MCP-T-### threat ID referenced
  here.
- [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) — canonical definitions for every MCP-AUTH/
  MCP-INSP/MCP-OPS/MCP-CPDP requirement ID referenced here.
- [`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md) — the principal/identity/credential model
  that §6 depends on but does not restate.
- [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md) — full traceability for the fixture classes
  in §10.
- [`CI-GATES.md`](CI-GATES.md) — classification of which of these compatibility gates are Existing /
  Insufficient / Proposed.
