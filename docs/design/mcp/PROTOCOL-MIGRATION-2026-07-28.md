# MCP Protocol Migration — frozen V1 → `2026-07-28`

**Status:** Design only. Nothing in this document is implemented or activated.
**Owner:** MCP Agent Security Gateway (ADR-0024)
**Authored:** 2026-08-24, during the MCP backend security review
**Supersedes nothing.** Extends `PROTOCOL-COMPATIBILITY.md`; the frozen V1
baseline recorded there is unchanged by this document.

---

## 1. Why this document exists

`internal/mcp/protocol/version.go` carried a stale factual claim: it listed
`2026-07-28` in the `rejected` map and described it as "a non-final RC kept as
comparison material only". That was true of the **2026-05-21 release candidate**.
The specification was **released as final on 2026-07-28** after a ten-week
validation period.

The comment has been corrected. **The allowlist has not been changed**, and must
not be changed as a side effect of correcting it:

```go
var supported = map[Version]struct{}{
    VersionPrimary: {}, // 2025-11-25
    VersionFloor:   {}, // 2025-06-18
}
```

Rejecting `2026-07-28` is now a *deliberate, dated* decision rather than an
out-of-date one. This document records what adopting it would actually require.

## 2. What changed in `2026-07-28`

The release is the largest revision in MCP's history. The relevant normative
changes, grouped by what they cost Culvert:

### 2.1 Stateless protocol core

| V1 (`2025-11-25` / `2025-06-18`) | `2026-07-28` |
|---|---|
| `initialize` / `notifications/initialized` handshake | **Removed.** No handshake. |
| `Mcp-Session-Id` response + request header | **Removed.** No session identifier. |
| Protocol version negotiated once, at initialize | Carried in `_meta` on **every** request |
| Client identity / capabilities exchanged once | Carried in `_meta` on **every** request |
| Server capabilities learned from `InitializeResult` | `server/discover` RPC, callable at any time, **not mandatory** |

### 2.2 Header-level routing

Two new **required** headers carry what previously only the JSON-RPC body knew:

- `Mcp-Method` — the JSON-RPC method name
- `Mcp-Name` — the tool / prompt / resource name

The stated purpose is that gateways and load balancers can route and authorize on
headers without inspecting the body.

### 2.3 Caching

`tools/list`, `prompts/list`, `resources/list` and `resources/read` responses gain
`ttlMs` and `cacheScope`, enabling client-side caching of tool descriptors.

### 2.4 Authorization hardening

- RFC 9207 issuer validation required.
- `application_type` added to Dynamic Client Registration.
- Client credentials bound to the issuing authorization server.
- **CIMD** (Client ID Metadata Documents) replaces DCR as the standard.

### 2.5 Multi Round-Trip Requests (MRTR)

Server-initiated interactions (`elicitation/create`, `sampling/createMessage`)
become stateless: the server returns `resultType: "input_required"` and the client
re-submits with `inputResponses` attached.

### 2.6 Deprecations and extensions

- Roots, Sampling, Logging and the HTTP+SSE transport are deprecated with a
  twelve-month minimum migration window.
- **Tasks** and **EMA** (Enterprise Managed Authorization) are formalized as
  namespaced extensions (`io.modelcontextprotocol/tasks` and siblings).

## 3. What this costs Culvert

The V1 baseline is not merely a parser — several security controls are *built on*
V1's statefulness. Each of the following is a load-bearing invariant, with a test
suite behind it, that `2026-07-28` removes the substrate for:

| Control | Where | Depends on |
|---|---|---|
| Immutable session-identity binding | `internal/mcp/identity/binding.go` | A session id. One identity per session, rebind rejected. |
| Cross-server session confusion defence | `computeFingerprint` includes the server id | A session that can be *reused* at all |
| Lifecycle admission (the reviewed six methods) | `internal/mcp/session` + `protocol.Admission` | `initialize` establishing a lifecycle state machine |
| Session cap / sweeper / TTL | `session.Manager`, `Listener.sweepLoop` | Sessions existing |
| Per-session outstanding-request bound | `limits.MaxOutstandingPerSession` | Sessions existing |
| Version pinning per session | `sess.SetNegotiatedVersion` | Negotiation happening once |

Under a stateless protocol, "one identity per session, immutable" has to become
**"one identity per request, cross-checked against a caller-stable binding key"**
— a genuinely different design, not a parser change. That is the single largest
item of work here and it is an ADR-level decision, not an implementation detail.

### 3.1 Per-control stateless replacements

Naming the replacement for each control is the work that turns §3's table from a list
of losses into a design. Added 2026-08-25.

The load-bearing observation is that the substrate already exists. A stateless protocol
removes the *session id*, not the caller's identity — and Culvert already derives, per
request, a cryptographically verified statement about who is presenting the credential:
`identity.SenderConstraint` (`ConfirmDPoP` from the RFC 9449 proof's `jkt`, `ConfirmMTLS`
from the client certificate's `x5t#S256`). That value is verified, not asserted, and it
is stable across requests from the same caller. It is the natural binding key.

| Control | V1 substrate | Stateless replacement | Status |
|---|---|---|---|
| Immutable session-identity binding | session id | Per-request binding key = the verified sender constraint (`jkt` / cert thumbprint). "One identity per session, rebind rejected" becomes "the subject claimed by this request must equal the subject this binding key has been seen with", enforced against a bounded, TTL'd key→subject map. | **Designable now.** Needs an ADR: the map's bound, eviction (the `internal/authstate` fair-share pattern applies — a flooding key must evict itself), and behaviour on first sight. |
| Cross-server session confusion | server id inside `computeFingerprint` | Unchanged. `computeFingerprint` already spans capability, tenant, subject, client, agent, resource, server and tool and contains **no session id** — it is already a stateless value. `Mcp-Name` routing supplies the server id per request instead of per session. | **No work.** Verified 2026-08-25. |
| Lifecycle admission (six methods) | `initialize` state machine | Per-request method admission against the transport-declared version. The admitted set is already a static allowlist; what disappears is the ordering constraint (`initialize` first), not the allowlist. | **Simplification, not a gap.** |
| Session cap / sweeper / TTL | sessions existing | Replaced by the per-connection request budget (already shipped, OVN-07) plus the existing per-listener `MaxConcurrent`/`QueueDepth`. These bound the same resource without needing a session to hang state on. | **Already shipped.** |
| Per-session outstanding-request bound | sessions existing | Same as above — the per-connection budget is strictly the better control, because it bounds the socket that actually consumes the workers rather than a logical session a client can mint at will. | **Already shipped.** |
| Version pinning per session | negotiation happening once | Per-request transport-declared version, normalized through `protocol.Adapter` before any later stage. The adapter seam is invoked as of this review, so a V2 message is normalized at exactly one point. | **Seam exists.** |

**The one genuine gap: a bearer-only deployment has no stable binding key.** With
`sender_constraint: none` there is no `jkt` and no certificate thumbprint, so per-request
binding degrades to "trust the token's `sub`" — which is what a bearer token means, but is
strictly weaker than V1's immutable session binding. Three options, none of which should be
chosen here:

1. Require a sender constraint for V2 (the shipped observe default is already
   `sender_constraint: mtls`, so this costs most deployments nothing).
2. Accept the degradation for bearer-only and say so on the status surface, so it is
   visibly absent rather than silently weaker.
3. Derive a weaker binding key from the token itself (e.g. its `jti`), accepting that a
   caller who can mint tokens can mint binding keys.

Option 1 is the recommendation, and it is an ADR decision precisely because it changes what
configurations are permitted. It should be settled BEFORE any V2 implementation begins, not
during — the binding model determines the shape of everything else in this table.

## 4. Migration architecture — additive V2 adapter

The repository already declares the right boundary:

```go
type Adapter interface {
    Version() Version
    Normalize(msg jsonrpc.Message) (jsonrpc.Message, error)
}
```

Until this review it was **declared and never invoked** — the pipeline decoded a
message and passed it straight downstream, so the boundary that is supposed to
keep protocol version out of every later stage did not exist at runtime. It is now
invoked from `pipeline.processPost` (`normalizeForVersion`), immediately after the
strict decode and before any session logic, on the transport-declared wire
version. For the two V1 revisions the adapters are the identity, so the change is
behaviour-preserving — but the seam is real, and it is where V2 lands.

### 4.1 Non-negotiable constraints on the V2 work

1. **V1 stays frozen.** `VersionPrimary` and `VersionFloor` keep their exact
   current semantics. A V2 adapter must not alter a V1 request's handling in any
   way, and the existing V1 test suites are the regression wall.
2. **The allowlist is never widened without an adapter.** Adding `2026-07-28` to
   `supported` before a V2 adapter exists would admit a wire shape the kernel
   cannot represent — the exact best-effort interpretation MCP-PROTO-010 forbids.
3. **Normalization is one-way and total.** V2 normalizes *into* the existing
   version-agnostic internal representation. No downstream stage may branch on
   version. If a V2 concept cannot be expressed in the internal representation,
   the internal representation is extended for both versions — the adapter never
   leaks a version-shaped field downstream.
4. **No silent downgrade in either direction.** A V2 client must not be answered
   as V1, and a V1 client must not be answered as V2.
5. **The upstream leg migrates separately.** `upstreamclient` negotiates its own
   version with the registered server; a V2 client leg does not imply a V2
   upstream leg. The two are independently gated.

### 4.2 Staged plan

Each stage is independently reviewable and independently revertible. **No stage
activates the next.**

**V2-0 — seam (DONE).** `protocol.AdapterFor` is invoked from the request path;
`wireVersion` resolves the transport-declared revision; a present-but-unsupported
revision is *not* laundered to the primary. Behaviour-identical for V1.

**V2-1 — internal representation.** Extend the kernel message representation with
the facts V2 carries per request and V1 carries per session: protocol version,
client identity, client capabilities. For V1 the adapter fills them from the
session; for V2 from `_meta`. No wire change, no new admitted version. This is
where the "session-derived vs request-derived facts" split is proven by tests,
against V1 only.

**V2-2 — stateless identity binding (ADR REQUIRED).** Design and record how
one-identity-per-session becomes one-identity-per-request without losing:
- rebind rejection (a second, different identity on the same *caller-stable*
  binding key),
- cross-server confusion rejection (the server id must stay in the binding
  fingerprint),
- the bounded-cardinality property the session cap currently provides — a
  stateless protocol removes the natural bound on how many distinct binding keys
  an unauthenticated caller can mint, so the replacement needs its own explicit
  cap and eviction policy (compare `internal/authstate`'s fair-share eviction,
  which exists for exactly this failure mode on the SWG side).

This is a **blocker** for V2-3 and must not be improvised during implementation.

**V2-3 — V2 adapter, behind the frozen allowlist.** Implement
`Normalize` for `2026-07-28` — `_meta` extraction, `server/discover`,
`Mcp-Method`/`Mcp-Name` cross-checks — with `2026-07-28` still ABSENT from
`supported`. The adapter is exercised only by tests. Nothing on the wire changes.

**V2-4 — header/body agreement.** `Mcp-Method` and `Mcp-Name` are attacker-supplied
duplicates of body facts, so they are a **confusion surface, not a shortcut**. The
rule must be: the body remains authoritative, and a header that disagrees with the
body is a rejection, never a resolution. (The same anti-ambiguity posture as the
duplicate-singleton-header rule added in this review — these two headers must join
the guarded singleton set.) Routing on the header is acceptable *before* the body
is read only if the post-read cross-check is unconditional.

**V2-5 — authorization delta.** RFC 9207 issuer validation, `application_type`,
client-credential/AS binding, and the CIMD direction. CIMD replacing DCR is a
trust-model change (the client's identity document becomes a fetched, potentially
attacker-influenced URL) and needs its own threat-model pass — treat it as a
sibling of the SSRF-guarded release-catalog fetch, not as an OAuth detail.

**V2-6 — activation review.** Only here does `2026-07-28` enter `supported`, and
only behind an explicit operator opt-in with a documented downgrade path.

### 4.3 Explicitly out of scope for V2

- **MRTR** — server-initiated `elicitation/create` / `sampling/createMessage` are
  outside the admitted V1 method set today and stay outside it. Admitting a
  server-initiated round trip is a trust-boundary change (the upstream server
  gains the ability to drive the client), and ADR-0024's Model-A posture excludes
  it.
- **Roots / Sampling / Logging / HTTP+SSE** — deprecated upstream and never
  admitted here. No work required.
- **Tasks / EMA extensions** — namespaced extensions, separately reviewable. EMA
  is directly relevant to Culvert's product position and deserves its own design
  note, but it is not a prerequisite for V2.

## 5. Risk of NOT migrating

Recorded so the decision is balanced rather than a default:

- **Client compatibility erosion.** As SDKs default to `2026-07-28`, a client that
  cannot fall back to `2025-11-25` cannot talk to Culvert at all. The counter-offer
  path (`Negotiate` returns the primary with `CounterOffered`) only helps clients
  that still implement V1.
- **Upstream compatibility erosion.** The same applies to registered MCP servers
  on the upstream leg, where Culvert is the client.
- **Ecosystem authorization drift.** If CIMD becomes the norm, a Culvert
  deployment pinned to DCR diverges from how its customers' IdPs issue MCP client
  identities.

None of these are security regressions, and none justify widening the allowlist
ahead of the staged work above. They justify **scheduling** it.

## 6. Traceability

| Item | Status |
|---|---|
| Stale "non-final RC" comment corrected | DONE (this review) |
| `protocol.Adapter` invoked from the request path | DONE (this review) |
| `wireVersion` refuses to launder an unsupported revision | DONE (this review) |
| Anti-weakening test pinning the seam is reached | DONE (`TestVersionAdapter_RequestPathInvokesTheSeam`) |
| V1 allowlist unchanged | DONE — `supported` is byte-identical |
| V2-1 … V2-6 | NOT STARTED |
| Stateless identity binding ADR | NOT STARTED — **blocker for V2-3** |
