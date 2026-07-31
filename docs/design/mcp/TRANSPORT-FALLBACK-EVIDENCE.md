# MCP Transport-Fallback Evidence Matrix — terminal rejection without legacy SSE fallback

**Status:** Accepted-baseline authority (PR-0 / RPR-4 design artifact; documentation-only remediation of
board blocker [#929](https://github.com/KidCarmi/Culvert/issues/929), coordinated with **Gate 3 / D-1**). No
control below is implemented — this is design-time authority only, and the runtime lands in PR-1+ per slice
ownership. **[ADR-0024](../../adr/0024-mcp-agent-security-gateway-trust-boundary.md) is Accepted. D-1 is
CLOSED — the V1 baseline is frozen (see [OPEN-DECISIONS.md](OPEN-DECISIONS.md) §D-1). PR-1 implementation is
GO (protocol-kernel scope only).** This document records the **transport portion** of the closed D-1
baseline: primary `2025-11-25`, floor `2025-06-18`, all other revisions (incl. `2024-11-05`, `2025-03-26`,
`2026-07-28`) rejected.

This file is the **single authoritative evidence base** for every normative transport / HTTP-status /
legacy-fallback statement the RPR-4 posture makes. Every such statement is bound to one of: (1) official MCP
specification text; (2) official MCP schema/lifecycle text; (3) observed behavior in an official SDK; (4)
observed behavior in a clearly identified representative SDK when no official SDK implements the path. A
statement with none of these is recorded **UNRESOLVED**, never chosen by preference.

---

## 0. Current official MCP release state (re-verified at execution time)

Re-verified **2026-07-31** from official primary sources (the docs site returns 403 to unauthenticated
fetch; the authoritative source is the specification GitHub repository, cloned at the commit below).

- **`2025-11-25` is the Current stable revision.** **`2026-07-28` is a Release Candidate (RC/draft), NOT
  final.** The official RC announcement states the *"release candidate for the next Model Context Protocol
  (MCP) specification is now available"* and that *"the final specification ships on July 28, 2026"* — i.e.
  it is **not yet** the stable/current version. (Blog: `blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/`,
  verified 2026-07-31.)
- Prior stable revisions in scope for the 2025-era discussion: `2025-06-18` and `2025-11-25`. Earlier
  revisions `2024-11-05` (legacy HTTP+SSE) and `2025-03-26` exist but are **excluded** from the Culvert V1
  admitted set (see §2 and §7).
- **Spec source-of-truth commit:** `modelcontextprotocol/modelcontextprotocol` @
  `73763114e511106fc07543f6096b3a814b1a3583` (branch `main`, committed 2026-07-30). Revision directories
  under `docs/specification/<revision>/` are frozen per revision.

**Governance guardrail:** the `2026-07-28` RC is **comparison / evidence only** in this document. Nothing
here makes 2026-era stateless behavior part of the V1 stable baseline; the closed D-1 baseline **rejects**
`2026-07-28`, and admitting any 2026-era revision would require a **separate future decision** beyond this
V1 baseline (it is not admitted by the current closure).

---

## 1. Two protocol eras — explicitly separated (never collapsed)

The design separates two structurally different protocol eras. A 2025-era initialize / status / session
rule **MUST NOT** be applied to the 2026 era, and a 2026-era stateless/discovery rule **MUST NOT** be
applied to the 2025 era.

### 1a. 2025-era — sessionful Streamable HTTP (the V1 candidate baseline)

Applies to the eventually-approved subset of `2025-06-18` and `2025-11-25`. Characteristics
(spec-verified, §4): an `initialize` / `notifications/initialized` handshake; protocol-version negotiation
carried in the initialize exchange; **optional** protocol sessions (`Mcp-Session-Id`); `MCP-Protocol-Version`
required on subsequent HTTP requests; optional GET/SSE server→client stream; and a documented
backwards-compatibility probe for legacy `2024-11-05` HTTP+SSE servers. This is the era to which the
status-code contract in §6 applies.

### 1b. 2026-era — stateless RC/draft (`2026-07-28`) — COMPARISON / EVIDENCE ONLY, NON-BINDING

The `2026-07-28` RC removes or materially changes: the `initialize`/`initialized` handshake (removed); the
protocol-level session and `Mcp-Session-Id` (removed); portions of GET/SSE server→client behavior (replaced
by a stateless `InputRequiredResult` re-issue pattern); and the server→client interaction model (stateless
core — *"any MCP request can land on any server instance"*). Because this revision is a **non-final RC**,
its behavior is recorded here for comparison and forward-evidence **only**. It is **not** a V1 stable
baseline rule and **MUST NOT** be treated as one unless a separate future decision (beyond the closed V1
D-1 baseline) admits a final specification revision.

---

## 2. Legacy `2024-11-05` HTTP+SSE exclusion (binding V1 invariant)

Culvert V1 hosts **no** legacy `2024-11-05` HTTP+SSE transport pair. Concretely, and as an explicit
supported-transport **decision** (not an accidental omission):

- **no** legacy SSE endpoint that emits an `endpoint` event as its first SSE event;
- **no** legacy POST endpoint paired with such an SSE endpoint;
- **no** compatibility alias or redirect that reaches either;
- **no** configuration switch, profile flag, YAML/env/CLI/API/GUI field, or "allow-unknown transport era"
  option that can enable either.

Evidence that this is a first-class transport choice, not a gap: the official MCP specification defines the
legacy transport only in `docs/specification/2024-11-05/`, and the official TypeScript SDK isolates the
legacy server that emits the `endpoint` event into a **separate opt-in package**
(`@modelcontextprotocol/server-legacy`); the default server package emits no `endpoint` event. A server
therefore hosts the legacy endpoint-event transport only by deliberately depending on that package — which
Culvert does not do. (Source: `typescript-sdk` @ `cc4b416`, `packages/server-legacy/package.json`; the
default `packages/server/src` emits no `endpoint` event.)

---

## 3. No pre-negotiation held stream (binding V1 invariant)

For the 2025-era Culvert endpoint, this is an **invariant**, not merely a connection-count bound:

- **No** GET path may allocate an SSE stream before a valid negotiated session — or other explicitly
  authorized stream context — exists.
- A legacy-probe GET (a client that concluded Culvert is a legacy server and issued the follow-on GET)
  **MUST** terminate without retaining a stream.
- A response path that cannot produce the legacy `endpoint` event **MUST NEVER** open a `text/event-stream`
  and hold it open waiting; it returns the terminal status instead (§6).
- **N rejected clients MUST leave zero retained streams.** (Load assertion specified at PR-5; see §9 fixture 10.)

This closes the #929 self-amplifying vector: an unauthenticated, pre-initialize, indefinitely-held stream
per rejected client, reachable precisely via the security-rejection path (`MCP-T-078`, `MCP-PROTO-017`).

---

## 4. Evidence matrix (normative spec vs observed SDK — separate rows where they differ)

Fourteen columns. Normative specification rows carry `spec` in the *SDK/source observed* column; SDK rows
name the SDK. A spec requirement and an SDK fallback implementation that diverge are **separate rows**.
`VERIFIED` = backed by exact revision (spec) or exact commit (SDK); `CONFLICTING` = a sourced spec-vs-SDK
divergence; `UNRESOLVED` = no primary source settles it, so it is not a binding decision. Source-locator
abbreviations: `SPEC` = `modelcontextprotocol/modelcontextprotocol@73763114` (revision dirs frozen);
`TS` = `typescript-sdk@cc4b416` (tag `@modelcontextprotocol/client@2.0.0`); `PY` = `python-sdk@a4f4ccd`;
`GO` = `go-sdk@0c004ee`.

| Era / revision | Request stage | Trigger / input | Normative server response | HTTP status | JSON-RPC body / result shape | Client follow-on behavior | SDK / source observed | Legacy-SSE probe possible | Stream allocation permitted | Culvert V1 decision | Impl gate | Evidence status | Source locator |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2025-era (2025-06-18 / 2025-11-25) | initial initialize | client offers a version the server supports | server MUST respond with the same version | 200 | InitializeResult with negotiated version | proceeds; no probe | spec | no | no | counter-offer/echo at HTTP 200 | PR-1 | VERIFIED | SPEC lifecycle.mdx@2025-11-25 L165-171 |
| 2025-era (2025-06-18 / 2025-11-25) | initial initialize | client offers an unsupported version | server MUST respond with another version it supports (counter-offer) | 200 | InitializeResult with server-selected version | if client cannot support it, client SHOULD disconnect (clean, no probe) | spec | no | no | PREFER 200 counter-offer; never a 4xx hard reject here | PR-1 | VERIFIED | SPEC lifecycle.mdx@2025-11-25 L165-171 |
| 2025-era (2025-06-18 / 2025-11-25) | initial initialize | initialize failure illustrated as a JSON-RPC error | error MAY be carried; transport MAY 400 | 200 or 400 | JSON-RPC error -32602 Unsupported protocol version with data.supported and data.requested | on HTTP 400 the client MAY start the legacy probe; on HTTP 200 no HTTP-status probe trigger | spec | yes on 400 / no on 200 | no | avoid 4xx on initialize; if terminal, guarantee follow-on GET is 405 zero-stream | PR-1 | VERIFIED | SPEC lifecycle.mdx@2025-11-25 L273-283; transports.mdx L95-99 |
| 2025-era (2025-06-18 / 2025-11-25) | GET | GET to the MCP endpoint without a valid negotiated session/context | server MUST return text/event-stream OR HTTP 405 Method Not Allowed | 405 | none (no body required) | 405 means no SSE at endpoint; a legacy-probe GET that receives 405 gets no endpoint event and terminates | spec | this row IS the probe target | no | return 405; allocate zero stream | PR-1 primitive / PR-5 listener | VERIFIED | SPEC transports.mdx@2025-11-25 L137-141 |
| 2025-era (2025-06-18 / 2025-11-25) | protocol-version header | invalid or unsupported MCP-Protocol-Version header | server MUST respond 400 Bad Request | 400 | JSON-RPC error MAY accompany | 400 is a spec-listed probe trigger; client MAY issue the follow-on GET, which MUST be terminal 405 | spec | yes | no | adopt 400 as-is; ensure follow-on GET is 405 zero-stream | PR-1 / PR-5 | VERIFIED | SPEC transports.mdx@2025-11-25 L277-280, L299-307 |
| 2025-era (2025-06-18 / 2025-11-25) | protocol-version header | header ABSENT and the server has no other way to identify the version | server SHOULD assume 2025-03-26 | n/a | n/a | proceeds as 2025-03-26 (sessionless first-request case) | spec | no | no | UNRESOLVED sessionless ruling (D-1); with session/context Culvert has another way and honoring is conformant; do NOT silently admit 2025-03-26 | PR-1 (D-1) | UNRESOLVED | SPEC transports.mdx@2025-11-25 L274-277 |
| 2025-era (2025-06-18 / 2025-11-25) | missing session | request (other than initialize) without MCP-Session-Id when the server requires one | server SHOULD respond 400 Bad Request | 400 | JSON-RPC error MAY accompany | 400 is a spec-listed probe trigger; follow-on GET MUST be terminal 405 zero-stream | spec | yes | no | 400; follow-on GET 405, zero stream | PR-1 / PR-5 | VERIFIED | SPEC transports.mdx@2025-11-25 L207-210, L299-307 |
| 2025-era (2025-06-18 / 2025-11-25) | terminated session | request carrying a terminated or unknown session id | server MUST respond 404 Not Found | 404 | JSON-RPC error MAY accompany (SDKs surface Session terminated) | conformant clients re-initialize on 404; 404 is ALSO a spec-listed probe trigger, so follow-on GET MUST be terminal 405 zero-stream | spec | yes | no | 404; follow-on GET 405, zero stream | PR-1 / PR-5 | VERIFIED | SPEC transports.mdx@2025-11-25 L211-212, L299-307 |
| 2025-era (2025-06-18 / 2025-11-25) | DELETE | client DELETE to terminate a session when termination is unsupported | server MAY respond 405 Method Not Allowed | 405 | none | client accepts that termination is not offered (benign); no stream involved | spec | 405 is a GET-probe trigger, but this DELETE follows an established session, not a pre-negotiation probe | no | 405; zero stream | PR-1 / PR-5 | VERIFIED | SPEC transports.mdx@2025-11-25 L215-219 |
| 2025-era (2025-06-18 / 2025-11-25) | subsequent POST | malformed / oversized / over-bounds request | kernel emits a bounded, non-leaky JSON-RPC error; over-bounds MAY 400 | 200 or 400 | bounded JSON-RPC error, no internal state | client sees an error; no stream opened | spec + Culvert design | depends on HTTP status; if 400, follow-on GET MUST be 405 zero-stream | no | bounded error, zero stream | PR-1 | VERIFIED | SPEC transports.mdx@2025-11-25 L95-99; MCP-PROTO-006/013 |
| 2024-11-05 (legacy) | GET (legacy probe target) | client concluded a legacy server and issued GET expecting an SSE stream whose first event is endpoint | legacy server would open text/event-stream and emit endpoint | 200 (legacy) | SSE endpoint event as first event | client waits for endpoint, then POSTs to the advertised URL | spec | this IS the legacy transport Culvert excludes | no (Culvert never opens it) | NOT HOSTED — Culvert emits no endpoint event and returns 405 on this GET | PR-1 / PR-5 | VERIFIED | SPEC transports.mdx@2025-11-25 L299-307; 2024-11-05 transports |
| 2025-era SDK (app-level) | initialize connect | any error thrown by StreamableHTTP client.connect() | n/a (client-side) | n/a | n/a | catch-ANY fallback: constructs SSEClientTransport (legacy 2024) and connects it | TS | yes (catch-any, not status-specific) | the legacy SSE client then opens a hanging GET (next row) | Culvert must return 405 on that GET so the fallback terminates with zero retained stream | PR-5 | VERIFIED | TS packages/client/src/client/client.examples.ts L56-75 |
| 2025-era SDK (legacy client) | GET (legacy SSE) | SSEClientTransport connect opens EventSource GET | n/a | n/a | awaits endpoint event before resolving connect | BLOCKS awaiting the endpoint event; if none arrives it hangs until the EventSource errors/times out | TS | yes | client-side stream held until endpoint or error | Culvert 405 makes the EventSource error immediately; Culvert retains zero server-side stream | PR-5 | VERIFIED | TS packages/client/src/client/sse.ts L244-256 |
| 2025-era SDK | GET (standalone) | streamable client GET receives 405 | n/a | 405 | none | treats 405 as benign: no SSE offered, no per-request stream retained | TS | n/a | no | consistent with Culvert 405 zero-stream posture | PR-5 | VERIFIED | TS packages/client/src/client/streamableHttp.ts L609-618 |
| 2025-era SDK | initialize | HTTP 200 carrying a JSON-RPC error | n/a | 200 | JSON-RPC error | spec: 200 is not an HTTP-status probe trigger; BUT the app-level catch-any wrapper treats the thrown connect error as a fallback trigger and probes legacy anyway | TS | yes via catch-any (diverges from the HTTP-status rule) | see legacy-client row | this is WHY Culvert prefers a 200 SUCCESS counter-offer over a 200-carried error | PR-1 / PR-5 | CONFLICTING | TS client.examples.ts L56-75 vs SPEC transports.mdx L299-307 |
| 2025-era SDK | session 404 | streamable client receives 404 with a session id | n/a | 404 | Session terminated / ErrSessionMissing | treats 404 as session terminated and re-initializes (does not legacy-probe when it holds a session) | PY, GO | no (reinitialize path) | no | Culvert 404 for terminated session is safe against these clients | PR-5 | VERIFIED | PY streamable_http.py L342-368; GO streamable_client.go L181 |
| 2025-era SDK | GET / DELETE | streamable client GET expects text/event-stream or 405; DELETE-close | n/a | 405 | none | 405 is spec-compliant no-SSE; Close sends DELETE; server 404 ends session | GO | n/a | no | consistent with Culvert 405/404 posture | PR-5 | VERIFIED | GO streamable_client.go L114-119, L164, L52 |
| 2025-era SDK (legacy client) | GET (legacy SSE) | Python SSEClientTransport connects | n/a | n/a | first event MUST be endpoint; sse_read_timeout default 300s | holds the SSE read up to sse_read_timeout awaiting endpoint | PY | yes | client-side stream held up to 300s | Culvert 405 aborts it immediately; zero server-side retention | PR-5 | VERIFIED | PY src/mcp/client/sse.py L35, L54-81 |
| 2025-era SDK (auto probe) | connect | server/discover probe, any rpc-error outcome | n/a | n/a | n/a | denylist: every non-disjoint-modern rpc-error falls back to the 2025 initialize handshake (NOT the 2024 SSE endpoint transport) | PY, TS | no (this fallback is the 2025 initialize, not the 2024 legacy SSE) | no | confirms 2026 negotiation is separated from 2025 legacy SSE fallback | PR-5 | VERIFIED | PY _probe.py L1-107; TS probeClassifier.ts L1-140 |
| 2026-era RC (2026-07-28) NON-BINDING | initialize / session | RC removes initialize/initialized handshake, protocol sessions and Mcp-Session-Id; stateless core | n/a (stateless) | n/a | modern per-request _meta; InputRequiredResult replaces persistent SSE | modern client uses server/discover + the -32022 corrective; a modern-only client has NO legacy fallback | spec, TS, PY | no | no | EXCLUDED from V1 (non-final RC); comparison only; era MUST NOT be collapsed with 2025 | n/a (not V1) | VERIFIED | SPEC 2026-07-28/basic/index.mdx L182-184; TS probeClassifier.ts; PY _probe.py |
| 2026-era RC (2026-07-28) NON-BINDING | negotiation | modern server answers with -32022 UnsupportedProtocolVersion and a mutual version | n/a | n/a | -32022 with data.supported | client re-sends the probe once at the offered version (select-and-continue), then throws on a second rejection | TS | no (distinct from 2024 legacy SSE probe) | no | comparison only; not a V1 rule | n/a (not V1) | VERIFIED | TS probeClassifier.ts L108-140; versionNegotiation.ts |

---

## 5. Official-SDK behavior summary (exact commits)

Inspection of official SDK **source** (not examples), for the questions #929 requires. Representative SDKs
were not needed: all three official SDKs implement the client transport path.

| SDK | Commit / tag | Legacy-SSE fallback trigger | Status-specific or catch-any | HTTP 200 + JSON-RPC error → fallback? | 400 body parsed before fallback? | 404 + session id → reinitialize vs legacy probe | GET timeout / held-stream behavior | Opened legacy stream bounded/aborted? | 2026 negotiation separated from 2025 fallback? |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TypeScript | `cc4b416` (`@modelcontextprotocol/client@2.0.0`) | app-level `try StreamableHTTP … catch → SSEClientTransport` | catch-ANY (any thrown connect error) | yes — a thrown 200-carried error trips the catch-any wrapper | 400 parsed as ProtocolError only for modern-enveloped (2026) requests; else surfaced as SdkHttpError | 404 handling on the streamable path; standalone 405-GET is benign | legacy SSE client blocks in connect awaiting the endpoint event | client-side EventSource ends on error/close; a 405 aborts it at once | yes — probeClassifier + versionNegotiation isolate the -32022 corrective from the legacy `initialize` fallback |
| Python | `a4f4ccd` | `mode="auto"` server/discover probe; explicit legacy `initialize` fallback | denylist (every non-disjoint-modern rpc-error → legacy) | yes — an rpc-error outcome falls through to legacy per the denylist | 404 mapped to Session terminated (INVALID_REQUEST); ≥400 bodies read | 404 → Session terminated → reinitialize (not a 2024 SSE probe) | legacy `sse.py` holds the SSE read up to `sse_read_timeout` (default 300s) awaiting endpoint | bounded by `sse_read_timeout`; a 405 aborts immediately | yes — `_probe.py` denylist targets the 2025 `initialize` handshake, not the 2024 SSE transport |
| Go | `0c004ee` | separate `sse.go` (2024 hanging-GET endpoint transport) vs `streamable_client.go` | streamable client is status-aware (405 terminal, 404 = session missing) | not on the streamable path; legacy SSE is a distinct transport a caller selects | ≥400 bodies handled; 404 → `ErrSessionMissing` | 404 → `ErrSessionMissing` → reinitialize | legacy `sse.go` is a hanging GET whose first event MUST be endpoint | the hanging GET closes on Close/context; 405 on GET is terminal | yes — the 2024 legacy SSE transport is a separate type, not reached from the streamable client's error path |

**Cross-SDK conclusions (VERIFIED):** (1) the legacy-2024 `endpoint`-event client exists in every official
SDK as a hanging GET that blocks awaiting `endpoint`; against a server that never emits it, the client holds
its **own** stream until timeout/error. (2) A `405` on GET is treated as terminal / no-SSE by all three. (3)
A `404` with a session id drives **reinitialize**, not a 2024 legacy probe, in Python and Go. (4) The
2026-era `server/discover` + `-32022` negotiation is **separated** from the 2024 legacy SSE fallback in all
three. (5) The TypeScript app-level fallback is **catch-any**, so it can be triggered by a thrown 200-carried
error — the CONFLICTING row in §4 and the reason Culvert prefers a **200 success counter-offer** (§6).

---

## 6. Binding V1 transport posture (each decision + its source)

Subject to D-1, the 2025-era status-code contract, re-derived from the evidence above (not copied from
#929):

1. **Initialize version negotiation — prefer the 200 counter-offer.** When the client's requested version is
   supported, the server returns the same version; when unsupported, the server returns another supported
   version as the `InitializeResult`, at **HTTP 200**. If the client cannot support the server's selected
   version, it **SHOULD disconnect** — a clean termination, not a probe. Preferring a 200 success over any
   4xx (or a 200-carried error) avoids **both** the spec's 4xx legacy-probe trigger and the SDK catch-any
   app-fallback. (Source: SPEC lifecycle L165-171, L273-283; TS catch-any CONFLICTING row.)
2. **GET without valid context → 405, zero stream.** A GET to the MCP endpoint without a valid negotiated
   session (or other authorized stream context) returns **HTTP 405 Method Not Allowed** — the
   spec-sanctioned terminal alternative to `text/event-stream` — and allocates **no** stream. Never return
   an empty or indefinitely-held `text/event-stream`. (Source: SPEC transports L137-141; TS 405-benign,
   GO 405-terminal.)
3. **Invalid/unsupported `MCP-Protocol-Version` header → 400.** Adopted as-is because the transport text
   mandates it. Because 400 is a spec-listed probe trigger, the follow-on GET **MUST** be the 405 zero-stream
   terminal of decision 2. (Source: SPEC transports L277-280, L299-307.)
4. **Missing `MCP-Session-Id` (server requires session) → 400**; **terminated/unknown session → 404**;
   **DELETE when termination unsupported → 405.** Each is spec-supported; each 400/404/405 is a possible
   probe trigger, so each **MUST** be followed by the 405 zero-stream terminal on the follow-on GET, and none
   may leave a held stream. (Source: SPEC transports L207-219, L299-307; PY/GO 404→reinitialize.)
5. **Malformed / over-bounds request → bounded JSON-RPC error, zero stream.** Per `MCP-PROTO-006/013`; a 400
   carrier still routes through the 405 zero-stream follow-on. (Source: SPEC transports L95-99; MCP-PROTO-006/013.)
6. **Legacy 2024 exclusion + no-pre-negotiation-stream** are the §2 and §3 invariants, owned by the new
   `MCP-PROTO-017` and threatened by `MCP-T-078`.

For every `400`/`404`/`405` above: the row states the client follow-on behavior and proves the
zero-retention outcome (the follow-on GET is 405 and allocates no stream). No status here is chosen by
preference; each carries a source, and the one genuinely open item is recorded UNRESOLVED in §7.

---

## 7. Sessionless absent-version-header ruling (D-1 — UNRESOLVED, not chosen here)

The spec's *"SHOULD assume `2025-03-26`"* is **conditioned on the server having no other way to identify the
version**. The distinction the board identified is preserved:

- **When negotiated session state — or an equivalent trusted context — identifies the version, Culvert has
  "another way,"** so honoring that identified version is **conformant, not a deviation**. This narrows Gate 3
  conflict **C-7** materially (§8).
- **The genuine open question is the sessionless / first-request case.** This is recorded as **UNRESOLVED**
  and left to **D-1**; this PR supplies the ruling D-1 needs but does **not** close D-1.

The record must state the consequence: **admitting `2025-03-26` is not neutral.** It can alter (a) **batch
policy** (`2025-03-26` permits JSON-RPC batch arrays the baseline removes); (b) **version-header
expectations** (`2025-03-26` defines no `MCP-Protocol-Version` header); and (c) the **method/capability
surface**. Therefore Culvert **MUST NOT silently admit `2025-03-26`** on the sessionless path; any admission
is an explicit D-1 decision, tested (§9 fixture 8). (Source: SPEC transports L274-277; the batch/header
consequences are the `2025-03-26` revision's own definitions.)

---

## 8. Gate 3 amendment record (mirrors the #923 amendment comment)

This document records the Gate 3 changes RPR-4 requires; the authoritative amendment is posted as a **new
comment** on [#923](https://github.com/KidCarmi/Culvert/issues/923) (linked from the PR body — history is not
edited silently):

- **C-6 is WITHDRAWN as a false positive.** C-6 alleged that requiring an out-of-allowlist `initialize`
  version to be rejected diverges from the S2 counter-offer duty. It does not: the Gate 3 §2 proposal **is
  already** a counter-offer, and an initialize-layer rejection is itself spec-illustrated (the `-32602`
  Unsupported-protocol-version error). The live question was only the **HTTP status that carries it**, which
  #929/RPR-4 owns (decision 1, §6).
- **A-7 is REMOVED.** A-7 framed a decision — "spec-conformant counter-offer vs Culvert hard reject (C-6)" —
  that no longer exists once C-6 is withdrawn: Culvert uses the counter-offer, so there is nothing to decide.
- **C-7 is NARROWED** to the **sessionless / first-request** absent-`MCP-Protocol-Version` case only (§7). A
  gateway holding negotiated session state has "another way" to identify the version, so honoring it is
  conformant; only the sessionless case is a genuine deviation needing a recorded D-1 decision. (Approval
  item A-2, which pairs with C-7, is narrowed the same way.)
- **Status-code behavior is split by request stage and protocol era** (this document's §4 matrix), not stated
  as a single global rule.
- **No D-1 approval is implied** and **Architecture approval remains pending.** `2025-11-25` remains the
  current stable baseline candidate and `2026-07-28` remains excluded while non-final — unless official
  status has changed (re-verified 2026-07-31: unchanged).

---

## 9. Fixture matrix and D-1 dependencies

Specified, not implemented. Structural / registry / status-terminal / zero-stream properties block at
**PR-1** (primitive) or **PR-5** (listener). D-1 is now **CLOSED**, so the selected version set is fixed;
fixtures whose expected values depend on it are therefore no longer D-1-blocked but remain **`IMPL-PENDING`**
(no implementation exists) and MUST NOT be marked green until implemented in PR-1/PR-5.

| # | Fixture | Asserts | Source basis | Gate |
| --- | --- | --- | --- | --- |
| 1 | Official-SDK unsupported-version sequence | client offers an unsupported version; every HTTP request recorded; sequence terminates deterministically; zero streams retained | TS/PY/GO client transport | PR-5 (IMPL-PENDING; version set fixed by the closed D-1) |
| 2 | Initialize counter-offer | server returns an evidence-backed supported-version InitializeResult at 200; compatible client continues; incompatible client disconnects; no legacy SSE probe unless an observed SDK proves otherwise | SPEC lifecycle L165-171; TS | PR-1 / PR-5 (IMPL-PENDING; version set fixed by the closed D-1) |
| 3 | 400 header fallback path | invalid/unsupported MCP-Protocol-Version → 400; observed SDK follow-on; terminal GET = 405; zero streams retained | SPEC transports L277-307; SDKs | PR-1 / PR-5 |
| 4 | 404 session path | terminated session → 404; observed SDK reinitialize/fallback; zero streams retained | SPEC transports L211-212; PY/GO | PR-1 / PR-5 |
| 5 | DELETE / 405 path | DELETE termination unsupported → 405; observed client behavior; zero streams retained | SPEC transports L215-219 | PR-1 / PR-5 |
| 6 | GET without valid session/context | terminal 405; no text/event-stream; no allocation | SPEC transports L137-141 | PR-1 / PR-5 |
| 7 | Missing session identifier | missing MCP-Session-Id → 400; observed SDK behavior; no retained stream | SPEC transports L207-210 | PR-1 / PR-5 |
| 8 | Sessionless absent-version-header | the exact closed D-1 ruling asserted (sessionless missing header → `400`; no silent `2025-03-26` admission) | §7 | PR-1, **IMPL-PENDING** |
| 9 | Legacy endpoint negative | no route/config pair can emit an endpoint event | §2 | PR-1 / PR-5 |
| 10 | Load case | N rejected clients ⇒ zero retained pre-negotiation streams | §3 | **PR-5** (specified now) |
| 11 | Protocol-era separation | 2025 initialize/session fixtures cannot be applied to a 2026-era handler; 2026 stateless/discovery fixtures cannot silently fall into 2025 legacy SSE probing | §1 | PR-1 / PR-5 |
| 12 | Catch-any-failure client | a representative catch-any-fallback client's failure branches all terminate; no held stream | TS catch-any (§4 CONFLICTING) | PR-5 |

The **PR-1 gate proves structural/terminal/zero-stream properties only**; it does **not** claim the PR-5
runtime listener assertions (load, N-client zero-retention) are implemented, and it does **not** claim any
IMPL-PENDING fixture is green (no MCP implementation exists).

---

## Cross-references

- [PROTOCOL-COMPATIBILITY.md](PROTOCOL-COMPATIBILITY.md) §1 (legacy exclusion), §2 (negotiation), §4
  (Streamable HTTP + SSE lifecycle), §7 (unsupported), §9 (downgrade) — all defer status/transport facts to
  this evidence base.
- [SECURITY-REQUIREMENTS.md](SECURITY-REQUIREMENTS.md) — `MCP-PROTO-017` (legacy-transport exclusion +
  no-pre-negotiation-stream), and the augmented `MCP-PROTO-010/013`, `MCP-INSP-009`, `MCP-OPS-002`,
  `MCP-PROTO-016`.
- [THREAT-MODEL.md](THREAT-MODEL.md) §11 `MCP-T-078` (security-rejection-path legacy fallback + retained
  unauthenticated stream) and DFD-17.
- [DATA-FLOW-DIAGRAMS.md](DATA-FLOW-DIAGRAMS.md) DFD-17 (probe → terminal GET → zero stream).
- [OPEN-DECISIONS.md](OPEN-DECISIONS.md) **D-1** (CLOSED — V1 baseline frozen; sessionless absent-header → `400` ruling recorded) and [PR1-ENTRY-CLOSURE.md](PR1-ENTRY-CLOSURE.md).
- [CI-GATES.md](CI-GATES.md) / [TEST-TRACEABILITY-MATRIX.md](TEST-TRACEABILITY-MATRIX.md) — the fixture rows above.
