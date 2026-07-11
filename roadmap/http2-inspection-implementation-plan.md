# HTTP/2 Inspection — Implementation Plan (PR-split)

Status: Phase 1 (plan under review). Authority for the H2-inspection work.
Companion docs: `mitm-engine-panw-review.md` (verdict), `http2-inspection-impact-review.md` (blast radius),
`google-captcha-swg-investigation.md` (why).

## Validation of the review against the repository (Phase 1, done)

Confirmed with code evidence (Go 1.25.12, baseline build + inspect tests green):

| Review claim | Evidence | Verdict |
|---|---|---|
| 3 block writers hardcode `HTTP/1.1…Connection: close` | `internal/fileblock/fileblock.go:300`, `scanner.go:64`, `security_scan.go:131` | CONFIRMED |
| …and already take a `Write([]byte)` interface (seam half-cut) | `fileblock.go:293-296` (`Write`+`Close`), `scanner.go:59`, `security_scan.go:127` | CONFIRMED — lowers PR1 risk |
| H1 parse/serialize spine in one loop | `proxy_tunnel.go:676,715,722,738,770` | CONFIRMED |
| Connection-keyed stall deadlines | `proxy_tunnel.go:674` (per-iter), `proxy_http.go:40` (per-Read) | CONFIRMED |
| Client ALPN pinned `http/1.1` | `proxy_tunnel.go:473` | CONFIRMED |
| Upstream inspect leg offers NO ALPN | `proxy_tunnel.go:505-520` (no `NextProtos`) | CONFIRMED |
| Content plane protocol-neutral | scanners take `*http.Request`/`*http.Response`/`[]byte` | CONFIRMED |
| `x/net/http2` available, unimported | `go.mod` x/net v0.56.0; import probe compiles; no in-tree import | CONFIRMED |

**Hidden-coupling sweep (beyond the 3 seams):**
- No other production literal `HTTP/1.1 <status>` writers (only the CONNECT-200 line `proxy_tunnel.go:378`,
  which is tunnel establishment, protocol-neutral, and pre-ALPN — not a block/response writer).
- `handleWebSocket` (`proxy_tunnel.go:107,144`) uses `http.ReadResponse`/`resp.Write` — a *separate* H1
  path (plain WS upgrade), not on the inspect stream loop; unaffected by H2-inspect (WS-over-H2 handled
  by NOT advertising `ENABLE_CONNECT_PROTOCOL`, so clients use this H1 path).
- `removeHopHeaders` (`proxy_tunnel.go:975`) is `http.Header` map ops — neutral, but re-adding hop headers
  is impossible on H2; the H2 leg must use an h2 transport (not `req.Write`) so framing is library-owned.
- No per-connection state in the scanners (verified: DPI/ClamAV/YARA/CDR are stateless per call) — the
  single-request-per-conn assumption lives ONLY in the loop + the 2 deadline sites.

**Conclusion: the review's TARGETED-REFACTOR verdict is upheld.** No additional structural coupling found.

## Minimal refactor required for H2

1. A protocol-neutral **block responder** (interface + H1 impl今 = today's bytes; H2 impl later).
2. An **ALPN fork** after the client handshake: `http/1.1` → existing loop untouched; `h2` → new handler.
3. A **new `handleInspectH2`** built on `x/net/http2` server (client leg) + transport (upstream leg),
   reusing the scan/scrub/file-block/CDR chain verbatim, with per-stream lifecycle from the library.
4. **Stream-through** for non-bufferable content + a concurrency-capped buffer budget.
5. A **config decision** (`resolveH2Inspect`) — default = strip-alpn (today's behavior) until validated.

Everything else in the engine is untouched.

## PR split (stacked; each self-contained, H1 preserved, tests green)

### PR0 — Characterization tests (lock current H1 behavior). NO product code.
- Lock: client ALPN negotiates `http/1.1`; the exact block-page bytes of all 3 writers; WebSocket-101
  raw-relay; stall deadline re-arm; large-response integrity; identity scrub on inner request; bypass
  ≠ MITM. Most already exist (`mitm_inspect_e2e_test.go`, `proxy_slowloris_body_test.go`,
  `proxy_websocket_status_test.go`, `fileblock_test.go`); add explicit ALPN + block-byte assertions where
  missing. This is the oracle for PR1–PR3.
- Exit: new tests green; `go test -race` green.

### PR1 — Extract `blockResponder` seam (pure refactor, behavior-identical).
- New `blockResponder` interface + `h1BlockResponder` writing today's exact bytes. Migrate `scanBlockConn`,
  `dpiBlock`, `fileblock.BlockConn` call sites to it. No wire change; PR0 bytes are the oracle.
- Exit: PR0 tests unchanged & green; fmt/vet/lint/race green.

### PR2 — Negotiated-protocol plumbing + `resolveH2Inspect` decision (no wire change).
- Plumb `clientTLS.ConnectionState().NegotiatedProtocol` + a `resolveH2Inspect(match)` that returns
  **strip-alpn** always (behavior unchanged: client ALPN stays `http/1.1`, upstream stays no-ALPN).
  Add the fork skeleton `switch negotiated { case "h2": … default: <existing loop> }` where the `h2`
  arm is unreachable until PR3 flips ALPN. Feature-flagged, default OFF.
- Exit: no behavioral change; all tests green.

### PR3 — `handleInspectH2` (the core; gated OFF by default).
- Offer `h2,http/1.1` on both legs ONLY when the flag is on for the rule. `h2` client conn via
  `(*http2.Server).ServeConn` + `http.Handler`; upstream via `http2.Transport`. Each stream runs the
  existing scrub → file-block → scanInspectBody → CDR chain, blocking via the H2 `blockResponder` impl.
  Do NOT advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` (WS falls back to H1). Per-stream lifecycle,
  flow control, `MaxConcurrentStreams` from the library.
- Exit: new H2 e2e tests (h2 client ↔ proxy ↔ h2 origin: allow, file-block, scan-block, large body,
  identity scrub) green; H1 path byte-identical; race green.

### PR4 — Streaming safety (gRPC/SSE stream-through + memory budget).
- Mandatory stream-through for `application/grpc`, `text/event-stream` (extend `bodyNeedsBuffering`);
  cap `maxScanBufferBytes × MaxConcurrentStreams` against a global budget; conservative
  `MaxConcurrentStreams` (~100).
- Exit: streaming tests (a never-ending stream is not buffered; memory bounded) green.

### PR5 — Config surface + API + UI (AFTER product-design validation — see below).
- Expose the H2-inspect decision on the correct existing policy surface (not a new toggle unless
  justified). API endpoint + UI + config-version snapshot per repo GUI-parity rules. Default preserves
  today's behavior.

### PR6 — Docs + risk register.
- Operator doc (when to enable, Strip-ALPN semantics, gRPC caveat), update CLAUDE.md architecture note,
  record residual risks (TLS-fingerprint still Go's; H3/QUIC still unsupported).

## Product-design validation gate (blocks PR5)

Before any admin-facing config: compare against PAN-OS (Decryption Profile → SSL Forward Proxy →
Strip ALPN), Zscaler, Netskope, Forcepoint. Decide whether the control belongs on an access/decryption
rule, a decryption profile, a compatibility profile, or stays internal. **Prefer reusing the existing
policy-rule `SSLAction`/decryption surface over inventing a new enum/toggle.** Document the decision and
any deviation from commercial practice before implementing PR5.

## Git topology

Work proceeds as sequential, self-contained commits on the designated branch
`claude/google-captcha-swg-investigation-p7meha` (each commit = one PR-equivalent unit, independently
reviewable). A single PR to `main` is opened when the stack is green; splitting into stacked GitHub PRs
is available on request.

## Phase 1 review consolidation (v2) — three independent reviewers

Reviewers: (R1) commercial SWG/decryption architect, (R2) HTTP/2+TLS security, (R3) senior Go
runtime/networking. All three: **APPROVE-WITH-CHANGES** — strategy sound, H1 path well-protected,
transport-plane details under-specified. Every blocking finding is resolved below; the plan is revised
accordingly. No blocking findings remain open.

### Resolved blocking findings (these amend PR1–PR5)

**RF1 — ALPN reconciliation: kill "prefer downgrade"; use upstream-first protocol mirroring (R1-B1,
R2-downgrade, R3).** The code already handshakes the ORIGIN first (`proxy_tunnel.go:566`) before the
client (`:644`). So: after the upstream handshake, read the origin's `NegotiatedProtocol` and **mirror it
onto the forged-leaf client ALPN offer**. This collapses the impossible quadrant (ALPN is fixed at TLS
handshake — you cannot renegotiate a client that already chose h2). The four quadrants become:

| client offer (mirrored) | origin negotiated | action |
|---|---|---|
| h2 | h2 | `handleInspectH2` (both legs h2) |
| http/1.1 | http/1.1 | existing H1 loop |
| http/1.1 | h2 | impossible by construction (we only offer h2 to client if origin took h2) |
| h2 | h1 | impossible by construction (mirroring) |

No in-proxy h2↔h1 translation bridge in v1. If the origin won't speak h2, the client is offered
http/1.1 (today's behavior). This is the strip-ALPN fallback, now origin-driven.

**RF2 — Per-rule/per-tunnel ALPN needs `GetConfigForClient`, not the shared global (R1-B2, R2-B3).**
`mitmClientTLSConfig` is a process-global mutated by `rotateMITMTicketKeys`. PR2 introduces a
`GetConfigForClient` (or `GetConfigForClient`-returned per-conn clone) that injects `NextProtos` from
(a) the resolved rule's H2 setting AND (b) the origin's mirrored protocol (RF1), while preserving the
CA-rotation ticket-key invalidation invariant (share the ticket keys / `SetSessionTicketKeys` state, do
not deep-clone it). Post-resumption the code MUST read `ConnectionState().NegotiatedProtocol` and branch
on it (TLS 1.3 re-selects ALPN on resumed handshakes; the `upstreamSessionCache` is keyed by ServerName
only, `:448`).

**RF3 — Upstream leg: per-conn `NewClientConn`, never a pooled/coalescing transport (R3-B1, R2-B1).**
Wrap the already-dialed, SSRF-guarded, self-verified `upstreamTLS *tls.Conn` (`:565`) via
`(*http2.Transport).NewClientConn(upstreamTLS)` → a `*http2.ClientConn`, and `RoundTrip` each client
stream on it. This (a) inherits the existing `isPrivateHost`+`ssrfControl` guard (SSRF closed — R2-B1),
(b) guarantees one origin conn per (identity, origin) — no cross-identity pooling, (c) structurally
prevents H2 connection coalescing. **Forbidden:** routing the inspect leg through `getUpstreamTransport()`
(add a one-line rule to CLAUDE.md's upstream-transport-ownership note). **GOAWAY trade-off (R2-B1):** a
`NewClientConn` over a single conn cannot redial on origin GOAWAY; v1 maps origin GOAWAY/conn-reset to
per-stream failure toward the client and tears down the tunnel — the browser opens a fresh conn → new
CONNECT → new tunnel (standard GOAWAY handling). Documented, accepted for v1.

**RF4 — `:authority` validation + forged-leaf SAN scope (R2-B2, R1 coalescing).** Policy/scan state is
keyed on the CONNECT `hostOnly`. Every h2 stream carries its own `:authority`; PR3 MUST reject a stream
whose `:authority` ≠ the CONNECT authority with **421 Misdirected Request** (RFC 9113 §8.1.2.3/§8.3.1).
Forge the leaf with a **single SAN = the CONNECT host** so browsers do not coalesce other origins onto
the tunnel.

**RF5 — `blockResponder` needs TWO entry points; design in PR1 (R1, R2-B4).** Pre-headers block →
`:status 403` + DATA + `END_STREAM`. Post-headers block (stream-through, gRPC/SSE) → `RST_STREAM`
(`CANCEL`/`INTERNAL_ERROR`), never a 403 body, **never `Connection: close`** (RFC 9113 §8.2.2). The H1
impl keeps today's exact bytes (pre-headers only; the H1 path can't stream-block after commit anyway).
This changes the PR1 interface shape — so it is designed now, not retrofitted. The proxy's own block
RST_STREAMs must count toward (not trip) the reset-rate budget.

**RF6 — Per-stream body-stall timer is real work, not "free" (R3-B2).** `http2.Server.IdleTimeout` fires
only at ZERO open streams; a single trickling stream is unbounded. PR3/PR4 add a per-stream inactivity
reader that cancels the *stream* (via `req.Context()`/timer), not the conn. `conn.SetReadDeadline`
(H1-only) is dropped on the H2 path.

**RF7 — Global, backpressured memory budget; peak-multiple math (R3, R2).** Ceiling is
`maxScanBufferBytes × concurrent_streams × conns` — a **global** weighted-semaphore/byte-accounted
**blocking** acquire (NOT the `geoTrackSem` drop-on-full pattern — dropping a scan = bypass or fail).
Peak per stream ≈ 3× `maxScanBufferBytes` (raw body + CDR copy + decompressed copy); `decompressForScan`
output MUST be bounded (gzip bomb amplifies ×N streams). Failure mode = fail-closed block page / 503-eq,
stated explicitly. gRPC/SSE stream-through = never admitted to the buffer.

**RF8 — Trailers (R2).** H2 responses carry trailers (gRPC `grpc-status`). The buffered reassembly
(`MultiReader` at `:971`) drops `resp.Trailer`; both buffered and stream-through paths MUST forward
trailers on the H2 leg.

**RF9 — Explicit H2 limits + CI version floor (R2, R3).** Pin on BOTH `http2.Server` and the upstream
`http2.Transport`/`ClientConn`: `MaxConcurrentStreams` (~100; server default is 250, confirmed
`x/net@v0.56.0/http2/server.go:62`), `MaxReadFrameSize`, `MaxDecoderHeaderTableSize`,
`MaxUploadBufferPerStream/PerConnection`. Add a CI/compile assertion pinning `x/net` ≥ the
rapid-reset (0.17.0) + CONTINUATION-flood (0.23.0) fixes. **Confirmed: `go.mod` pins v0.56.0 — past
both.**

**RF10 — Shutdown/GOAWAY wiring (R3-S1).** `handleInspectH2` keeps `recordActiveConn(±1)` (already at
`:652`) AND registers a shutdown hook that sends GOAWAY / closes the h2 conn so `drainActiveTunnels`
(`main_shutdown.go`) actually drains H2 streams. Wired in PR3 (not deferred to PR4).

**RF11 — ALPN fork position (R3-S4).** The fork sits **above** `clientBR := bufio.NewReaderSize(clientTLS,
32*1024)` (`:666`); the h2 arm passes `clientTLS` **directly** to `ServeConn` (any pre-read into a bufio
would strand the h2 preface). PR2's skeleton is positioned there, with an assertion that no `Read` on
`clientTLS` precedes `ServeConn`.

### Product-design correction (R1 — overrides the earlier "reuse SSLAction" note)

Commercial comparison (verified): **PAN-OS** puts Strip-ALPN on the **Decryption Profile** (SSL Forward
Proxy tab), not the access rule; H2 inspection is a profile/global posture. **Zscaler / Netskope /
Forcepoint** inspect H2 automatically within decryption with no separate protocol knob (H2 is transparent
to their decrypt-or-not policy). So the knob is a **compatibility/fallback control on the decryption
surface**, PAN-OS-style.

**Decision:** do **NOT** extend the `SSLAction` enum (it answers "decrypt?" — orthogonal to "at what
protocol?"). Add a dedicated field on the **rule's existing TLS-options surface, alongside
`TLSSkipVerify`** (Culvert's nearest decryption-profile equivalent) — a tri-state `H2Inspect:
default|enable|strip-alpn` (or `StripALPN bool`), applied only when `SSLAction==Inspect`, default =
strip-alpn (today's behavior). This reuses the existing policy/decryption surface (satisfying "prefer
reusing existing surfaces") **without** overloading the decrypt/bypass axis. PR5 implements it there;
`SSLAction` stays a clean two-value enum.

### Added/strengthened tests (fold into PR3/PR4)

Cross-protocol quadrant e2e (h2↔h2, h1↔h1, and proof the mixed quadrants can't occur); `:authority`
mismatch → 421; coalescing isolation; request-smuggling via H2 (`Transfer-Encoding`/`Connection`/`TE`/
`Upgrade` rejected, not reforwarded); malformed/duplicate pseudo-headers; CONTINUATION flood + Rapid
Reset (client leg AND malicious-origin upstream leg); HPACK/decompression bomb bounded under concurrency;
identity-scrub on the H2 rebuilt request; SSRF on the H2 upstream dial; block-after-HEADERS → RST_STREAM
(no illegal `Connection: close`); trailers/GOAWAY; goroutine-leak (K×M streams return to baseline);
shutdown-with-active-streams; high-concurrency `-race` over the daemon-backed scanners (ClamAV/YARA hold
sockets — H1-serial never exercised concurrency). PR0 already locks the strip-ALPN downgrade oracle.

## Phase 1 final corrections (v3) — supersede where they conflict with v2

Five owner corrections. These are binding and override any looser v2 wording.

### C1 — ALPN sequence: intersection of client-offer ∩ policy ∩ origin (v3.1)

The effective protocol is the **intersection of three inputs**: the client's ClientHello ALPN offer, the
decryption policy (`StripALPN`), and the origin's capability. A naive "offer h2 upstream, then offer only
what the origin took downstream" can strand an **HTTP/1.1-only client** (origin picks h2 → downstream
offers only h2 → no common protocol → client handshake fails). The client offer MUST bound the upstream
offer. Full sequence, per inspected CONNECT:

1. **Observe the client's offered ALPN** without consuming/stranding bytes the eventual H1/H2 handler
   needs. **Go mechanism:** the forged-leaf `tls.Config.GetConfigForClient(chi *ClientHelloInfo)` exposes
   `chi.SupportedProtos` (the client's ALPN list) at the START of the client handshake — but we need it
   BEFORE the upstream handshake to shape the upstream offer, and the upstream handshake happens first in
   the current code (`:566`). Resolution: **do the client handshake first is not an option** (we need
   the origin protocol to constrain the client). Instead, peek the client's ALPN from the buffered
   ClientHello without completing the handshake. Concretely: the inspect path already peeks the first
   client byte (`clientBuf.Reader.Peek`, `:598`) to detect TLS; extend that to parse the ClientHello
   ALPN extension read-only from the buffered bytes (a bounded, well-defined TLS record parse — the same
   technique the PR0 characterization test uses to assert ALPN, and what the NetLog decode did). This
   observes `clientOffer []string` **without consuming** the bytes `tls.Server` will re-read (we hand
   `tls.Server` a `readerConn` wrapping the same buffered reader — `:643` — so no strand, and no pre-read
   that could break a later `ServeConn` since `ServeConn` reads the H2 preface which arrives only AFTER
   this TLS handshake completes). If ALPN parsing fails/absent, treat `clientOffer` as `["http/1.1"]`
   (conservative).
2. **Apply `StripALPN`** (see C2): `stripALPN := resolveStripALPN(match)`.
3. **Build the upstream offer from the allowed intersection:**
   - `stripALPN == true` → upstream `["http/1.1"]`.
   - native H2 (`stripALPN == false`) AND client offered `h2` → upstream `["h2","http/1.1"]`.
   - native H2 but client offered only `http/1.1` → upstream `["http/1.1"]`.
4. **Negotiate upstream:** dial + `HandshakeContext`; `up := upstreamTLS.ConnectionState().NegotiatedProtocol`
   (read post-resumption — never assume the cached session's protocol; the LRU cache is ServerName-keyed).
5. **Select the same negotiated protocol downstream:** forge-leaf offer = `[up]` (a single protocol the
   client is guaranteed to also support, because `up` came from an offer already intersected with the
   client's list in step 3). `up` can only be `h2` when the client offered `h2`.
6. **Dispatch on the downstream negotiated protocol:** `h2` → `handleInspectH2`; `http/1.1` → H1 loop.

Because the upstream offer is bounded by the client offer (step 3), `up` is always in the client's
support set, so step 5 never strands the client, and the mixed quadrants remain impossible. **Required
test (C4 PR-merge blocker): an HTTP/1.1-only client through a native-H2 rule to an h2-capable origin must
complete and be inspected over H1** — do not assume every inspected client offers h2. Validate the
ClientHello-ALPN-peek mechanism against Go's TLS APIs in PR2; if read-only ClientHello ALPN extraction
proves infeasible without a handshake, fall back to `GetConfigForClient` + accepting that the upstream
offer for native-H2 rules is always `["h2","http/1.1"]` and the DOWNSTREAM constraint (step 5) is what
prevents the strand — but then step 5 must offer `["h2","http/1.1"]` (not `[up]`) to an h1-only client
whenever `up=="h2"` is impossible, i.e. re-derive from `chi.SupportedProtos ∩ [up]`. The intersection is
the invariant; the peek-vs-GetConfigForClient plumbing is a PR2 implementation choice to be reviewer-validated.

### C2 — Minimal product model with presence semantics: `StripALPN *bool` (v3.1)

A plain persisted `bool` cannot distinguish an **old rule where the field is absent** from a **new rule
explicitly setting `StripALPN=false`** — both deserialize to `false`, which would silently switch
existing deployments to native H2 on upgrade. Use a presence-aware representation on the existing per-rule
TLS-options surface (alongside `TLSSkipVerify`):

```go
StripALPN *bool `json:"stripAlpn,omitempty"` // nil = absent (pre-feature) => strip; else explicit
```

(or an equivalent config-versioning/migration mechanism with the same three-way semantics). **Resolver
contract (binding):**

```text
field absent (nil) on a pre-feature rule → strip = true   (today's HTTP/1.1 downgrade)
explicit *StripALPN == true              → strip = true
explicit *StripALPN == false             → native H2 inspection
```

`resolveStripALPN(match) bool` implements exactly this. **No `default|enable|strip-alpn` tri-state** —
Culvert's policy model has no rule inheritance/profile nesting a tri-state would express; a presence-aware
bool is the minimal faithful model. Administrator UX stays a single checkbox (unchecked/absent = strip);
presence tracking is an internal persistence concern, not surfaced as a third UI state.

**Migration (binding):** an existing rule deserialized from current config has `StripALPN == nil` →
`resolveStripALPN` returns `true` → byte-for-byte current downgrade behavior. Pinned by a test that loads
a pre-feature rule JSON and asserts `strip==true`. The default flips to native H2 only through a
documented operator rollout decision post-H2-qualification, never as an upgrade side effect. Config-surface
registry (`config_surfaces.go`) + export/import + rollback parity updated when the field lands (PR5).

### C3 — Post-commit enforcement: gRPC ≠ SSE, always with a reason code

Once response HEADERS are committed on a stream-through response, enforcement differs by protocol and
MUST be auditable:
- **gRPC** (`content-type: application/grpc*`): prefer a **protocol-valid terminal trailer** —
  `grpc-status` (non-OK, e.g. `PERMISSION_DENIED`) + `grpc-message` in the HEADERS trailer + `END_STREAM`
  — whenever enforcement can still be expressed that way. A gRPC client surfaces this as a clean RPC
  error, not a transport failure.
- **SSE** (`text/event-stream`): a terminal trailer is not meaningful; terminate the stream after commit.
- **`RST_STREAM` only as the last resort** — when no valid terminal response/trailer can still be emitted
  safely (headers+some DATA already flushed, non-gRPC, or the trailer window is gone).
- **Every post-commit enforcement emits an auditable reason code** (e.g. `blocked_post_commit_grpc_trailer`,
  `blocked_post_commit_sse_terminate`, `blocked_post_commit_rst`) through the existing audit/request-log
  path. The `blockResponder` H2 impl carries a reason argument on the post-commit entry point.

**Binding behavioral invariants (not a frozen signature):** separate pre-commit and post-commit block
operations; protocol-valid gRPC trailers where possible; SSE termination and RST_STREAM only when
appropriate; an audit reason for every post-commit enforcement. **Do NOT lock the API to
`PostCommit(contentType, reasonCode string)`** — the responder must act on **actual stream state and
capabilities** (whether headers/DATA are already flushed, whether a trailer window remains, the stream
handle for RST), not merely a content-type string. The concrete `blockResponder` post-commit signature is
DERIVED from the real lifecycle extracted in PR2 (see C5), and the three reviewers validate the resulting
API shape from the PR1/PR2 diff — not from this document. PR1 therefore ships only the pre-commit seam
(the sole shape all three current writers actually exercise today) and leaves post-commit to PR2/PR3.

### C4 — Validation gates split by delivery stage

Tests are classified; do NOT weaken coverage, but do NOT make every adversarial case block the first
functional H2 PR:
- **PR-merge blockers** (every PR): fmt/vet/lint, `-race`, H1-path regression (PR0 oracle + existing
  suite unchanged), and for a PR's own new surface: functional correctness + goroutine-leak + the
  protocol-neutral-contract invariant (C5).
- **Native-H2 default-enable blockers** (gate flipping the default OFF→ON, C2): full cross-protocol
  quadrant proof, `:authority`/421 + coalescing isolation, request-smuggling rejection, CONTINUATION
  flood + Rapid Reset (client AND malicious-origin legs), HPACK/decompression-bomb bounds under
  concurrency, SSRF-on-H2-dial, trailers/GOAWAY, per-stream stall, global memory-budget backpressure,
  high-concurrency `-race` over daemon-backed scanners.
- **Post-delivery hardening** (tracked, not release-blocking): fuzz corpus for the framer boundary,
  soak/load, additional malformed-frame matrices, 0-RTT re-verification if the toolchain gains early
  data.

The functional H2 PR (PR3) ships behind the default-OFF flag and needs only the PR-merge-blocker class
green; the default-enable class gates PR5's rollout, not PR3's merge.

### C5 — Invariant: ONE inspection pipeline, protocol-neutral exchange contract

**No H2 implementation may create a second inspection pipeline.** H1 and H2 MUST invoke the *same*
policy → scan → CDR → file-block orchestration through a **protocol-neutral exchange contract**, with no
protocol branching inside the scan/CDR/file-block/scrub functions. The contract must naturally support the
full lifecycle: **request inspection → upstream round-trip → buffered response inspection → stream-through
response** (+ block via a `blockResponder`). PR2 extracts this seam by lifting the REAL lifecycle out of
the current H1 inner loop (`proxy_tunnel.go:671-787`) — the exact function name/signature (e.g. some
`inspectExchange(...)`) is **DERIVED from that extraction, not pre-frozen here**. PR3's H2 handler calls
the SAME seam per stream. A test asserts both paths route through one instrumented choke point (an H1 and
an H2 e2e both hit it), making "reused verbatim" a structural guarantee. The three reviewers validate the
extracted contract's shape from the PR2 diff.

## Implementation review consolidation — PR1/PR2a diff (3 reviewers)

All three (SWG architect, HTTP/2+TLS security, Go runtime) returned **APPROVE-WITH-CHANGES** on the
committed PR1+PR2a. Unanimous points, all actioned:

- **Ship PR1+PR2a** — behavior-neutral, byte-exact, fail-safe resolver. ✓
- **Test hardening (landed):** explicit-`false` JSON round-trip (the load-bearing C2 guarantee); `fileblock.BlockConn`
  H1 golden byte-lock; upstream-leg no-ALPN oracle; CRLF-cannot-inject-a-second-response (verified via
  `http.ReadResponse`, not string-count); `h1BlockResponder` does-not-close-conn contract.
- **`fileblock` migration is PR2b's first act** (all three): make `internal/fileblock` a **pure detector** —
  wire emission moves to the main-package responder; drop the H1 force-close on the H2 path (a per-stream
  block must never close the shared conn; `Connection: close` is illegal on H2, RFC 9113 §8.2.2).
- **Product design confirmed:** `StripALPN` on the rule TLS-options surface (alongside `TLSSkipVerify`) is
  the faithful mapping of PAN-OS's "on the decryption surface" — Culvert has no separate profile object, so
  this per-rule TLS-options block *is* the decryption-profile equivalent. Do not overload `SSLAction`.
- **`resolveStripALPN` must be consulted only on `SSLAction==Inspect`** at the PR3 call site (gate + test).

**Consolidated PR2b design (derived from the extraction, not pre-frozen):**
- Widen `inspectFileBlocked`/`inspectCDBlocked`/`inspectMagicBlock`/`scanInspectBody`/`runCDRStage` from
  `*tls.Conn`/`net.Conn` → the `blockResponder` seam. **No inspection function may name a conn or branch on
  protocol** — the single mechanical invariant of C5. (PR2b-1: DONE — all block emitters route through one
  responder; asserted by `TestC5_AllBlockEmittersRouteThroughResponder`.)
- The seam must own **both** sinks — block-emit AND clean-**deliver** (`resp.Write`); leaving `resp.Write`
  in the H1 loop moves only half the seam. Model the upstream round-trip and client delivery as
  function-typed transport hooks on an exchange object (H1: `req.Write`+`ReadResponse` / `resp.Write`;
  H2: `NewClientConn.RoundTrip` / stream write) so scanners stay conn-free. (PR2b-2.)
- **Preserve `resp.Trailer`** through the `MultiReader` reassembly (`proxy_tunnel.go:971`) — it currently
  drops trailers (RF8); the H2 deliver needs gRPC `grpc-status` trailers. (PR2b-2.)
- Per-stream stall timer lives at the **transport edge**, not the seam; H1 keeps `stallDetectReadCloser`
  verbatim (PR3/RF6).
- **Post-commit responder is still NOT frozen** — it must take a stream-state object
  (`headersFlushed`/`dataFlushed`/`trailerWindowOpen` + typed capability `isGRPC`/`isSSE` + stream handle +
  structured reason), derived from the H2 lifecycle in PR3. Never `PostCommit(contentType, reason string)`.
- **C1 ClientHello ALPN peek confirmed sound** (not `GetConfigForClient` for the upstream-offer input, due
  to upstream-first handshake ordering): bounded read-only parse of the buffered plaintext ClientHello via
  the existing `clientBuf.Reader`, non-stranding (the H2 preface is post-handshake ciphertext on another
  layer), fail-closed to `["http/1.1"]` on parse failure; **must be fuzzed** (new attack surface).
  `GetConfigForClient` is used only to inject the per-conn **downstream** `NextProtos`, sharing (not
  cloning) the ticket-key state (RF2). Read `NegotiatedProtocol` post-resumption on both legs.
- **GOAWAY/drain:** `ServeConn` on a hijacked conn has no per-conn `Shutdown`; PR3 must register active h2
  conns for GOAWAY-on-shutdown and map origin GOAWAY → per-stream fail + tunnel teardown (RF3/RF10).

## Definition of done

Reviewed plan (3 reviewers, no blocking findings — **DONE, v2; v3 owner corrections applied**) →
reviewed implementation (3 reviewers per PR) → green CI (fmt/vet/lint/race) → PRs ready for merge →
updated docs → residual risks documented.
