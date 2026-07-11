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

## Definition of done

Reviewed plan (3 reviewers, no blocking findings — **DONE, v2**) → reviewed implementation (3 reviewers
per PR) → green CI (fmt/vet/lint/race) → PRs ready for merge → updated docs → residual risks documented.
