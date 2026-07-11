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

## Definition of done

Reviewed plan (3 reviewers, no blocking findings) → reviewed implementation (3 reviewers per PR) →
green CI (fmt/vet/lint/race) → PRs ready for merge → updated docs → residual risks documented.
