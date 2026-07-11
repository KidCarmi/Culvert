# Adding HTTP/2 Support to Culvert's SSL-Inspection Path — Impact Review

**Question:** what happens / breaks / changes if we make the MITM inspect path HTTP/2-aware,
and how does Palo Alto implement this?
**Audience:** SWG developers.
**Method:** full read of `handleTunnelInspect` and every function it calls (see the H1-assumption
inventory), plus PAN-OS HTTP/2-inspection documentation.

---

## 0. TL;DR

- Culvert's inspect path is **structurally H1-only by one deliberate lever**: the forged-leaf ALPN is
  pinned to `http/1.1` (`proxy_tunnel.go:473`), and everything downstream is a hand-rolled
  `http.ReadRequest`/`req.Write`/`http.ReadResponse`/`resp.Write` keep-alive loop
  (`proxy_tunnel.go:666-787`). Remove the pin *without* adding a framer and **every H2 client is
  dropped** — `http.ReadRequest` chokes on the H2 connection preface (`proxy_tunnel.go:676`),
  which is strictly worse than today.
- The **good news**: everything *downstream of parsing* — DPI, ClamAV, YARA, CDR, file-block logic,
  header scrubbing — already operates on `*http.Request`/`*http.Response` and `resp.Body`, so it is
  **protocol-version-agnostic and reused as-is**. The dependency `golang.org/x/net v0.56.0`
  (contains `http2`) is already vendored.
- The **hard part** is not re-plumbing the scanners; it's two *model-level* mismatches that require
  real redesign: **(a) per-connection read deadlines vs. H2 multiplexing**, and **(b) whole-connection
  raw-relay for WebSocket/101 vs. RFC 8441 Extended CONNECT per-stream**.
- **PAN-OS does exactly what we'd build**: a full per-stream H2 proxy (decrypt → inspect each stream →
  re-encrypt), ALPN negotiated on *both* legs, with a **"Strip ALPN"** downgrade-to-H1 as the explicit
  fallback. Culvert's *current* permanent behavior **is** PAN-OS's Strip-ALPN mode — we're just making
  it the exception instead of the rule.

---

## 1. How Palo Alto implements it (the reference model)

From PAN-OS documentation (App-ID and HTTP/2 Inspection; Decryption Profile → SSL Forward Proxy):

1. **H2 is the default when decryption is on** (PAN-OS ≥ 9.0). The firewall is a **full proxy**: it
   terminates the client's H2/TLS, inspects, and **re-encrypts** onto its own connection to the origin.
2. **ALPN on both legs.** The firewall negotiates ALPN with the client (offering `h2`) and separately
   with the server. It inspects **stream-by-stream** — each H2 stream is treated as an independent
   request/response for App-ID + Content-ID (AV, vuln, URL filtering, file blocking).
3. **ECDHE required.** H2 inspection requires ECDHE key exchange for the SSL session (RSA key-exchange
   sessions can't be inspected as H2). Culvert already forges ECDSA P-256 leaves and negotiates
   TLS 1.2+/AEAD (`TestMITM_ForgedLeafTLSPosture`, `mitm_inspect_e2e_test.go:501`), so this is satisfied.
4. **The fallback is "Strip ALPN".** When H2 inspection isn't wanted or a site misbehaves, the admin
   attaches a decryption profile with **Strip ALPN**: the firewall empties the ALPN extension, so the
   handshake negotiates **HTTP/1.1** and the firewall decrypts at H1 level. When ALPN is empty/absent,
   PAN-OS **downgrades H2→H1 or classifies as unknown TCP** — i.e., exactly Culvert's `http/1.1` pin
   today, and exactly what happens on our upstream leg (no `NextProtos`, `proxy_tunnel.go:505-520`).

**Key takeaway:** the industry model is *H2 full-proxy by default, H1 strip-ALPN as escape hatch*.
Culvert is stuck permanently in the escape hatch. The Google-CAPTCHA problem is that Strip-ALPN makes
Chrome→Google look anomalous (Chrome never uses H1 to Google). PAN-OS avoids it by defaulting to H2.

---

## 2. What changes, breaks, or crashes — component by component

### 2.1 Will crash / hard-break if H2 reaches the current loop

| Site | File:line | What happens under H2 today | Required change |
|---|---|---|---|
| ALPN pin (client leaf) | `proxy_tunnel.go:473` | Forces H1; **remove naively → next row fires** | Offer `h2,http/1.1`; branch on negotiated proto |
| `http.ReadRequest(clientBR)` | `proxy_tunnel.go:676` | **Fails on H2 preface** `PRI * HTTP/2.0…`, breaks loop, closes conn — client dropped | Replace with `http2.Framer` / an H2 server conn when ALPN=h2 |
| `req.Write(upstreamTLS)` | `proxy_tunnel.go:715` | Serializes **H1 wire format** even if struct came from H2 → mismatched with an h2 upstream | Use `http2.Transport`/framer on the upstream leg |
| `http.ReadResponse(upstreamBR, req)` | `proxy_tunnel.go:722` | Can't parse H2 DATA/HEADERS frames | Same |
| `resp.Write(clientTLS)` | `proxy_tunnel.go:770`, `:738` | Writes H1 bytes onto an h2-negotiated client conn → protocol error | Emit HEADERS+DATA frames on the stream |
| `bufio.NewReaderSize(…, 32*1024)` | `proxy_tunnel.go:666-667` | Line-oriented reader; wrong tool for HPACK/framing | Framer-based reader |

**Net:** naively dropping the ALPN pin turns a *silent-but-working* H1 downgrade into *broken H2*.
The ALPN pin and the parse spine must change **together**, or not at all.

### 2.2 Will silently corrupt output if not ported

The three **block-page writers** hand-synthesize literal `HTTP/1.1 403 …\r\nConnection: close\r\n\r\n`
onto the raw `tls.Conn`:

- `scanBlockConn` — `security_scan.go:127-138`
- `dpiBlock` — `scanner.go:59-71`
- `fileblock.BlockConn` — `internal/fileblock/fileblock.go:287-300` (pinned by
  `internal/fileblock/fileblock_test.go:168-169`)

Under H2 these are malformed: (a) `HTTP/1.1` status lines aren't valid on an h2 stream, and (b)
**`Connection: close` is illegal in H2** (RFC 7540 §8.1.2.2 forbids connection-specific headers). Each
must gain an H2 variant that writes a HEADERS frame (`:status 403`) + DATA + `END_STREAM` (H2 uses
`RST_STREAM`/`GOAWAY`, not `Connection: close`, to end things). This is why the block writers currently
take a `net.Conn`/`*tls.Conn` instead of an `http.ResponseWriter` — they'd need refactoring to a
writer abstraction that both legs implement.

### 2.3 Needs real redesign (model mismatch, not re-plumbing)

**(a) Per-connection read deadlines vs. multiplexing.** The slowloris/stall defenses set deadlines on
the *single underlying conn*:
- `clientTLS.SetReadDeadline(now+60s)` once per loop iteration — `proxy_tunnel.go:674`
- `stallDetectReadCloser` re-arms `clientTLS.SetReadDeadline` on every body `Read` — `proxy_tunnel.go:688`,
  type in `proxy_http.go:30-42`, timeout `proxy_http.go:16`

Under H2 one conn carries many concurrent streams. A `conn.SetReadDeadline` aborts **all** streams, not
the one slow stream — the mechanism is *fundamentally incompatible* with multiplexing. H2 replaces it
with per-stream flow control + `SETTINGS` (max concurrent streams, initial window) and per-stream idle
accounting. Tests pinning the old model: `proxy_slowloris_body_test.go:46-217` (5 tests) — these keep
passing for the H1 path but a new H2 path needs its own stall model + tests. **`golang.org/x/net/http2`'s
server already implements flow control and `MaxConcurrentStreams`**, so adopting its server conn gives
this largely for free — which is the strongest argument for *not* hand-rolling a framer.

**(b) WebSocket/101 vs. RFC 8441.** The 101-upgrade branch (`proxy_tunnel.go:735-759`) writes the 101 to
the client then raw-relays the **entire** TLS conn. H2 has **no 101** (forbidden); WebSocket-over-H2 is
**Extended CONNECT** with a `:protocol=websocket` pseudo-header, gated by
`SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 8441). You cannot raw-relay the whole conn because the WebSocket
lives on *one stream* alongside unrelated streams. An H2 path must detect the Extended-CONNECT stream and
relay that stream only. **Simplest correct v1: don't advertise `ENABLE_CONNECT_PROTOCOL` on the forged
leaf** → clients won't attempt WS-over-H2 and fall back to H1+`Upgrade`, which the existing 101 branch
already handles. gRPC (H2 DATA streams, `content-type: application/grpc`) also needs care: long-lived,
bidirectional, and the scan buffer (`maxScanBufferBytes`, `security_scan.go:144`) would stall a stream
if it waits for a body that never ends — see §2.5.

### 2.4 Reused unchanged (version-agnostic — the reassuring part)

All operate on parsed structs / `[]byte` bodies:
- `scanInspectBody` (`proxy_tunnel.go:890-973`) — reads `resp.Body`, header-based content typing.
- `inspectFileBlocked`/`inspectCDBlocked` (`proxy_tunnel.go:798-866`) — URL/header logic (only the
  *block-writer* call needs the H2 variant from §2.2).
- `runCDRStage` (`cdr_proxy.go:392-435`) — takes `[]byte` + `*http.Request`.
- DPI/ClamAV/YARA/magic: `safeDPIScan`, `safeScanBody*`, `IsBlockedArchive`, `CheckMagicVsContentType`
  (`security_scan.go:75-114`, `filemagic.go:20`) — pure byte scanners.
- `scrubForwardedHeaders` (`proxy.go:43-70`) — `http.Header` map ops.
- `removeHopHeaders` (`proxy_tunnel.go:975-991`) — `http.Header` ops, **but** it's H1-framing semantics;
  on H2 the illegal headers must be dropped *and never re-added* (`req.Write` re-adds them — another
  reason to abandon `req.Write` on the H2 path).
- Request logging/accounting: `recordRequestLogOnly` (`store.go:1037`), `SSL_INNER`
  (`proxy_tunnel.go:702`), `recordInspectBlock` (`proxy.go:95`) — per-parsed-request; **fine if each
  H2 stream is treated as a request** (they currently fire once per H1 iteration; the cadence maps
  cleanly to per-stream).

### 2.5 Behavioral changes even when nothing "breaks"

- **Concurrency profile flips.** H1 loop = strictly one request in flight per conn. H2 = up to
  `MaxConcurrentStreams` concurrent. The scanners are called from a single goroutine today; per-stream
  H2 means N concurrent `scanInspectBody` calls per conn. Check: `geoTrackSem` (256, `proxy.go:617`),
  the scan-buffer memory ceiling (`maxScanBufferBytes` × concurrent streams), and any shared state in
  ClamAV/YARA clients. Memory ceiling is now *per-conn × streams*, not *per-conn*.
- **Buffer-to-block vs. streaming.** `scanInspectBody` buffers up to `maxScanBufferBytes()` before
  forwarding (true prevention). On a long-lived H2 stream (gRPC, large download, SSE) this can stall the
  stream. Today the H1 path has the same property but one stream ≈ one conn; under H2 a single stalled
  stream shouldn't wedge the conn. Need per-stream "buffer up to N, then stream-through" semantics.
- **Head-of-line elimination.** Removing the H1 downgrade is the *point* — Google/modern origins see a
  real H2 client. That's the fix for the CAPTCHA. But it also means App-ID/DPI now sees interleaved
  streams; ordering assumptions (if any) in logging must not assume sequential completion.
- **TLS resumption tests.** `proxy_tunnel_tls_resume_test.go:98,175` build configs with
  `NextProtos: []string{"http/1.1"}` mirroring the pin; adding `h2` changes resumption ALPN and these
  need updating. `TestMITM_ForgedLeafTLSPosture` doesn't assert ALPN directly but exercises the leaf.

---

## 3. Test fallout inventory

| Test | File:line | Why it's affected |
|---|---|---|
| `TestMITM_ForgedLeafTLSPosture` | `mitm_inspect_e2e_test.go:501` | Exercises forged-leaf handshake; review if ALPN gains `h2` |
| TLS resume tests | `proxy_tunnel_tls_resume_test.go:98,175` | Hardcode `NextProtos: http/1.1` |
| `TestStallDetectReadCloser_*` (5) | `proxy_slowloris_body_test.go:46-217` | Pin per-conn-deadline stall model (H1-only) |
| `TestHandleWebSocket_Non101NotTunneled` | `proxy_websocket_status_test.go:26` | Pins 101-only upgrade→raw-relay |
| fileblock block-page bytes | `internal/fileblock/fileblock_test.go:168` | Asserts literal `HTTP/1.1 403` |
| inspect e2e suite | `mitm_inspect_e2e_test.go` (Non-TLS fallback, scrub, bypass, blocked, bad-cert, large-response, cert-cache-rotate, origin-interop) | Drive the H1 loop end-to-end |

None of these *have* to break if H2 is added as a **parallel branch** keyed on negotiated ALPN, leaving
the H1 loop intact for `http/1.1` clients (see §4). That is the low-risk path.

---

## 4. Recommended implementation shape (PAN-OS-style, minimal blast radius)

**Do NOT rip out the H1 loop.** Add an ALPN fork after the client handshake:

```
handleTunnelInspect:
  upstream = dial + TLS  (offer NextProtos ["h2","http/1.1"])   // was: no ALPN
  clientTLS = tls.Server(forged leaf, NextProtos ["h2","http/1.1"])  // was: ["http/1.1"]

  switch clientTLS.ConnectionState().NegotiatedProtocol {
    case "h2":
        if upstream negotiated "h2":  handleInspectH2(clientTLS, upstreamTLS, ...)   // NEW
        else:                          // client wants h2, origin only h1
                                       // v1: Strip-ALPN downgrade — re-handshake client as h1,
                                       // or bridge h2-client↔h1-origin (harder). Prefer downgrade.
    default (http/1.1):  <existing H1 loop, unchanged>            // EXISTING, untouched
  }
```

`handleInspectH2` uses `golang.org/x/net/http2`:
- **Client leg:** an `http2.Server`-driven conn (`(*http2.Server).ServeConn`) with a `http.Handler`
  that receives each stream as a normal `*http.Request` with an `http.ResponseWriter`. This gives us
  flow control, `MaxConcurrentStreams`, and per-stream lifecycle **for free** — solving §2.3(a).
- **Upstream leg:** an `http2.Transport` (or reuse the pooled transport's h2 capability) to re-originate
  each stream to the origin over h2.
- **Per stream:** run the *existing* `scrubForwardedHeaders` / file-block / `scanInspectBody` / CDR /
  DPI chain (all version-agnostic, §2.4). Block via a new `ResponseWriter`-based block emitter
  (refactor the three `net.Conn` block writers to a small `blockResponder` interface with H1 and H2
  impls — §2.2).
- **WebSocket/gRPC v1:** do **not** advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`; WS clients fall back
  to H1+Upgrade (existing 101 branch handles it). For gRPC/streaming, treat non-bufferable content-types
  (`application/grpc`, SSE `text/event-stream`) as stream-through (skip the buffer-to-block), mirroring
  the existing `bodyNeedsBuffering` gate (`security_scan.go:173`).

**Scope estimate:** the new `handleInspectH2` + `blockResponder` refactor + upstream ALPN + stall/limit
config + a new H2 e2e test suite. The scanners, CDR, file-block logic, and header scrubbers are reused
verbatim. The H1 path is untouched, so the existing test suite stays green and H2 is additive.

**Config surface (GUI-parity per CLAUDE.md):** add a per-rule/profile toggle mirroring PAN-OS —
`H2Inspect: on|strip-alpn` (default: inspect for new deployments; strip-alpn = today's behavior as the
safe fallback). Needs the admin API endpoint + UI panel per the repo's GUI-parity rule.

---

## 5. Risks & sequencing

1. **Highest risk:** the ALPN fork must be atomic with the parse-path fork — a half-done change (drop
   the pin, no H2 handler) drops every H2 client. Gate H2 behind a config flag defaulting to the current
   H1/strip-ALPN behavior; flip per-rule for Google first, validate with a NetLog, then widen.
2. **Memory:** scan-buffer ceiling becomes per-stream × concurrent streams. Cap `MaxConcurrentStreams`
   conservatively (e.g. 100, matching browsers) and account buffer memory against a global budget.
3. **Streaming stalls:** buffer-to-block on unbounded H2 streams (gRPC/SSE) wedges the stream — the
   stream-through gate for non-bufferable content-types is **required**, not optional, for H2.
4. **Interop:** validate against Google (the original repro), plus a gRPC service and an SSE endpoint,
   before default-on.

**Suggested order:** (1) upstream ALPN offer + negotiated-proto plumbing → (2) `blockResponder` refactor
of the 3 writers → (3) `handleInspectH2` via `x/net/http2` server+transport, reusing scanners →
(4) per-rule `H2Inspect` config + API + UI → (5) H2 e2e tests + gRPC/SSE stream-through → (6) default-on
for Google, measure CAPTCHA rate.

---

## 6. Bottom line vs. the CAPTCHA problem

Making the inspect path H2-aware removes **the single most anomalous signal Google sees** (a "Chrome"
speaking HTTP/1.1) and brings Culvert to parity with how PAN-OS decrypts Google today — *without*
excluding Google from inspection. It does **not** by itself fix the TLS-fingerprint difference (Go's
`crypto/tls` ClientHello ≠ Chrome's) or the shared-egress-IP reputation; those remain (see the main
investigation report). But H2 parity + a warmed/dedicated egress IP is the combination that lets you
keep Google under full inspection and stop the `/sorry` challenges — which is precisely the posture PAN-OS
customers run.
