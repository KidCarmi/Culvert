# Native HTTP/2 SSL Inspection

## Why

When Culvert inspects an HTTPS tunnel (SSL Forward Proxy / MITM), it historically
**downgraded the inspected connection to HTTP/1.1**: the forged-leaf ALPN offered
only `http/1.1`, and the upstream leg offered no ALPN. That downgrade is a strong
anti-bot signal — a "Chrome" that speaks HTTP/1.1 to Google is anomalous, and it is
a primary cause of Google `/sorry/index` reCAPTCHA challenges on inspected traffic
(see `roadmap/google-captcha-swg-investigation.md`).

**Native HTTP/2 inspection** lets Culvert inspect an HTTPS tunnel *as HTTP/2* end to
end — the client and origin both negotiate `h2`, and Culvert decrypts, inspects, and
re-encrypts each HTTP/2 stream through the same policy/scan/CDR/file-block pipeline
used for HTTP/1.1. This is the same posture PAN-OS ships (HTTP/2 inspection by
default, "Strip ALPN" as the downgrade escape hatch).

## Enabling it

Native H2 is **opt-in per policy rule** via the `stripAlpn` field on an
`SSLAction: Inspect` rule:

| `stripAlpn` | Behavior |
|---|---|
| absent / `true` | **Strip ALPN — HTTP/1.1 downgrade (default, unchanged).** Every pre-existing rule resolves here; an upgrade never silently changes inspection behavior. |
| `false` | **Native HTTP/2 inspection.** The tunnel negotiates `h2` on both legs when the client and origin both support it; otherwise it transparently falls back to HTTP/1.1 inspection (no client is ever stranded). |

Example rule (JSON):

```json
{
  "priority": 10,
  "name": "inspect-search-h2",
  "destCategory": "search-engines",
  "sslAction": "Inspect",
  "stripAlpn": false,
  "action": "allow"
}
```

The presence-aware `*bool` semantics mean: leaving the field unset keeps today's
HTTP/1.1 downgrade; you must set `stripAlpn: false` explicitly to enable native H2.

### How the protocol is chosen (ALPN intersection)

Per inspected tunnel, Culvert computes the effective protocol as the **intersection
of the client's ALPN offer, the rule's `stripAlpn` policy, and the origin's
capability**:

1. Send `200 Connection Established`, then read the client's offered ALPN from its
   ClientHello (read-only, fail-closed to `http/1.1` on any parse issue).
2. Offer the upstream `h2,http/1.1` only when the rule is native **and** the client
   offered `h2`; otherwise `http/1.1`.
3. Handshake upstream; constrain the forged-leaf offer to exactly what the origin
   negotiated.
4. Dispatch: `h2` on both legs → native H2 inspection; otherwise the shared HTTP/1.1
   inspection loop.

Because the upstream offer is bounded by the client's offer, the mixed quadrants
(h1-client/h2-origin, h2-client/h1-origin) cannot arise, so an HTTP/1.1-only client
is never stranded.

## What is inspected

Native H2 runs the **same** enforcement pipeline as HTTP/1.1 — there is one
inspection path, not a second one:

- forwarded-header scrubbing (`X-User-Identity`, private XFF/X-Real-IP),
- hop-by-hop header stripping,
- file-type blocking (extension / profile / Content-Disposition / MIME / magic bytes),
- CDR (content disarm), DPI signatures, ClamAV, YARA,
- per-rule "log full URL" and the `SSL_INNER` trace log,
- gRPC trailer (`grpc-status`) forwarding.

Blocks are emitted as an HTTP/2 `403` on the offending stream (no illegal
`Connection: close`); a policy block never tears down the shared connection or its
sibling streams.

## Security posture

- **Per-stream inactivity watchdog** — each stream is cancelled (RST_STREAM) if no
  body byte moves in either direction within the stall timeout (default 60s, the
  same as the HTTP/1.1 body-stall bound). It re-arms during both the scan-buffering
  and delivery phases, so a slow-but-steady stream (SSE, gRPC server-streaming,
  large download) is not falsely reset.
- **Per-connection concurrency cap** — `MaxConcurrentStreams = 32`. This is the
  primary per-connection memory bound: the scan pipeline buffers up to
  `maxScanBufferBytes` per in-flight response, so worst-case buffered memory is
  `maxScanBufferBytes × 32` per malicious connection. Plan connection capacity
  accordingly. It also equals the effective Rapid-Reset (CVE-2023-44487) cap.
  Separately, the response-delivery copy uses a pooled 128 KiB relay buffer per
  in-flight stream (shared `relayBufPool`, the same buffer every other tunnel relay
  uses), so the delivery-side copy footprint is up to `128 KiB × 32 = 4 MiB` per
  inspected H2 connection. These buffers are pooled and GC-reclaimed, not leaked;
  the copy path itself allocates nothing per response (it replaced `io.Copy`'s
  per-response 32 KiB allocation).
- **Frame/header caps** — `MaxReadFrameSize` and header-list-size (`MaxHeaderBytes`)
  pinned at 1 MiB.
- **Rapid Reset (CVE-2023-44487)** and the HTTP/2 **CONTINUATION flood
  (CVE-2023-45288)** are mitigated by default in the vendored `golang.org/x/net`.
- **No SSRF via `:authority`** — the upstream HTTP/2 connection is pinned to the
  CONNECT target, so a client-supplied `:authority`/`:path` cannot redirect a
  request to a different host. Content inspection runs regardless of authority.
- **Truncation safety** — an upstream that commits response headers then aborts
  mid-body resets the client stream rather than delivering a clean-but-truncated
  `200`.
- **Graceful GOAWAY on shutdown** — on process shutdown (SIGTERM, `docker compose
  down`/`stop`, maintenance-agent upgrade restart) every active inspected-H2 tunnel
  is sent a client **GOAWAY** so it stops opening new streams and its in-flight
  streams finish, rather than being cut by a bare FIN/RST. The drain sequence:
  (1) close the CONNECT listener; (2) fence new inspected-H2 tunnels and send the
  first GOAWAY wave; (3) wait up to **15s** on the tunnel-drain, re-sending GOAWAY
  each 500 ms so a late-registering tunnel is also signaled; (4) at the 15s deadline,
  **force-close** any still-open inspected-H2 client legs (the backstop) so an
  endless in-flight stream (SSE, gRPC server-streaming, multi-GB download) gets a
  deterministic teardown instead of relying on the container SIGKILL grace. The
  compose `proxy` service sets `stop_grace_period: 60s` to cover the full envelope —
  **keep it ≥ the drain envelope or the orchestrator will SIGKILL mid-drain and the
  GOAWAY becomes cosmetic.** Observability: `culvert_h2_inspect_active` (gauge),
  `culvert_h2_inspect_drain_goaway_total` (tunnels active when the drain started),
  `culvert_h2_inspect_drain_forced_total` (backstop closes). `goaway − forced`
  *approximates* how many drained gracefully — treat it as a heuristic, not an exact
  identity (a tunnel that registered after the drain start and was then force-closed
  counts in `forced` but not `goaway`).
  - **Scope:** this drains on *process shutdown only*. Live ADR-0005 HA transitions
    (`selfFence`/`enterStandbyResync` on lease loss) and hot config-snapshot pushes
    are in-process role/config changes that do **not** run the shutdown hooks, so
    inspected-H2 flows are **not** drained there — by design: the fencing lease
    governs Control-Plane write-authority, not Data-Plane proxying, so in-flight
    decrypted flows on a demoting node are unaffected by lease loss and need no drain.

## Known limitations / deferred hardening

These are safe to run opt-in but should be understood before enabling widely:

- **`:authority` pinning / 421 Misdirected Request** is not enforced. This is *not*
  a new exposure — the HTTP/1.1 inspection path forwards the inner `Host` to the
  pinned upstream identically today, and the single-SAN forged leaf already prevents
  a conformant client from coalescing unrelated origins. It is tracked as a **shared
  HTTP/1.1 + HTTP/2** hardening item, not an H2-only one.
- **TLS session resumption** for native tunnels is disabled (a perf optimization,
  not a correctness gap) — native tunnels use a per-connection forged-leaf config.
- **Configurability** — the stall timeout and `MaxConcurrentStreams` are currently
  compile-time constants. Exposing them as admin-tunable decryption-profile settings
  (PAN-OS-style) is a planned follow-up.

## Recommendation

Enable native H2 for anti-abuse / bot-sensitive destinations you must keep under
inspection (Google Search, etc.) — it removes the HTTP/1.1-downgrade signal that
triggers reCAPTCHA. Note that native H2 does **not** change the upstream TLS
*fingerprint* (Culvert re-originates TLS with Go's stack, not the client's), so for
destinations that fingerprint the TLS ClientHello, combine native H2 with a
bypass-from-inspection rule or a warmed/dedicated egress IP as described in the
investigation report.
