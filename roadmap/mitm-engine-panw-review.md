# PAN-OS Architect Review — Culvert MITM Engine: Refactor or OK?

**Reviewer perspective:** Distinguished Engineer, PAN-OS Decryption (SSL Forward Proxy / HTTP/2 Inspection)
**Artifact:** `handleTunnelInspect` and its call graph (`proxy_tunnel.go`, `proxy_http.go`, `security_scan.go`, `scanner.go`, `internal/fileblock`, `cdr_proxy.go`)
**Question:** Does the MITM engine need a refactor, or is the engine as-built OK (H2 being a bolt-on)?

---

## VERDICT: TARGETED REFACTOR

**Not a rewrite. Not "ship as-is."** The engine core is sound — a real full proxy with a
protocol-neutral content plane. But the transport plane hardcodes HTTP/1.1 in **three named
seams plus one deadline model**, and those must be cut *before* H2 ships. Sign-off is granted
to *add* H2 to this engine, conditional on the three items below landing first, in order.

**Maturity rating: 6.5 / 10** vs. a commercial decryption engine.

---

## What's genuinely sound (do NOT touch)

- **Full-proxy shape.** Independent dual-TLS termination (client forged leaf `proxy_tunnel.go:643`,
  origin TLS `:565`) + real decrypt→inspect→re-encrypt loop (`:671-787`). Not a peek-and-splice.
- **Protocol-neutral content plane** — the load-bearing strength. Every scanner/policy function
  (`inspectFileBlocked:798`, `scanInspectBody:890`, `runCDRStage`, DPI/ClamAV/YARA) operates on
  `*http.Request`/`*http.Response`/`[]byte`, never wire bytes. H2 plugs in at the parse boundary and
  the entire security pipeline is reused verbatim. Most OSS MITMs get this wrong; Culvert got it right.
- **True prevention semantics** — buffer-to-block before first byte reaches the client.
- **Security hygiene above grade** — two-layer SSRF guard (`isPrivateHost` + `ssrfControl`, defeats
  DNS rebinding), fail-closed upstream verify, CA-rotation-driven ticket-key invalidation, hop-header
  scrubbing on the decrypted inner request, non-TLS peek fallback, idle reaping with resumable read
  deadlines that correctly avoid write-deadline TLS corruption.
- **ECDHE/AEAD forged-leaf posture** — satisfies the same key-exchange requirement PAN-OS H2 imposes.

## What's H1-welded (the targeted refactor)

1. **Block emitters hardcode H1 bytes.** `scanBlockConn` (`security_scan.go:127`), `dpiBlock`
   (`scanner.go:59`), `fileblock.BlockConn` (`internal/fileblock/fileblock.go:293`) all hand-write
   `HTTP/1.1 403…Connection: close` onto a raw `net.Conn`. Under H2 that's malformed twice
   (`HTTP/1.1` status line invalid on a stream; **`Connection: close` forbidden by RFC 7540 §8.1.2.2**).
   **Localized wart, not pervasive coupling** — 3 functions, a handful of call sites, all inside the
   inspect path, and the block *decision* is already split from block *emission*. They're already
   parameterized on a `Write` interface (half the seam done).

2. **Stall/slowloris state is connection-keyed, not stream-keyed.** `clientTLS.SetReadDeadline`
   (`proxy_tunnel.go:674`) + `stallDetectReadCloser` re-arming the same conn deadline
   (`proxy_tunnel.go:688`, `proxy_http.go:30`). A conn deadline aborts **all** H2 streams — the one
   architectural incompatibility with multiplexing. **But the assumption doesn't run into the policy
   plane** (scanners hold no per-conn state), so it's a swappable mechanism confined to the transport
   spine, not a state-keying decision baked through the engine.

3. **Monolithic loop.** Parse/policy/serialize are sequenced inline in one `for` loop
   (`proxy_tunnel.go:671-787`, carrying `//nolint:gocognit,gocyclo,cyclop,funlen`). No interface at the
   parse↔policy↔serialize seams. Because the content plane *is* already decomposed, the monolith is
   confined to the transport spine — the layer you replace per-protocol anyway.

Plus: **WebSocket model doesn't survive H2.** The 101 branch raw-relays the whole conn
(`proxy_tunnel.go:737-759`) — correct for H1+Upgrade, wrong for H2 (no 101; RFC 8441 Extended CONNECT
lives on one stream). Engine's discipline (gates raw-relay strictly on status 101) gives the clean v1
answer: don't advertise `ENABLE_CONNECT_PROTOCOL`, let WS fall back to H1.

## Sign-off conditions (required, in this order)

1. **Cut the `blockResponder` seam first** — H1 + H2 impls, migrate all three writers + call sites off
   the raw `net.Conn`, land green on the H1 path with existing tests as the oracle, *before* any H2 code.
2. **Adopt `golang.org/x/net/http2`'s server conn** (already vendored) for the client leg — fork on
   negotiated ALPN, `http/1.1`→existing loop untouched, `h2`→new `handleInspectH2` running each stream
   through the same scrub/file-block/scan/CDR chain. Per-stream flow control + `MaxConcurrentStreams`
   for free. **Do not hand-roll a framer; do not mutate the existing loop.**
3. **Mandatory stream-through for non-bufferable content** (`application/grpc`, `text/event-stream`)
   and cap `maxScanBufferBytes × MaxConcurrentStreams` against a global memory ceiling. Conservative
   `MaxConcurrentStreams` (~100).

## Bottom line

Sound H1 full-proxy + clean content plane + transport plane that hardcodes H1 in three named places and
one deadline model = **the definition of a targeted refactor, not a rewrite**. What Culvert documents as
its "limitation" (`proxy_tunnel.go:664`, permanent H1 downgrade) is precisely PAN-OS's **Strip-ALPN
fallback made permanent**. The work is to make it the exception (H2 default, strip-ALPN as the escape
hatch via a per-rule `H2Inspect: on | strip-alpn` toggle), not to rebuild the engine that enforces it.
