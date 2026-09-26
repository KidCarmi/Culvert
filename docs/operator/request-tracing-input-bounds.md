# Client tracing headers are bounded (SEC-REQID-1)

## What changed

Culvert accepts two tracing headers from the client and reuses them as the
request's correlation identity:

| Header          | Purpose                                    |
| --------------- | ------------------------------------------ |
| `X-Request-Id`  | Culvert's own per-request correlation id   |
| `Traceparent`   | W3C Trace Context, propagated to upstreams |

Both are now **bounded and charset-checked at the point they are read**
(`setupRequestTracing`, `proxy.go`). A value that cannot be retained safely is
replaced with a freshly generated one, exactly as if the header had been absent.

**No request is ever refused because of a tracing header.** A correlation id is
a diagnostic aid, never a security-decision input, so refusing traffic over one
would turn a hardening change into an outage on an in-line gateway. The only
consequence of a rejection is that the correlation id for that request is
Culvert's instead of the client's.

## What is accepted

A client-supplied value is adopted when it is:

* present **exactly once** — a repeated header is refused, because ambiguous
  correlation is not correlation;
* non-empty;
* at most **128 bytes** (`X-Request-Id`) or **255 bytes** (`Traceparent`); and
* made entirely of **visible ASCII with no whitespace** — bytes `0x21`–`0x7E`.

When a value is refused, the freshly minted one **replaces the whole field**, so
exactly one value is forwarded upstream and mirrored on the response. A rejection
reports the total bytes across every value the client sent, not just the first.

Replacing a `Traceparent` also **drops any `Tracestate`** the client sent. W3C
Trace Context makes `tracestate` meaningful only relative to its `traceparent`,
so keeping it would forward a pair the client never sent — Culvert's minted trace
context carrying the client's vendor state — which an upstream may accept as
belonging to that new trace. The same applies to a `Tracestate` that arrives with
no `Traceparent` at all. A client whose `Traceparent` is **accepted** keeps its
`Tracestate` byte-for-byte: ordinary propagation through a forward proxy is not
disturbed. Culvert never reads `tracestate` — it is deleted or forwarded, never
parsed, logged or exported.

That admits every correlation-id encoding in real use: UUIDs (36 bytes), nginx
`$request_id` (32), ULIDs (26), base64url, and a W3C version-00 traceparent
(55). Culvert's own generated request id is 16 hex characters.

It excludes three classes. The first two are what the bound is really for; the
third is defence in depth against something net/http already refuses:

* **Whitespace, including the space character and `TAB`.** This is the
  wire-reachable half, and the one that matters. The value reaches roughly
  twenty process-log sites — every `POLICY_*` decision line, `AUTH_FAIL`,
  `IP_BLOCKED`, `RATE_LIMITED`, `BLOCKED`, `INVALID_HOST` — where it is rendered
  inside a space-separated `{req_id=… identity=… action=…}` block, so a value
  containing a space or a `TAB` injects extra `key=value` tokens that a
  first-wins log parser reads in preference to the real ones. net/http carries
  both bytes through to the handler, so Culvert's own bound is what stops them.
* **Every byte `0x80`–`0xFF`.** net/http does not restrict non-ASCII in a header
  value at all, so without this bound a correlation id could carry arbitrary
  bytes into the log, the response header and the upstream.
* **Control characters** (`0x00`–`0x1F`, `0x7F`) are excluded too, as
  defence in depth — but **they are not reachable over the wire**, and an
  earlier version of this page said otherwise. Measured against a real
  net/http server (`request_tracing_wire_bounds_test.go`): of 256 byte values,
  224 are delivered into a header value verbatim and 32 draw a **400 Bad
  Request before the handler runs** — exactly `0x00`–`0x1F` minus `TAB`, plus
  `0x7F`. `net/http`'s own `textproto.ReadMIMEHeader` refuses them, and every
  path that reaches the bound is parsed by it. So `ESC`, `NUL` and `BEL` never
  reached the forensic log; the earlier claim came from a test that set the
  header on a hand-built request rather than sending it over a socket. The
  partition is now pinned by a wall, so a future Go release that began
  carrying a control byte would fail the build rather than quietly widen what
  reaches the log.

## Why the length bound matters

The proxy listener sets no `MaxHeaderBytes`, so net/http's 1 MiB default was the
only ceiling on `X-Request-Id`. Measured against the real handler before this
change: **eight requests carrying a 512 KiB request id wrote 4,194,968 bytes
into the process log.**

The process log is a `fileutil.RotatingFile` capped at 50 MB that keeps exactly
one archive, so the entire retained record is 100 MB and rotates away in
seconds under that load. Every one of those writes *succeeds*, so the logsink
backpressure counter and every storage-health surface stay green while the
evidence is destroyed (CWE-778, OWASP A09:2021). This is the same amplification
class as CHAOS-63, reached through the **unauthenticated data plane** rather
than the admin API.

The `Traceparent` bound closes the matching OTLP exposure:
`internal/otlp.ParseTraceparent` splits the value and hands the pieces straight
to the exported span, so an unbounded traceparent was an unbounded,
attacker-chosen span attribute on the collector.

## What you will see

### Metrics

```
culvert_tracing_header_rejected_total{header="x_request_id"}
culvert_tracing_header_rejected_total{header="traceparent"}
```

Two fixed series — never a label derived from the rejected value, which is by
definition attacker-chosen.

### Admin UI

**Settings → Tracing Headers Replaced**, beside the log I/O rows (what the bound
protects is the integrity of the process log). Also on `GET /api/stats` as
`tracingHeaderRejected`.

### Process log

One line at onset, then at most one per minute, with the magnitude carried by
the counter — a mitigation for a write-amplification defect must not become one:

```
WARN Tracing: replaced an unusable client X-Request-Id from 198.51.100.7 (524288 bytes, limit 128, visible-ASCII only); 1 replaced since boot
```

The **rejected value itself is never logged**, in the line or anywhere else.
Echoing it to explain the rejection would perform exactly the amplification
being prevented. The length and the running count are what you need.

## Alerting

```yaml
- alert: CulvertTracingHeaderAbuse
  expr: increase(culvert_tracing_header_rejected_total[15m]) > 0
  annotations:
    summary: >-
      A source is sending Culvert oversized or control-character-carrying
      tracing headers — likely an attempt at log forgery or at flooding the
      process log through the proxy data plane.
```

A small, steady count from one source is usually a misconfigured upstream
emitting a non-conforming correlation id; traffic is unaffected and the only
cost is a broken trace chain for that client. A large or bursty count is abuse.

## If a legitimate client is affected

Symptom: a client's trace chain breaks at Culvert — its correlation id does not
appear in Culvert's logs or in the upstream's.

1. Check `culvert_tracing_header_rejected_total` to confirm the value is being
   replaced rather than lost somewhere else.
2. Capture the client's header and check it against the rules above. In practice
   the cause is whitespace or a non-ASCII byte, not length.
3. Fix it at the client. The bounds are **constants, with no configuration
   surface** — deliberately, on the same reasoning as `jwksStaleMaxAge`: a knob
   here could only ever widen the window in which untrusted bytes reach the
   forensic log, and the limits are already far above every real encoding.

## Recorded, not fixed

* The proxy listener still sets no `MaxHeaderBytes`, so net/http's 1 MiB default
  applies to headers generally. Lowering it changes which ordinary requests a
  forward proxy accepts, which is a product decision rather than this concern.
  With both tracing headers bounded, no *retained* value is unbounded any more.
* `internal/otlp.ParseTraceparent` still performs no format validation. It is
  now fed only bounded, visible-ASCII input, so the exposure is size- and
  charset-bounded; strict W3C validation would be a trace-context semantics
  change rather than an input-bounds one.
