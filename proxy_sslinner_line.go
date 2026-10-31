package main

import "sync"

// proxy_sslinner_line.go — the SSL_INNER trace line, emitted once per inner
// request of every DECRYPTED tunnel (the H1 keep-alive loop in proxy_tunnel.go
// and the H2 stream handler in proxy_tunnel_h2.go).
//
// WHY THIS LINE GETS ITS OWN EMITTER. On an inspecting gateway this is the
// highest-frequency log site in the product. The enclosing CONNECT is logged
// once and then carries every HTTP request the client makes over that
// connection, so where the policy decision line is paid per TUNNEL, this one is
// paid per inner REQUEST — tens to hundreds of times more often on a
// keep-alive-heavy browser session, and it is the dominant request class
// whenever TLS inspection is on. It is also unconditional: there is no level
// gate, so every deployment with inspection enabled pays it on every request.
//
// It was two copies of one logger.Printf with six %-verbs and four sanitizeLog
// arguments. fmt pays for that shape in OBJECTS: the variadic ...any slice, one
// heap box per string operand (a non-constant string in an interface escapes),
// and strconv.Quote's rune-by-rune walk behind %q. Measured below: six
// allocations per line at every path length.
//
// ── WHY NOT THE emitPolicyDecision SHAPE (measured, and REJECTED) ────────────
//
// The obvious move is the one proxy.go already made for the policy decision
// line: render with appends into a stack scratch and hand the result to
// logger.Output(depth, string(b)). That shape is a NET REGRESSION here, and the
// reason is a property of log.Logger that the policy line's short, bounded
// operands hide.
//
// log.Logger.Printf appends the formatted line into the Logger's OWN reused
// buffer (fmt.Appendf into l.buf) and never materializes a string, so fmt's cost
// is a handful of small FIXED objects and ZERO bytes for the line itself — 96
// B/op whatever the line's length. logger.Output takes a STRING, so the append
// shape must pay `string(b)`: one heap allocation and one copy of the WHOLE
// line. Below ~100 bytes the five saved objects win; past that the line-sized
// allocation dominates and keeps growing.
//
// Measured by the in-tree benchmark (BenchmarkSSLInnerLine, go1.27.3,
// linux/amd64, 4-core Xeon @2.80GHz, discarding sink, shipped LstdFlags,
// medians of n=5), swept over request-path length — the only operand whose size
// varies:
//
//	path  │  before: logger.Printf  │ rejected: append+string │  AFTER: append+%s
//	bytes │   (the pre-change form) │   (emitPolicyDecision)  │  (pooled, SHIPPED)
//	    8 │   843 ns    96 B    6x  │   483 ns    96 B    1x  │   554 ns   24 B  1x
//	   40 │   984 ns    96 B    6x  │   518 ns   128 B    1x  │   509 ns   24 B  1x
//	  200 │  1018 ns    96 B    6x  │   766 ns   288 B    1x  │   671 ns   24 B  1x
//	  500 │  1141 ns    96 B    6x  │  1510 ns  1472 B    2x  │   931 ns   24 B  1x
//	 2048 │  2082 ns    96 B    6x  │  3752 ns  4609 B    2x  │  1727 ns   24 B  1x
//
// The middle column is the dead end, kept in the benchmark as
// sslInnerLineRejectedEmit and recorded here so the next pass does not rebuild
// it. It is the FASTEST form on a tiny path and 1.32x SLOWER than the code it
// replaces at 500 bytes and 1.80x slower at the bound — and 500 bytes is an
// ordinary CDN asset URL, not a pathological input. Its bytes/op climbs with the
// line while every other column's stays flat, which is the allocation it cannot
// avoid.
//
// Request paths here are bounded at 2 KiB (boundRetainedPath,
// proxy_path_bounds.go), not at the ~240 bytes a policy decision line tops out
// at, so the crossover sits inside this line's live range and outside the policy
// line's. The precedent was sound for that line and does not transfer to this
// one; that is a fact about log.Logger's buffer, not about either line's author.
//
// ── WHAT SHIPS ───────────────────────────────────────────────────────────────
//
// Render with appends, then hand the LOGGER THE BYTES (`%s` on a []byte), so the
// line is appended into log.Logger's reused buffer exactly as the format string
// was and is never materialized as a string. That keeps fmt's zero-bytes-for-
// the-line property AND drops the operand boxing, so it is faster at every
// length measured, including the 2 KiB bound: 6 objects to 1, and 96 B/op to a
// FLAT 24 B/op whatever the line's length (the one remaining object is fmt's
// ...any slice carrying the single []byte operand). Time per line falls 18% at
// the bound to 48% at an ordinary 40-byte path.
//
// The carrier is POOLED rather than a stack array, which is not a
// micro-preference but the difference between the win and a loss: `%s` passes
// the buffer to fmt as an `any`, so it ESCAPES, and a stack scratch therefore
// becomes a heap allocation of the whole array — measured 536 B/op for a 24-byte
// line with a 512-byte scratch, worse than the code it replaces. A pooled buffer
// is already heap-resident and is reused, so it allocates nothing in steady
// state and no growth copy survives the first few lines.
//
// WHAT MAKES THE APPENDS SAFE TO READ is that they are not trusted. The format
// string survives as an executable specification in
// TestSSLInnerLine_RenderIsByteIdentical, which renders every branch both ways,
// drives each awkward value through every operand position, and requires the
// bytes to match — plus FuzzSSLInnerLine. These lines are consumed by SIEM
// forwarders, operator greps and the edge-case lab's interception proof
// (EDGE-CASE-LAB-ARCHITECTURE.md reads SSL_INNER as the MITM witness), so
// byte-identity is the acceptance condition for the whole change, not a nicety.
//
// The line is deliberately still UNGATED. Gating it behind the existing debug
// level (logger.go's GetLogLevel) would remove 100% of this cost rather than
// ~25% of it, and that is the larger opportunity — but it is a change to an
// observability contract that operator documentation and the edge-case harness
// both depend on, so it is a product decision and not a performance change. It
// is reported, not taken, by this change.

// sslInnerLinePool carries one rendered SSL_INNER line. Pooled for the escape
// reason above.
//
// The buffer is handed to logger.Printf and returned to the pool as soon as that
// returns, which is safe because nothing downstream retains it:
// log.Logger.Output copies the formatted bytes into its own reused l.buf before
// calling the destination's Write, and internal/logsink.Writer.Write copies
// again into its own pooled carrier before queuing. A sink that retained the
// slice it was handed would already be broken for every other log line in the
// product, since log.Logger hands it the same reused buffer every time.
var sslInnerLinePool = sync.Pool{
	New: func() any { b := make([]byte, 0, sslInnerLineInitialCap); return &b },
}

// sslInnerLineInitialCap is the capacity a fresh carrier starts at: the fixed
// furniture is ~40 bytes and an ordinary line (client IP, method, host, path)
// lands near 120, so 512 absorbs the common case and the long-asset-URL case
// without a growth copy. It is a starting size, not a bound — append grows past
// it and the cap guard below decides what goes back.
const sslInnerLineInitialCap = 512

// sslInnerLineMaxPooled caps the capacity returned to the pool, so one
// request with a path at its 2 KiB retention bound cannot make every pooled
// carrier permanently that large. Same guard, and the same value, as
// internal/logsink's maxPooledLine.
const sslInnerLineMaxPooled = 4096

// logSSLInnerRequest emits the SSL_INNER trace line for one inner request of a
// decrypted tunnel, and owns the file-filtering branch both transports used to
// derive separately — so H1/H2 parity is now structural rather than two format
// strings that have to be kept in step by hand.
//
// clientIP, method, hostOnly and path are RAW: sanitizeLog is applied here, at
// the single point each reaches the line, which keeps the CWE-117 barrier
// exactly where the Printf form had it — at the emitter, on the value, before
// the sink. path is additionally bounded by boundRetainedPath, as it was at both
// call sites (register row PX-22 / X-1; the process log is sink 1 in
// proxy_path_bounds.go's inventory).
//
// The filter token reaches the buffer BARE because it is one of two
// compile-time constants, which is the same set the Printf form passed bare
// through %s. The profile name is admin-configured rather than client-chosen,
// but it is sanitized and quoted anyway, because that is what %q did.
func logSSLInnerRequest(clientIP, method, hostOnly, path string, match *PolicyMatch) {
	filter := "off"
	profile := ""
	if match != nil && match.Rule != nil && match.Rule.FileFiltering {
		filter = "on"
		profile = sanitizeLog(string(match.Rule.FileProfile))
	}

	bp, _ := sslInnerLinePool.Get().(*[]byte)
	b := (*bp)[:0]
	b = append(b, "SSL_INNER "...)
	b = append(b, sanitizeLog(clientIP)...)
	b = append(b, ' ')
	b = append(b, sanitizeLog(method)...)
	b = append(b, ' ')
	b = append(b, sanitizeLog(hostOnly)...)
	// Host and path are adjacent with no separator — "%s%s" in the replaced
	// format string. Preserved verbatim: these lines are parsed downstream.
	b = append(b, sanitizeLog(boundRetainedPath(path))...)
	b = append(b, " (profile="...)
	b = appendQuotedForLog(b, profile)
	b = append(b, " filter="...)
	b = append(b, filter...)
	b = append(b, ')')

	// "%s" on a []byte writes the bytes verbatim — byte-identical to the string
	// the replaced format string produced — and goes into log.Logger's reused
	// buffer rather than a fresh string. Printf fixes its own call depth, so
	// under Lshortfile/Llongfile the line would attribute to this file instead
	// of the caller; that is inert in the shipped configuration, where
	// setupLogger uses LstdFlags only and file/line is never computed.
	logger.Printf("%s", b)

	// Store the grown slice back before returning it, or the capacity the
	// growth bought is thrown away on every line.
	*bp = b
	if cap(b) <= sslInnerLineMaxPooled {
		sslInnerLinePool.Put(bp)
	}
}
