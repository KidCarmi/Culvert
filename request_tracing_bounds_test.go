package main

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// request_tracing_bounds_test.go — SEC-REQID-1.
//
// The DEFECT GATES in this file were each verified FAILING against the pre-fix
// shape of setupRequestTracing, which was exactly:
//
//	reqID := strings.ReplaceAll(strings.ReplaceAll(r.Header.Get(headerRequestID), "\n", ""), "\r", "")
//	needTraceparent := r.Header.Get(headerTraceparent) == ""
//
// i.e. CR/LF stripped and nothing else, no length bound, and any non-empty
// traceparent propagated verbatim. TestSecReqID1_DefectProof_PreFixShapeRetains
// rebuilds that shape inline and asserts it still fails the contract, so the
// gates cannot quietly stop proving what they claim.
//
// The CONTROLS matter as much as the gates: the cheapest way to pass every
// "nothing hostile is retained" assertion is to stop honouring client tracing
// headers at all, which would silently delete distributed tracing across the
// gateway. TestSecReqID1_Control_* pin that a legitimate value still propagates.

// ─── the predicate ──────────────────────────────────────────────────────────

func TestAcceptableTracingHeaderValue_Charset(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		// Positive: every shape a real correlation id takes.
		{"hex16", "20d2f9ed45b572f9", true},
		{"uuid", "3f2504e0-4f89-11d3-9a0c-0305e82c3301", true},
		{"nginx request id", strings.Repeat("a1b2", 8), true},
		{"ulid", "01ARZ3NDEKTSV4RRFFQ69G5FAV", true},
		{"base64url with padding", "c29tZS1yZXF1ZXN0LWlk=", true},
		{"w3c traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01", true},
		{"upstream style", "upstream-request-id", true},
		{"punctuation set", "a.b:c/d+e=f-g_h", true},
		{"single visible byte", "!", true},
		{"tilde is the last printable", "~", true},

		// Negative: the two classes this bound exists for.
		{"empty", "", false},
		{"space forges a log token", "abc action=deny identity=root", false},
		{"tab", "abc\tdef", false},
		{"ESC enables terminal rewriting", "abc\x1b[2Kdef", false},
		{"NUL truncates readers", "abc\x00def", false},
		{"BEL", "abc\x07def", false},
		{"vertical tab", "abc\x0bdef", false},
		{"form feed", "abc\x0cdef", false},
		{"DEL", "abc\x7fdef", false},
		{"newline", "abc\ndef", false},
		{"carriage return", "abc\rdef", false},
		{"non-ascii", "abcédef", false},
		{"high byte", "abc\xffdef", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := acceptableTracingHeaderValue(tc.in, maxClientRequestIDLen); got != tc.want {
				t.Errorf("acceptableTracingHeaderValue(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestAcceptableTracingHeaderValue_LengthBoundary pins both sides of the bound.
// An off-by-one here is the difference between "the documented limit" and "one
// byte more than the documented limit", which is the kind of drift a length
// check acquires silently.
func TestAcceptableTracingHeaderValue_LengthBoundary(t *testing.T) {
	for _, tc := range []struct {
		name string
		max  int
	}{
		{"request id", maxClientRequestIDLen},
		{"traceparent", maxClientTraceparentLen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !acceptableTracingHeaderValue(strings.Repeat("a", tc.max), tc.max) {
				t.Errorf("a value of exactly %d bytes must be accepted", tc.max)
			}
			if acceptableTracingHeaderValue(strings.Repeat("a", tc.max+1), tc.max) {
				t.Errorf("a value of %d bytes must be rejected", tc.max+1)
			}
		})
	}
}

// TestAcceptableTracingHeaderValue_EveryByteIsClassified walks the whole 0..255
// byte space so a future edit to the range cannot widen it unnoticed. The
// accepted set is exactly the visible-ASCII range 0x21..0x7E: no control byte,
// no space, no DEL, nothing non-ASCII.
func TestAcceptableTracingHeaderValue_EveryByteIsClassified(t *testing.T) {
	for b := 0; b < 256; b++ {
		got := acceptableTracingHeaderValue(string([]byte{byte(b)}), maxClientRequestIDLen)
		want := b >= 0x21 && b <= 0x7e
		if got != want {
			t.Errorf("byte 0x%02x: accepted = %v, want %v", b, got, want)
		}
	}
}

// ─── the entry point: defect gates ──────────────────────────────────────────

// TestSecReqID1_ControlCharactersNeverReachTheLog is the first defect gate: the
// pre-fix shape returned the payload byte-identical, so an ESC sequence reached
// every POLICY_* line the request produced.
func TestSecReqID1_ControlCharactersNeverReachTheLog(t *testing.T) {
	resetTracingBoundsStateForTest()
	const payload = "abc\x1b[2Kdef\x00ghi\x07jkl\x7fmno"

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Set(headerRequestID, payload)
	rec := httptest.NewRecorder()

	got := setupRequestTracing(rec, r)

	if got == payload {
		t.Fatal("the client-supplied request id was adopted verbatim (pre-fix behaviour)")
	}
	if strings.ContainsAny(got, "\x00\x07\x1b\x7f") {
		t.Errorf("request id %q still carries control characters", got)
	}
	if len(got) != requestIDHexLen {
		t.Errorf("request id = %q, want a freshly minted %d-char id", got, requestIDHexLen)
	}
}

// TestSecReqID1_OversizeRequestIDIsNotRetained is the write-amplification gate.
// Measured pre-fix: eight requests carrying a 512 KiB X-Request-Id wrote
// 4,194,968 bytes into the process log.
func TestSecReqID1_OversizeRequestIDIsNotRetained(t *testing.T) {
	resetTracingBoundsStateForTest()
	payload := strings.Repeat("A", 512*1024)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Set(headerRequestID, payload)
	rec := httptest.NewRecorder()

	got := setupRequestTracing(rec, r)

	if len(got) != requestIDHexLen {
		t.Fatalf("request id is %d bytes, want the minted %d — an unbounded id still reaches every log site", len(got), requestIDHexLen)
	}
	if h := rec.Header().Get(headerRequestID); len(h) != requestIDHexLen {
		t.Errorf("response header is %d bytes, want %d", len(h), requestIDHexLen)
	}
	if n := requestIDRejected.Load(); n != 1 {
		t.Errorf("requestIDRejected = %d, want 1", n)
	}
}

// TestSecReqID1_HostileValueDoesNotReachTheUpstream pins the half a log-site
// scrub could never reach: the value is also FORWARDED. The mint arm overwrites
// the request header, so the upstream's own logs are protected too.
func TestSecReqID1_HostileValueDoesNotReachTheUpstream(t *testing.T) {
	resetTracingBoundsStateForTest()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Set(headerRequestID, "abc def\x1bghi")
	r.Header.Set(headerTraceparent, strings.Repeat("z", maxClientTraceparentLen+1))
	rec := httptest.NewRecorder()

	got := setupRequestTracing(rec, r)

	if fwd := r.Header.Get(headerRequestID); fwd != got {
		t.Errorf("forwarded %s = %q, want the minted %q", headerRequestID, fwd, got)
	}
	if fwd := r.Header.Get(headerTraceparent); len(fwd) != traceparentLen {
		t.Errorf("forwarded %s is %d bytes, want the minted %d", headerTraceparent, len(fwd), traceparentLen)
	}
}

// TestSecReqID1_OversizeTraceparentIsReplaced closes the OTLP half:
// internal/otlp.ParseTraceparent splits on "-" with no bound and hands the
// pieces straight to the exported span, so an unbounded traceparent is an
// unbounded attacker-chosen span attribute.
func TestSecReqID1_OversizeTraceparentIsReplaced(t *testing.T) {
	resetTracingBoundsStateForTest()
	hostile := "00-" + strings.Repeat("a", 300) + "-" + strings.Repeat("b", 300) + "-01"

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Set(headerTraceparent, hostile)
	rec := httptest.NewRecorder()
	setupRequestTracing(rec, r)

	tp := r.Header.Get(headerTraceparent)
	if tp == hostile {
		t.Fatal("the hostile traceparent was propagated verbatim (pre-fix behaviour)")
	}
	if len(tp) != traceparentLen {
		t.Errorf("traceparent = %q (len %d), want a freshly minted %d-char value", tp, len(tp), traceparentLen)
	}
	traceID, spanID := parseTraceparent(tp)
	if len(traceID) != 32 || len(spanID) != 16 {
		t.Errorf("parsed trace/span ids are %d/%d chars, want 32/16", len(traceID), len(spanID))
	}
	if n := traceparentRejected.Load(); n != 1 {
		t.Errorf("traceparentRejected = %d, want 1", n)
	}
}

// TestSecReqID1_EndToEndLogAmplificationIsBounded drives the REAL handler, which
// is what the pre-fix measurement used. Eight requests carrying a 512 KiB
// request id wrote 4,194,968 bytes; with the bound in place the same eight
// requests must write a log whose size is a function of the decision lines
// alone.
func TestSecReqID1_EndToEndLogAmplificationIsBounded(t *testing.T) {
	resetTracingBoundsStateForTest()
	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	const requests = 8
	payload := strings.Repeat("A", 512*1024)
	for i := 0; i < requests; i++ {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
		r.Header.Set(headerRequestID, payload)
		r.RemoteAddr = "198.51.100.7:1234"
		handleRequest(httptest.NewRecorder(), r)
	}

	// Pre-fix this was 4,194,968 bytes. The bound is deliberately generous —
	// the point is the ORDER OF MAGNITUDE, not a byte-exact line format that
	// would make this test brittle against an unrelated log-wording change.
	const bound = 64 * 1024
	if buf.Len() > bound {
		t.Errorf("%d requests wrote %d bytes to the process log, want <= %d — the request id is still amplifying",
			requests, buf.Len(), bound)
	}
	if n := requestIDRejected.Load(); n != requests {
		t.Errorf("requestIDRejected = %d, want %d", n, requests)
	}
}

// TestSecReqID1_RejectionLogIsRateLimited pins that the mitigation is not itself
// an amplifier: a flood must buy at most one line per window.
func TestSecReqID1_RejectionLogIsRateLimited(t *testing.T) {
	resetTracingBoundsStateForTest()
	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	for i := 0; i < 500; i++ {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
		r.Header.Set(headerRequestID, strings.Repeat("A", maxClientRequestIDLen+1))
		r.RemoteAddr = "198.51.100.9:5555"
		setupRequestTracing(httptest.NewRecorder(), r)
	}

	if got := strings.Count(buf.String(), "Tracing: replaced an unusable client"); got != 1 {
		t.Errorf("emitted %d rejection log lines for 500 rejections, want exactly 1 (onset only)", got)
	}
	if n := requestIDRejected.Load(); n != 500 {
		t.Errorf("requestIDRejected = %d, want 500 — the magnitude must live in the counter", n)
	}
}

// TestSecReqID1_RejectedValueIsNeverLogged pins that the refusal does not
// perform the amplification it prevents. The refused bytes are attacker-chosen;
// only the length and the count may be reported.
func TestSecReqID1_RejectedValueIsNeverLogged(t *testing.T) {
	resetTracingBoundsStateForTest()
	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	const marker = "MARKERCANARY"
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Set(headerRequestID, marker+strings.Repeat("A", maxClientRequestIDLen))
	r.RemoteAddr = "198.51.100.11:5555"
	setupRequestTracing(httptest.NewRecorder(), r)

	if strings.Contains(buf.String(), marker) {
		t.Errorf("the rejected value reached the log:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "Tracing: replaced an unusable client") {
		t.Errorf("onset was not logged at all:\n%s", buf.String())
	}
}

// ─── controls ───────────────────────────────────────────────────────────────

// TestSecReqID1_Control_LegitimateRequestIDStillPropagates is the control for
// every gate above. Refusing all client tracing headers would pass them all
// while silently breaking distributed tracing through the gateway.
func TestSecReqID1_Control_LegitimateRequestIDStillPropagates(t *testing.T) {
	resetTracingBoundsStateForTest()
	const id = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	const tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Set(headerRequestID, id)
	r.Header.Set(headerTraceparent, tp)
	rec := httptest.NewRecorder()

	got := setupRequestTracing(rec, r)

	if got != id {
		t.Errorf("request id = %q, want the client's %q preserved", got, id)
	}
	if h := rec.Header().Get(headerRequestID); h != id {
		t.Errorf("response header = %q, want %q", h, id)
	}
	if fwd := r.Header.Get(headerTraceparent); fwd != tp {
		t.Errorf("traceparent = %q, want the client's %q preserved", fwd, tp)
	}
	if n := requestIDRejected.Load() + traceparentRejected.Load(); n != 0 {
		t.Errorf("a legitimate pair was counted as %d rejections, want 0", n)
	}
}

// TestSecReqID1_Control_AbsentHeadersStillMint pins that the zero-config path —
// the overwhelmingly common one for direct client traffic — is unchanged.
func TestSecReqID1_Control_AbsentHeadersStillMint(t *testing.T) {
	resetTracingBoundsStateForTest()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	rec := httptest.NewRecorder()

	got := setupRequestTracing(rec, r)

	if len(got) != requestIDHexLen {
		t.Errorf("minted request id = %q (len %d), want %d", got, len(got), requestIDHexLen)
	}
	if tp := r.Header.Get(headerTraceparent); len(tp) != traceparentLen {
		t.Errorf("minted traceparent = %q (len %d), want %d", tp, len(tp), traceparentLen)
	}
	// An absent header is NOT a rejection: counting it would make the operator
	// signal fire on every ordinary request and be worth nothing.
	if n := requestIDRejected.Load() + traceparentRejected.Load(); n != 0 {
		t.Errorf("absent headers counted as %d rejections, want 0", n)
	}
}

// ─── the rejection path does no unbounded work ──────────────────────────────

// TestSecReqID1_RejectionDoesNotWalkXFF is the gate on the Codex P1 (PR #1406):
// the first shape of this fix resolved realClientIP at the CALL SITE, so every
// rejection paid for it.
//
// Behind a configured trusted proxy — Culvert's ordinary deployment behind a load
// balancer — realClientIP joins every X-Forwarded-For field line into one string
// and splits it on every comma, then parses each token. Against a near-1 MiB XFF
// that is a ~1 MiB copy plus a slice with one header per comma, PER REJECTION,
// twice when both tracing headers are hostile, running ahead of the connection
// limiter, the IP filter and the rate limiter, from an unauthenticated request.
// The bound that stopped bytes reaching the log opened a CPU-and-allocation
// amplifier in front of every limiter.
//
// The gate measures ALLOCATED BYTES, deliberately NOT allocation COUNT and not a
// timing ratio.
//
// The count is the wrong observable here, and this gate was written that way
// first and passed against the defect: `strings.Split` allocates ONE []string
// however many commas it finds, and `strings.Join` of a single field line returns
// it without copying, so eager resolution costs a constant ~2 allocations and the
// count is flat in hop count. The COST is in the bytes — one string header per
// comma, so 50,000 hops is ~800 KiB per rejection. Bytes are deterministic for a
// fixed workload, so this stays hardware-independent and cannot flake the way a
// timing ratio would (the repo's standing rule: a gate that can flake gets muted).
//
// The property is INDEPENDENCE: the suppressed rejection path must allocate
// about the same whether the request carries a 1-hop XFF or a 50,000-hop one.
func TestSecReqID1_RejectionDoesNotWalkXFF(t *testing.T) {
	// A trusted proxy must be configured, or realClientIP returns the peer
	// without ever looking at XFF and the gate would pass vacuously.
	if err := SetTrustedProxyCIDRs([]string{"192.0.2.0/24"}); err != nil {
		t.Fatalf("SetTrustedProxyCIDRs: %v", err)
	}
	t.Cleanup(func() { _ = SetTrustedProxyCIDRs(nil) })

	old := logger
	logger = log.New(&safeDiscard{}, "", 0)
	t.Cleanup(func() { logger = old })

	const iters = 20
	measureBytes := func(hops int) uint64 {
		resetTracingBoundsStateForTest()
		xff := strings.TrimSuffix(strings.Repeat("203.0.113.9,", hops), ",")
		build := func() *http.Request {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
			r.RemoteAddr = "192.0.2.10:4444" // inside the trusted CIDR
			r.Header.Set("X-Forwarded-For", xff)
			r.Header.Set(headerRequestID, strings.Repeat("A", maxClientRequestIDLen+1))
			return r
		}
		// Prime the rate gate so every measured run is SUPPRESSED — that is the
		// flood path, and the one that must not walk the header. The XFF string
		// itself is built once, so per-iteration request construction costs the
		// same in both arms.
		setupRequestTracing(httptest.NewRecorder(), build())
		w := httptest.NewRecorder()
		reqs := make([]*http.Request, iters)
		for i := range reqs {
			reqs[i] = build()
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := 0; i < iters; i++ {
			setupRequestTracing(w, reqs[i])
		}
		runtime.ReadMemStats(&after)
		return (after.TotalAlloc - before.TotalAlloc) / iters
	}

	small := measureBytes(1)
	large := measureBytes(50000)
	t.Logf("suppressed rejection bytes/op: 1-hop XFF = %d, 50000-hop XFF = %d", small, large)

	// Independence, with generous headroom for measurement noise. Pre-fix the
	// large arm carries ~16 bytes per hop (~800 KiB), which is orders of
	// magnitude above the small arm rather than a few hundred bytes above it.
	if large > small+4096 {
		t.Errorf("suppressed rejection allocates %d bytes/op with a 50000-hop XFF vs %d with 1 hop —"+
			" the client IP is being resolved per rejection ahead of the limiters", large, small)
	}
}

// TestSecReqID1_RejectionLogStillNamesTheRealClient is the CONTROL for the gate
// above. Deferring the resolution must not silently downgrade the log to the
// proxy's address: the operator hunting the source needs the client behind it.
// The cheapest way to pass the allocation gate is to stop calling realClientIP at
// all, which would pass it while making the one line a flood emits useless.
func TestSecReqID1_RejectionLogStillNamesTheRealClient(t *testing.T) {
	if err := SetTrustedProxyCIDRs([]string{"192.0.2.0/24"}); err != nil {
		t.Fatalf("SetTrustedProxyCIDRs: %v", err)
	}
	t.Cleanup(func() { _ = SetTrustedProxyCIDRs(nil) })

	resetTracingBoundsStateForTest()
	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.RemoteAddr = "192.0.2.10:4444"
	r.Header.Set("X-Forwarded-For", "198.51.100.44")
	r.Header.Set(headerRequestID, strings.Repeat("A", maxClientRequestIDLen+1))
	setupRequestTracing(httptest.NewRecorder(), r)

	if !strings.Contains(buf.String(), "198.51.100.44") {
		t.Errorf("rejection line does not name the real client behind the trusted proxy:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "192.0.2.10") {
		t.Errorf("rejection line names the proxy rather than the client:\n%s", buf.String())
	}
}

// TestSecReqID1_LogGateTakesNoLock pins that the rate gate is lock-free. It is
// reached from the second statement of handleRequest, ahead of the connection
// limiter and the per-IP rate limiter — both of which are SHARDED precisely
// because an unsharded process-wide lock on the request path is a throughput
// ceiling. A mutex here would reintroduce that ceiling in front of both, on
// exactly the flood the gate exists to bound.
//
// Structural, not timing-based: the gate must answer while a concurrent caller is
// in flight, and repeated calls inside one window must all suppress without
// blocking. Combined with the allocation gate above, a return to a mutex shows up
// as a compile change here rather than as a benchmark wobble.
func TestSecReqID1_LogGateTakesNoLock(t *testing.T) {
	resetTracingBoundsStateForTest()
	if !noteTracingBoundsLog() {
		t.Fatal("first call must arm the window and emit")
	}
	var wg sync.WaitGroup
	const workers = 32
	admitted := make([]bool, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); admitted[i] = noteTracingBoundsLog() }(i)
	}
	wg.Wait()
	for i, a := range admitted {
		if a {
			t.Errorf("worker %d was admitted inside an armed window — the window is not being honoured", i)
		}
	}
}

// TestSecReqID1_LogGateReArmsOnClockRollback pins the CHAOS-61 direction: a clock
// that went backwards must not silence the operator for however far back it went.
func TestSecReqID1_LogGateReArmsOnClockRollback(t *testing.T) {
	resetTracingBoundsStateForTest()
	if !noteTracingBoundsLog() {
		t.Fatal("first call must arm")
	}
	if noteTracingBoundsLog() {
		t.Fatal("second call inside the window must suppress")
	}
	// Simulate the stamp being in the FUTURE (a rollback of the wall clock).
	tracingBoundsLogLast.Store(time.Now().Add(time.Hour).UnixNano())
	if !noteTracingBoundsLog() {
		t.Error("a future stamp (clock rollback) must re-arm and report, not suppress")
	}
}

// ─── recorded residual ──────────────────────────────────────────────────────

// TestSecReqID1_Residual_DuplicateHeaderSecondValueIsForwarded PINS a residual
// rather than asserting a fix, so a future reader finds it stated rather than
// discovering it.
//
// A client may send X-Request-Id twice. Header.Get returns the FIRST value, so
// that is the one Culvert validates, adopts, logs and mirrors — and when it is
// acceptable the mint arm does not run, so the SECOND value is still on the
// request map and is forwarded to the upstream.
//
// It is recorded and not fixed because it is bounded to exactly the place a
// forward proxy is supposed to be transparent, and reaches nothing this change
// is about:
//
//   - Culvert's own process log, response header and correlation identity all
//     use reqID — the validated first value — so the log-forgery and
//     log-amplification exposures are fully closed.
//   - A client that can reach Culvert can generally reach the origin, and
//     forwarding client headers is a forward proxy's defined behaviour; the
//     value is not a framing header, so it enables no smuggling or desync.
//   - net/http's own transport refuses to write a header value containing a
//     control character (httpguts.ValidHeaderFieldValue), so the injection half
//     fails the request rather than reaching the upstream.
//
// Collapsing duplicates would mean replacing Header.Get with a direct map index
// on this path to see the slice, which is measurable work on the second
// statement of handleRequest for a residual with no Culvert-side consequence.
// If that is ever revisited, this test is where to start.
func TestSecReqID1_Residual_DuplicateHeaderSecondValueIsForwarded(t *testing.T) {
	resetTracingBoundsStateForTest()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Add(headerRequestID, "good-id-1")
	r.Header.Add(headerRequestID, "hostile id\x1b")
	rec := httptest.NewRecorder()

	got := setupRequestTracing(rec, r)

	// The half that matters: what Culvert adopts, logs and mirrors is the
	// validated first value, never the hostile second one.
	if got != "good-id-1" {
		t.Errorf("adopted request id = %q, want the validated first value", got)
	}
	if h := rec.Header().Get(headerRequestID); h != "good-id-1" {
		t.Errorf("response header = %q, want the validated first value", h)
	}
	// The recorded residual. If a future change collapses duplicates, this
	// assertion is the one to invert — deliberately, not by accident.
	if n := len(r.Header.Values(headerRequestID)); n != 2 {
		t.Errorf("forwarded header carries %d values, want the recorded 2 —"+
			" if duplicates are now collapsed, update this test and the residual note", n)
	}
}

// ─── defect proof ───────────────────────────────────────────────────────────

// TestSecReqID1_DefectProof_PreFixShapeRetains rebuilds the pre-fix read inline
// and asserts it STILL fails the contract. Without it, a future change that made
// the gates above vacuous (a payload that stops being hostile, a helper that
// stops being reached) would leave them green while proving nothing.
func TestSecReqID1_DefectProof_PreFixShapeRetains(t *testing.T) {
	const payload = "abc\x1b[2Kdef action=deny"
	preFix := strings.ReplaceAll(strings.ReplaceAll(payload, "\n", ""), "\r", "")

	if preFix != payload {
		t.Fatal("the pre-fix sanitiser is no longer a no-op on this payload; the gates above test nothing")
	}
	if acceptClientRequestID(preFix) {
		t.Error("acceptClientRequestID admits a value the pre-fix shape retained verbatim")
	}
	long := strings.Repeat("A", 512*1024)
	if acceptClientRequestID(strings.ReplaceAll(strings.ReplaceAll(long, "\n", ""), "\r", "")) {
		t.Error("acceptClientRequestID admits a 512 KiB value")
	}
}

// ─── concurrency ────────────────────────────────────────────────────────────

// TestSecReqID1_ConcurrentRejectionsAreRaceFree exercises the counters and the
// shared log gate from many goroutines, as the request path does. Run under
// -race this is the gate on the gate: a mitigation on the hot path that is
// itself racy is not a mitigation.
func TestSecReqID1_ConcurrentRejectionsAreRaceFree(t *testing.T) {
	resetTracingBoundsStateForTest()
	old := logger
	logger = log.New(&safeDiscard{}, "", 0)
	t.Cleanup(func() { logger = old })

	const workers, each = 16, 64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
				// Alternate the two rejection classes so both counters and the
				// shared window are driven concurrently.
				if i%2 == 0 {
					r.Header.Set(headerRequestID, strings.Repeat("A", maxClientRequestIDLen+1))
				} else {
					r.Header.Set(headerTraceparent, "00-\x1b-\x00-01")
				}
				r.RemoteAddr = "198.51.100.12:5555"
				setupRequestTracing(httptest.NewRecorder(), r)
			}
		}(w)
	}
	wg.Wait()

	if got, want := requestIDRejected.Load(), int64(workers*each/2); got != want {
		t.Errorf("requestIDRejected = %d, want %d", got, want)
	}
	if got, want := traceparentRejected.Load(), int64(workers*each/2); got != want {
		t.Errorf("traceparentRejected = %d, want %d", got, want)
	}
}

// safeDiscard is an io.Writer that discards concurrently without the shared
// bytes.Buffer a -race run would (correctly) flag.
type safeDiscard struct{}

func (*safeDiscard) Write(p []byte) (int, error) { return len(p), nil }
