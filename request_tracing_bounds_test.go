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

// ─── the bare-field emitter depends on this bound ───────────────────────────

// TestSecReqID1_BareReqIDInDecisionLineIsSafeOnlyBecauseOfTheBound pins the
// interaction between this bound and `emitPolicyDecision` (proxy.go), which
// appends `reqID` to the decision line BARE — no sanitizeLog, no quoting.
//
// That emitter's own doc lists reqID in its bare set. What makes the bare append
// safe is NOT the inline CR/LF scrub but the entry-point bound here: visible
// ASCII, no whitespace, bounded length. This gate proves the dependency in both
// directions, because a comment asserting it is worth less than a test enforcing
// it — and the emitter and the bound live in different functions that a future
// change could move independently.
//
// The DEFECT PROOF half matters most: it calls emitPolicyDecision DIRECTLY with
// a hostile reqID, bypassing setupRequestTracing, and shows the brace block IS
// forgeable when an unbounded value reaches it. So the gate cannot be satisfied
// by the emitter having quietly become safe on its own.
func TestSecReqID1_BareReqIDInDecisionLineIsSafeOnlyBecauseOfTheBound(t *testing.T) {
	// A payload that survives the inline CR/LF scrub entirely: a space forges
	// extra key=value tokens inside `{req_id=… identity=… action=…}`, and the
	// ESC rewrites what an operator tailing the log sees.
	const forge = "x action=allow identity=root\x1b[2K"

	t.Run("bound makes the bare append safe", func(t *testing.T) {
		resetTracingBoundsStateForTest()
		withNoProxyCredentialBackend(t)
		var buf bytes.Buffer
		old := logger
		logger = log.New(&buf, "", 0)
		t.Cleanup(func() { logger = old })

		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
		r.Header.Set(headerRequestID, forge)
		r.RemoteAddr = "198.51.100.21:1234"
		handleRequest(httptest.NewRecorder(), r)

		line := buf.String()
		if strings.Contains(line, "\x1b") {
			t.Errorf("an ESC byte reached the decision line:\n%q", line)
		}
		// Exactly one of each token: the real ones. A forged pair would double them.
		if n := strings.Count(line, " action="); n != 1 {
			t.Errorf("decision line carries %d ` action=` tokens, want 1 — the brace block was forged:\n%q", n, line)
		}
		if n := strings.Count(line, " identity="); n != 1 {
			t.Errorf("decision line carries %d ` identity=` tokens, want 1 — the brace block was forged:\n%q", n, line)
		}
		if !strings.Contains(line, "req_id=") {
			t.Fatalf("no decision line was emitted; this gate is testing nothing:\n%q", line)
		}
	})

	// DEFECT PROOF: the emitter itself is NOT what makes this safe. Handed an
	// unbounded value directly it forges the block, exactly as the pre-bound
	// request path did. If this sub-test ever stops failing to forge, the bare
	// set changed and the rationale on policyDecision needs revisiting.
	t.Run("defect proof: the emitter alone does not protect the block", func(t *testing.T) {
		var buf bytes.Buffer
		old := logger
		logger = log.New(&buf, "", 0)
		t.Cleanup(func() { logger = old })

		emitPolicyDecision(&policyDecision{
			verb: "POLICY_ALLOW", action: "allow", rule: "r", clientIP: "198.51.100.21",
			hostSep: http.MethodGet, host: "example.com", reqID: forge, identity: "",
		})

		line := buf.String()
		if n := strings.Count(line, " action="); n < 2 {
			t.Errorf("an unbounded reqID no longer forges the brace block (%d ` action=` tokens) —"+
				" the bare-field set or the emitter changed; re-check the policyDecision rationale:\n%q", n, line)
		}
		if !strings.Contains(line, "\x1b") {
			t.Errorf("an unbounded reqID no longer carries an ESC into the line — re-check the rationale:\n%q", line)
		}
	})
}

// ─── duplicate headers (the former residual, now closed) ────────────────────

// TestSecReqID1_DuplicateHeaderIsCollapsed is the INVERSION its own predecessor
// asked for.
//
// It previously pinned a recorded residual: a client may send X-Request-Id
// TWICE, `Header.Get` validates only value [0], and an acceptable first value
// paired with a hostile second one took the ACCEPT branch — which does not Set —
// so both values stayed on r.Header and went to the upstream. That test's own
// closing line said "if a future change collapses duplicates, this assertion is
// the one to invert — deliberately, not by accident." This is that change.
//
// It was recorded rather than fixed on the stated ground that collapsing would
// mean "measurable work on the second statement of handleRequest". Codex (P2)
// pushed back, and measuring rather than re-arguing settled it the other way:
// indexing the header map directly is 7.3 ns against 27-42 ns for Header.Get —
// roughly 4x CHEAPER, 0 allocations either way — because it skips
// CanonicalMIMEHeaderKey's scan. The cost objection was not just weak, it was
// backwards, and the residual also evaded the rejection counters, so an operator
// watching culvert_tracing_header_rejected_total saw nothing while a source
// probed with duplicate headers.
//
// A duplicate is now unusable on its face, for both headers: ambiguous
// correlation is not correlation. The mint arm runs and Set collapses the field
// to exactly one value.
func TestSecReqID1_DuplicateHeaderIsCollapsed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		first  string
		second string
		want   int // minted length
	}{
		{"request id", headerRequestID, "good-id-1", "hostile id\x1b", requestIDHexLen},
		{"request id, both valid", headerRequestID, "good-id-1", "good-id-2", requestIDHexLen},
		{"traceparent", headerTraceparent,
			"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
			"00-" + strings.Repeat("a", 300) + "-b-01", traceparentLen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetTracingBoundsStateForTest()
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
			r.Header.Add(tc.header, tc.first)
			r.Header.Add(tc.header, tc.second)
			rec := httptest.NewRecorder()

			setupRequestTracing(rec, r)

			vals := r.Header.Values(tc.header)
			if len(vals) != 1 {
				t.Fatalf("forwarded %s carries %d values, want exactly 1 — duplicates must be collapsed", tc.header, len(vals))
			}
			if vals[0] == tc.first || vals[0] == tc.second {
				t.Errorf("forwarded %s = %q, want a freshly minted value (neither client value)", tc.header, vals[0])
			}
			if len(vals[0]) != tc.want {
				t.Errorf("forwarded %s = %q (len %d), want a minted %d-char value", tc.header, vals[0], len(vals[0]), tc.want)
			}
			// The probe must be VISIBLE: the whole point of counting is that an
			// operator watching the metric sees a duplicate-header source.
			if n := requestIDRejected.Load() + traceparentRejected.Load(); n != 1 {
				t.Errorf("duplicate %s counted %d rejections, want 1", tc.header, n)
			}
		})
	}
}

// TestSecReqID1_DuplicateRejectionCountsEveryValuesBytes pins that the reported
// length is the total the client actually sent, not just value [0]'s. Reporting
// only the first value would under-state a duplicate-header flood in the one
// line per window an operator gets.
func TestSecReqID1_DuplicateRejectionCountsEveryValuesBytes(t *testing.T) {
	resetTracingBoundsStateForTest()
	var buf bytes.Buffer
	old := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = old })

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Add(headerRequestID, "short")                   // 5
	r.Header.Add(headerRequestID, strings.Repeat("A", 4096)) // 4096
	r.RemoteAddr = "198.51.100.31:5555"
	setupRequestTracing(httptest.NewRecorder(), r)

	if !strings.Contains(buf.String(), "4101 bytes") {
		t.Errorf("rejection line does not report the total across both values (want 4101 bytes):\n%s", buf.String())
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

// TestSecReqID1_MintedTraceparentDropsTracestate pins the W3C pairing rule that
// SEC-REQID-1's replacement arm would otherwise break: tracestate is meaningful
// only relative to its traceparent, so when an unusable traceparent is replaced
// the tracestate it was issued under must not survive. Leaving it forwards a
// combination the client never sent — Culvert's minted trace context carrying
// the client's arbitrary vendor state — which an upstream may accept as part of
// that new trace (Codex P2).
//
// Every sub-case is a shape that REACHES the mint arm, so each is a distinct way
// to orphan a tracestate, not a restatement of one.
func TestSecReqID1_MintedTraceparentDropsTracestate(t *testing.T) {
	const vendorState = "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"

	for _, tc := range []struct {
		name string
		vals []string // Traceparent values the client sends (nil = header absent)
	}{
		{"oversize traceparent", []string{"00-" + strings.Repeat("a", 300) + "-b-01"}},
		{"control character in traceparent", []string{"00-0af7651916cd43dd8448eb211c80319c-b7ad6b71\x1b69203331-01"}},
		{"whitespace in traceparent", []string{"00-0af7651916cd 43dd8448eb211c80319c-b7ad6b7169203331-01"}},
		{"duplicate traceparent", []string{
			"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
			"00-1bf7651916cd43dd8448eb211c80319c-c7ad6b7169203331-01",
		}},
		// A tracestate with NO traceparent at all is malformed by the same rule,
		// and this is the arm that mints without any rejection being counted.
		{"tracestate with no traceparent", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetTracingBoundsStateForTest()
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
			for _, v := range tc.vals {
				r.Header.Add(headerTraceparent, v)
			}
			r.Header.Set(headerTracestate, vendorState)

			setupRequestTracing(httptest.NewRecorder(), r)

			if got := r.Header.Values(headerTracestate); len(got) != 0 {
				t.Errorf("forwarded %s = %q, want it dropped alongside the replaced traceparent",
					headerTracestate, got)
			}
			// The traceparent must actually have been replaced — otherwise this
			// test could pass against a build that simply deletes tracestate and
			// never mints, which is not the contract.
			tp := r.Header.Values(headerTraceparent)
			if len(tp) != 1 {
				t.Fatalf("forwarded %s carries %d values, want exactly 1", headerTraceparent, len(tp))
			}
			if len(tp[0]) != traceparentLen {
				t.Errorf("forwarded %s = %q (len %d), want a minted %d-char value",
					headerTraceparent, tp[0], len(tp[0]), traceparentLen)
			}
			for _, sent := range tc.vals {
				if tp[0] == sent {
					t.Errorf("forwarded %s = %q, want a freshly minted value", headerTraceparent, tp[0])
				}
			}
		})
	}
}

// TestSecReqID1_ValidTraceparentKeepsTracestate is the CONTROL for the test
// above. The cheapest way to pass it is to delete tracestate unconditionally,
// which would silently break ordinary W3C propagation through the proxy for
// every well-behaved client — a far worse outcome than the defect. A client that
// supplies a USABLE traceparent must keep its tracestate byte-for-byte.
func TestSecReqID1_ValidTraceparentKeepsTracestate(t *testing.T) {
	resetTracingBoundsStateForTest()
	const (
		validTP     = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
		vendorState = "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"
	)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Set(headerTraceparent, validTP)
	r.Header.Set(headerTracestate, vendorState)

	setupRequestTracing(httptest.NewRecorder(), r)

	if got := r.Header.Get(headerTraceparent); got != validTP {
		t.Fatalf("forwarded %s = %q, want the client's value propagated unchanged", headerTraceparent, got)
	}
	if got := r.Header.Get(headerTracestate); got != vendorState {
		t.Errorf("forwarded %s = %q, want %q — a usable traceparent must keep its tracestate",
			headerTracestate, got, vendorState)
	}
	if n := traceparentRejected.Load(); n != 0 {
		t.Errorf("valid traceparent counted %d rejections, want 0", n)
	}
}

// withNoProxyCredentialBackend pins the one precondition the request-path gates
// above depend on: that handleRequest reaches a POLICY decision rather than
// stopping at AUTH_FAIL.
//
// They assert on the `{req_id=… identity=… action=…}` brace block, which only
// `emitPolicyDecision` writes. If any earlier test in the package leaves a
// credential configured on the process-global cfg — `AuthEnabled()` is
// `c.user != "" || c.provider != nil`, and dozens of tests call
// `cfg.SetAuth(...)` — the request is refused before policy evaluation and the
// line emitted is `AUTH_FAIL (no-credentials) … {req_id=… action=block}`, which
// carries ZERO ` identity=` tokens and reads to the gate exactly like a forged
// brace block. So the gate reported a log-injection failure whose real cause
// was a leaked global three test files away.
//
// It is ORDER-DEPENDENT, not flaky: it passes in isolation and under most
// shuffle seeds, and fails under the ones that schedule such a test first
// (reproduced against CI's own seed, then reproduced deterministically by
// inserting a one-line `cfg.SetAuth` leaker ahead of it — byte-identical
// failure text). A test must establish the state it depends on rather than
// inherit it; leaving that to whatever ran before is what makes
// `-count=2 -shuffle=on` a lottery.
//
// The whole credential surface is saved and restored under cfg.mu — the same
// shape `ui_e2e_smoke_test.go`'s fixture uses — because restoring through
// `cfg.SetAuth("", "")` re-derives state rather than putting back what was
// there. The auth result cache is cleared in both directions: entries keyed on
// a credential this test is about to remove (or re-add) must not answer for it.
func withNoProxyCredentialBackend(t *testing.T) {
	t.Helper()
	cfg.mu.Lock()
	prevUser, prevHash, prevOutcome := cfg.user, cfg.passHash, cfg.defaultAuthOutcome
	prevProvider := cfg.provider
	cfg.user, cfg.passHash, cfg.provider = "", nil, nil
	cfg.defaultAuthOutcome = OutcomeExempt
	cfg.mu.Unlock()
	cfg.cache.clear()
	t.Cleanup(func() {
		cfg.mu.Lock()
		cfg.user, cfg.passHash, cfg.provider = prevUser, prevHash, prevProvider
		cfg.defaultAuthOutcome = prevOutcome
		cfg.mu.Unlock()
		cfg.cache.clear()
	})
}
