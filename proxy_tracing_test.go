package main

// proxy_tracing_test.go — correctness contract for setupRequestTracing
// (proxy.go) and the tracing-ID generators (connlimit.go).
//
// The optimization these tests guard is a COST-ONLY change: canonical header
// keys and one CSPRNG draw for both IDs. Every observable — the header names
// on the wire, the values' shapes, the client-supplied passthrough, the
// CWE-117 sanitisation — must be exactly what the sequential, non-canonical
// shape produced. So these tests are written against the OBSERVABLES, and the
// central one is a differential against a verbatim copy of the pre-change body.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// legacySetupRequestTracing is a VERBATIM copy of setupRequestTracing as it
// stood before the canonical-key / single-draw change. It is the oracle for
// the differential test below and the frozen baseline for the benchmarks in
// proxy_tracing_bench_test.go, so the comparison stays reproducible in-tree.
//
// It calls the FROZEN generators below, never the production ones, and that is
// the whole point rather than a stylistic choice. It first shipped calling
// generateTraceparent — which this change rewrote to delegate to
// generateTraceIDs — so the "before" side of the comparison was drawing 32
// random bytes and keeping the NEW 71-byte combined allocation instead of the
// old 24-byte draw and 55-byte string. That inflated the legacy row's B/op by
// one size class and, worse, left the baseline free to move whenever
// production moved: a future rewrite of either generator would have silently
// re-based the very numbers this file exists to hold still (Codex review of
// PR #1326). A frozen baseline must depend on NOTHING that can change.
//
// Do not "modernise" this copy or point it back at the production generators —
// its whole value is being the old shape.
func legacySetupRequestTracing(w http.ResponseWriter, r *http.Request) string {
	reqID := strings.ReplaceAll(strings.ReplaceAll(r.Header.Get("X-Request-ID"), "\n", ""), "\r", "")
	if reqID == "" {
		reqID = legacyGenerateRequestID()
		r.Header.Set("X-Request-ID", reqID)
	}
	w.Header().Set("X-Request-ID", reqID)

	if r.Header.Get("Traceparent") == "" {
		r.Header.Set("Traceparent", legacyGenerateTraceparent())
	}
	return reqID
}

// legacyGenerateRequestID is a VERBATIM copy of generateRequestID. That
// function is UNCHANGED by this PR, so this copy is byte-for-byte identical to
// production today — it exists so the frozen baseline above cannot be re-based
// by a future edit to the production generator.
func legacyGenerateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

// legacyGenerateTraceparent is a VERBATIM copy of the standalone traceparent
// encoder as it stood before generateTraceparent was folded onto
// generateTraceIDs. It is the frozen baseline for
// BenchmarkGenerateTraceIDs_Separate and the oracle for
// TestGenerateTraceIDs_ParsesInProductionConsumer, which proves the fold
// changed the COST of producing a traceparent and not its FORM.
func legacyGenerateTraceparent() string {
	var buf [24]byte // 16 (trace-id) + 8 (parent-id)
	if _, err := rand.Read(buf[:]); err != nil {
		return "00-00000000000000000000000000000000-0000000000000000-01"
	}
	var out [55]byte
	out[0], out[1], out[2] = '0', '0', '-'
	hex.Encode(out[3:35], buf[:16])
	out[35] = '-'
	hex.Encode(out[36:52], buf[16:])
	out[52], out[53], out[54] = '-', '0', '1'
	return string(out[:])
}

// TestLegacyBaselineIsSelfContained pins the property the finding above was
// about: the frozen baseline must not reach a production symbol whose cost this
// PR changed, or the "before" column silently tracks "after".
//
// It is a source scan rather than a behavioural check because the defect is
// invisible at runtime — calling generateTraceparent produced a perfectly valid
// traceparent, just at the new cost.
func TestLegacyBaselineIsSelfContained(t *testing.T) {
	// Anchored to pkgSourceDir() rather than the CWD — the repo's
	// TestTestFileReadsAreCWDIndependent wall requires it, so a concurrent
	// os.Chdir in another test cannot flake this one.
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "proxy_tracing_test.go"))
	if err != nil {
		t.Fatalf("read own source: %v", err)
	}
	body, ok := funcBodyOf(string(src), "func legacySetupRequestTracing(")
	if !ok {
		t.Fatal("could not locate legacySetupRequestTracing in this file")
	}
	for _, production := range []string{"generateTraceIDs(", "setupRequestTracing("} {
		if strings.Contains(body, production) {
			t.Errorf("legacySetupRequestTracing calls %s — the frozen baseline must not "+
				"reach production code this PR changed", production)
		}
	}
	// The two generators are the specific trap: the legacy* copies contain the
	// production names as a SUFFIX, so match on a call that is not preceded by
	// the "legacy" prefix.
	for _, call := range []string{"generateTraceparent()", "generateRequestID()"} {
		if strings.Contains(body, call) && !strings.Contains(body, "legacyG"+call[1:]) {
			t.Errorf("legacySetupRequestTracing calls the production %s rather than the frozen copy", call)
		}
	}
}

// funcBodyOf returns the text between the first "{" after decl and the first
// line consisting solely of "}" — enough for the single flat function above.
func funcBodyOf(src, decl string) (string, bool) {
	i := strings.Index(src, decl)
	if i < 0 {
		return "", false
	}
	rest := src[i:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

// TestGenerateTraceIDs_ParsesInProductionConsumer closes the loop against the
// code that actually reads the header. recordRequestTelemetry (proxy.go) feeds
// the traceparent to parseTraceparent, which splits on '-' and takes fields 1
// and 2 as the trace-id and span-id for OTLP export.
//
// The combined encoder writes the traceparent at offset 16 of a larger buffer
// instead of offset 0 — exactly the kind of change that silently shifts a
// field by a byte and produces a value that still LOOKS plausible. So the
// layout is checked by the real consumer, against the frozen standalone
// encoder's output as the oracle, rather than only by a regexp.
func TestGenerateTraceIDs_ParsesInProductionConsumer(t *testing.T) {
	check := func(t *testing.T, source, tp string) {
		t.Helper()
		traceID, spanID := parseTraceparent(tp)
		if len(traceID) != 32 {
			t.Errorf("%s: parseTraceparent(%q) trace-id %q has len %d, want 32", source, tp, traceID, len(traceID))
		}
		if len(spanID) != 16 {
			t.Errorf("%s: parseTraceparent(%q) span-id %q has len %d, want 16", source, tp, spanID, len(spanID))
		}
		if _, err := hex.DecodeString(traceID); err != nil {
			t.Errorf("%s: trace-id %q is not hex: %v", source, traceID, err)
		}
		if _, err := hex.DecodeString(spanID); err != nil {
			t.Errorf("%s: span-id %q is not hex: %v", source, spanID, err)
		}
	}

	for i := 0; i < 32; i++ {
		_, tp := generateTraceIDs()
		check(t, "generateTraceIDs", tp)
		check(t, "generateTraceparent", generateTraceparent())
		// The frozen standalone encoder is the oracle for the field WIDTHS the
		// combined one has to reproduce at its new offset.
		check(t, "legacyGenerateTraceparent", legacyGenerateTraceparent())
	}

	// Field positions must be identical between the two encoders, not merely
	// both well-formed: same total length, same separator offsets.
	_, got := generateTraceIDs()
	want := legacyGenerateTraceparent()
	if len(got) != len(want) {
		t.Fatalf("traceparent length %d, frozen encoder produces %d", len(got), len(want))
	}
	for _, i := range []int{2, 35, 52} {
		if got[i] != '-' || want[i] != '-' {
			t.Errorf("separator offset %d: combined %q, frozen %q", i, got[i], want[i])
		}
	}
	if got[:3] != want[:3] || got[53:] != want[53:] {
		t.Errorf("version/flags fields diverged: combined %q…%q, frozen %q…%q",
			got[:3], got[53:], want[:3], want[53:])
	}
}

// tracingCases are the four shapes a request can arrive in, by which of the
// two tracing headers the client supplied.
func tracingCases() []struct {
	name      string
	reqHeader http.Header
} {
	return []struct {
		name      string
		reqHeader http.Header
	}{
		{"neither", http.Header{}},
		{"client-request-id", http.Header{"X-Request-Id": {"client-supplied-id"}}},
		{"client-traceparent", http.Header{
			"Traceparent": {"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
		}},
		{"both", http.Header{
			"X-Request-Id": {"client-supplied-id"},
			"Traceparent":  {"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
		}},
	}
}

func cloneHeader(h http.Header) http.Header {
	c := http.Header{}
	for k, v := range h {
		c[k] = append([]string(nil), v...)
	}
	return c
}

// TestRequestTracing_CanonicalKeysAreWireIdentical is the core equivalence
// proof: for every arrival shape, the new implementation must leave the
// request and response header MAPS carrying the same KEYS and the same
// client-supplied values as the legacy body, and must serialise to the same
// bytes modulo the random IDs.
//
// Keys are the load-bearing half. http.Header.Write emits the map key
// verbatim, so if the canonical spelling had changed which key Set stored
// under, the header name on the wire would have changed with it. It does not:
// Set canonicalised "X-Request-ID" to "X-Request-Id" before this change too.
func TestRequestTracing_CanonicalKeysAreWireIdentical(t *testing.T) {
	for _, tc := range tracingCases() {
		t.Run(tc.name, func(t *testing.T) {
			newReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
			newReq.Header = cloneHeader(tc.reqHeader)
			newRec := httptest.NewRecorder()
			newID := setupRequestTracing(newRec, newReq)

			oldReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
			oldReq.Header = cloneHeader(tc.reqHeader)
			oldRec := httptest.NewRecorder()
			oldID := legacySetupRequestTracing(oldRec, oldReq)

			assertSameHeaderKeys(t, "request", oldReq.Header, newReq.Header)
			assertSameHeaderKeys(t, "response", oldRec.Header(), newRec.Header())

			// The stored request ID must equal the returned one on both.
			if got := newReq.Header.Get("X-Request-ID"); got != newID {
				t.Errorf("request header X-Request-Id = %q, returned id %q", got, newID)
			}
			if got := newRec.Header().Get("X-Request-ID"); got != newID {
				t.Errorf("response header X-Request-Id = %q, returned id %q", got, newID)
			}

			// Client-supplied values pass through untouched, identically.
			if tc.reqHeader.Get("X-Request-Id") != "" && newID != oldID {
				t.Errorf("client-supplied request id: new %q, legacy %q", newID, oldID)
			}
			if want := tc.reqHeader.Get("Traceparent"); want != "" {
				if got := newReq.Header.Get("Traceparent"); got != want {
					t.Errorf("client traceparent overwritten: got %q want %q", got, want)
				}
			}

			// And the serialised request headers agree byte for byte once the
			// generated values are masked out.
			var oldBuf, newBuf bytes.Buffer
			if err := oldReq.Header.Write(&oldBuf); err != nil {
				t.Fatalf("write legacy header: %v", err)
			}
			if err := newReq.Header.Write(&newBuf); err != nil {
				t.Fatalf("write new header: %v", err)
			}
			oldWire := maskGeneratedIDs(oldBuf.String())
			newWire := maskGeneratedIDs(newBuf.String())
			if oldWire != newWire {
				t.Errorf("wire form diverged:\nlegacy: %q\nnew:    %q", oldWire, newWire)
			}
		})
	}
}

func assertSameHeaderKeys(t *testing.T, which string, oldH, newH http.Header) {
	t.Helper()
	if len(oldH) != len(newH) {
		t.Errorf("%s header key count: legacy %d %v, new %d %v", which, len(oldH), headerKeysOf(oldH), len(newH), headerKeysOf(newH))
		return
	}
	for k := range oldH {
		if _, ok := newH[k]; !ok {
			t.Errorf("%s header lost key %q (new keys: %v)", which, k, headerKeysOf(newH))
		}
	}
}

func headerKeysOf(h http.Header) []string {
	ks := make([]string, 0, len(h))
	for k := range h {
		ks = append(ks, k)
	}
	return ks
}

var (
	hexRunRe      = regexp.MustCompile(`\b[0-9a-f]{16,32}\b`)
	traceparentRe = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`)
)

// maskGeneratedIDs blanks the random hex runs so two independent runs of the
// same code path compare equal on everything EXCEPT the entropy.
func maskGeneratedIDs(s string) string { return hexRunRe.ReplaceAllString(s, "X") }

// TestRequestTracing_CanonicalKeysMatchGoCanonicalisation pins the two
// constants against net/http's own canonicalisation. If a future Go release
// changed how it canonicalises either name, the constants would silently stop
// being the fast-path spelling — the cost would come back with no test
// failing anywhere else.
func TestRequestTracing_CanonicalKeysMatchGoCanonicalisation(t *testing.T) {
	for _, tc := range []struct{ literal, constant string }{
		{"X-Request-ID", headerRequestID},
		{"Traceparent", headerTraceparent},
	} {
		h := http.Header{}
		h.Set(tc.literal, "v")
		if _, ok := h[tc.constant]; !ok {
			t.Errorf("Header.Set(%q) does not store under %q (stored: %v) — "+
				"the canonical constant has drifted from Go's canonicalisation",
				tc.literal, tc.constant, headerKeysOf(h))
		}
	}
}

// TestGenerateTraceIDs_Shape covers the combined generator's output contract:
// widths, hex alphabet, a well-formed traceparent, and that the two returned
// strings do not share bytes (they are cut from disjoint halves of one draw).
func TestGenerateTraceIDs_Shape(t *testing.T) {
	reqID, tp := generateTraceIDs()

	if len(reqID) != requestIDHexLen {
		t.Errorf("request id %q: len %d, want %d", reqID, len(reqID), requestIDHexLen)
	}
	if len(tp) != traceparentLen {
		t.Errorf("traceparent %q: len %d, want %d", tp, len(tp), traceparentLen)
	}
	if !traceparentRe.MatchString(tp) {
		t.Errorf("traceparent %q does not match the W3C shape", tp)
	}
	if strings.ContainsAny(reqID, "ABCDEF") {
		t.Errorf("request id %q is not lowercase hex", reqID)
	}
	// The request ID is drawn from bytes 0:8 and the parent-id from 24:32, so
	// the two must not coincide — sharing one draw must not correlate them.
	if parent := tp[36:52]; parent == reqID {
		t.Errorf("request id %q equals the traceparent parent-id — the two IDs share random bytes", reqID)
	}
	if traceID := tp[3:35]; strings.Contains(traceID, reqID) {
		t.Errorf("request id %q appears inside trace-id %q", reqID, traceID)
	}
}

// TestGenerateTraceIDs_Unique guards the obvious catastrophic failure of a
// buffered/shared-draw implementation: handing the same ID to two requests.
func TestGenerateTraceIDs_Unique(t *testing.T) {
	const n = 4096
	ids := make(map[string]struct{}, n)
	tps := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id, tp := generateTraceIDs()
		if _, dup := ids[id]; dup {
			t.Fatalf("duplicate request id %q after %d draws", id, i)
		}
		if _, dup := tps[tp]; dup {
			t.Fatalf("duplicate traceparent %q after %d draws", tp, i)
		}
		ids[id], tps[tp] = struct{}{}, struct{}{}
	}
}

// TestGenerateTraceparent_MatchesLoneForm pins that delegating
// generateTraceparent to generateTraceIDs did not change its output contract —
// the same width and shape the standalone encoder produced.
func TestGenerateTraceparent_MatchesLoneForm(t *testing.T) {
	for i := 0; i < 64; i++ {
		tp := generateTraceparent()
		if len(tp) != traceparentLen || !traceparentRe.MatchString(tp) {
			t.Fatalf("generateTraceparent() = %q, not a well-formed traceparent", tp)
		}
	}
	if got := len(generateRequestID()); got != requestIDHexLen {
		t.Errorf("generateRequestID() len %d, want %d", got, requestIDHexLen)
	}
}

// TestRequestTracing_SanitisesClientRequestID keeps the CWE-117 contract
// visible: a client-supplied request ID carrying CR/LF must never reach a log
// line or the response header. The sanitiser moved position in the rewrite (it
// now runs before the traceparent probe rather than after the request-ID Set),
// so its effect is pinned rather than assumed.
//
// THE EXACT-RESIDUAL ASSERTION HERE WAS INVERTED BY SEC-REQID-1, and the reason
// is written into the payload this test has always used. It previously required
// the surviving value to equal "abcX-Injected: 1def" — i.e. it pinned as CORRECT
// the fact that everything except the CR/LF bytes came through verbatim,
// including the spaces in the test's own `X-Injected: 1` example. That residual
// is the defect: the decision lines render the id inside a space-separated
// `{req_id=… identity=… action=…}` block, so a value containing a space injects
// additional key=value tokens, and every C0 control byte other than CR/LF (ESC,
// NUL, BEL, DEL) survived too — where sanitizeLog, the convention everywhere
// else in this tree, scrubs all of them.
//
// The contract is now the stronger one: a value that cannot be retained safely
// is not retained AT ALL — a fresh id is minted, exactly as for an absent
// header. The CR/LF half is unchanged and still asserted, because the inline
// strings.ReplaceAll is the barrier CodeQL's go/log-injection query recognises
// on this value and must stay on every path.
func TestRequestTracing_SanitisesClientRequestID(t *testing.T) {
	resetTracingBoundsStateForTest()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Set(headerRequestID, "abc\r\nX-Injected: 1\ndef")
	rec := httptest.NewRecorder()

	got := setupRequestTracing(rec, r)

	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("returned request id %q still carries CR/LF", got)
	}
	// Nothing the client chose survives: the value is replaced wholesale.
	if strings.Contains(got, "X-Injected") || strings.Contains(got, "abc") || strings.Contains(got, "def") {
		t.Errorf("client-chosen bytes survived into the request id %q", got)
	}
	if len(got) != requestIDHexLen {
		t.Errorf("request id = %q (len %d), want a freshly minted %d-char id", got, len(got), requestIDHexLen)
	}
	if h := rec.Header().Get(headerRequestID); h != got {
		t.Errorf("response header %q does not mirror the minted id %q", h, got)
	}
	if n := requestIDRejected.Load(); n != 1 {
		t.Errorf("requestIDRejected = %d, want 1", n)
	}
}

// TestRequestTracing_GeneratesOnlyWhatIsMissing pins the three-arm switch
// against the sequential form's decision: each header is generated if and only
// if the client did not supply it. A switch that generated both whenever
// EITHER was missing would still pass every shape test above while burning a
// draw — and would overwrite a client's traceparent, breaking trace
// propagation.
func TestRequestTracing_GeneratesOnlyWhatIsMissing(t *testing.T) {
	const clientTP = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

	// Client supplied a traceparent but no request ID: the traceparent must
	// survive verbatim and a request ID must appear.
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r.Header.Set(headerTraceparent, clientTP)
	id := setupRequestTracing(httptest.NewRecorder(), r)
	if got := r.Header.Get(headerTraceparent); got != clientTP {
		t.Errorf("client traceparent replaced: got %q want %q", got, clientTP)
	}
	if len(id) != requestIDHexLen {
		t.Errorf("no request id generated: %q", id)
	}

	// Client supplied a request ID but no traceparent: the ID must survive and
	// a well-formed traceparent must appear.
	r2 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r2.Header.Set(headerRequestID, "caller-id")
	id2 := setupRequestTracing(httptest.NewRecorder(), r2)
	if id2 != "caller-id" {
		t.Errorf("client request id replaced: got %q", id2)
	}
	if tp := r2.Header.Get(headerTraceparent); !traceparentRe.MatchString(tp) {
		t.Errorf("no traceparent generated: %q", tp)
	}

	// Client supplied both: nothing is generated, both survive.
	r3 := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", http.NoBody)
	r3.Header.Set(headerRequestID, "caller-id")
	r3.Header.Set(headerTraceparent, clientTP)
	if id3 := setupRequestTracing(httptest.NewRecorder(), r3); id3 != "caller-id" {
		t.Errorf("client request id replaced: got %q", id3)
	}
	if got := r3.Header.Get(headerTraceparent); got != clientTP {
		t.Errorf("client traceparent replaced: got %q want %q", got, clientTP)
	}
}
