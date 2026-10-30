package main

// CHAOS-106 — the response path refuses a disproportionate expansion.
//
// internal/secscan owns the bound and its unit gates
// (decompress_ratio_chaos_test.go). These are the main-side half: the bound is
// only a defense if every caller that asks for an expansion actually FAILS
// CLOSED when it is refused. A caller that ignored the refusal and scanned the
// compressed bytes instead would turn the bound into a scanner bypass — the
// attacker would choose the ratio that silences the scanners.
//
// Both production response paths are covered, because the origin picks which
// one it is on: the SSL-inspect path (scanInspectBody, the primary SWG path)
// and the plain-HTTP path (scanHTTPResponseBody). Each gate carries its own
// negative control, since a change that blocked all compressed traffic would
// also pass the positive assertion.

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// chaos106ScanWindow is wide enough to buffer the whole fixture below, so the
// refusal under test is the EXPANSION bound and never the scan window: a
// window-truncated gzip stream fails to decompress at all and would take the
// pre-existing fallback path instead, proving nothing.
const chaos106ScanWindow = 1 << 20

// chaos106Bomb returns a gzip stream of ~20 MiB of zeros. That compresses to
// roughly 20 KiB, which is both inside chaos106ScanWindow and past the point
// where secscan's small-response floor decides, so the ratio bound is what
// refuses it.
func chaos106Bomb(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(make([]byte, 20<<20)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if int64(buf.Len()) > chaos106ScanWindow {
		t.Fatalf("fixture compressed to %d bytes, past the %d scan window — the window would refuse it first",
			buf.Len(), int64(chaos106ScanWindow))
	}
	return buf.Bytes()
}

// chaos106Gzip returns a gzip stream of ordinary, honestly-compressible
// content: the negative control every gate below needs.
func chaos106Gzip(t *testing.T, payload []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// closeSpyBody records whether the pipeline closed the origin body. A refusal
// that leaked the upstream body would hold a connection and its buffers for
// the client's own timeout, which is the regime the refusal exists to avoid.
type closeSpyBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *closeSpyBody) Close() error { b.closed.Store(true); return nil }

// ─── SSL-inspect path (the primary SWG path) ─────────────────────────────────

func chaos106InspectFixture(t *testing.T, body []byte, encoding string) (*spyResponder, *closeSpyBody, scanBodyOutcome) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://cdn.example.com/payload.bin", http.NoBody)
	spyBody := &closeSpyBody{Reader: bytes.NewReader(body)}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"application/octet-stream"},
			"Content-Encoding": []string{encoding},
		},
		ContentLength: int64(len(body)),
		Body:          spyBody,
	}
	br := &spyResponder{}
	out := scanInspectBody(req, req, resp, br, nil, ProxyIdentity{ClientIP: "198.51.100.44"}, "cdn.example.com", nil)
	return br, spyBody, out
}

func TestCHAOS106_ScanInspectBody_RefusesADisproportionateExpansion(t *testing.T) {
	withScanLimit(t, chaos106ScanWindow)

	before := secscan.Counters().DecompressBombs
	br, spyBody, out := chaos106InspectFixture(t, chaos106Bomb(t), "gzip")

	if out != scanBlocked {
		t.Fatalf("outcome = %v, want scanBlocked — the inspect path admitted a response no scanner could read", out)
	}
	if br.calls != 1 {
		t.Errorf("block emissions = %d, want exactly 1 through the responder choke point", br.calls)
	}
	if !spyBody.closed.Load() {
		t.Error("the origin body was not closed on the refusal path")
	}
	if got := secscan.Counters().DecompressBombs - before; got != 1 {
		t.Errorf("DecompressBombs delta = %d, want 1 — the refusal must be countable", got)
	}
}

// Negative control: ordinary compressed traffic still reaches the client, and
// the reassembled body is byte-identical to what the origin sent. Without this,
// a change that refused every Content-Encoding would pass the gate above.
func TestCHAOS106_ScanInspectBody_StillDeliversOrdinaryGzip(t *testing.T) {
	withScanLimit(t, chaos106ScanWindow)

	payload := bytes.Repeat([]byte("ordinary page content, honestly compressible\n"), 64)
	wire := chaos106Gzip(t, payload)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://cdn.example.com/page.html", http.NoBody)
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"application/octet-stream"},
			"Content-Encoding": []string{"gzip"},
		},
		ContentLength: int64(len(wire)),
		Body:          io.NopCloser(bytes.NewReader(wire)),
	}
	br := &spyResponder{}
	out := scanInspectBody(req, req, resp, br, nil, ProxyIdentity{ClientIP: "198.51.100.45"}, "cdn.example.com", nil)
	t.Cleanup(func() { _ = resp.Body.Close() })

	if out != scanClean {
		t.Fatalf("outcome = %v, want scanClean for ordinary gzip", out)
	}
	if br.calls != 0 {
		t.Errorf("block emissions = %d, want 0 — ordinary compressed traffic must not be blocked", br.calls)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reassembled body read: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Errorf("reassembled body is not the wire bytes: got %d, want %d", len(got), len(wire))
	}
}

// ─── Plain-HTTP path ─────────────────────────────────────────────────────────

func TestCHAOS106_ScanHTTPResponseBody_RefusesADisproportionateExpansion(t *testing.T) {
	withScanLimit(t, chaos106ScanWindow)

	wire := chaos106Bomb(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://files.example.com/archive.bin", http.NoBody)
	r.RemoteAddr = "198.51.100.46:5560"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Encoding": []string{"gzip"}},
		ContentLength: -1, // chunked: the shape that skips every pre-check
		Body:          io.NopCloser(bytes.NewReader(wire)),
	}
	w := httptest.NewRecorder()

	before := secscan.Counters().DecompressBombs
	handled, readErr := scanHTTPResponseBody(w, r, resp, ProxyIdentity{})

	if !handled {
		t.Fatal("handled = false — the plain-HTTP path forwarded a response no scanner could read")
	}
	if readErr != nil {
		t.Errorf("upstreamReadErr = %v, want nil: a refusal is this node's decision, not an upstream fault, and must not charge the upstream breaker", readErr)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if bytes.Contains(w.Body.Bytes(), wire[:16]) {
		t.Error("the refused response body leaked into the block page")
	}
	if got := secscan.Counters().DecompressBombs - before; got != 1 {
		t.Errorf("DecompressBombs delta = %d, want 1", got)
	}
}

func TestCHAOS106_ScanHTTPResponseBody_StillDeliversOrdinaryGzip(t *testing.T) {
	withScanLimit(t, chaos106ScanWindow)

	payload := bytes.Repeat([]byte("ordinary page content, honestly compressible\n"), 64)
	wire := chaos106Gzip(t, payload)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://files.example.com/page.html", http.NoBody)
	r.RemoteAddr = "198.51.100.47:5561"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Encoding": []string{"gzip"}},
		ContentLength: -1,
		Body:          io.NopCloser(bytes.NewReader(wire)),
	}
	w := httptest.NewRecorder()

	handled, readErr := scanHTTPResponseBody(w, r, resp, ProxyIdentity{})
	if handled {
		t.Fatalf("ordinary gzip was handled (blocked); recorder status %d", w.Code)
	}
	if readErr != nil {
		t.Errorf("upstreamReadErr = %v, want nil", readErr)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reassembled body read: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Errorf("reassembled body is not the wire bytes: got %d, want %d", len(got), len(wire))
	}
}

// ─── The structural half ─────────────────────────────────────────────────────

// Every decompressForScan call site must handle the refusal. This is a SOURCE
// gate for the same reason cp_grpc_bind_chaos_test.go bans logFatalf
// structurally: a reintroduced caller that discarded the refusal with `_`
// would compile, pass every behavioural test above (which exercise only the
// two paths that exist today), and silently reopen the bypass. The compiler
// already forces a second return value to be received; what it cannot force
// is that the value be CONSULTED.
func TestCHAOS106_EveryDecompressCallSiteConsultsTheRefusal(t *testing.T) {
	callers := map[string]string{
		"proxy_tunnel.go": "scanBody, bomb := decompressForScan(",
		"proxy_http.go":   "scanData, bomb := decompressForScan(",
		"cdr_proxy.go":    "newScan, bomb := decompressForScan(",
	}
	for file, want := range callers {
		src := chaos106Source(t, file)
		if !strings.Contains(src, want) {
			t.Errorf("%s: no call site binding the refusal (%q). A caller that drops it with `_` turns the CHAOS-106 bound into a scanner bypass.", file, want)
			continue
		}
		// And the bound value must be branched on, not merely bound.
		if !strings.Contains(src, "if bomb {") {
			t.Errorf("%s: binds the refusal but never branches on it", file)
		}
	}
	// A discarded refusal anywhere in the tree is the shape this bans.
	for _, file := range []string{"proxy_tunnel.go", "proxy_http.go", "cdr_proxy.go", "security_scan.go"} {
		src := chaos106Source(t, file)
		if strings.Contains(src, ", _ := decompressForScan(") || strings.Contains(src, ", _ = decompressForScan(") {
			t.Errorf("%s: discards the decompression refusal", file)
		}
	}
}

// chaos106Source reads one of this package's own source files, anchored to the
// package directory via pkgSourceDir() rather than the process CWD — the
// requirement static_read_wall_test.go enforces for every structural wall.
func chaos106Source(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pkgSourceDir(), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
