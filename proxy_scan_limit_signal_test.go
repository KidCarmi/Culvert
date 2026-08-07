package main

// Scan-window truncation signalling.
//
// `logScanLimitExceeded` (Finding 4.2) is the operator's only notification
// that response bytes reached a client without ClamAV/YARA/DPI ever seeing
// them. It used to have exactly ONE call site: the plain-HTTP pre-check on a
// DECLARED Content-Length. Every other way a body outruns the scan window was
// silent:
//
//   - the SSL-inspect path (scanInspectBody) has no Content-Length pre-check
//     at all, so an over-limit decrypted download was scanned to the window,
//     reassembled, and streamed with no counter/log/alert — the primary SWG
//     path was the blind one;
//   - the plain-HTTP path skips its pre-check whenever the length is not
//     declared, so chunked transfer encoding suppressed the signal too.
//
// Both shapes are chosen by the ORIGIN, so the one case that was instrumented
// is precisely the one an attacker can decline to use. These tests pin the
// signal on both paths, pin the boundary that a naive `len(buf) == limit`
// check gets wrong, and pin that adding the probe byte never alters the bytes
// the client receives.

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/scanner"
	"github.com/KidCarmi/Culvert/internal/secscan"
)

// testScanLimit is deliberately tiny so the fixtures stay readable; the
// production default is 5 MiB.
const testScanLimit = 64

// withScanLimit points BOTH buffer limits (security scanner and DPI) at limit
// so maxScanBufferBytes() — the max of the two — is exactly limit on the
// inspect path, and globalSecScanner.MaxBytes() is exactly limit on the
// plain-HTTP path. Production singletons are restored afterwards.
func withScanLimit(t *testing.T, limit int64) {
	t.Helper()
	origSec, origDPI := globalSecScanner, dpiScanner
	globalSecScanner = secscan.New(secscan.Deps{Clam: cleanClam{}})
	globalSecScanner.Init("", limit, nil)
	dpiScanner = scanner.New(limit)
	t.Cleanup(func() { globalSecScanner, dpiScanner = origSec, origDPI })
}

// scanSkippedDelta runs fn and reports how many scan_skipped events it
// recorded. The counter is a process-global atomic, so the test asserts on the
// DELTA rather than an absolute value — the suite runs shuffled and with
// -count=2, and sibling tests increment the same counter.
func scanSkippedDelta(fn func()) int64 {
	before := secscan.Counters().ScanSkipped
	fn()
	return secscan.Counters().ScanSkipped - before
}

// ─── readScanPrefix: the boundary the naive check gets wrong ─────────────────

func TestReadScanPrefix_TruncationBoundary(t *testing.T) {
	const limit = 8
	tests := []struct {
		name      string
		body      string
		wantScan  string
		wantOver  string
		truncated bool
	}{
		{name: "empty body", body: "", wantScan: "", wantOver: "", truncated: false},
		{name: "well under the limit", body: "abc", wantScan: "abc", wantOver: "", truncated: false},
		{
			// The case a `len(buf) == limit` heuristic reports as truncated:
			// the scanner saw EVERY byte, so nothing was forwarded unscanned
			// and a signal here would be a false positive on every response
			// whose length happens to equal the limit.
			name: "exactly at the limit is NOT truncated",
			body: "12345678", wantScan: "12345678", wantOver: "", truncated: false,
		},
		{
			name: "one byte past the limit is truncated",
			body: "123456789", wantScan: "12345678", wantOver: "9", truncated: true,
		},
		{
			name: "far past the limit is truncated",
			body: "12345678abcdefghijklmnop", wantScan: "12345678", wantOver: "a", truncated: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scan, overflow, truncated, err := readScanPrefix(strings.NewReader(tc.body), limit)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if truncated != tc.truncated {
				t.Errorf("truncated = %v, want %v", truncated, tc.truncated)
			}
			if string(scan) != tc.wantScan {
				t.Errorf("scan window = %q, want %q", scan, tc.wantScan)
			}
			if string(overflow) != tc.wantOver {
				t.Errorf("overflow probe = %q, want %q", overflow, tc.wantOver)
			}
			// The bytes handed to the scanner must be EXACTLY what the
			// pre-existing io.LimitReader(body, limit) read produced.
			if int64(len(scan)) > limit {
				t.Errorf("scan window %d bytes exceeds limit %d — scanners would see more than configured", len(scan), limit)
			}
		})
	}
}

// A non-positive limit means there is no scan window: read nothing, report
// nothing. Guards against the limit+1 idiom turning a "scanning disabled"
// configuration into a 1-byte read that reports every response as truncated.
func TestReadScanPrefix_NonPositiveLimitReadsNothing(t *testing.T) {
	for _, limit := range []int64{0, -1} {
		body := strings.NewReader("content that must stay unread")
		scan, overflow, truncated, err := readScanPrefix(body, limit)
		if err != nil {
			t.Fatalf("limit=%d: unexpected error: %v", limit, err)
		}
		if len(scan) != 0 || len(overflow) != 0 || truncated {
			t.Errorf("limit=%d: want no read and no signal, got scan=%q overflow=%q truncated=%v", limit, scan, overflow, truncated)
		}
		if rest, _ := io.ReadAll(body); string(rest) != "content that must stay unread" {
			t.Errorf("limit=%d: body was consumed: %q", limit, rest)
		}
	}
}

// A read error must propagate (the caller fails closed with a 502 — CHAOS-17)
// and must NEVER be reported as a truncation: a failed read is not "content
// forwarded unscanned", it is content that never reaches the client at all.
func TestReadScanPrefix_ReadErrorPropagatesAndIsNotTruncation(t *testing.T) {
	body := &erroringBody{
		prefix: strings.NewReader("partial"),
		err:    errors.New("read tcp: connection reset by peer"),
	}
	scan, overflow, truncated, err := readScanPrefix(body, 1024)
	if err == nil {
		t.Fatal("read error must propagate so the caller can fail closed")
	}
	if truncated {
		t.Error("a failed read must not be reported as a scan-window truncation")
	}
	if scan != nil || overflow != nil {
		t.Errorf("error return must yield no buffers, got scan=%q overflow=%q", scan, overflow)
	}
}

// ─── plain-HTTP path: chunked responses no longer suppress the signal ────────

// newChunkedResponse builds a response with an UNDECLARED length — the shape
// that skipped the Content-Length pre-check entirely.
func newChunkedResponse(body []byte) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{},
		ContentLength: -1,
		Body:          io.NopCloser(bytes.NewReader(body)),
	}
}

func TestScanHTTPResponseBody_ChunkedOverLimitSignalsScanSkipped(t *testing.T) {
	withScanLimit(t, testScanLimit)

	// Clean prefix inside the window, payload past it: the scanners never see
	// the tail, but the client receives all of it.
	content := append(bytes.Repeat([]byte("A"), testScanLimit), []byte("PAYLOAD-BEYOND-THE-SCAN-WINDOW")...)
	r := httptest.NewRequest(http.MethodGet, "http://files.example.com/big.bin", http.NoBody)
	r.RemoteAddr = "198.51.100.9:5555"
	resp := newChunkedResponse(content)
	w := httptest.NewRecorder()

	var handled bool
	var scanReadErr error
	delta := scanSkippedDelta(func() { handled, scanReadErr = scanHTTPResponseBody(w, r, resp) })

	if handled {
		t.Fatalf("clean prefix must not be blocked; recorder: %d %q", w.Code, w.Body.String())
	}
	if scanReadErr != nil {
		t.Fatalf("no upstream read error expected, got %v", scanReadErr)
	}
	if delta != 1 {
		t.Errorf("scan_skipped delta = %d, want 1 — an over-limit chunked response was forwarded unscanned with no operator signal", delta)
	}
	// The signal must not cost correctness: the client's copy stays
	// byte-identical, including the overflow probe byte.
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reassembled body read: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("reassembled body corrupted: got %d bytes, want %d", len(got), len(content))
	}
}

func TestScanHTTPResponseBody_UnderLimitDoesNotSignal(t *testing.T) {
	withScanLimit(t, testScanLimit)

	content := bytes.Repeat([]byte("B"), testScanLimit/2)
	r := httptest.NewRequest(http.MethodGet, "http://files.example.com/small.bin", http.NoBody)
	r.RemoteAddr = "198.51.100.9:5556"
	resp := newChunkedResponse(content)
	w := httptest.NewRecorder()

	delta := scanSkippedDelta(func() { scanHTTPResponseBody(w, r, resp) })
	if delta != 0 {
		t.Errorf("scan_skipped delta = %d, want 0 — a fully scanned response must never raise the unscanned-content signal", delta)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, content) {
		t.Fatalf("reassembled body mismatch: got %q want %q", got, content)
	}
}

// Boundary: a body whose length is EXACTLY the scan limit was fully inspected.
// Signalling here would train operators to ignore the alert.
func TestScanHTTPResponseBody_ExactlyAtLimitDoesNotSignal(t *testing.T) {
	withScanLimit(t, testScanLimit)

	content := bytes.Repeat([]byte("C"), testScanLimit)
	r := httptest.NewRequest(http.MethodGet, "http://files.example.com/exact.bin", http.NoBody)
	r.RemoteAddr = "198.51.100.9:5557"
	resp := newChunkedResponse(content)
	w := httptest.NewRecorder()

	delta := scanSkippedDelta(func() { scanHTTPResponseBody(w, r, resp) })
	if delta != 0 {
		t.Errorf("scan_skipped delta = %d, want 0 at exactly the limit (false positive)", delta)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, content) {
		t.Fatalf("reassembled body mismatch at the boundary: got %d bytes want %d", len(got), len(content))
	}
}

// Regression pin for the pre-existing declared-Content-Length pre-check: it
// still signals, and still signals exactly once (the pre-check returns before
// any buffering, so it can never double-count with the new truncation probe).
func TestScanHTTPResponseBody_DeclaredOverLimitStillSignalsOnce(t *testing.T) {
	withScanLimit(t, testScanLimit)

	content := bytes.Repeat([]byte("D"), testScanLimit*4)
	r := httptest.NewRequest(http.MethodGet, "http://files.example.com/declared.bin", http.NoBody)
	r.RemoteAddr = "198.51.100.9:5558"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{},
		ContentLength: int64(len(content)),
		Body:          io.NopCloser(bytes.NewReader(content)),
	}
	w := httptest.NewRecorder()

	delta := scanSkippedDelta(func() { scanHTTPResponseBody(w, r, resp) })
	if delta != 1 {
		t.Errorf("scan_skipped delta = %d, want exactly 1 for a declared over-limit body", delta)
	}
}

// ─── SSL-inspect path: the signal that never existed ─────────────────────────

// inspectScanFixture drives scanInspectBody with the minimum production
// wiring: a clean ClamAV engine, no CDR client, no host exclusions.
func inspectScanFixture(t *testing.T, body []byte) (*http.Response, scanBodyOutcome, int64) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://cdn.example.com/payload.bin", http.NoBody)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		ContentLength: int64(len(body)),
		Body:          io.NopCloser(bytes.NewReader(body)),
	}
	var out scanBodyOutcome
	delta := scanSkippedDelta(func() {
		out = scanInspectBody(req, req, resp, &spyResponder{}, nil, ProxyIdentity{}, "cdn.example.com", "198.51.100.11", nil)
	})
	return resp, out, delta
}

func TestScanInspectBody_OverLimitSignalsScanSkipped(t *testing.T) {
	withScanLimit(t, testScanLimit)

	content := append(bytes.Repeat([]byte("E"), testScanLimit), []byte("MALWARE-PAST-THE-WINDOW")...)
	resp, out, delta := inspectScanFixture(t, content) //nolint:bodyclose // body closed via t.Cleanup on the next line
	t.Cleanup(func() { _ = resp.Body.Close() })

	if out != scanClean {
		t.Fatalf("clean prefix must yield scanClean, got %v", out)
	}
	if delta != 1 {
		t.Errorf("scan_skipped delta = %d, want 1 — the SSL-inspect path forwarded %d unscanned bytes with no counter, log or alert",
			delta, len(content)-testScanLimit)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reassembled body read: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("reassembled decrypted body corrupted: got %d bytes, want %d", len(got), len(content))
	}
}

func TestScanInspectBody_UnderLimitDoesNotSignal(t *testing.T) {
	withScanLimit(t, testScanLimit)

	content := bytes.Repeat([]byte("F"), testScanLimit-1)
	resp, out, delta := inspectScanFixture(t, content) //nolint:bodyclose // body closed via t.Cleanup on the next line
	t.Cleanup(func() { _ = resp.Body.Close() })

	if out != scanClean {
		t.Fatalf("want scanClean, got %v", out)
	}
	if delta != 0 {
		t.Errorf("scan_skipped delta = %d, want 0 for a fully inspected body", delta)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, content) {
		t.Fatalf("reassembled body mismatch: got %d bytes want %d", len(got), len(content))
	}
}

func TestScanInspectBody_ExactlyAtLimitDoesNotSignal(t *testing.T) {
	withScanLimit(t, testScanLimit)

	content := bytes.Repeat([]byte("G"), testScanLimit)
	resp, out, delta := inspectScanFixture(t, content) //nolint:bodyclose // body closed via t.Cleanup on the next line
	t.Cleanup(func() { _ = resp.Body.Close() })

	if out != scanClean {
		t.Fatalf("want scanClean, got %v", out)
	}
	if delta != 0 {
		t.Errorf("scan_skipped delta = %d, want 0 at exactly the limit (false positive)", delta)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(got, content) {
		t.Fatalf("reassembled body mismatch at the boundary: got %d bytes want %d", len(got), len(content))
	}
}

// A body READ error must still fail closed (CHAOS-17 / scanReadError) and must
// NOT be laundered into a truncation signal.
func TestScanInspectBody_ReadErrorStillFailsClosed(t *testing.T) {
	withScanLimit(t, testScanLimit)

	req := httptest.NewRequest(http.MethodGet, "https://cdn.example.com/reset.bin", http.NoBody)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		ContentLength: -1,
		Body: &erroringBody{
			prefix: strings.NewReader("partial"),
			err:    errors.New("read tcp: connection reset by peer"),
		},
	}
	var out scanBodyOutcome
	delta := scanSkippedDelta(func() {
		out = scanInspectBody(req, req, resp, &spyResponder{}, nil, ProxyIdentity{}, "cdn.example.com", "198.51.100.12", nil)
	})
	if out != scanReadError {
		t.Fatalf("want scanReadError (fail closed), got %v", out)
	}
	if delta != 0 {
		t.Errorf("scan_skipped delta = %d, want 0 — a failed read delivers nothing, so nothing was forwarded unscanned", delta)
	}
}

// ─── concurrency ─────────────────────────────────────────────────────────────

// Every concurrent over-limit response must be counted exactly once (the
// counter is an atomic; this also runs the new probe/reassembly path under
// -race).
func TestScanLimitSignal_ConcurrentResponsesEachCountedOnce(t *testing.T) {
	withScanLimit(t, testScanLimit)

	const workers = 16
	content := append(bytes.Repeat([]byte("H"), testScanLimit), []byte("tail")...)

	delta := scanSkippedDelta(func() {
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := httptest.NewRequest(http.MethodGet, "http://files.example.com/race.bin", http.NoBody)
				r.RemoteAddr = "198.51.100.13:6000"
				resp := newChunkedResponse(content) //nolint:bodyclose // test NopCloser body; the reassembled body is read below
				handled, _ := scanHTTPResponseBody(httptest.NewRecorder(), r, resp)
				if handled {
					t.Error("clean prefix must not be blocked")
				}
				if got, _ := io.ReadAll(resp.Body); !bytes.Equal(got, content) {
					t.Errorf("concurrent reassembly corrupted the body: %d bytes, want %d", len(got), len(content))
				}
			}()
		}
		wg.Wait()
	})

	if delta != workers {
		t.Errorf("scan_skipped delta = %d, want %d — one signal per over-limit response", delta, workers)
	}
}
