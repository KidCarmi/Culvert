package main

// CHAOS-17 — plain-HTTP body-read-error alignment. When the upstream breaks
// mid-body while the response is being buffered for scanning, the exchange
// must fail (502) like the inspect path's scanReadError contract. The old
// behavior returned "not blocked", so the caller streamed the truncated
// prefix as a 200 — unscanned content delivered, corrupt payload cacheable
// downstream, and no signal anywhere.

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// stubYARALoaded flips BodyScanEnabled on without any real engine.
type stubYARALoaded struct{}

func (stubYARALoaded) Loaded() bool          { return true }
func (stubYARALoaded) Enabled() bool         { return false }
func (stubYARALoaded) Match([]byte) []string { return nil }

// brokenBody yields a few bytes, then a mid-stream error (origin RST).
type brokenBody struct {
	prefix io.Reader
	err    error
}

func (b *brokenBody) Read(p []byte) (int, error) {
	n, err := b.prefix.Read(p)
	if n > 0 {
		return n, nil
	}
	if errors.Is(err, io.EOF) {
		return 0, b.err
	}
	return n, err
}
func (b *brokenBody) Close() error { return nil }

func TestScanHTTPResponseBody_ReadErrorFailsExchange(t *testing.T) {
	origSec := globalSecScanner
	t.Cleanup(func() { globalSecScanner = origSec })
	sec := secscan.New(secscan.Deps{Yara: stubYARALoaded{}})
	sec.Init("", 0, nil) // enable; no ClamAV
	globalSecScanner = sec
	if !globalSecScanner.BodyScanEnabled() {
		t.Fatal("test scanner must report body scanning enabled")
	}

	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		ContentLength: -1, // unknown length: scan path must buffer
		Body: &brokenBody{
			prefix: strings.NewReader("partial-content-before-origin-reset"),
			err:    errors.New("read tcp: connection reset by peer"),
		},
	}

	before := secscan.Counters().ScanError
	req := httptest.NewRequest(http.MethodGet, "http://example.test/file.bin", http.NoBody)
	req.RemoteAddr = "198.51.100.77:4242"
	w := httptest.NewRecorder()

	if !scanHTTPResponseBody(w, req, resp) {
		t.Fatal("read error must fail the exchange (return true), not stream a truncated 200")
	}
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "partial-content") {
		t.Fatalf("truncated upstream prefix must not reach the client, got %q", body)
	}
	if got := secscan.Counters().ScanError; got != before+1 {
		t.Fatalf("ScanError counter = %d, want %d", got, before+1)
	}
}

func TestScanHTTPResponseBody_CleanBodyStillStreams(t *testing.T) {
	// Guard the non-error path: a fully readable clean body is reassembled and
	// NOT blocked (the 502 branch must trigger only on a read error).
	origSec := globalSecScanner
	t.Cleanup(func() { globalSecScanner = origSec })
	sec := secscan.New(secscan.Deps{Yara: stubYARALoaded{}})
	sec.Init("", 0, nil)
	globalSecScanner = sec

	const payload = "plain clean content"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		ContentLength: int64(len(payload)),
		Body:          io.NopCloser(strings.NewReader(payload)),
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/ok.txt", http.NoBody)
	req.RemoteAddr = "198.51.100.77:4242"
	w := httptest.NewRecorder()

	if scanHTTPResponseBody(w, req, resp) {
		t.Fatalf("clean body must not be blocked; recorder: %d %q", w.Code, w.Body.String())
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != payload {
		t.Fatalf("reassembled body = %q (err %v), want %q", got, err, payload)
	}
}
