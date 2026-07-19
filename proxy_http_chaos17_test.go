package main

// CHAOS-17 regression: a body READ error while buffering a plain-HTTP response
// for scanning must fail closed (502), mirroring the inspect path's
// scanReadError contract. Pre-fix, the error path returned false with the
// buffered prefix silently discarded — the client received a truncated body
// that had also bypassed ClamAV/YARA/DPI scanning entirely.

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// chaos17Clam is a minimal ClamScanner so BodyScanEnabled() is true; the read
// error fires before any scanner runs, so the verdict is irrelevant.
type chaos17Clam struct{}

func (chaos17Clam) Ping() error                       { return nil }
func (chaos17Clam) Scan([]byte) (string, bool, error) { return "", false, nil }

// truncatedBody yields a prefix and then a mid-stream transport error,
// simulating an origin RST/GOAWAY while the scan buffer is being filled.
type truncatedBody struct {
	data []byte
	off  int
}

func (b *truncatedBody) Read(p []byte) (int, error) {
	if b.off < len(b.data) {
		n := copy(p, b.data[b.off:])
		b.off += n
		return n, nil
	}
	return 0, errors.New("read: connection reset by peer")
}

func (b *truncatedBody) Close() error { return nil }

func TestScanHTTPResponseBody_ReadErrorFailsClosed(t *testing.T) {
	origSec := globalSecScanner
	origRemote := globalRemoteScanner
	t.Cleanup(func() {
		globalSecScanner = origSec
		globalRemoteScanner = origRemote
	})
	globalRemoteScanner = &RemoteScanner{} // disabled
	globalSecScanner = secscan.New(secscan.Deps{Clam: chaos17Clam{}})
	globalSecScanner.Init("", 1<<20, newHashCache(16, time.Minute))
	if !globalSecScanner.BodyScanEnabled() {
		t.Fatal("test scaffold: body scanning must be active")
	}

	req := httptest.NewRequest(http.MethodGet, "http://chaos17-origin.example/file.bin", nil)
	req.RemoteAddr = "198.51.100.17:40001"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		Body:          &truncatedBody{data: []byte("partial content before the origin reset")},
		ContentLength: -1,
	}
	w := httptest.NewRecorder()

	handled := scanHTTPResponseBody(w, req, resp)
	if !handled {
		t.Fatal("read error must be handled here (fail-closed), not fall through to streaming a truncated, unscanned body")
	}
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway, got %d", w.Code)
	}
}

func TestScanHTTPResponseBody_CleanBodyStillStreams(t *testing.T) {
	// Guard the other side of the contract: an intact body that scans clean is
	// reassembled and NOT handled here.
	origSec := globalSecScanner
	origRemote := globalRemoteScanner
	t.Cleanup(func() {
		globalSecScanner = origSec
		globalRemoteScanner = origRemote
	})
	globalRemoteScanner = &RemoteScanner{}
	globalSecScanner = secscan.New(secscan.Deps{Clam: chaos17Clam{}})
	globalSecScanner.Init("", 1<<20, newHashCache(16, time.Minute))

	body := "intact clean content"
	req := httptest.NewRequest(http.MethodGet, "http://chaos17-origin.example/ok.txt", nil)
	req.RemoteAddr = "198.51.100.17:40002"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          io.NopCloser(&truncatedBody{data: []byte(body), off: 0}),
		ContentLength: int64(len(body)),
	}
	// A LimitReader bounded at MaxBytes stops before the error when
	// ContentLength fits — but ReadAll reads to EOF, so give it a clean EOF.
	resp.Body = io.NopCloser(io.LimitReader(&truncatedBody{data: []byte(body)}, int64(len(body))))
	w := httptest.NewRecorder()

	if scanHTTPResponseBody(w, req, resp) {
		t.Fatalf("clean body must not be handled by the scan pipeline; recorder: %d %q", w.Code, w.Body.String())
	}
	streamed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reassembled body read: %v", err)
	}
	if string(streamed) != body {
		t.Fatalf("reassembled body mismatch: %q", streamed)
	}
}
