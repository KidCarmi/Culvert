package main

// CHAOS-17: a body READ error while buffering a plain-HTTP response for
// scanning must fail CLOSED (502, response handled), mirroring the inspect
// path's scanReadError contract (proxy_tunnel.go). Before the fix the error
// path returned false, so the caller streamed the response unscanned AND
// truncated (the consumed prefix was never reassembled).

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// cleanClam is a ClamScanner that never matches; it exists to flip
// BodyScanEnabled on so scanHTTPResponseBody actually buffers the body.
type cleanClam struct{}

func (cleanClam) Ping() error                                      { return nil }
func (cleanClam) Scan([]byte) (name string, found bool, err error) { return "", false, nil }

// erroringBody yields a prefix then fails the read (origin RST mid-body).
type erroringBody struct {
	prefix io.Reader
	err    error
}

func (e *erroringBody) Read(p []byte) (int, error) {
	n, err := e.prefix.Read(p)
	if err == io.EOF {
		return n, e.err
	}
	return n, err
}

func (e *erroringBody) Close() error { return nil }

// withBodyScanScanner swaps in an enabled scanner whose only engine is
// cleanClam, restoring the production singleton afterwards.
func withBodyScanScanner(t *testing.T) {
	t.Helper()
	orig := globalSecScanner
	globalSecScanner = secscan.New(secscan.Deps{Clam: cleanClam{}})
	globalSecScanner.Init("", 0, nil)
	t.Cleanup(func() { globalSecScanner = orig })
}

func TestScanHTTPResponseBody_ReadErrorFailsClosed(t *testing.T) {
	withBodyScanScanner(t)

	r := httptest.NewRequest(http.MethodGet, "http://files.example.com/download.bin", http.NoBody)
	r.RemoteAddr = "198.51.100.7:4321"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{},
		ContentLength: -1,
		Body: &erroringBody{
			prefix: strings.NewReader("partial content the origin managed to send"),
			err:    errors.New("read tcp: connection reset by peer"),
		},
	}
	w := httptest.NewRecorder()

	handled, upstreamReadErr := scanHTTPResponseBody(w, r, resp)
	if !handled {
		t.Fatal("body read error must be handled fail-closed (pre-fix: returned false → forwarded unscanned + truncated)")
	}
	if upstreamReadErr == nil {
		t.Fatal("the upstream read error must be surfaced so the caller can charge the breaker attribution (CHAOS-11)")
	}
	if w.Code != http.StatusBadGateway {
		t.Fatalf("want 502 Bad Gateway, got %d", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "Bad Gateway") {
		t.Fatalf("want Bad Gateway error body, got %q", body)
	}
}

func TestScanHTTPResponseBody_CleanBodyReassembled(t *testing.T) {
	withBodyScanScanner(t)

	content := []byte("perfectly ordinary clean response body")
	r := httptest.NewRequest(http.MethodGet, "http://files.example.com/ok.txt", http.NoBody)
	r.RemoteAddr = "198.51.100.7:4321"
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{},
		ContentLength: int64(len(content)),
		Body:          io.NopCloser(bytes.NewReader(content)),
	}
	w := httptest.NewRecorder()

	handled, upstreamReadErr := scanHTTPResponseBody(w, r, resp)
	if handled {
		t.Fatalf("clean body must not be blocked; recorder: %d %q", w.Code, w.Body.String())
	}
	if upstreamReadErr != nil {
		t.Fatalf("clean pass must not report an upstream read error, got %v", upstreamReadErr)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reassembled body read: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("reassembled body mismatch: got %q want %q", got, content)
	}
}
