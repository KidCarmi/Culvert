package main

// Guards the assumption that keeps the plain-HTTP forward step from allocating
// a 32 KiB copy buffer per response.
//
// handleHTTP ends in io.Copy(w, resp.Body) (proxy_http.go). io.Copy allocates
// its own 32 KiB buffer UNLESS src has WriteTo or dst has ReadFrom. The
// readErrTracker wrapping the upstream body has only Read, so the whole
// saving rests on dst: the *http.response that net/http hands every proxy
// request implements io.ReaderFrom and copies through a POOLED buffer.
//
// Two ways that can silently break, each costing 32 KiB of garbage on every
// forwarded response:
//
//  1. net/http stops implementing ReaderFrom on its response type.
//  2. Culvert starts wrapping the PROXY-plane ResponseWriter. Embedding
//     http.ResponseWriter in a wrapper promotes only the three interface
//     methods, so ReaderFrom is masked — exactly what trackedRW
//     (crashguard.go) does on the ADMIN plane, where it is harmless because
//     no large body copy runs there. A wrapper like it on the proxy plane
//     would be a throughput regression with no visible code change at the
//     io.Copy call site.
//
// Interface assertions only: deterministic and hardware independent, so this
// belongs in the normal suite rather than behind the benchgate tag.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestForwardResponseWriterImplementsReaderFrom pins reason (1): the writer a
// real listener passes to the handler takes io.Copy's pooled fast path.
func TestForwardResponseWriterImplementsReaderFrom(t *testing.T) {
	seen := make(chan bool, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, ok := w.(io.ReaderFrom)
		seen <- ok
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL) //nolint:noctx // loopback test server, no cancellation contract to carry
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if ok := <-seen; !ok {
		t.Error("the ResponseWriter handleHTTP receives does not implement io.ReaderFrom; " +
			"io.Copy in the forward step now allocates a 32 KiB buffer per response")
	}
}

// TestBenchRecorderImplementsReaderFrom pins the benchmark's fidelity to that
// production shape. A bare httptest.ResponseRecorder has no ReadFrom, so
// swapping readerFromRecorder back out silently re-inflates
// BenchmarkHTTPForward_HandleHTTP's B/op by ~32 KB (~3.7x the real total) and
// dilutes any genuine allocation regression against that constant.
func TestBenchRecorderImplementsReaderFrom(t *testing.T) {
	if _, ok := interface{}(readerFromRecorder{httptest.NewRecorder()}).(io.ReaderFrom); !ok {
		t.Fatal("readerFromRecorder must implement io.ReaderFrom to model the production copy path")
	}
	// Negative control: the bare recorder is the shape that caused the
	// inflated measurement, so pin that it really does lack ReadFrom.
	if _, ok := interface{}(httptest.NewRecorder()).(io.ReaderFrom); ok {
		t.Fatal("httptest.ResponseRecorder now implements io.ReaderFrom; " +
			"readerFromRecorder is obsolete and should be removed")
	}
}

// TestReaderFromRecorderCopiesBodyFaithfully proves the pooled ReadFrom is
// byte-faithful: a measurement harness that loses or corrupts body bytes would
// make every B/op number read against it meaningless.
func TestReaderFromRecorderCopiesBodyFaithfully(t *testing.T) {
	rr := httptest.NewRecorder()
	w := readerFromRecorder{rr}

	// Larger than the 32 KiB pooled buffer, so the copy loop runs several
	// times and a stale or short-reused buffer would show up here.
	payload := make([]byte, (32<<10)*2+1234)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	n, err := io.Copy(w, newSingleReader(payload))
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if n != int64(len(payload)) {
		t.Errorf("copied %d bytes, want %d", n, len(payload))
	}
	if got := rr.Body.Bytes(); !bytes.Equal(got, payload) {
		t.Errorf("body mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// newSingleReader returns a reader with only Read, so io.Copy cannot bypass
// the ReaderFrom path under test via a WriteTo shortcut (which is what
// bytes.Reader would do).
func newSingleReader(b []byte) io.Reader { return &readOnlyReader{b: b} }

type readOnlyReader struct {
	b   []byte
	off int
}

func (r *readOnlyReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}
