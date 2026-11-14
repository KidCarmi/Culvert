package main

// proxy_http_forward_bench_test.go — before/after evidence for the plain-HTTP
// forward step (proxy_http.go), which used to build an http.Client per request
// and now calls the upstream transport directly.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkHTTPForward' -benchmem -count=6 .
//
// BenchmarkHTTPForward_LegacyClientPerRequest is the FROZEN pre-change shape,
// kept so the comparison stays reproducible in-tree rather than living only in
// a commit message. It is deliberately a verbatim copy of the code that was
// removed; it is not called by production and must not be "kept in sync" with
// handleHTTP — its whole value is that it does not move.
//
// Measured on this machine (Go 1.26, linux/amd64, 4 vCPU, real *http.Transport
// against a local origin, 5-header browser-shaped request):
//
//	legacy (http.Client per request)   90 allocs/op   11.50 KB/op
//	direct (Transport.RoundTrip)       81 allocs/op   10.72 KB/op
//	                                   -9 (-10%)      -783 B (-6.8%)
//
// The removed allocations are all wrapper, not exchange: a full Header.Clone of
// the client's header map (http.Client.makeHeadersCopier, for redirect handling
// that CheckRedirect had already forbidden), the redirect body-rewind wrapper
// (setupRewindBody), the cancelTimerBody wrapper around the response body, and
// the http.Client value itself. ns/op improves too, but over loopback it is
// syscall-dominated and too noisy to quote — allocs/op is the honest signal and
// the one TestBenchGate_HTTPForwardAllocs gates on.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// benchForwardOrigin serves a small fixed body — enough to exercise the
// response path without letting body size dominate the measurement.
func benchForwardOrigin(b *testing.B) *httptest.Server {
	b.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello world"))
	}))
	b.Cleanup(s.Close)
	return s
}

// benchForwardRequest builds a proxy-shaped request: absolute URL, RequestURI
// cleared, and the handful of headers a real browser sends. Header count is
// load-bearing here — it is what the removed Header.Clone had to copy.
func benchForwardRequest(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, http.NoBody)
	r.RequestURI = ""
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Accept-Encoding", "gzip, deflate")
	r.Header.Set("X-Request-Id", "eb14c832b0e8b750")
	return r
}

// forwardDirect is the shipped forward step (proxy_http.go), reduced to the
// part this benchmark measures.
func forwardDirect(tr *http.Transport, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), upstreamRequestTimeout)
	defer cancel()
	resp, err := tr.RoundTrip(r.WithContext(ctx))
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

// forwardLegacyClient is the pre-change forward step, frozen. Do not update it.
func forwardLegacyClient(tr *http.Transport, r *http.Request) error {
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: upstreamRequestTimeout,
	}
	resp, err := client.Do(r)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

func benchForward(b *testing.B, fwd func(*http.Transport, *http.Request) error) {
	origin := benchForwardOrigin(b)
	tr := &http.Transport{MaxIdleConns: 512, MaxIdleConnsPerHost: 64}
	b.Cleanup(tr.CloseIdleConnections)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := fwd(tr, benchForwardRequest(origin.URL+"/some/path")); err != nil {
			b.Fatalf("forward: %v", err)
		}
	}
}

func BenchmarkHTTPForward_Direct(b *testing.B) { benchForward(b, forwardDirect) }

func BenchmarkHTTPForward_LegacyClientPerRequest(b *testing.B) {
	benchForward(b, forwardLegacyClient)
}

// BenchmarkHTTPForward_DirectParallel checks that the win holds under
// concurrency rather than only on a serial loop — the allocations removed were
// per-request garbage, which is exactly what costs most when many cores are
// allocating at once.
func BenchmarkHTTPForward_DirectParallel(b *testing.B) {
	benchForwardParallel(b, forwardDirect)
}

func BenchmarkHTTPForward_LegacyParallel(b *testing.B) {
	benchForwardParallel(b, forwardLegacyClient)
}

func benchForwardParallel(b *testing.B, fwd func(*http.Transport, *http.Request) error) {
	origin := benchForwardOrigin(b)
	tr := &http.Transport{MaxIdleConns: 512, MaxIdleConnsPerHost: 64}
	b.Cleanup(tr.CloseIdleConnections)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := fwd(tr, benchForwardRequest(origin.URL+"/some/path")); err != nil {
				b.Fatalf("forward: %v", err)
			}
		}
	})
}

// benchCopyBufPool mirrors net/http's internal copy-buffer pool (the 32 KiB
// buffer its (*response).ReadFrom borrows per response), so the benchmark
// charges the same per-request cost production does: none.
var benchCopyBufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// readerFromRecorder is httptest.ResponseRecorder PLUS the io.ReaderFrom that
// the real *http.response implements.
//
// It exists for measurement fidelity, not speed. handleHTTP ends in
// io.Copy(w, resp.Body) (proxy_http.go). io.Copy takes dst's ReaderFrom fast
// path when dst has one, and the *http.response serving every production
// request does: net/http's ReadFrom copies through a POOLED 32 KiB buffer, so
// the shipped forward step allocates NO copy buffer per request. A bare
// ResponseRecorder has no ReadFrom, so io.Copy fell back to its generic path
// and allocated a fresh 32 KiB buffer on every iteration — one allocation and
// ~32 KB/op that production never pays, which inflated this benchmark's B/op
// from ~12 KB to ~44.7 KB. That is ~3.7x the "real per-request total" the
// benchmark exists to report, and it diluted any genuine B/op regression
// against a 32 KB constant.
//
// Implementing ReaderFrom over a pooled buffer restores the production shape
// while keeping the in-process isolation that makes this benchmark cheap and
// deterministic. The end-to-end number through a real listener (where w is a
// true *http.response) is BenchmarkPerfQual_ProxyHTTPForward.
type readerFromRecorder struct{ *httptest.ResponseRecorder }

func (w readerFromRecorder) ReadFrom(src io.Reader) (int64, error) {
	bp := benchCopyBufPool.Get().(*[]byte)
	defer benchCopyBufPool.Put(bp)
	// The embedded *httptest.ResponseRecorder is passed, never w itself, so
	// the copy cannot recurse back into this method. The recorder has no
	// ReaderFrom of its own, so io.CopyBuffer uses the pooled buffer.
	return io.CopyBuffer(w.ResponseRecorder, src, *bp)
}

// BenchmarkHTTPForward_HandleHTTP measures the whole shipped handler, so the
// forward-step saving above can be read against the real per-request total
// rather than in isolation.
//
// The ResponseWriter is readerFromRecorder, not a bare httptest recorder, so
// the response-body copy takes the same pooled-buffer path it takes in
// production; see that type for why a bare recorder overstated B/op by ~32 KB.
func BenchmarkHTTPForward_HandleHTTP(b *testing.B) {
	origin := benchForwardOrigin(b)

	orig := upstreamTransportPtr.Load()
	b.Cleanup(func() { upstreamTransportPtr.Store(orig) })
	upstreamTransportPtr.Store(&http.Transport{MaxIdleConns: 512, MaxIdleConnsPerHost: 64})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		handleHTTP(readerFromRecorder{rr}, benchForwardRequest(origin.URL+"/some/path"), ProxyIdentity{})
		if rr.Code != http.StatusOK {
			b.Fatalf("status %d", rr.Code)
		}
	}
}

// BenchmarkHTTPForward_LargeBody pins that the change is neutral on throughput:
// the allocations removed are per-request fixed cost, so a body-dominated
// request should show the same bytes/op delta and no regression in ns/op.
func BenchmarkHTTPForward_LargeBody(b *testing.B) {
	payload := make([]byte, 256<<10)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	b.Cleanup(origin.Close)

	tr := &http.Transport{MaxIdleConns: 512, MaxIdleConnsPerHost: 64}
	b.Cleanup(tr.CloseIdleConnections)

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := forwardDirect(tr, benchForwardRequest(origin.URL)); err != nil {
			b.Fatalf("forward: %v", err)
		}
	}
}
