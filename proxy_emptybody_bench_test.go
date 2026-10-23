package main

// proxy_emptybody_bench_test.go — before/after evidence for leaving a
// known-empty request body as the http.NoBody sentinel instead of wrapping it
// (proxy_http.go prepareHTTPForward, proxy_tunnel.go's inspected inner loop).
//
// WHY THIS IS A HOT PATH. Both wrappers ran unconditionally on every forwarded
// request. Bodyless methods (GET and HEAD) are the overwhelming majority of
// proxied web traffic, and on an inspecting gateway every decrypted inner
// request takes the second site too. So the cost below was paid on most
// requests the product serves.
//
// WHAT IT COST. net/http keys its no-body fast path on the IDENTITY of
// http.NoBody (Request.outgoingLength), so wrapping the sentinel reports the
// body length as UNKNOWN. newTransferWriter — shared by Transport.RoundTrip and
// Request.Write, i.e. by both legs — then resolves the unknown:
//
//   - GET/HEAD/DELETE/OPTIONS/PROPFIND/SEARCH: probeRequestBody spawns a
//     goroutine to read one byte, behind a buffered channel and a 200 ms
//     time.Timer, and blocks the request line on that channel round trip.
//   - any other method: no probe; the empty body is framed as
//     "Transfer-Encoding: chunked" instead of "Content-Length: 0".
//
// The *Wrapped benchmarks are the FROZEN pre-change shape — a verbatim copy of
// the wrapping the shipped code no longer does on the sentinel. They are not
// called by production and must not be "kept in sync"; their whole value is
// that they do not move.
//
// Measured on this container class (Go 1.26.10, linux/amd64, 4 vCPU Xeon
// @2.1GHz, real *http.Transport against a local origin over keep-alive),
// median of n=5 at -benchtime=5000x / 20000x:
//
//	                                 ns/op    B/op  allocs/op
//	EmptyBodyForward_Sentinel        84933    9643      68
//	EmptyBodyForward_Wrapped         88105   10471      79   (+11 allocs, +828 B)
//	EmptyBodyForward_POSTSentinel    85578    9658      69
//	EmptyBodyForward_POSTWrapped     93273   10313      81   (+12 allocs, +655 B)
//	EmptyBodyInnerWrite_Sentinel      1222     253       6
//	EmptyBodyInnerWrite_Wrapped       4228     665      13   (+7 allocs, 3.5x ns)
//
// Read the ALLOCATION columns as the signal on the forward pair: ns/op there is
// loopback- and scheduler-bound on a shared 4-vCPU runner and the two medians
// overlap across runs, so it is NOT evidence. Allocation counts are
// deterministic, which is why the gate keys on them
// (proxy_emptybody_benchgate_test.go, -tags benchgate).
//
// The inner-write pair is the exception and the strongest evidence here: it
// carries no network at all, so its 1.2 µs → 4.2 µs is the probe's channel
// round trip and nothing else, reproduced in all 5 runs with no overlap.
//
// End to end, BenchmarkPerfQual_ProxyHTTPForward goes from 176 to 165 allocs/op
// and ~14 765 to ~13 895 B/op, identically at rules=10/100/500 and in every run
// of an A/B against the pre-change tree. Its ns/op and cpu-ns/op move in the
// same direction (~-3%) but inside the runner's spread, so they are reported as
// directional only, not as the result.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// benchEmptyBodyRequest builds a proxy-shaped request whose body is the
// stdlib's known-empty sentinel — exactly what net/http's readTransfer hands a
// handler for a bodyless request, and what http.ReadRequest hands the
// inspected inner loop.
func benchEmptyBodyRequest(b *testing.B, method, target string) *http.Request {
	b.Helper()
	r := httptest.NewRequestWithContext(context.Background(), method, target, http.NoBody)
	if r.Body != http.NoBody {
		b.Fatalf("test premise broken: server-shaped %s body is %T, want http.NoBody", method, r.Body)
	}
	r.RequestURI = ""
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	r.Header.Set("Accept-Encoding", "gzip, deflate")
	return r
}

// wrapEmptyBodyLegacy is the pre-change wrapping, frozen. Do not update it.
// It is prepareHTTPForward's body wrapper with no sentinel check, which is the
// shape that made the length unknown.
//
// The one deliberate deviation from the shipped line is the nil ResponseWriter:
// MaxBytesReader consults it only to emit the 413 when the limit trips, which an
// empty body cannot do, so the measured path is identical and the benchmark does
// not need a recorder it would never touch.
func wrapEmptyBodyLegacy(r *http.Request) {
	r.Body = &countingReader{r: http.MaxBytesReader(nil, r.Body, maxRequestBody)}
}

// benchEmptyBodyForward drives a real *http.Transport round trip against a
// local origin, with the request body either left as the sentinel or wrapped in
// the frozen legacy shape. What it measures is the FRAMING decision net/http
// makes from that body and the exchange that follows.
//
// It deliberately does NOT call prepareHTTPForward: routing through it would
// fold the scrub, rewrite and policy-adjacent work of the real handler into a
// number that is supposed to isolate the framing cost. The consequence is that
// this benchmark cannot notice a wrapper reintroduced inside
// prepareHTTPForward — it wraps the request itself. That contract is held by
// TestPrepareHTTPForward_EmptyBodyKeepsSentinel in the normal suite.
func benchEmptyBodyForward(b *testing.B, method string, wrap bool) {
	origin := benchForwardOrigin(b)
	tr := &http.Transport{MaxIdleConnsPerHost: 4}
	b.Cleanup(tr.CloseIdleConnections)

	// Warm one keep-alive connection so the dial is not inside the measurement.
	if resp, err := tr.RoundTrip(benchEmptyBodyRequest(b, method, origin.URL)); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := benchEmptyBodyRequest(b, method, origin.URL)
		if wrap {
			wrapEmptyBodyLegacy(r)
		}
		resp, err := tr.RoundTrip(r)
		if err != nil {
			b.Fatalf("round trip: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func BenchmarkEmptyBodyForward_Sentinel(b *testing.B) {
	benchEmptyBodyForward(b, http.MethodGet, false)
}

func BenchmarkEmptyBodyForward_Wrapped(b *testing.B) {
	benchEmptyBodyForward(b, http.MethodGet, true)
}

// The POST pair isolates the OTHER arm of the framing decision: no probe, but
// the empty body is re-framed as chunked, which costs the chunk writer plus the
// extra terminator bytes on the wire.
func BenchmarkEmptyBodyForward_POSTSentinel(b *testing.B) {
	benchEmptyBodyForward(b, http.MethodPost, false)
}

func BenchmarkEmptyBodyForward_POSTWrapped(b *testing.B) {
	benchEmptyBodyForward(b, http.MethodPost, true)
}

// benchEmptyBodyInnerWrite measures the SSL-inspected inner leg in isolation:
// Request.Write onto a buffer, which is the step proxy_tunnel.go performs onto
// the upstream TLS conn. No network, so the gap between the two variants is the
// framing decision and nothing else.
//
// Isolation cuts the same way as the forward pair above: the inspected loop is
// not run here, so a wrapper reintroduced inside it would not show up in this
// number. TestInspectInnerLeg_EmptyBodyKeepsClientFraming drives the real
// tunnel and is what holds that contract.
// The request is built ONCE, outside the measurement, so what is timed is the
// framing decision and the serialization — nothing else. Re-serializing one
// request is safe and deterministic for both arms: an empty body yields
// (0, io.EOF) on every read, and Request.Write mutates only the transferWriter
// it builds internally, never the request.
func benchEmptyBodyInnerWrite(b *testing.B, wrap bool) {
	r := benchEmptyBodyRequest(b, http.MethodGet, "http://origin.example/path")
	if wrap {
		wrapEmptyBodyLegacy(r)
	}
	var buf bytes.Buffer
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		if err := r.Write(&buf); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}

func BenchmarkEmptyBodyInnerWrite_Sentinel(b *testing.B) { benchEmptyBodyInnerWrite(b, false) }
func BenchmarkEmptyBodyInnerWrite_Wrapped(b *testing.B)  { benchEmptyBodyInnerWrite(b, true) }

// The parallel pair is where the probe's cost is worst: every in-flight
// bodyless request holds its own goroutine, channel and runtime timer, so the
// pressure is on the scheduler and the timer heap, not just the allocator.
func benchEmptyBodyForwardParallel(b *testing.B, wrap bool) {
	origin := benchForwardOrigin(b)
	tr := &http.Transport{MaxIdleConnsPerHost: 64}
	b.Cleanup(tr.CloseIdleConnections)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := benchEmptyBodyRequest(b, http.MethodGet, origin.URL)
			if wrap {
				wrapEmptyBodyLegacy(r)
			}
			resp, err := tr.RoundTrip(r)
			if err != nil {
				b.Errorf("round trip: %v", err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	})
}

func BenchmarkEmptyBodyForward_ParallelSentinel(b *testing.B) {
	benchEmptyBodyForwardParallel(b, false)
}

func BenchmarkEmptyBodyForward_ParallelWrapped(b *testing.B) {
	benchEmptyBodyForwardParallel(b, true)
}
