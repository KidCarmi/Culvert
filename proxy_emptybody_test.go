package main

// proxy_emptybody_test.go — contracts for leaving a known-empty request body as
// the http.NoBody sentinel on the two legs that serialize an outbound request
// (proxy_http.go prepareHTTPForward, proxy_tunnel.go's inspected inner loop).
//
// The change is a COST change, so each test here names one thing the removed
// wrapper was doing and proves the skip still does it — plus one thing the
// wrapper was doing WRONG, which the skip fixes and which is therefore a
// visible wire change that needs pinning rather than hiding.

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// serverShapedRequest returns the request a handler actually receives, by
// parsing raw wire bytes with the same net/http machinery the proxy's listener
// and the inspected inner loop both use (http.ReadRequest → readTransfer).
// Constructing it this way rather than with httptest.NewRequest is the point:
// the premise under test is what the STDLIB puts in r.Body, not what a test
// helper does.
func serverShapedRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ReadRequest(%q): %v", raw, err)
	}
	return req
}

// TestEmptyBodySentinel_StdlibPremise pins the assumption the whole change
// rests on: net/http hands a bodyless request the http.NoBody sentinel, and
// hands a request WITH a body something else. If a future Go release stops
// doing this, the skip silently stops firing (a pure cost regression, not a
// correctness one) and this test says so.
func TestEmptyBodySentinel_StdlibPremise(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantEmpty bool
	}{
		{"GET no body", "GET /p HTTP/1.1\r\nHost: h\r\n\r\n", true},
		{"HEAD no body", "HEAD /p HTTP/1.1\r\nHost: h\r\n\r\n", true},
		{"POST content-length 0", "POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n", true},
		{"POST with body", "POST /p HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nabcd", false},
		{"POST chunked", "POST /p HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := serverShapedRequest(t, tc.raw)
			if got := requestBodyIsKnownEmpty(req.Body); got != tc.wantEmpty {
				t.Errorf("requestBodyIsKnownEmpty(%T) = %v, want %v", req.Body, got, tc.wantEmpty)
			}
		})
	}
}

// TestEmptyBodySentinel_ScopeIsExactlyTheSentinel is the negative control. A
// body that happens to be empty but is NOT the sentinel must still be wrapped:
// the skip is allowed to assume "no bytes" only where the stdlib guarantees it,
// never from a length that could be a stand-in for "unknown".
func TestEmptyBodySentinel_ScopeIsExactlyTheSentinel(t *testing.T) {
	if requestBodyIsKnownEmpty(nil) {
		t.Error("nil body reported as the known-empty sentinel; the nil branch must keep its own handling")
	}
	if requestBodyIsKnownEmpty(io.NopCloser(strings.NewReader(""))) {
		t.Error("a non-sentinel empty reader reported as known-empty; scope must be the sentinel's identity only")
	}
}

// TestPrepareHTTPForward_EmptyBodyKeepsSentinel is the forward leg's contract:
// no wrapper installed, and no counter returned — which is the same nil the
// caller already handled for a request with no body at all.
func TestPrepareHTTPForward_EmptyBodyKeepsSentinel(t *testing.T) {
	r := serverShapedRequest(t, "GET http://origin.example/p HTTP/1.1\r\nHost: origin.example\r\n\r\n")
	rr := httptest.NewRecorder()

	_, counter := prepareHTTPForward(rr, r)

	if counter != nil {
		t.Errorf("counter = %p, want nil for a known-empty body", counter)
	}
	if r.Body != http.NoBody {
		t.Errorf("r.Body = %T, want the http.NoBody sentinel preserved", r.Body)
	}
}

// TestPrepareHTTPForward_RealBodyStillWrappedAndCounted proves the skip did not
// disarm the wrapper for the requests it exists for: a real body is still
// counted, and the count is still what statBytesSent is charged.
func TestPrepareHTTPForward_RealBodyStillWrappedAndCounted(t *testing.T) {
	const payload = "hello upstream"
	r := serverShapedRequest(t, "POST http://origin.example/p HTTP/1.1\r\nHost: origin.example\r\nContent-Length: 14\r\n\r\n"+payload)
	rr := httptest.NewRecorder()

	_, counter := prepareHTTPForward(rr, r)
	if counter == nil {
		t.Fatal("counter = nil for a real body; the sent-bytes accounting is gone")
	}
	if _, err := io.ReadAll(r.Body); err != nil {
		t.Fatalf("read wrapped body: %v", err)
	}
	if counter.count != int64(len(payload)) {
		t.Errorf("counter.count = %d, want %d", counter.count, len(payload))
	}
}

// forwardedUpstreamRequest runs handleHTTP against a recording origin and
// returns the request line/headers the ORIGIN saw. That is the only place the
// framing decision is observable, and the only place it matters.
func forwardedUpstreamRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	withDirectTransport(t)

	seen := make(chan *http.Request, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		seen <- r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()

	req := serverShapedRequest(t, strings.ReplaceAll(raw, "ORIGIN", origin.URL))
	req.Host = strings.TrimPrefix(origin.URL, "http://")
	rr := httptest.NewRecorder()
	handleHTTP(rr, req, ProxyIdentity{})

	if rr.Code != http.StatusOK {
		t.Fatalf("proxy status = %d, want 200 (body %q)", rr.Code, rr.Body.String())
	}
	select {
	case got := <-seen:
		return got
	default:
		t.Fatal("origin never saw the forwarded request")
		return nil
	}
}

// TestHandleHTTP_EmptyBodyGETFramingUnchanged is the equivalence pin: the wire
// the origin sees for a bodyless GET is what it always was. Before this change
// net/http reached the same wire by probing the wrapped body on a goroutine;
// now it reaches it directly. Same bytes, no probe.
func TestHandleHTTP_EmptyBodyGETFramingUnchanged(t *testing.T) {
	got := forwardedUpstreamRequest(t, "GET ORIGIN/p HTTP/1.1\r\nHost: origin\r\n\r\n")

	if te := got.TransferEncoding; len(te) != 0 {
		t.Errorf("origin saw Transfer-Encoding %v on a bodyless GET, want none", te)
	}
	if got.ContentLength > 0 {
		t.Errorf("origin saw ContentLength = %d on a bodyless GET, want 0 or absent", got.ContentLength)
	}
}

// TestHandleHTTP_EmptyBodyPOSTKeepsContentLengthZero pins the wire change this
// also fixes, so it is a recorded decision rather than a surprise.
//
// A client's "POST ... Content-Length: 0" used to reach the origin re-framed as
// "Transfer-Encoding: chunked" with a zero-length chunked body: wrapping the
// sentinel made the length unknown, and for methods that normally DO carry a
// body net/http does not probe — it chunks. A forward proxy re-framing a
// request the client framed correctly is wrong on its own terms, and origins,
// WAFs and CDNs do not all treat the two equivalently. Keeping the sentinel
// forwards the client's own framing.
func TestHandleHTTP_EmptyBodyPOSTKeepsContentLengthZero(t *testing.T) {
	got := forwardedUpstreamRequest(t, "POST ORIGIN/p HTTP/1.1\r\nHost: origin\r\nContent-Length: 0\r\n\r\n")

	if te := got.TransferEncoding; len(te) != 0 {
		t.Errorf("origin saw Transfer-Encoding %v for a Content-Length: 0 POST, want none — the client's framing must be forwarded, not rewritten", te)
	}
	if got.ContentLength != 0 {
		t.Errorf("origin saw ContentLength = %d, want 0", got.ContentLength)
	}
}

// TestHandleHTTP_EmptyBodyBytesSentUnchanged proves the accounting the removed
// counter was there for is unaffected: an empty body contributed 0 before and
// contributes 0 now.
func TestHandleHTTP_EmptyBodyBytesSentUnchanged(t *testing.T) {
	sent0 := atomic.LoadInt64(&statBytesSent)
	forwardedUpstreamRequest(t, "GET ORIGIN/p HTTP/1.1\r\nHost: origin\r\n\r\n")
	if delta := atomic.LoadInt64(&statBytesSent) - sent0; delta != 0 {
		t.Errorf("statBytesSent delta = %d, want 0 for a bodyless request", delta)
	}
}

// TestInspectInnerLeg_EmptyBodyKeepsClientFraming covers the SECOND site,
// through the real inspected tunnel rather than a stand-in: CONNECT, forged
// leaf, decrypted inner request, rq.Write onto the upstream TLS conn. That
// write runs the same newTransferWriter framing decision as the forward leg, so
// the stall-detector wrap had the same effect on it — and this is the traffic
// class that matters most on an inspecting gateway, where nearly every request
// is an inner one.
//
// The inner request is a Content-Length: 0 POST because that is the arm with an
// observable difference: before the guard the upstream saw it re-framed as
// chunked. A bodyless inner GET reaches the same wire either way (it was the
// probe goroutine that paid for it), so framing alone cannot pin that arm; the
// benchmarks are its evidence.
func TestInspectInnerLeg_EmptyBodyKeepsClientFraming(t *testing.T) {
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)

	type seen struct {
		te   []string
		clen int64
		hits int
	}
	var got seen
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		got.te = r.TransferEncoding
		got.clen = r.ContentLength
		got.hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("inner-ok"))
	}))
	defer upstream.Close()

	proxyURL := startTestProxy(t)
	inspectRule(true) // skip-verify: httptest's upstream leaf is self-signed

	tc, err := connectAndTLS(proxyURL.Host, upstream.Listener.Addr().String(), "inspect.test", proxyRoots)
	if err != nil {
		t.Fatalf("inspect handshake: %v", err)
	}
	defer tc.Close() //nolint:errcheck // test cleanup

	_, _ = fmt.Fprint(tc, "POST /p HTTP/1.1\r\nHost: inspect.test\r\n"+
		"Content-Length: 0\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read inspected response: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "inner-ok" {
		t.Fatalf("inspected POST: status=%d body=%q, want 200 inner-ok", resp.StatusCode, body)
	}
	if got.hits != 1 {
		t.Fatalf("upstream reached %d times, want 1", got.hits)
	}
	if len(got.te) != 0 {
		t.Errorf("upstream saw Transfer-Encoding %v for an inner Content-Length: 0 POST, want none — the inspected leg must forward the client's framing, not rewrite it", got.te)
	}
	if got.clen != 0 {
		t.Errorf("upstream saw ContentLength = %d, want 0", got.clen)
	}
}
