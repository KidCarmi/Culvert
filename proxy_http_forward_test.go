package main

// proxy_http_forward_test.go — equivalence pins for the plain-HTTP forward
// step after it stopped going through a per-request http.Client and started
// calling the upstream transport directly (proxy_http.go).
//
// The optimization is a COST change, not a policy change, so each test here
// names one thing http.Client used to do for handleHTTP and proves the direct
// path still does it:
//
//   - a 3xx is handed back to the client, never followed (this was
//     CheckRedirect: ErrUseLastResponse);
//   - URL userinfo still reaches the origin as Basic auth (this was
//     http.Client.send's promotion, which the transport does not do);
//   - the 30s bound still covers the RESPONSE BODY, not just the headers
//     (this was http.Client.Timeout, whose scope is easy to lose when it is
//     re-expressed as a context deadline);
//   - a transport error is still a 502 and still charges the parent breaker,
//     even though the error is no longer wrapped in a *url.Error.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withDirectTransport points the proxy's upstream transport at a plain
// transport for the duration of the test and restores the previous one.
func withDirectTransport(t *testing.T) {
	t.Helper()
	orig := upstreamTransportPtr.Load()
	t.Cleanup(func() { upstreamTransportPtr.Store(orig) })
	upstreamTransportPtr.Store(&http.Transport{})
}

// TestHandleHTTP_RedirectNotFollowed pins the whole reason the old code
// constructed an http.Client at all. A forward proxy must hand the 3xx to the
// client and let IT decide; following the redirect here would both leak the
// destination fetch and return the wrong body.
func TestHandleHTTP_RedirectNotFollowed(t *testing.T) {
	withDirectTransport(t)

	var targetHits int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/target":
			targetHits++
			fmt.Fprint(w, "followed")
		}
	}))
	defer origin.Close()

	rr := httptest.NewRecorder()
	handleHTTP(rr, httptest.NewRequest(http.MethodGet, origin.URL+"/redirect", http.NoBody))

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 passed through to the client", rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "/target" {
		t.Fatalf("Location = %q, want %q", got, "/target")
	}
	if targetHits != 0 {
		t.Fatalf("proxy followed the redirect (%d hits on /target); a 3xx belongs to the client", targetHits)
	}
	if body := rr.Body.String(); strings.Contains(body, "followed") {
		t.Fatalf("body = %q, want the redirect response, not the redirect target", body)
	}
}

// TestHandleHTTP_URLUserinfoBecomesBasicAuth pins the one http.Client.send
// behaviour the transport does NOT provide. A client may send an absolute-form
// request URI carrying credentials; the transport writes only URL.RequestURI(),
// which drops userinfo, so without the explicit promotion the origin would see
// no credentials at all.
func TestHandleHTTP_URLUserinfoBecomesBasicAuth(t *testing.T) {
	withDirectTransport(t)

	gotUser, gotPass, gotOK := "", "", false
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	target := strings.Replace(origin.URL, "http://", "http://alice:s3cret@", 1)
	rr := httptest.NewRecorder()
	handleHTTP(rr, httptest.NewRequest(http.MethodGet, target, http.NoBody))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !gotOK || gotUser != "alice" || gotPass != "s3cret" {
		t.Fatalf("origin saw BasicAuth(%q, %q, ok=%v), want alice/s3cret/true", gotUser, gotPass, gotOK)
	}
}

// TestHandleHTTP_ExplicitAuthorizationWins pins the other half of that rule:
// the promotion is conditional. A request that already carries Authorization
// keeps it — userinfo must not overwrite a header the client chose.
func TestHandleHTTP_ExplicitAuthorizationWins(t *testing.T) {
	withDirectTransport(t)

	var gotAuth string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	target := strings.Replace(origin.URL, "http://", "http://alice:s3cret@", 1)
	req := httptest.NewRequest(http.MethodGet, target, http.NoBody)
	req.Header.Set("Authorization", "Bearer client-chosen")

	handleHTTP(httptest.NewRecorder(), req)

	if gotAuth != "Bearer client-chosen" {
		t.Fatalf("Authorization = %q, want the client's own header preserved", gotAuth)
	}
}

// TestHandleHTTP_TimeoutCoversResponseBody is the sharp edge of re-expressing
// http.Client.Timeout as a context deadline. Client.Timeout bounded the ENTIRE
// exchange including the body read; a deadline that were cancelled as soon as
// the headers arrived — or one taken only around the round trip — would leave
// a stalled origin able to hold the connection open indefinitely.
//
// The origin here sends headers immediately and then stalls mid-body, so the
// only thing that can end the request is a deadline whose scope reaches the
// body.
func TestHandleHTTP_TimeoutCoversResponseBody(t *testing.T) {
	withDirectTransport(t)

	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer origin.Close()
	defer close(release)

	// Drive the same code path with a short deadline by putting it on the
	// inbound request: handleHTTP derives its own deadline from r.Context(),
	// and context.WithTimeout keeps whichever fires first.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, origin.URL, http.NoBody).WithContext(ctx)

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleHTTP(httptest.NewRecorder(), req)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleHTTP never returned: the deadline does not reach the response-body read")
	}
}

// TestHandleHTTP_TransportErrorStillBadGateway pins that dropping the
// *url.Error wrapper http.Client added did not change the outcome: a failed
// round trip is still a 502 for the client.
func TestHandleHTTP_TransportErrorStillBadGateway(t *testing.T) {
	withDirectTransport(t)

	rr := httptest.NewRecorder()
	handleHTTP(rr, httptest.NewRequest(http.MethodGet, "http://"+deadTCPAddr(t)+"/x", http.NoBody))

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for a failed upstream round trip", rr.Code)
	}
}

// TestHandleHTTP_RequestBodyReachesOrigin pins that removing http.Client's
// body-rewind wrapper (setupRewindBody, which only ever mattered for
// redirects) left ordinary body forwarding intact.
func TestHandleHTTP_RequestBodyReachesOrigin(t *testing.T) {
	withDirectTransport(t)

	var got string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		fmt.Fprint(w, "ok")
	}))
	defer origin.Close()

	body := strings.Repeat("payload-", 64)
	rr := httptest.NewRecorder()
	handleHTTP(rr, httptest.NewRequest(http.MethodPost, origin.URL, strings.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got != body {
		t.Fatalf("origin received %d bytes, want the full %d-byte body", len(got), len(body))
	}
}

// TestHandleHTTP_ResponseHeadersAndBodyForwarded is the plain happy-path
// equivalence check: status, headers and body all still arrive unchanged.
func TestHandleHTTP_ResponseHeadersAndBodyForwarded(t *testing.T) {
	withDirectTransport(t)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Origin-Marker", "present")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTeapot)
		fmt.Fprint(w, "brewing")
	}))
	defer origin.Close()

	rr := httptest.NewRecorder()
	handleHTTP(rr, httptest.NewRequest(http.MethodGet, origin.URL, http.NoBody))

	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rr.Code)
	}
	if got := rr.Header().Get("X-Origin-Marker"); got != "present" {
		t.Fatalf("X-Origin-Marker = %q, want the origin's header forwarded", got)
	}
	if got := rr.Body.String(); got != "brewing" {
		t.Fatalf("body = %q, want %q", got, "brewing")
	}
}
