package upstreamclient

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// pinnedTestServer starts a TLS server, returns a client resolving to it, its
// target, and a counter of accepted TCP connections.
func pinnedTestServer(t *testing.T, h http.HandlerFunc) (*Client, Target, *atomic.Int64, func()) {
	t.Helper()
	restore := ssrf.AllowLoopbackForTest()

	var conns atomic.Int64 // LIVE connections: +1 on accept, -1 on close
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			conns.Add(1)
		case http.StateClosed, http.StateHijacked:
			conns.Add(-1)
		}
	}
	srv.StartTLS()

	cert := srv.TLS.Certificates[0]
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		cert.Leaf = leaf
	}
	pin := spkiPin(&cert)

	ipStr, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	addr, _ := netip.ParseAddr(ipStr)
	c := newTestClient(t, fixedResolver{addrs: []netip.Addr{addr}})
	tgt := Target{ServerID: "s1", Endpoint: "https://" + ipStr + ":" + portStr, PinnedIdentity: pin}
	return c, tgt, &conns, func() { srv.Close(); restore() }
}

// SEC-MCP-10. roundTrip builds a fresh http.Transport per attempt. A Go
// Transport's idle connections are owned by the Transport, and it sets no
// IdleConnTimeout, so once the Transport goes out of scope its idle connections
// (and their read/write loop goroutines) are never reclaimed: every upstream call
// permanently leaked one socket and two goroutines. On a gateway making one
// upstream call per agent tool invocation that is an unbounded file-descriptor
// leak — and it silently made MaxConnsPerServer meaningless, since no two calls
// ever shared a pool.
//
// The transport's idle connections must be released when the call completes.
func TestTransport_IdleConnectionsAreReleasedPerCall(t *testing.T) {
	c, tgt, conns, done := pinnedTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"u-s1","result":{}}`)
	})
	defer done()

	const calls = 6
	for i := 0; i < calls; i++ {
		if _, err := c.Call(context.Background(), tgt, "tools/list", nil, CallOptions{Idempotent: true}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	// Each call must have released its connection. With the leak, the server sees a
	// fresh connection per call AND every previous one is still open; releasing them
	// makes the live count collapse to zero.
	//
	// ConnState is delivered asynchronously, so allow a bounded settle.
	live := int64(-1)
	for i := 0; i < 200; i++ {
		if live = conns.Load(); live == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if live != 0 {
		t.Fatalf("%d upstream connection(s) still open after %d completed calls", live, calls)
	}
}

// SEC-MCP-13. A redirect must never leave the APPROVED SERVER's identity. The
// hop-count bound alone does not express that: with MaxRedirects raised above
// zero, a compromised or misconfigured upstream could redirect the gateway's
// broker-materialized request to any host of its choosing. The dial is pinned, so
// the escape is bounded — but "bounded by a defense two layers down" is not the
// same as "refused", and the redirect target is attacker-chosen data reaching a
// credentialed request.
func TestTransport_RedirectOffTheApprovedHostIsRefused(t *testing.T) {
	c, tgt, _, done := pinnedTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/mcp", http.StatusTemporaryRedirect)
	})
	defer done()

	// Raise the hop budget so the count bound is NOT what refuses this.
	lim, err := NewLimits(LimitConfig{MaxRedirects: 3})
	if err != nil {
		t.Fatal(err)
	}
	c.cfg.Limits = lim

	_, err = c.Call(context.Background(), tgt, "tools/list", nil, CallOptions{})
	if err == nil {
		t.Fatal("a redirect to a different host must be refused")
	}
	// It must be refused for LEAVING THE APPROVED SERVER, not incidentally by the
	// hop budget or a downstream TLS failure.
	if r := mcperr.ReasonOf(err); r != mcperr.ReasonUpstreamTLSIdentity {
		t.Fatalf("reason = %v, want upstream_tls_identity (redirect left the approved server)", r)
	}
}

// A redirect that stays on the approved server (a different path on the same
// host) is still permitted within the hop budget: the containment is about
// IDENTITY, not about forbidding redirects that the operator opted into.
func TestTransport_SameHostRedirectIsStillAllowed(t *testing.T) {
	var hits atomic.Int64
	c, tgt, _, done := pinnedTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			http.Redirect(w, r, "/mcp/v2", http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"u-s1","result":{}}`)
	})
	defer done()

	lim, err := NewLimits(LimitConfig{MaxRedirects: 3})
	if err != nil {
		t.Fatal(err)
	}
	c.cfg.Limits = lim

	if _, err := c.Call(context.Background(), tgt, "tools/list", nil, CallOptions{}); err != nil {
		t.Fatalf("a same-host redirect within budget must be followed: %v", err)
	}
	if hits.Load() < 2 {
		t.Fatalf("redirect was not followed (hits=%d)", hits.Load())
	}
}

// OVN-04. The approved server's identity is host AND port. Canonical.Host is the
// bare hostname (the port is a separate field), so a host-only comparison admitted
// a redirect to a different port on the same name — and because the dialer is
// pinned to the original port, that request would silently reach a DIFFERENT
// endpoint than the one it named.
func TestTransport_RedirectToAnotherPortOnTheSameHostIsRefused(t *testing.T) {
	// The redirect target is derived from the SERVER's own address, published after
	// startup, never from the request's Host header. Two reasons: a fixture that
	// reflects a client-supplied header back into a Location is a textbook open
	// redirect (gosec G710) even when the "client" is this test, and the fixture is
	// more honest this way — the scenario under test is an upstream choosing a
	// different port on its own name, which does not depend on what the caller sent.
	var redirectTo atomic.Pointer[string]
	c, tgt, _, done := pinnedTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		loc := redirectTo.Load()
		if loc == nil {
			t.Error("upstream was called before the redirect target was published")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, *loc, http.StatusTemporaryRedirect)
	})
	defer done()

	// Same host, DIFFERENT port — the exact shape a host-only check admitted.
	otherPort := "https://" + net.JoinHostPort(mustURL(t, tgt.Endpoint).Hostname(), "9443") + "/mcp"
	redirectTo.Store(&otherPort)

	lim, err := NewLimits(LimitConfig{MaxRedirects: 3})
	if err != nil {
		t.Fatal(err)
	}
	c.cfg.Limits = lim

	_, err = c.Call(context.Background(), tgt, "tools/list", nil, CallOptions{})
	if err == nil {
		t.Fatal("a redirect to a different port must be refused")
	}
	if r := mcperr.ReasonOf(err); r != mcperr.ReasonUpstreamTLSIdentity {
		t.Fatalf("reason = %v, want upstream_tls_identity", r)
	}
}

// The port comparison must be like-for-like: an https redirect that omits the port
// means 443, and must not be refused merely for being written without one.
func TestTransport_RedirectPortDefaultsAreNormalized(t *testing.T) {
	if got := redirectPort(mustURL(t, "https://h/x")); got != "443" {
		t.Fatalf("implicit https port = %q, want 443", got)
	}
	if got := redirectPort(mustURL(t, "http://h/x")); got != "80" {
		t.Fatalf("implicit http port = %q, want 80", got)
	}
	if got := redirectPort(mustURL(t, "https://h:8443/x")); got != "8443" {
		t.Fatalf("explicit port = %q, want 8443", got)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
