package main

// Review-shift proof (TLS interception): on the default (strip-ALPN) inspect
// path the proxy completes its OWN verified TLS handshake with the origin
// BEFORE it looks at what the client sends. If the client's first byte is not a
// TLS handshake record, handleTunnelInspect "falls back to raw relay" — and the
// relay's upstream leg is that already-established TLS session. A client that
// simply does not start TLS therefore gets its plaintext bytes wrapped in TLS
// and delivered to the HTTPS origin, and the answer relayed back, with no inner
// request ever parsed: no inner-host pin, no file-block, no DPI, no scan, no
// per-request log row.
//
// The fallback cannot serve the non-TLS protocols its comment names (SSH, RDP):
// an origin that does not speak TLS fails the upstream handshake and the tunnel
// is 502'd before the peek. On this path it is reachable only when the origin
// DOES speak TLS and the client does not.

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestInspect_PlaintextClientCannotReachOriginUninspected sends the SAME inner
// request — one naming a host the tunnel was never authorized for — down the
// SAME inspected tunnel twice. Over TLS (the control) the inner-host pin
// refuses it and the origin is never contacted. As plaintext it must be refused
// too; today the origin receives it and the client gets the origin's answer.
func TestInspect_PlaintextClientCannotReachOriginUninspected(t *testing.T) {
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)
	resetInnerHostMismatchStateForTest()
	t.Cleanup(resetInnerHostMismatchStateForTest)

	var (
		mu    sync.Mutex
		hosts []string
	)
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		mu.Unlock()
		_, _ = w.Write([]byte("origin-answered-uninspected"))
	}))
	defer origin.Close()
	_, port, err := net.SplitHostPort(origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("origin addr: %v", err)
	}
	// A NAMED CONNECT target, so the inner-host pin applies (it deliberately
	// does not fire for an IP-literal tunnel — see inspect_host_pin.go).
	target := net.JoinHostPort("localhost", port)

	proxyURL := startTestProxy(t)
	inspectRule(true) // skip-verify: the httptest origin is self-signed

	const innerReq = "GET /exfil HTTP/1.1\r\nHost: not-authorized.example\r\nConnection: close\r\n\r\n"
	seen := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), hosts...)
	}

	// ── Control: the request arrives inside TLS and is inspected ─────────────
	tc, err := connectAndTLS(proxyURL.Host, target, "localhost", proxyRoots)
	if err != nil {
		t.Fatalf("control: inspected tunnel: %v", err)
	}
	if _, err := tc.Write([]byte(innerReq)); err != nil {
		t.Fatalf("control: write inner request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("control: read inner response: %v", err)
	}
	_ = resp.Body.Close()
	_ = tc.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("control: status = %d, want 403 (inner-host pin)", resp.StatusCode)
	}
	if got := seen(); len(got) != 0 {
		t.Fatalf("control: origin was contacted (%q) — the harness is not exercising inspection", got)
	}

	// ── Proof: the identical request, sent as plaintext on the same rule ─────
	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if err := readCONNECT200(conn); err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	if _, err := conn.Write([]byte(innerReq)); err != nil {
		t.Fatalf("write plaintext inner request: %v", err)
	}
	// Whatever the proxy does with a non-TLS client, the client must not get an
	// answer from the origin. A closed/reset connection is the secure outcome,
	// so a read error here is not a failure.
	if presp, rerr := http.ReadResponse(bufio.NewReader(conn), nil); rerr == nil {
		_ = presp.Body.Close()
		if presp.StatusCode == http.StatusOK {
			t.Errorf("plaintext client received %d from the origin through an INSPECT rule", presp.StatusCode)
		}
	}
	if got := seen(); len(got) != 0 {
		t.Errorf("origin received %d uninspected request(s) with Host %q on a tunnel authorized for %q: "+
			"the proxy wrapped a plaintext client's bytes in its own upstream TLS session", len(got), got, target)
	}
	if got := proxyInnerHostMismatchBlocked.Load(); got != 1 {
		t.Errorf("inner-host mismatch counter = %d, want 1 (the control only) — sanity", got)
	}
}
