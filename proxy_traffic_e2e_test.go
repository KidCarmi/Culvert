package main

// Proxy traffic-plane E2E smoke tests (CI quality program — PR-1).
//
// Unlike the bulk of proxy_test.go (which unit-tests handleRequest with an
// httptest.NewRecorder), these tests push REAL traffic through a REAL proxy
// listener: an HTTP client / raw TCP socket on one side, an in-process upstream
// fixture on the other. They answer concrete production questions:
//
//   - Does a CONNECT tunnel actually relay bytes end-to-end? (byte-exact echo)
//   - Does a DENIED CONNECT never reach the upstream?
//   - Does default-deny hold on the real proxy path — including under 10
//     concurrent clients?
//   - Does an allow rule let traffic reach the upstream, and a block rule not?
//   - Is a client-spoofed X-User-Identity header stripped before forwarding?
//
// Everything is hermetic: no public internet, no example.com, no Docker. The
// only deliberate relaxation is removing the loopback CIDRs from privateCIDRs
// for the duration of a CONNECT test (restored on cleanup) so the real SSRF
// guard, dialer, and relay can run unchanged against a 127.0.0.1 fixture. The
// SSRF logic itself is untouched; TestUNAUTH_CONNECT_SSRFBlocksLoopback still
// proves the guard rejects loopback when it is NOT relaxed.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestProxyE2E_WebSocket_PipelinedClientBytes proves the WebSocket relay does
// not strand client bytes that arrive pipelined with the Upgrade request. The
// client writes the Upgrade request AND a payload in a SINGLE write, so the
// proxy's HTTP server buffers the payload into the hijacked reader; the fix
// relays that reader (not the raw conn) to the target, so the payload must
// arrive upstream. (Regression test for the discarded-hijack-buffer class of
// bug shared by handleTunnelBypass / handleWebSocket / handleTunnelInspect.)
func TestProxyE2E_WebSocket_PipelinedClientBytes(t *testing.T) {
	allowLoopbackTunnel(t) // handleWebSocket SSRF-guards the target host

	const payload = "PIPELINED-WS-FRAME-AFTER-HANDSHAKE"
	got := make(chan string, 1)

	// Fake WebSocket upstream: read the Upgrade request, reply 101, then read the
	// relayed client payload and report it.
	ln, err := ctxListen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		ubr := bufio.NewReader(c)
		for { // drain request headers
			line, err := ubr.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")) //nolint:errcheck // test I/O; error not actionable
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(ubr, buf); err != nil {
			got <- "ERR:" + err.Error()
			return
		}
		got <- string(buf)
	}()

	proxyURL := startTestProxy(t)
	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Upgrade request + payload in ONE write so the server buffers the payload.
	target := ln.Addr().String()
	req := "GET http://" + target + "/ws HTTP/1.1\r\nHost: " + target +
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if _, err := conn.Write([]byte(req + payload)); err != nil {
		t.Fatalf("write upgrade+payload: %v", err)
	}

	status, err := readConnectStatus(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if status != http.StatusSwitchingProtocols {
		t.Fatalf("proxy upgrade status = %d, want 101", status)
	}

	select {
	case g := <-got:
		if g != payload {
			t.Errorf("upstream received %q, want %q — pipelined client bytes were stranded in the hijack buffer", g, payload)
		}
	case <-time.After(4 * time.Second):
		t.Errorf("upstream never received the pipelined payload — bytes stranded in the discarded hijack buffer")
	}
}

// TestProxyE2E_HostHeaderSpoofCannotBypassPolicy proves policy is evaluated on
// the request-target authority (what the proxy actually dials), NOT the
// spoofable Host header. A client sends an absolute-form request to a BLOCKED
// host while setting the Host header to an ALLOWED host; the proxy must block
// it. If policy ever keyed on the Host header instead, this is a critical
// policy-evasion / host-confusion bypass.
func TestProxyE2E_HostHeaderSpoofCannotBypassPolicy(t *testing.T) {
	proxyURL := startTestProxy(t)
	policyStore.rules = nil
	// Block one host; allow everything else. The two outcomes are
	// distinguishable: keying on the URL host → 403 (block-evil); keying on the
	// Host header (allowed.example) → allow-rest → dial → 502. So 403 proves the
	// proxy used the request-target, not the header.
	policyStore.Add(PolicyRule{Priority: 1, Name: "block-evil", DestFQDN: "blocked.example", Action: ActionBlockPage})
	policyStore.Add(PolicyRule{Priority: 2, Name: "allow-rest", DestFQDN: "*", Action: ActionAllow})

	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Absolute-form target = blocked.example; spoofed Host header = allowed.example.
	if _, err := fmt.Fprint(conn, "GET http://blocked.example/ HTTP/1.1\r\nHost: allowed.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Host-header spoof: got %d, want 403 — policy must key on the request-target host (blocked.example), "+
			"not the Host header (allowed.example). A non-403 means a host-confusion policy bypass.", resp.StatusCode)
	}
}

// ─── fixtures ────────────────────────────────────────────────────────────────

// echoServer is an in-process TCP echo upstream on a random loopback port. It
// counts accepted connections so a test can assert whether the proxy ever
// reached the upstream (e.g. a denied CONNECT must not).
type echoServer struct {
	ln      net.Listener
	addr    string
	accepts int64
}

func startEchoServer(t *testing.T) *echoServer {
	t.Helper()
	ln, err := ctxListen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo fixture listen: %v", err)
	}
	es := &echoServer{ln: ln, addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return // listener closed on cleanup
			}
			atomic.AddInt64(&es.accepts, 1)
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn) //nolint:errcheck // echo until peer closes
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return es
}

func (es *echoServer) acceptCount() int64 { return atomic.LoadInt64(&es.accepts) }

// countingBackend is an HTTP upstream that records whether it was reached and
// what it received, so HTTP-path tests can assert "upstream reached / not
// reached" and identity-header scrubbing.
type countingBackend struct {
	hits         int64
	gotIdentity  int64 // incremented if a client-spoofed X-User-Identity leaked through
	lastMethod   atomic.Value
	lastBodySeen atomic.Value
}

func startCountingBackend(t *testing.T) (*httptest.Server, *countingBackend) {
	t.Helper()
	cb := &countingBackend{}
	cb.lastMethod.Store("")
	cb.lastBodySeen.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&cb.hits, 1)
		cb.lastMethod.Store(r.Method)
		if r.Header.Get("X-User-Identity") != "" {
			atomic.AddInt64(&cb.gotIdentity, 1)
		}
		body, _ := io.ReadAll(r.Body)
		cb.lastBodySeen.Store(string(body))
		// Echo the body back so the client can verify round-trip integrity.
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck // test I/O; error not actionable
	}))
	t.Cleanup(srv.Close)
	return srv, cb
}

func (cb *countingBackend) hitCount() int64 { return atomic.LoadInt64(&cb.hits) }

// ─── SSRF seam (loopback only, restored on cleanup) ──────────────────────────

// allowLoopbackTunnel temporarily removes the loopback ranges from privateCIDRs
// so the real CONNECT path can reach a 127.0.0.1 fixture. Production code is
// unchanged; only this package var is swapped, and it is restored on cleanup.
func allowLoopbackTunnel(t *testing.T) {
	t.Helper()
	orig := privateCIDRs
	lo4 := net.ParseIP("127.0.0.1")
	lo6 := net.ParseIP("::1")
	filtered := make([]*net.IPNet, 0, len(orig))
	for _, c := range orig {
		if c.Contains(lo4) || c.Contains(lo6) {
			continue // drop loopback ranges
		}
		filtered = append(filtered, c)
	}
	privateCIDRs = filtered
	resetSSRFDNSCache()
	t.Cleanup(func() {
		privateCIDRs = orig
		resetSSRFDNSCache()
	})
}

func resetSSRFDNSCache() {
	ssrfDNSCache = &dnsSSRFCache{entries: make(map[string]dnsSSRFEntry)}
}

// ─── CONNECT byte relay ──────────────────────────────────────────────────────

// TestProxyE2E_CONNECT_ByteRelay proves a CONNECT tunnel relays bytes exactly,
// in both directions, through the real proxy listener and relay loop.
func TestProxyE2E_CONNECT_ByteRelay(t *testing.T) {
	allowLoopbackTunnel(t)
	echo := startEchoServer(t)
	proxyURL := startTestProxy(t) // default-allow

	baseGoroutines := runtime.NumGoroutine()

	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", proxyURL.Host, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Establish the tunnel.
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.addr, echo.addr); err != nil {
		t.Fatalf("write CONNECT to echo %s: %v", echo.addr, err)
	}
	br := bufio.NewReader(conn)
	// Read the CONNECT response by hand (status line + headers up to the blank
	// line) and keep `br` for the tunnel bytes. Using http.ReadResponse here is
	// a trap: for a CONNECT request it binds resp.Body to the live tunnel, and
	// Body.Close() then disturbs the connection.
	status, err := readConnectStatus(br)
	if err != nil {
		t.Fatalf("read CONNECT response from proxy (target=%s): %v", echo.addr, err)
	}
	if status != http.StatusOK {
		t.Fatalf("CONNECT to allowed loopback target %s: got %d, want 200 (tunnel established)", echo.addr, status)
	}

	// Relay a unique payload and assert the echo is byte-exact.
	payload := []byte("culvert-tunnel-probe-0xA5A5-end-to-end-relay-check")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload into tunnel: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echoed payload back through tunnel: %v (read %q so far)", err, got)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("tunnel relay corrupted payload:\n got  %q\n want %q", got, payload)
	}

	if echo.acceptCount() != 1 {
		t.Errorf("echo upstream accept count = %d, want 1 (tunnel should reach upstream exactly once)", echo.acceptCount())
	}

	// Close the client side and assert relay goroutines drain (no tunnel leak).
	conn.Close()
	assertGoroutinesSettle(t, baseGoroutines)
}

// TestProxyE2E_CONNECT_DeniedDoesNotReachUpstream proves a policy-blocked
// CONNECT is refused at the proxy and the upstream is never dialed.
func TestProxyE2E_CONNECT_DeniedDoesNotReachUpstream(t *testing.T) {
	allowLoopbackTunnel(t) // loopback would otherwise be SSRF-blocked; we want the POLICY block to be the cause
	echo := startEchoServer(t)
	proxyURL := startTestProxy(t)

	// Block everything via policy.
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "block-all-connect", DestFQDN: "*", Action: ActionBlockPage})

	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.addr, echo.addr); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	status, err := readConnectStatus(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if status == http.StatusOK {
		t.Fatalf("blocked CONNECT to %s returned 200 — tunnel must NOT be established when policy denies", echo.addr)
	}
	if status != http.StatusForbidden {
		t.Errorf("blocked CONNECT: got %d, want 403", status)
	}

	// Give any (erroneous) dial a moment to land, then assert it never did.
	time.Sleep(100 * time.Millisecond)
	if n := echo.acceptCount(); n != 0 {
		t.Errorf("DENIED CONNECT reached upstream %d time(s) — upstream must be unreachable on a policy block", n)
	}
}

// ─── HTTP forward: POST round-trip + identity-header scrubbing ────────────────

// TestProxyE2E_HTTPForward_PostAndIdentityStrip proves the real proxy path
// forwards a POST body intact AND strips a client-spoofed X-User-Identity
// header before it reaches the upstream (authorization headers are set
// internally, never trusted from the client).
func TestProxyE2E_HTTPForward_PostAndIdentityStrip(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startTestProxy(t) // default-allow

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	body := []byte("payload-body-round-trip")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, backend.URL+"/submit", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("X-User-Identity", "attacker@evil.example") // spoof attempt
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy POST failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST through proxy: got %d, want 200", resp.StatusCode)
	}
	echoed, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(echoed, body) {
		t.Errorf("POST body round-trip mismatch:\n got  %q\n want %q", echoed, body)
	}
	if cb.hitCount() != 1 {
		t.Errorf("backend hit count = %d, want 1", cb.hitCount())
	}
	if got := cb.lastMethod.Load().(string); got != http.MethodPost {
		t.Errorf("backend saw method %q, want POST", got)
	}
	if atomic.LoadInt64(&cb.gotIdentity) != 0 {
		t.Errorf("client-spoofed X-User-Identity LEAKED to upstream — must be scrubbed on the proxy path")
	}
}

// ─── Policy through the real proxy path ───────────────────────────────────────

// TestProxyE2E_PolicyThroughProxy validates allow / block / default-deny end to
// end: the proxy response AND whether the upstream was actually reached.
func TestProxyE2E_PolicyThroughProxy(t *testing.T) {
	cases := []struct {
		name        string
		configure   func()
		wantStatus  int
		wantReached bool
	}{
		{
			name: "allow_rule_reaches_upstream",
			configure: func() {
				policyStore.rules = nil
				policyStore.Add(PolicyRule{Priority: 1, Name: "allow-all", DestFQDN: "*", Action: ActionAllow})
			},
			wantStatus:  http.StatusOK,
			wantReached: true,
		},
		{
			name: "block_rule_does_not_reach_upstream",
			configure: func() {
				policyStore.rules = nil
				policyStore.Add(PolicyRule{Priority: 1, Name: "block-all", DestFQDN: "*", Action: ActionBlockPage})
			},
			wantStatus:  http.StatusForbidden,
			wantReached: false,
		},
		{
			name:        "default_deny_does_not_reach_upstream",
			configure:   func() { policyStore.rules = nil; setDefaultPolicyAction("deny") },
			wantStatus:  http.StatusForbidden,
			wantReached: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend, cb := startCountingBackend(t)
			proxyURL := startTestProxy(t) // sets default-allow + clears rules; cleanup restores
			tc.configure()

			client := &http.Client{
				Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
				Timeout:   5 * time.Second,
			}
			resp, err := ctxGet(client, backend.URL+"/")
			if err != nil {
				t.Fatalf("proxy GET failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			reached := cb.hitCount() > 0
			if reached != tc.wantReached {
				t.Errorf("upstream reached = %v, want %v (backend hits=%d)", reached, tc.wantReached, cb.hitCount())
			}
		})
	}
}

// ─── Concurrency smoke: default-deny holds, then allow holds, under load ──────

// TestProxyE2E_Concurrency_DefaultDenyAndAllow drives 10 concurrent clients
// through the real proxy and proves the policy decision holds under
// concurrency: under default-deny every request is refused and the upstream is
// never reached; with an allow rule every request succeeds.
func TestProxyE2E_Concurrency_DefaultDenyAndAllow(t *testing.T) {
	const N = 10

	// Phase 1 — default deny under concurrency.
	backend, cb := startCountingBackend(t)
	proxyURL := startTestProxy(t)
	policyStore.rules = nil
	setDefaultPolicyAction("deny")

	statuses := runConcurrentGets(t, proxyURL, backend.URL, N)
	for i, s := range statuses {
		if s != http.StatusForbidden {
			t.Errorf("default-deny under concurrency: client %d got %d, want 403", i, s)
		}
	}
	if cb.hitCount() != 0 {
		t.Errorf("default-deny under concurrency: upstream reached %d time(s), want 0", cb.hitCount())
	}

	// Phase 2 — allow rule under concurrency (same proxy, fresh backend counter).
	backend2, cb2 := startCountingBackend(t)
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "allow-all", DestFQDN: "*", Action: ActionAllow})

	statuses = runConcurrentGets(t, proxyURL, backend2.URL, N)
	for i, s := range statuses {
		if s != http.StatusOK {
			t.Errorf("allow under concurrency: client %d got %d, want 200", i, s)
		}
	}
	if cb2.hitCount() != int64(N) {
		t.Errorf("allow under concurrency: upstream reached %d time(s), want %d", cb2.hitCount(), N)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// runConcurrentGets fires n GETs through the proxy in parallel and returns each
// status code (index-stable, no shared-slice races).
func runConcurrentGets(t *testing.T, proxyURL *url.URL, targetURL string, n int) []int {
	t.Helper()
	statuses := make([]int, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			client := &http.Client{
				Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
				Timeout:   5 * time.Second,
			}
			resp, err := ctxGet(client, targetURL+"/")
			if err != nil {
				t.Errorf("concurrent client %d: %v", idx, err)
				statuses[idx] = -1
				return
			}
			io.Copy(io.Discard, resp.Body) //nolint:errcheck // test I/O; error not actionable
			resp.Body.Close()
			statuses[idx] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	return statuses
}

// readConnectStatus reads the proxy's CONNECT reply (status line + headers up
// to the terminating blank line) from br and returns the HTTP status code,
// leaving br positioned at the first tunnel byte. It deliberately avoids
// http.ReadResponse, whose CONNECT body semantics would consume/close the
// tunnel.
func readConnectStatus(br *bufio.Reader) (int, error) {
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read status line: %w", err)
	}
	// "HTTP/1.1 200 Connection established\r\n"
	var proto string
	var code int
	if _, err := fmt.Sscanf(statusLine, "%s %d", &proto, &code); err != nil {
		return 0, fmt.Errorf("parse status line %q: %w", statusLine, err)
	}
	// Drain headers until the blank line.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return code, fmt.Errorf("read headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return code, nil
}

// assertGoroutinesSettle waits briefly for goroutine count to return near the
// baseline after a tunnel closes — best-effort leak detection (goroutine counts
// in a test binary are noisy, so the bound is generous).
func assertGoroutinesSettle(t *testing.T, baseline int) {
	t.Helper()
	const tolerance = 4
	deadline := time.Now().Add(2 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= baseline+tolerance {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("possible goroutine leak after tunnel close: have %d, baseline %d (tolerance %d)", n, baseline, tolerance)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}
