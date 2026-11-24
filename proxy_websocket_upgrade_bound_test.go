package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// wsSilentOrigin is an origin that accepts one connection, reads the forwarded
// request head, optionally writes reply, and then says nothing more. closed is
// closed when the PROXY closes its end of that connection — the observable
// proof that the handler released the origin leg.
type wsSilentOrigin struct {
	addr   string
	gotReq chan struct{}
	closed chan struct{}
}

func startWSSilentOrigin(t *testing.T, reply string) *wsSilentOrigin {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	o := &wsSilentOrigin{addr: ln.Addr().String(), gotReq: make(chan struct{}), closed: make(chan struct{})}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close() //nolint:errcheck // test cleanup
		br := bufio.NewReader(conn)
		for {
			line, rerr := br.ReadString('\n')
			if rerr != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		close(o.gotReq)
		if reply != "" {
			_, _ = io.WriteString(conn, reply)
		}
		// Never answer (further). Unblocks only when the peer closes.
		_, _ = io.Copy(io.Discard, br)
		close(o.closed)
	}()
	return o
}

func shortenWSUpgradeTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := wsUpgradeTimeout
	wsUpgradeTimeout = d
	t.Cleanup(func() { wsUpgradeTimeout = orig })
}

func wsUpgradeRequest(ctx context.Context, target string) *http.Request {
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://"+target+"/ws", http.NoBody)
	r.Host = target
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	return r
}

// An origin that accepts the connection and never answers the upgrade must not
// hold the handler past wsUpgradeTimeout. Before the bound existed this read
// had no deadline: the handler, the origin descriptor and the client's
// connection-limiter slot stayed pinned for as long as the origin kept TCP up.
func TestHandleWebSocket_SilentOriginIsBounded(t *testing.T) {
	allowLoopbackTunnel(t)
	setupProxyTest(t)
	shortenWSUpgradeTimeout(t, 200*time.Millisecond)
	origin := startWSSilentOrigin(t, "")

	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handleWebSocket(w, wsUpgradeRequest(context.Background(), origin.addr), nil, ProxyIdentity{ClientIP: "192.0.2.99"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleWebSocket still blocked on a silent origin long after wsUpgradeTimeout: the upgrade exchange is unbounded")
	}
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 for an origin that never answered the upgrade", w.Code)
	}
	select {
	case <-origin.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("origin leg still open after the handler returned")
	}
}

// A client that hangs up while the origin is silent must release the handler at
// once — not at the deadline. The timeout is left at its production value so
// only the context tie can end the wait inside the test's window.
func TestHandleWebSocket_ClientHangUpReleasesSilentOrigin(t *testing.T) {
	allowLoopbackTunnel(t)
	setupProxyTest(t)
	origin := startWSSilentOrigin(t, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handleWebSocket(w, wsUpgradeRequest(ctx, origin.addr), nil, ProxyIdentity{ClientIP: "192.0.2.99"})
		close(done)
	}()
	select {
	case <-origin.gotReq: // the handler is now parked in the response read
	case <-time.After(5 * time.Second):
		t.Fatal("origin never received the forwarded upgrade request")
	}
	cancel() // what net/http does to r.Context() when the client disconnects
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleWebSocket still blocked on the silent origin after the client hung up")
	}
	select {
	case <-origin.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("origin leg still open after the client hung up")
	}
}

// The same, through the real listener: the client sends the upgrade and closes
// its socket. net/http cancels r.Context() on that close, which is the only
// signal the handler has — so this pins that the production wiring delivers it.
func TestProxyE2E_WebSocket_ClientHangUpReleasesSilentOrigin(t *testing.T) {
	allowLoopbackTunnel(t)
	origin := startWSSilentOrigin(t, "")
	proxyURL := startTestProxy(t)

	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup; closed explicitly below
	if _, err := io.WriteString(conn, "GET http://"+origin.addr+"/ws HTTP/1.1\r\nHost: "+origin.addr+
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	select {
	case <-origin.gotReq:
	case <-time.After(5 * time.Second):
		t.Fatal("origin never received the forwarded upgrade request")
	}
	conn.Close() //nolint:errcheck // the hang-up under test
	select {
	case <-origin.closed:
	case <-time.After(10 * time.Second):
		t.Fatal("proxy still holds the origin leg after the client hung up (wsUpgradeTimeout is 30s, so only the context tie can release it here)")
	}
}

// A declined upgrade is an ordinary plain-HTTP response, and its body is read
// from the same origin leg: an origin that sends the head and then stalls the
// body must be bounded too (handleHTTP bounds the same read for a request
// without the Upgrade header).
func TestHandleWebSocket_DeclinedUpgradeStalledBodyIsBounded(t *testing.T) {
	allowLoopbackTunnel(t)
	setupProxyTest(t)
	shortenWSUpgradeTimeout(t, 200*time.Millisecond)
	origin := startWSSilentOrigin(t, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1000000\r\n\r\npartial")

	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handleWebSocket(w, wsUpgradeRequest(context.Background(), origin.addr), nil, ProxyIdentity{ClientIP: "192.0.2.99"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleWebSocket still blocked on a stalled declined-upgrade body long after wsUpgradeTimeout")
	}
	select {
	case <-origin.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("origin leg still open after the handler returned")
	}
}

// The bound covers the upgrade exchange ONLY. Once the origin answers 101 the
// tunnel must outlive wsUpgradeTimeout, and must survive the server cancelling
// r.Context() when the hijacking handler's request ends — a bound left armed in
// either form would sever every live WebSocket session.
func TestProxyE2E_WebSocket_TunnelOutlivesUpgradeBound(t *testing.T) {
	allowLoopbackTunnel(t)
	const bound = 250 * time.Millisecond
	shortenWSUpgradeTimeout(t, bound)

	ln, err := ctxListen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("ws upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close() //nolint:errcheck // test cleanup
		ubr := bufio.NewReader(c)
		for {
			line, rerr := ubr.ReadString('\n')
			if rerr != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_, _ = io.Copy(c, ubr) // echo
	}()

	proxyURL := startTestProxy(t)
	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	target := ln.Addr().String()
	if _, err := io.WriteString(conn, "GET http://"+target+"/ws HTTP/1.1\r\nHost: "+target+
		"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}
	br := bufio.NewReader(conn)
	status, err := readConnectStatus(br)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if status != http.StatusSwitchingProtocols {
		t.Fatalf("proxy upgrade status = %d, want 101", status)
	}

	time.Sleep(3 * bound) // idle well past the upgrade bound

	const payload = "FRAME-AFTER-THE-UPGRADE-BOUND"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write after the bound elapsed: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("echo after the bound elapsed: %v — the upgrade bound was left armed on an established tunnel", err)
	}
	if string(got) != payload {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
}
