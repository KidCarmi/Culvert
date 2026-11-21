package main

// CHAOS-125 — the INSPECTED TUNNEL'S SETUP WINDOW, closing CHAOS-32 (found
// 2026-07-07, sized "S", never implemented, and since duplicated into the
// native-ALPN leg added after it).
//
// An inspected tunnel's life has three phases and only the middle one was
// unbounded. The bypass relay registers with the drain immediately after its own
// 200 and is reaped by tunnelIdleTimeout; runH1InspectLoop arms a 60 s read
// deadline per iteration "so a slow client cannot hold the connection open
// indefinitely by trickling bytes". Between them sat the setup window — origin
// TLS handshake, first-byte peek, the native leg's ClientHello peeks, forged-leaf
// handshake — holding BOTH legs with no deadline on either, because
// net/http's hijackLocked clears the listener's ReadTimeout from the socket
// (rwc.SetDeadline(time.Time{})) and r.Context() is cancelled when the handler
// RETURNS, not when a hijacked client goes quiet. registerDrainableTunnel, which
// owns the activeConns increment and the drain's force-close handles, is only
// reached after both handshakes, so nothing counted these connections and
// nothing could end the wait.
//
// Measured on this tree before the bound existed: 100 clients that completed
// CONNECT to an inspect-marked host, read the 200 and then sent nothing held
// every leg open for as long as the test was willing to wait (8 s, 10 s — the
// code path has no timer at any length), 2 FDs and 1 goroutine each in the
// gateway, with no per-IP cap in the default configuration
// (connlimit MaxConnsPerIP = 0 = off).
//
// The gates below pin: both legs are released within the window on each
// dispatch, the stall is RECORDED (the native leg's peek failure returned in
// complete silence — no log, no metric, no row), a stalled ORIGIN handshake no
// longer pins the client, no auto-exclusion is learned from a client-side stall
// (it would teach the gateway to stop inspecting the host), and — the regression
// that would hurt most — an ESTABLISHED tunnel outlives the window, because the
// armed deadline is a write deadline too.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// shortenInspectSetupWindow narrows the production setup window for one test and
// restores it on cleanup (the h2StreamStallTimeout pattern).
func shortenInspectSetupWindow(t *testing.T, d time.Duration) {
	t.Helper()
	prev := sslInspectSetupTimeout
	sslInspectSetupTimeout = d
	t.Cleanup(func() { sslInspectSetupTimeout = prev })
}

// silentInspectClientProbe admits one client to an inspected tunnel and then has
// it say NOTHING. It reports how long the gateway took to release the client leg
// and whether the origin leg was released too.
//
// native selects the dispatch: the strip leg handshakes the origin BEFORE the
// peek (so the origin fixture must speak TLS and the stall holds a COMPLETED
// origin TLS session), while the native leg peeks first (so a plain TCP origin
// is enough and the stall holds a dialled origin socket).
func silentInspectClientProbe(t *testing.T, native bool, window time.Duration) (clientHeld time.Duration, clientReleased, originReleased bool) {
	t.Helper()
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackTunnel(t)
	setupInspectCA(t) // certMgr.Ready() ⇒ the inspect path is taken
	shortenInspectSetupWindow(t, window)

	rawLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = rawLn.Close() })

	ln := inspectProbeOriginListener(t, rawLn, native)

	originGone := make(chan struct{})
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close() //nolint:errcheck // test cleanup
		_, _ = io.Copy(io.Discard, c)
		close(originGone) // the gateway let the origin leg go
	}()

	proxyURL := startTestProxy(t)
	if native {
		inspectRuleNative()
	} else {
		inspectRule(true) // skip-verify for the self-signed fixture
	}

	target := rawLn.Addr().String()
	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	if err := readCONNECT200(conn); err != nil {
		t.Fatalf("CONNECT: %v", err)
	}

	// Admitted, and now silent. Before CHAOS-125 this read never returned.
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, rerr := conn.Read(make([]byte, 1))
	clientHeld = time.Since(start)
	clientReleased = rerr != nil && !isNetTimeout(rerr)

	select {
	case <-originGone:
		originReleased = true
	case <-time.After(5 * time.Second):
	}
	return clientHeld, clientReleased, originReleased
}

// inspectProbeOriginListener returns the origin fixture each dispatch needs: a
// plain TCP listener for the native leg (which peeks the client BEFORE the
// origin handshake, so the stall holds a dialled socket) and a TLS listener for
// the strip leg (which handshakes the origin FIRST, so the stall holds a
// completed origin TLS session).
func inspectProbeOriginListener(t *testing.T, rawLn net.Listener, native bool) net.Listener {
	t.Helper()
	if native {
		return rawLn
	}
	certPEM, keyPEM, _ := generateSelfSignedECDSA(t)
	upCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("upstream keypair: %v", err)
	}
	return tls.NewListener(rawLn, &tls.Config{Certificates: []tls.Certificate{upCert}}) // #nosec G402 -- test upstream fixture
}

// isNetTimeout reports whether err is the LOCAL read deadline expiring (the
// probe giving up), as opposed to the gateway closing the leg.
func isNetTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// requireClientHelloTimeoutRow asserts the stall was recorded in the ADR-0011
// taxonomy cell it belongs in — (client_hello, timeout) — rather than leaving
// the only trace in a log line (strip leg) or none at all (native leg).
func requireClientHelloTimeoutRow(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if e, ok := findDecFailEntry(t, "127.0.0.1"); ok {
			if e.Dec == nil {
				t.Fatal("DECRYPT_FAILED row for the stalled client has no dec block: the drill-down would not resolve")
			}
			if e.Dec.FailStage != "client_hello" || e.Dec.FailCategory != "timeout" {
				t.Fatalf("stalled-client taxonomy = (%q, %q), want (client_hello, timeout)", e.Dec.FailStage, e.Dec.FailCategory)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the reaped setup window recorded NO DECRYPT_FAILED row: the stall is invisible to every Decryption Health surface")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestChaos125_SilentClientOnStripInspectLegIsReaped: the strip dispatch holds a
// COMPLETED origin TLS session across its first-byte peek, so a client that goes
// quiet after the 200 spends the origin's handshake and then holds both legs.
func TestChaos125_SilentClientOnStripInspectLegIsReaped(t *testing.T) {
	const window = 600 * time.Millisecond
	held, clientReleased, originReleased := silentInspectClientProbe(t, false, window)

	if !clientReleased {
		t.Fatalf("the gateway held a silent admitted client's leg for %v with no sign of releasing it: "+
			"the setup window (%v) did not bound the first-byte peek", held, window)
	}
	if held < window/2 {
		t.Errorf("the client leg was released after %v, less than half the %v window: "+
			"this test is no longer measuring the deadline it claims to", held, window)
	}
	if !originReleased {
		t.Error("the ORIGIN leg survived the reaped setup window: a stalled client still pins an origin TLS session")
	}
	requireClientHelloTimeoutRow(t)
	if n := autoExclude().Len(); n != 0 {
		t.Errorf("SECURITY: a client-side stall learned %d auto-exclusion(s): anything able to open a CONNECT "+
			"and go quiet could teach the gateway to stop inspecting the host", n)
	}
}

// TestChaos125_SilentClientOnNativeInspectLegIsReaped: the native dispatch peeks
// BEFORE the origin handshake, so its stall window is the longer of the two
// (first-byte peek + peekClientALPN's record peeks + the forged-leaf handshake)
// and it holds a dialled origin socket throughout. A plain TCP origin is enough
// here, which is exactly the extra reachability this leg added.
func TestChaos125_SilentClientOnNativeInspectLegIsReaped(t *testing.T) {
	const window = 600 * time.Millisecond
	held, clientReleased, originReleased := silentInspectClientProbe(t, true, window)

	if !clientReleased {
		t.Fatalf("the gateway held a silent admitted client's leg for %v with no sign of releasing it: "+
			"the setup window (%v) did not bound the native leg's peeks", held, window)
	}
	if held < window/2 {
		t.Errorf("the client leg was released after %v, less than half the %v window", held, window)
	}
	if !originReleased {
		t.Error("the ORIGIN leg survived the reaped setup window: a stalled client still pins a dialled origin socket")
	}
	requireClientHelloTimeoutRow(t)
	if n := autoExclude().Len(); n != 0 {
		t.Errorf("SECURITY: a client-side stall learned %d auto-exclusion(s) on the native leg", n)
	}
}

// TestChaos125_StalledOriginHandshakeDoesNotPinTheClientLeg covers the other end
// of the same window with the other actor: an origin that completes the TCP
// handshake and then never speaks TLS. The strip leg's
// upstreamTLS.HandshakeContext(r.Context()) is bounded by nothing of its own —
// the dialer's 10 s Timeout covers the dial only, and nothing cancels that
// context here — so before this bound the handler and the client's own
// connection were pinned for as long as the origin cared to hold them. The
// client is NOT yet hijacked at that point, so the observable is the 502.
func TestChaos125_StalledOriginHandshakeDoesNotPinTheClientLeg(t *testing.T) {
	const window = 700 * time.Millisecond
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackTunnel(t)
	setupInspectCA(t)
	shortenInspectSetupWindow(t, window)

	// An origin that accepts and then says nothing, forever.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()

	proxyURL := startTestProxy(t)
	inspectRule(true)

	target := ln.Addr().String()
	conn, err := dialTimeout(proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	start := time.Now()
	reply := make([]byte, 0, 64)
	one := make([]byte, 1)
	for len(reply) < 12 {
		if _, rerr := io.ReadFull(conn, one); rerr != nil {
			t.Fatalf("a blackholing origin's TLS handshake pinned the inspect handler and the client leg "+
				"for %v: the setup window (%v) did not bound it (read: %v)", time.Since(start), window, rerr)
		}
		reply = append(reply, one[0])
	}
	if string(reply[:12]) != "HTTP/1.1 502" {
		t.Fatalf("CONNECT reply = %q, want the 502 a failed origin handshake owes the client", reply[:12])
	}
	if held := time.Since(start); held > 10*time.Second {
		t.Errorf("the 502 took %v to arrive, far beyond the %v window", held, window)
	}
}

// TestChaos125_EstablishedInspectedTunnelOutlivesTheSetupWindow is the
// regression gate that matters most. The window arms an absolute SetDeadline,
// which is a WRITE deadline as well as a read one: left armed, it would abort a
// perfectly healthy inspected tunnel's response delivery one window after setup
// — turning a stall bound into an outage. Both dispatches must clear BOTH legs
// the moment the tunnel is established, so this tunnel serves a request after
// idling well past its own window, and a second one after idling again (the
// keep-alive leg the per-iteration deadline owns from there).
func TestChaos125_EstablishedInspectedTunnelOutlivesTheSetupWindow(t *testing.T) {
	const window = 500 * time.Millisecond
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)
	shortenInspectSetupWindow(t, window)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("still-here"))
	}))
	defer upstream.Close()
	target := upstream.Listener.Addr().String()

	proxyURL := startTestProxy(t)
	inspectRule(true)

	tc, err := connectAndTLS(proxyURL.Host, target, "inspect.test", proxyRoots)
	if err != nil {
		t.Fatalf("inspect handshake: %v", err)
	}
	defer tc.Close() //nolint:errcheck // test cleanup
	_ = tc.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(tc)
	for i, label := range []string{"after one idle window", "after a second idle window"} {
		time.Sleep(3 * window) // idle well past the setup budget
		closeHdr := ""
		if i == 1 {
			closeHdr = "Connection: close\r\n"
		}
		if _, werr := fmt.Fprintf(tc, "GET /%d HTTP/1.1\r\nHost: inspect.test\r\n%s\r\n", i, closeHdr); werr != nil {
			t.Fatalf("%s: writing through an established inspected tunnel failed (%v): "+
				"a setup-window deadline was left armed on the client leg", label, werr)
		}
		resp, rerr := http.ReadResponse(br, nil)
		if rerr != nil {
			t.Fatalf("%s: reading through an established inspected tunnel failed (%v): "+
				"a setup-window deadline was left armed", label, rerr)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close() //nolint:errcheck // test cleanup
		if resp.StatusCode != http.StatusOK || string(body) != "still-here" {
			t.Fatalf("%s: status=%d body=%q, want 200 still-here", label, resp.StatusCode, body)
		}
	}
}
