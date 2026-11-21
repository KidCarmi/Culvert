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
	"bytes"
	"context"
	"crypto/tls"
	"errors"
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
//
// preamble, when non-empty, is written right after the 200 and BEFORE the
// silence: it lets a test stall the client part-way into its ClientHello rather
// than before its first byte.
func silentInspectClientProbe(t *testing.T, native bool, window time.Duration, preamble []byte) (clientHeld time.Duration, clientReleased, originReleased bool) {
	clientHeld, clientReleased, originReleased, _ = silentInspectClientProbeRx(t, native, window, preamble)
	return clientHeld, clientReleased, originReleased
}

// silentInspectClientProbeRx is silentInspectClientProbe that also reports how
// many bytes the origin fixture received before the gateway released it. On the
// native leg the origin is plain TCP, so any byte at all is the gateway starting
// an origin TLS handshake.
func silentInspectClientProbeRx(t *testing.T, native bool, window time.Duration, preamble []byte) (clientHeld time.Duration, clientReleased, originReleased bool, originRx int64) {
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

	originGone := make(chan int64, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer c.Close() //nolint:errcheck // test cleanup
		n, _ := io.Copy(io.Discard, c)
		originGone <- n // the gateway let the origin leg go
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
	if len(preamble) > 0 {
		if _, err := conn.Write(preamble); err != nil {
			t.Fatalf("write preamble: %v", err)
		}
	}

	// Admitted, and now silent. Before CHAOS-125 this read never returned.
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, rerr := conn.Read(make([]byte, 1))
	clientHeld = time.Since(start)
	clientReleased = rerr != nil && !isNetTimeout(rerr)

	select {
	case originRx = <-originGone:
		originReleased = true
	case <-time.After(5 * time.Second):
	}
	return clientHeld, clientReleased, originReleased, originRx
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
	held, clientReleased, originReleased := silentInspectClientProbe(t, false, window, nil)

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
	held, clientReleased, originReleased := silentInspectClientProbe(t, true, window, nil)

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

// TestChaos125_PartialClientHelloOnNativeLegIsAClientStall: the native leg's
// stall window does not end at the first byte. A client that sends the 0x16
// that opens a TLS handshake record and then goes quiet passes the first-byte
// peek, and the setup deadline then expires INSIDE peekClientALPN's record
// peeks. That read failure is the same client-side stall as a silent client and
// must be recorded as one, (client_hello, timeout), not swallowed as an
// ordinary "no ALPN offer" downgrade: that downgrade went on to start an origin
// TLS handshake for a dead client and recorded the stall as
// (upstream_handshake, ...), charging a client's silence to a healthy origin in
// Decryption Health.
func TestChaos125_PartialClientHelloOnNativeLegIsAClientStall(t *testing.T) {
	const window = 600 * time.Millisecond
	held, clientReleased, originReleased, originRx := silentInspectClientProbeRx(t, true, window, []byte{0x16})

	if !clientReleased {
		t.Fatalf("the gateway held a client stalled mid-ClientHello for %v with no sign of releasing it", held)
	}
	if held < window/2 {
		t.Errorf("the client leg was released after %v, less than half the %v window", held, window)
	}
	if !originReleased {
		t.Error("the ORIGIN leg survived the reaped setup window on a partial ClientHello")
	}
	requireClientHelloTimeoutRow(t)
	if originRx != 0 {
		t.Errorf("the gateway sent the origin %d byte(s) for a client that never delivered its ClientHello: "+
			"it started an origin TLS handshake for a stalled client", originRx)
	}
	if n := autoExclude().Len(); n != 0 {
		t.Errorf("SECURITY: a partial-ClientHello stall learned %d auto-exclusion(s)", n)
	}
}

// captureClientHelloRecord returns the first TLS record a real crypto/tls client
// sends (its ClientHello) for the given ALPN offer, so the peek tests run
// against wire bytes rather than a hand-built approximation.
func captureClientHelloRecord(t *testing.T, nextProtos []string) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	defer func() { _ = srv.Close() }()
	go func() {
		tc := tls.Client(cli, &tls.Config{ServerName: "peek.test", NextProtos: nextProtos, MinVersion: tls.VersionTLS12})
		_ = tc.HandshakeContext(context.Background()) // fails once srv closes; only its first record matters
		_ = cli.Close()
	}()
	_ = srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(srv, hdr); err != nil {
		t.Fatalf("read ClientHello record header: %v", err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(srv, body); err != nil {
		t.Fatalf("read ClientHello record body: %v", err)
	}
	return append(hdr, body...)
}

// inspectPeekReader wraps src the way the native leg sees the hijacked client:
// a bufio.Reader of net/http's connection-reader size.
func inspectPeekReader(src io.Reader) *bufio.Reader { return bufio.NewReaderSize(src, 4<<10) }

// TestChaos125_PeekClientALPNFallbackIsNotAFailure pins the half of
// peekClientALPN's contract the partial-ClientHello fix must not disturb: when
// the client's record IS delivered but yields no usable ALPN offer, the answer
// is the HTTP/1.1 fallback with NO error, so the tunnel goes on to be inspected
// over HTTP/1.1 exactly as before rather than being recorded as a client-hello
// failure. The positive control proves the parser is actually reached.
func TestChaos125_PeekClientALPNFallbackIsNotAFailure(t *testing.T) {
	noALPN := captureClientHelloRecord(t, nil)
	withALPN := captureClientHelloRecord(t, []string{"h2", "http/1.1"})
	garbage := append([]byte{0x16, 0x03, 0x01, 0x00, 0x08}, []byte("notahelo")...)
	oversized := append([]byte{0x16, 0x03, 0x01, 0xff, 0xff}, make([]byte, 0xffff)...)

	cases := []struct {
		name string
		in   []byte
		want []string
	}{
		{"complete ClientHello with no ALPN extension", noALPN, []string{"http/1.1"}},
		{"complete handshake record that does not parse", garbage, []string{"http/1.1"}},
		{"record larger than the buffered window", oversized, []string{"http/1.1"}},
		{"non-handshake record type", []byte{0x17, 0x03, 0x03, 0x00, 0x00}, []string{"http/1.1"}},
		{"positive control: the client's real offer", withALPN, []string{"h2", "http/1.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := peekClientALPN(inspectPeekReader(bytes.NewReader(tc.in)))
			if err != nil {
				t.Fatalf("peekClientALPN returned %v for a delivered record: a legitimate HTTP/1.1 fallback "+
					"would be recorded as a client-hello failure and the tunnel refused", err)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("offer = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestChaos125_PeekClientALPNSurfacesClientReadFailures is the other half: a
// ClientHello the client never finished delivering is a read failure, and it
// must come back as an error the caller records on the client leg, never as
// the HTTP/1.1 fallback that sends the tunnel on to an origin handshake. The
// over-sized case matters because bufio reports an over-sized Peek as
// ErrBufferFull even when the fill underneath it failed.
func TestChaos125_PeekClientALPNSurfacesClientReadFailures(t *testing.T) {
	hello := captureClientHelloRecord(t, []string{"h2", "http/1.1"})
	cases := map[string][]byte{
		"only the record type byte":            {0x16},
		"a truncated record header":            {0x16, 0x03, 0x01},
		"a truncated ClientHello body":         hello[:len(hello)/2],
		"an over-sized record cut short early": append([]byte{0x16, 0x03, 0x01, 0xff, 0xff}, make([]byte, 100)...),
	}
	for name, in := range cases {
		t.Run(name+" then EOF", func(t *testing.T) {
			got, err := peekClientALPN(inspectPeekReader(bytes.NewReader(in)))
			if err == nil {
				t.Fatalf("offer = %q, nil error: a client that went away mid-ClientHello was treated as an ALPN fallback", got)
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				t.Fatalf("error = %v: the read failure was masked as a full buffer", err)
			}
		})
	}

	t.Run("a stall that reaches the read deadline", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer func() { _ = cli.Close() }()
		defer func() { _ = srv.Close() }()
		go func() { _, _ = cli.Write([]byte{0x16}) }()
		_ = srv.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		got, err := peekClientALPN(inspectPeekReader(srv))
		if err == nil {
			t.Fatalf("offer = %q, nil error: a stalled client was treated as an ALPN fallback", got)
		}
		if !isNetTimeout(err) {
			t.Fatalf("error = %v, want the deadline's timeout so it classifies as (client_hello, timeout)", err)
		}
		if stage, cat := classifyClientFailure(err); stage != "client_hello" || cat != "timeout" {
			t.Fatalf("classifyClientFailure = (%q, %q), want (client_hello, timeout)", stage, cat)
		}
	})
}

// TestChaos125_NativeLegClientWithoutALPNStillInspectsOverHTTP1 pins the
// fallback end to end on the native dispatch: a client whose ClientHello
// carries no ALPN extension at all is a legitimate client, not a stall. It must
// complete the forged-leaf handshake, be served through the HTTP/1.1 inspect
// loop (the origin is offered http/1.1 only, even though it speaks h2), and
// leave no DECRYPT_FAILED row behind.
func TestChaos125_NativeLegClientWithoutALPNStillInspectsOverHTTP1(t *testing.T) {
	t.Cleanup(reqlog.SwapRingForTest())
	allowLoopbackTunnel(t)
	_, proxyRoots := setupInspectCA(t)

	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin-Proto", r.Proto)
		_, _ = io.WriteString(w, "no-alpn-ok")
	}))
	origin.EnableHTTP2 = true // an h2-capable origin, so an h1 upstream leg is the fallback's doing
	origin.StartTLS()
	defer origin.Close()

	proxyURL := startTestProxy(t)
	inspectRuleNative()

	tc, proto := connectTLSWithProto(t, proxyURL.Host, origin.Listener.Addr().String(), "origin.test", proxyRoots, nil)
	if proto != "" {
		t.Fatalf("downstream ALPN = %q for a client that offered none", proto)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://origin.test/no-alpn", http.NoBody)
	if err := req.Write(tc); err != nil {
		t.Fatalf("write h1 request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		t.Fatalf("read h1 response through the native leg: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "no-alpn-ok" {
		t.Fatalf("body = %q, want the origin's response", body)
	}
	if p := resp.Header.Get("X-Origin-Proto"); p != "HTTP/1.1" {
		t.Fatalf("upstream leg proto = %q, want HTTP/1.1 (the no-ALPN fallback)", p)
	}
	if e, ok := findDecFailEntry(t, "127.0.0.1"); ok {
		t.Fatalf("a client with no ALPN offer recorded a DECRYPT_FAILED row (%+v): the fallback became a failure", e.Dec)
	}
}
