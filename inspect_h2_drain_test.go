package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// h2TCPPair returns a connected client/server TCP loopback pair. TCP (not
// net.Pipe) avoids the synchronous-pipe deadlock h2's concurrent preface/SETTINGS
// exchange can hit. Both ends are closed via t.Cleanup.
func h2TCPPair(t *testing.T) (cliConn, srvConn net.Conn) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srvCh := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			srvCh <- nil
			return
		}
		srvCh <- c
	}()
	cliConn, err = (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cliConn.Close() })
	srvConn = <-srvCh
	if srvConn == nil {
		t.Fatalf("accept failed")
	}
	t.Cleanup(func() { _ = srvConn.Close() })
	return cliConn, srvConn
}

// h2cTestConn is one served loopback conn as seen by a test.
type h2cTestConn struct {
	rt     http.RoundTripper // the single h2 client conn: every request goes over the one served conn
	srv    net.Conn          // server side, for closing the conn WITHOUT a GOAWAY
	goaway <-chan struct{}   // closed once the client leg has read a GOAWAY frame
}

// h2cLoopback serves `handler` on a LOCAL h2InspectShared through the production
// serveConn wiring (same ServeConnOpts as handleInspectH2, ctx as the per-tunnel
// context) and connects an http2.ClientConn to it over cleartext h2 (h2c) on a TCP
// loopback pair. The client leg's inbound bytes are also parsed by a frame sniffer
// so a test can tell a real GOAWAY from a plain close.
func h2cLoopback(t *testing.T, ctx context.Context, sh *h2InspectShared, handler http.Handler) *h2cTestConn {
	t.Helper()
	cliConn, srvConn := h2TCPPair(t)
	go sh.serveConn(ctx, srvConn, handler)
	sniffer, goaway := newH2GoawaySniffer(t, cliConn)
	cliConn = sniffer
	//lint:ignore SA1019 temporary compatibility bridge: x/net v0.59 deprecated this x/net/http2 API; kept until the inspected-H2 path migrates to Go's stdlib HTTP/2 APIs.
	cc, err := (&http2.Transport{}).NewClientConn(cliConn)
	if err != nil {
		t.Fatalf("client conn: %v", err)
	}
	return &h2cTestConn{rt: cc, srv: srvConn, goaway: goaway}
}

// h2GoawaySniffer tees every byte the client reads into an http2.Framer running on
// its own goroutine. The server-to-client byte stream is plain frames (no preface),
// so the framer sees exactly what the client sees.
type h2GoawaySniffer struct {
	net.Conn
	pw *io.PipeWriter
}

func (s *h2GoawaySniffer) Read(b []byte) (int, error) {
	n, err := s.Conn.Read(b)
	if n > 0 {
		_, _ = s.pw.Write(b[:n]) // the framer goroutine always drains, so this never wedges
	}
	return n, err
}

func newH2GoawaySniffer(t *testing.T, c net.Conn) (sniffed net.Conn, goawaySeen <-chan struct{}) {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	goaway := make(chan struct{})
	go func() {
		defer func() { _, _ = io.Copy(io.Discard, pr) }() // keep draining after any parse error
		fr := http2.NewFramer(io.Discard, pr)
		fr.SetMaxReadFrameSize(1 << 24)
		seen := false
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				var se http2.StreamError
				if errors.As(err, &se) {
					continue // stream-level parse errors are recoverable; keep reading
				}
				return
			}
			if _, ok := f.(*http2.GoAwayFrame); ok && !seen {
				seen = true
				close(goaway)
			}
		}
	}()
	return &h2GoawaySniffer{Conn: c, pw: pw}, goaway
}

// TestH2InspectDrain_GracefulGoawayCompletesInflightAndRefusesNew is the core
// mechanism test: with an in-flight stream held open, firing the graceful shutdown
// (GOAWAY) must (a) let that in-flight stream finish cleanly and (b) refuse a NEW
// stream on the same connection. Sequencing is barrier-based (channels), never
// time.Sleep, so it is deterministic under -race/-shuffle. Uses a LOCAL
// h2InspectShared, never the process globals.
func TestH2InspectDrain_GracefulGoawayCompletesInflightAndRefusesNew(t *testing.T) {
	sh := newH2InspectServer()
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-entered: // already signaled by a prior stream
		default:
			close(entered)
		}
		<-release // hold the stream in-flight until the test releases it
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "done")
	})
	cc := h2cLoopback(t, context.Background(), sh, handler)

	// Start an in-flight request and wait until the handler is running.
	type rtResult struct {
		body string
		err  error
	}
	resCh := make(chan rtResult, 1)
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://origin.test/inflight", http.NoBody)
		resp, err := cc.rt.RoundTrip(req)
		if err != nil {
			resCh <- rtResult{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resCh <- rtResult{body: string(b)}
	}()
	<-entered

	// Fire the graceful GOAWAY on the shared server while the stream is in flight.
	if err := gracefulShutdownH2InspectShared(sh, context.Background()); err != nil {
		t.Fatalf("graceful shutdown: %v", err)
	}

	// Let the in-flight stream finish; it must complete cleanly (GOAWAY lets
	// existing streams drain).
	close(release)
	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("in-flight stream must complete cleanly after GOAWAY, got err: %v", r.err)
		}
		if r.body != "done" {
			t.Fatalf("in-flight body = %q, want done", r.body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("in-flight stream did not complete within 10s after GOAWAY")
	}

	// The server must have sent a GOAWAY, and a NEW stream on the same conn must
	// be refused (GOAWAY stops new streams).
	assertH2GracefulGoaway(t, cc)
}

// h2GracefulGoawayErr returns nil only if the server sent a GOAWAY frame on cc
// AND a NEW stream is then refused. A RoundTrip error alone is not enough: a
// conn closed without a GOAWAY also fails RoundTrip, which is exactly the
// non-graceful teardown these tests guard against. wait bounds each phase; the
// refusal is polled because the client marks the conn un-usable only once it has
// processed the GOAWAY.
func h2GracefulGoawayErr(cc *h2cTestConn, wait time.Duration) error {
	select {
	case <-cc.goaway:
	case <-time.After(wait):
		return fmt.Errorf("no GOAWAY frame reached the client within %v", wait)
	}
	deadline := time.Now().Add(wait)
	for {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://origin.test/new", http.NoBody)
		resp, err := cc.rt.RoundTrip(req)
		if err != nil {
			return nil // GOAWAY seen and the new stream refused, as required
		}
		_ = resp.Body.Close()
		if time.Now().After(deadline) {
			return errors.New("new stream was accepted after GOAWAY; it must be refused")
		}
		time.Sleep(20 * time.Millisecond) //nolint:forbidigo // bounded poll for GOAWAY processing, not a sequencing sleep
	}
}

// assertH2GracefulGoaway fails the test unless cc got a GOAWAY and then refuses
// new streams.
func assertH2GracefulGoaway(t *testing.T, cc *h2cTestConn) {
	t.Helper()
	if err := h2GracefulGoawayErr(cc, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

// TestH2InspectDrain_GoawayAssertionRejectsPlainClose is the negative control for
// assertH2GracefulGoaway: a served conn that is hard-closed WITHOUT a GOAWAY makes
// RoundTrip fail (so an "any error means refused" check would pass), but the
// GOAWAY-aware assertion must reject it.
func TestH2InspectDrain_GoawayAssertionRejectsPlainClose(t *testing.T) {
	sh := newH2InspectServer()
	cc := h2cLoopback(t, context.Background(), sh, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://origin.test/up", http.NoBody)
	resp, err := cc.rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("conn did not serve a stream before the close: %v", err)
	}
	_ = resp.Body.Close()

	_ = cc.srv.Close() // non-graceful teardown: no GOAWAY frame is written

	err = h2GracefulGoawayErr(cc, time.Second)
	if err == nil || !strings.Contains(err.Error(), "no GOAWAY frame") {
		t.Fatalf("plain close must fail the GOAWAY assertion for the missing frame, got: %v", err)
	}
	// And the weakness being closed: the closed conn does fail RoundTrip, so a
	// refusal-only check would have accepted this teardown as graceful.
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://origin.test/after", http.NoBody)
	if resp2, rerr := cc.rt.RoundTrip(req2); rerr == nil {
		_ = resp2.Body.Close()
		t.Fatal("a hard-closed conn unexpectedly served a new stream")
	}
}

// TestH2InspectDrain_RefireReachesLateConn pins the per-tick re-fire contract
// (refireH2InspectGoaway): a tunnel that starts serving AFTER the first GOAWAY wave
// — a CONNECT that raced the admission fence — must still be GOAWAY'd by the next
// gracefulShutdownH2InspectShared call on the same shared server.
func TestH2InspectDrain_RefireReachesLateConn(t *testing.T) {
	sh := newH2InspectServer()
	if err := gracefulShutdownH2InspectShared(sh, context.Background()); err != nil {
		t.Fatalf("first wave: %v", err)
	}
	cc := h2cLoopback(t, context.Background(), sh, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	// Confirm the late conn is actually serving before the re-fire.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://origin.test/late", http.NoBody)
	resp, err := cc.rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("late conn did not serve a stream before the re-fire: %v", err)
	}
	_ = resp.Body.Close()

	if err := gracefulShutdownH2InspectShared(sh, context.Background()); err != nil {
		t.Fatalf("re-fire: %v", err)
	}
	assertH2GracefulGoaway(t, cc)
}

// TestH2InspectDrain_NilServerNoop pins that the inner helper is a fast no-op on a
// nil shared server (native H2 never used this run) — tested WITHOUT touching the
// process globals, so it is immune to -shuffle/-count ordering.
func TestH2InspectDrain_NilServerNoop(t *testing.T) {
	if err := gracefulShutdownH2InspectShared(nil, context.Background()); err != nil {
		t.Fatalf("nil shared server must be a no-op, got: %v", err)
	}
}

// TestH2InspectDrain_BackstopForceCloses proves the deadline backstop force-closes
// every registered client leg and reports the count. Uses local pipe conns and
// cleans up its own registry entries so it does not perturb other tests.
func TestH2InspectDrain_BackstopForceCloses(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	t.Cleanup(func() { _ = a2.Close(); _ = b2.Close() })

	beforeForced := atomic.LoadInt64(&statH2InspectForced)
	registerH2InspectConn(a1)
	registerH2InspectConn(b1)

	n := forceCloseH2InspectTunnels()
	if n < 2 {
		t.Fatalf("force-closed %d conns, want >= 2 (the two just registered)", n)
	}
	if got := atomic.LoadInt64(&statH2InspectForced) - beforeForced; got < 2 {
		t.Fatalf("forced counter delta = %d, want >= 2", got)
	}
	// The registered legs must actually be closed: a write now errors.
	if _, err := a1.Write([]byte("x")); err == nil {
		t.Fatal("registered conn a1 was not closed by the backstop")
	}
	// forceClose does not deregister (the tunnel's own defer does); clean up so the
	// map/gauge return to baseline for other tests.
	unregisterH2InspectConn(a1)
	unregisterH2InspectConn(b1)
}

// TestH2InspectDrain_ActiveGaugeBalances checks the active gauge is a balanced ±1
// around register/unregister (delta-based, not absolute — the gauge is a shared
// global).
func TestH2InspectDrain_ActiveGaugeBalances(t *testing.T) {
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	before := atomic.LoadInt64(&statH2InspectActive)
	registerH2InspectConn(c1)
	if got := atomic.LoadInt64(&statH2InspectActive) - before; got != 1 {
		t.Fatalf("gauge delta after register = %d, want 1", got)
	}
	unregisterH2InspectConn(c1)
	if got := atomic.LoadInt64(&statH2InspectActive) - before; got != 0 {
		t.Fatalf("gauge delta after unregister = %d, want 0", got)
	}
}

// TestH2InspectDrain_FenceRefusesNewTunnel proves the admission fence: with the
// shutting-down flag set, handleInspectH2 returns without registering a conn (the
// active gauge is unchanged) — a new decrypted flow is not admitted onto a departing
// node. The tls.Conns are never handshaked; handleInspectH2 returns at the fence and
// only Closes them via its deferred cleanup.
func TestH2InspectDrain_FenceRefusesNewTunnel(t *testing.T) {
	h2InspectShuttingDown.Store(true)
	defer h2InspectShuttingDown.Store(false)

	cp, cpPeer := net.Pipe()
	up, upPeer := net.Pipe()
	t.Cleanup(func() { _ = cpPeer.Close(); _ = upPeer.Close() })
	clientTLS := tls.Client(cp, &tls.Config{MinVersion: tls.VersionTLS12}) // never handshaked; only Closed
	upstreamTLS := tls.Client(up, &tls.Config{MinVersion: tls.VersionTLS12})
	outer := httptest.NewRequest(http.MethodConnect, "https://origin.test:443", http.NoBody)

	before := atomic.LoadInt64(&statH2InspectActive)
	handleInspectH2(outer, clientTLS, upstreamTLS, "origin.test", nil, ProxyIdentity{}, nil)
	if got := atomic.LoadInt64(&statH2InspectActive); got != before {
		t.Fatalf("fenced tunnel registered a conn (active gauge %d -> %d); the fence must refuse before registering", before, got)
	}
}
