package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// h2cLoopback wires an http2.Server (serving `handler` on a LOCAL h2InspectShared)
// to an http2.ClientConn over a TCP loopback socket, cleartext h2 (h2c). TCP (not
// net.Pipe) avoids the synchronous-pipe deadlock h2's concurrent preface/SETTINGS
// exchange can hit. Returns the client conn and the server-side net.Conn. Everything
// is torn down via t.Cleanup.
func h2cLoopback(t *testing.T, sh *h2InspectShared, handler http.Handler) (*http2.ClientConn, net.Conn) {
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
	cliConn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = cliConn.Close() })
	srvConn := <-srvCh
	if srvConn == nil {
		t.Fatalf("accept failed")
	}
	t.Cleanup(func() { _ = srvConn.Close() })
	go sh.srv.ServeConn(srvConn, &http2.ServeConnOpts{Handler: handler, BaseConfig: sh.base})
	cc, err := (&http2.Transport{}).NewClientConn(cliConn)
	if err != nil {
		t.Fatalf("client conn: %v", err)
	}
	return cc, srvConn
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
	cc, _ := h2cLoopback(t, sh, handler)

	// Start an in-flight request and wait until the handler is running.
	type rtResult struct {
		body string
		err  error
	}
	resCh := make(chan rtResult, 1)
	go func() {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://origin.test/inflight", http.NoBody)
		resp, err := cc.RoundTrip(req)
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

	// A NEW stream on the same conn must be refused (GOAWAY stops new streams). Poll
	// briefly: the client marks the conn un-usable once it processes the GOAWAY.
	deadline := time.Now().Add(5 * time.Second)
	for {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://origin.test/new", http.NoBody)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			break // refused, as required
		}
		_ = resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("new stream was accepted after GOAWAY; it must be refused")
		}
		time.Sleep(20 * time.Millisecond) //nolint:forbidigo // bounded poll for GOAWAY processing, not a sequencing sleep
	}
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
