package main

// socks5_connlimit_test.go — CHAOS-02 regression coverage.
//
// handleSOCKS5 historically never consulted connLimiter, so one client IP
// could open unbounded concurrent SOCKS5 tunnels (each pinning goroutines
// and FDs) under a per-IP limit the HTTP/CONNECT path enforced. The handler
// now Acquires/Releases the same per-IP budget as handleRequest.

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// socks5Greet dials the listener and performs the no-auth greeting. Returns
// the connection and whether the server answered the greeting ([05 00]).
func socks5Greet(t *testing.T, addr string) (net.Conn, bool) {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte{0x05, 0x01, 0x00})                  //nolint:errcheck // test: greeting write, error surfaced by the ReadFull below
	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck // test: deadline on a fresh conn cannot fail
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return conn, false
	}
	return conn, resp[0] == 0x05 && resp[1] == 0x00
}

func TestSOCKS5_ConnLimit_Enforced(t *testing.T) {
	setupProxyTest(t)

	oldConnLimiter := connLimiter
	connLimiter = newConnLimiter()
	connLimiter.Enable(1)
	t.Cleanup(func() { connLimiter = oldConnLimiter })

	ln := startSOCKS5Listener(t)
	defer func() { _ = ln.Close() }()

	// First session: completes the greeting and stays open — it holds the
	// single per-IP slot inside handleSOCKS5 for its full lifetime.
	conn1, ok := socks5Greet(t, ln.Addr().String())
	defer conn1.Close()
	if !ok {
		t.Fatal("first SOCKS5 session should negotiate under the limit")
	}

	// Second concurrent session from the same IP: over the limit — the
	// handler must close it before any negotiation, so the greeting read
	// fails instead of returning [05 00].
	conn2, ok := socks5Greet(t, ln.Addr().String())
	defer conn2.Close()
	if ok {
		t.Fatal("second concurrent SOCKS5 session negotiated — per-IP connection limit not enforced (CHAOS-02)")
	}

	// Closing the first session must release the slot (no leak): a fresh
	// session then succeeds. Release happens when the handler goroutine
	// unwinds, so poll briefly.
	conn1.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn3, ok := socks5Greet(t, ln.Addr().String())
		conn3.Close()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("slot never released after first session closed — connlimit leak in SOCKS5 path")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestSOCKS5_ConnLimit_DisabledIsNoOp pins that the default (limiter
// disabled) keeps the pre-change behavior: concurrent sessions all admit.
func TestSOCKS5_ConnLimit_DisabledIsNoOp(t *testing.T) {
	setupProxyTest(t)

	oldConnLimiter := connLimiter
	connLimiter = newConnLimiter() // disabled by default
	t.Cleanup(func() { connLimiter = oldConnLimiter })

	ln := startSOCKS5Listener(t)
	defer func() { _ = ln.Close() }()

	conn1, ok1 := socks5Greet(t, ln.Addr().String())
	defer conn1.Close()
	conn2, ok2 := socks5Greet(t, ln.Addr().String())
	defer conn2.Close()
	if !ok1 || !ok2 {
		t.Fatalf("disabled limiter must admit concurrent sessions (got %v, %v)", ok1, ok2)
	}
}
