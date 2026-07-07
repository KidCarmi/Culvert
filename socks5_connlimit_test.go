package main

// Chaos regression (CHAOS-02): SOCKS5 sessions must count against the same
// per-IP connection budget as the HTTP/CONNECT path (proxy.go handleRequest).
// Before the fix, one client IP could open thousands of concurrent SOCKS5
// tunnels under the rate-limit burst budget, each pinning two goroutines and
// two FDs indefinitely.

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKS5_ConnLimit_SecondConnectionRefused(t *testing.T) {
	setupProxyTest(t)

	oldConnLimiter := connLimiter
	connLimiter = newConnLimiter()
	connLimiter.Enable(1)
	t.Cleanup(func() { connLimiter = oldConnLimiter })

	ln := startSOCKS5Listener(t)
	defer func() { _ = ln.Close() }()

	// First connection: dial and hold. The handler acquires the sole slot for
	// this IP at entry, then blocks reading the greeting we never send.
	conn1, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	// Wait until the first handler has actually acquired the slot.
	deadline := time.Now().Add(5 * time.Second)
	for connLimiter.ActiveIPs() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("first handler never acquired a connlimit slot")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Second connection from the same IP: refused before SOCKS negotiation —
	// the greeting gets no reply and the connection is closed.
	conn2, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	conn2.Write([]byte{0x05, 0x01, 0x00})                  //nolint:errcheck
	conn2.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn2, buf); err == nil {
		t.Fatalf("expected second SOCKS5 connection to be refused, got greeting reply %x", buf)
	}
}

func TestSOCKS5_ConnLimit_ReleasedAfterSessionEnds(t *testing.T) {
	setupProxyTest(t)

	oldConnLimiter := connLimiter
	connLimiter = newConnLimiter()
	connLimiter.Enable(1)
	t.Cleanup(func() { connLimiter = oldConnLimiter })

	ln := startSOCKS5Listener(t)
	defer func() { _ = ln.Close() }()

	// Run a short session to completion (unsupported BIND command → 0x07
	// reply → handler returns → slot released).
	conn1, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn1.Write([]byte{0x05, 0x01, 0x00}) //nolint:errcheck
	resp := make([]byte, 2)
	conn1.SetReadDeadline(time.Now().Add(5 * time.Second))                          //nolint:errcheck
	io.ReadFull(conn1, resp)                                                        //nolint:errcheck
	conn1.Write([]byte{0x05, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50}) //nolint:errcheck
	reply := make([]byte, 10)
	io.ReadFull(conn1, reply) //nolint:errcheck
	conn1.Close()

	// The slot must free up once the handler exits.
	deadline := time.Now().Add(5 * time.Second)
	for connLimiter.ActiveIPs() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("connlimit slot not released after SOCKS5 session ended")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// A fresh connection must get a slot and reach negotiation.
	conn2, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	conn2.Write([]byte{0x05, 0x01, 0x00})                  //nolint:errcheck
	conn2.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	resp2 := make([]byte, 2)
	if _, err := io.ReadFull(conn2, resp2); err != nil {
		t.Fatalf("fresh connection after release should negotiate, read failed: %v", err)
	}
	if resp2[0] != 0x05 {
		t.Fatalf("expected SOCKS5 greeting reply, got %x", resp2)
	}
}
