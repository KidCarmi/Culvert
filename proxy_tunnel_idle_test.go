package main

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// CHAOS-03 regression tests: raw tunnel relays must reap half-open peers
// (no bytes in either direction for tunnelIdleTimeout) instead of pinning
// goroutines + FDs forever, while leaving graceful EOF teardown and byte
// accounting untouched. bidiRelayCounted is exercised in the CONNECT-bypass
// shape (each direction reads one peer conn and writes the other), which is
// the same wiring the WebSocket path uses via bufio wrappers.

// setTunnelIdleTimeout shortens the idle window for a test and restores it.
// Tests using it must not run in parallel (package-level var).
func setTunnelIdleTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := tunnelIdleTimeout
	tunnelIdleTimeout = d
	t.Cleanup(func() { tunnelIdleTimeout = old })
}

// idleTestTCPPair returns the two ends of a real loopback TCP connection so
// the splice-capable ReaderFrom path and CloseWrite semantics are exercised.
func idleTestTCPPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type acceptResult struct {
		c   net.Conn
		err error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		ch <- acceptResult{c, err}
	}()
	client, err = (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	res := <-ch
	if res.err != nil {
		client.Close()
		t.Fatalf("accept: %v", res.err)
	}
	t.Cleanup(func() { client.Close(); res.c.Close() })
	return client, res.c
}

// TestTunnelIdle_ReapsHalfOpenTunnel: both peers go silent without closing
// (the half-open case — peer still ACKs, never sends). The relay must return
// within a bounded multiple of the idle window instead of blocking forever.
func TestTunnelIdle_ReapsHalfOpenTunnel(t *testing.T) {
	setTunnelIdleTimeout(t, 300*time.Millisecond)

	clientProxy, clientPeer := net.Pipe()
	destProxy, destPeer := net.Pipe()
	t.Cleanup(func() {
		clientPeer.Close()
		destPeer.Close()
	})

	type counts struct{ toDest, toClient int64 }
	resCh := make(chan counts, 1)
	go func() {
		d, c := bidiRelayCounted(destProxy, clientProxy, clientProxy, destProxy)
		resCh <- counts{d, c}
	}()

	// Establish some one-way traffic so the tunnel is provably live first.
	go clientPeer.Write([]byte("hello")) //nolint:errcheck // test write; relay teardown may race the write
	buf := make([]byte, 5)
	if _, err := io.ReadFull(destPeer, buf); err != nil {
		t.Fatalf("initial relay read: %v", err)
	}

	// Now both peers go silent — no data, no FIN. Pre-fix this blocked forever.
	select {
	case r := <-resCh:
		if r.toDest != 5 {
			t.Errorf("toDest = %d, want 5", r.toDest)
		}
		if r.toClient != 0 {
			t.Errorf("toClient = %d, want 0", r.toClient)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("idle half-open tunnel was not reaped (pre-CHAOS-03 leak behavior)")
	}
}

// TestTunnelIdle_ActiveDirectionKeepsSilentDirectionAlive: traffic flowing in
// ONE direction must keep the whole tunnel alive past many idle windows (the
// shared activity stamp), and byte accounting must survive the periodic
// deadline pops. Only when traffic stops may the tunnel be reaped.
func TestTunnelIdle_ActiveDirectionKeepsSilentDirectionAlive(t *testing.T) {
	setTunnelIdleTimeout(t, 500*time.Millisecond)

	clientProxy, clientPeer := net.Pipe()
	destProxy, destPeer := net.Pipe()
	t.Cleanup(func() {
		clientPeer.Close()
		destPeer.Close()
	})

	type counts struct{ toDest, toClient int64 }
	resCh := make(chan counts, 1)
	go func() {
		d, c := bidiRelayCounted(destProxy, clientProxy, clientProxy, destProxy)
		resCh <- counts{d, c}
	}()
	go io.Copy(io.Discard, destPeer) //nolint:errcheck // drain so pipe writes complete

	var written atomic.Int64
	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				n, err := clientPeer.Write([]byte("xx"))
				written.Add(int64(n))
				if err != nil {
					return
				}
			}
		}
	}()

	// Stay active for well over two idle windows: the silent dest→client
	// direction pops its deadline repeatedly and must NOT reap the tunnel.
	time.Sleep(1200 * time.Millisecond)
	select {
	case <-resCh:
		t.Fatal("tunnel reaped while one direction was actively moving bytes")
	default:
	}

	close(stop)
	<-writerDone
	select {
	case r := <-resCh:
		if got, want := r.toDest, written.Load(); got != want {
			t.Errorf("toDest = %d, want %d (byte accounting must survive deadline pops)", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel not reaped after traffic stopped")
	}
}

// TestTunnelIdle_GracefulEOFTeardownUnchanged: with a long idle window, the
// normal teardown contract (CloseWrite propagates EOF, both directions drain,
// counts are exact) must be untouched by the idle machinery. Real TCP conns
// so CloseWrite and the ReaderFrom fast path are both in play.
func TestTunnelIdle_GracefulEOFTeardownUnchanged(t *testing.T) {
	setTunnelIdleTimeout(t, 10*time.Second)

	clientProxy, clientPeer := idleTestTCPPair(t)
	destProxy, destPeer := idleTestTCPPair(t)

	type counts struct{ toDest, toClient int64 }
	resCh := make(chan counts, 1)
	go func() {
		d, c := bidiRelayCounted(destProxy, clientProxy, clientProxy, destProxy)
		resCh <- counts{d, c}
	}()

	// client → dest: 5 bytes then FIN.
	if _, err := clientPeer.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if tc, ok := clientPeer.(*net.TCPConn); ok {
		tc.CloseWrite() //nolint:errcheck // test FIN
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(destPeer, buf); err != nil {
		t.Fatalf("dest read: %v", err)
	}

	// dest → client: 6 bytes then full close (upstream finished).
	if _, err := destPeer.Write([]byte("worldz")); err != nil {
		t.Fatalf("dest write: %v", err)
	}
	destPeer.Close()

	got := make([]byte, 6)
	if _, err := io.ReadFull(clientPeer, got); err != nil {
		t.Fatalf("client read: %v", err)
	}

	select {
	case r := <-resCh:
		if r.toDest != 5 || r.toClient != 6 {
			t.Errorf("counts = (%d,%d), want (5,6)", r.toDest, r.toClient)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("graceful EOF teardown did not complete promptly (idle window is 10s — this must be the EOF path)")
	}
}

// TestTunnelIdle_SOCKS5RelayReaped: the SOCKS5 relay shares the idle-bounded
// copy helper; a half-open SOCKS5 tunnel must be reaped too (it previously
// leaked exactly like the CONNECT paths, and holds a conn-limiter slot while
// it lives — CHAOS-02's residual).
func TestTunnelIdle_SOCKS5RelayReaped(t *testing.T) {
	setTunnelIdleTimeout(t, 300*time.Millisecond)

	clientProxy, clientPeer := idleTestTCPPair(t)
	destProxy, destPeer := idleTestTCPPair(t)
	_ = clientPeer
	_ = destPeer

	done := make(chan struct{})
	go func() {
		defer close(done)
		// TEST-NET-2 actor IP per the audit-assert convention.
		socks5Relay(clientProxy, destProxy, "198.51.100.77", "idle.example:443")
	}()

	// Neither peer ever sends: pre-fix socks5Relay blocked forever.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle SOCKS5 relay was not reaped")
	}
}
