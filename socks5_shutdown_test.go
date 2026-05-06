package main

import (
	"context"
	"net"
	"testing"
	"time"
)

// Tests for P1.5 / S4.SOCKS5 — SOCKS5 listener shutdown ownership.
//
// The shutdown invariant under test is:
//
//   "the SOCKS5 accept loop cannot remain detached after Stop closes the
//    listener."
//
// Stop closes the listener, then waits on srv.done (closed by the serve
// goroutine on exit) bounded by ctx. A successful Stop is therefore proof
// that:
//   - the accept loop observed errors.Is(err, net.ErrClosed) and returned
//     cleanly, NOT logging it as fatal or spinning,
//   - the goroutine fully exited.
//
// In-flight SOCKS5 tunnels are NOT drained — that is explicitly out of scope
// for P1.5 (tracked for Phase 2). These tests do not exercise the relay path.

// TestSocks5Server_StopWithoutDial_ExitsCleanly pins the listener-close
// contract on its own: bind, start, immediately Stop. No connections, no
// handleSOCKS5 invocations. If the serve loop logged net.ErrClosed as a
// transient accept error and `continue`'d, Stop would hang on srv.done and
// hit the ctx deadline — the test would fail with ctx.DeadlineExceeded.
func TestSocks5Server_StopWithoutDial_ExitsCleanly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	srv := newSOCKS5Server(ln)
	srv.Start()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := srv.Stop(ctx); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}
}

// TestSocks5Server_StopClosesListener proves the post-Stop contract: a dial
// to the bound address fails after Stop. We deliberately do NOT dial before
// Stop — that would spawn a handleSOCKS5 goroutine reading ipf/rl globals,
// which (because P1.5 explicitly does not drain in-flight tunnels) would
// outlive the test and race with the next test's setupProxyTest. The
// listener-close + serve-loop-exits invariant is covered by
// TestSocks5Server_StopWithoutDial_ExitsCleanly above; here we focus on
// the listener-rejects-new-connections side of the contract.
func TestSocks5Server_StopClosesListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	srv := newSOCKS5Server(ln)
	srv.Start()
	addr := srv.Addr().String()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := srv.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Post-Stop: subsequent dial fails.
	dialer := &net.Dialer{Timeout: 200 * time.Millisecond}
	postCtx, postCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer postCancel()
	if c, err := dialer.DialContext(postCtx, "tcp", addr); err == nil {
		c.Close()
		t.Errorf("dial after Stop succeeded; listener should be closed at %s", addr)
	}
}

// TestSocks5Server_StopNilReceiver pins the nil-safety contract for the
// early-fail path (initSOCKS5 was disabled or bind failed before assigning
// startupState.socks5Srv).
func TestSocks5Server_StopNilReceiver(t *testing.T) {
	var srv *socks5Server
	if err := srv.Stop(context.Background()); err != nil {
		t.Errorf("(nil).Stop = %v; want nil", err)
	}
}

// TestSocks5Server_StopIdempotent pins the idempotent contract: calling
// Stop twice (once successful, once on an already-closed listener) must
// return nil both times. A buggy implementation that surfaced
// net.ErrClosed from the second listener.Close would break this.
func TestSocks5Server_StopIdempotent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	srv := newSOCKS5Server(ln)
	srv.Start()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := srv.Stop(ctx); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := srv.Stop(ctx); err != nil {
		t.Errorf("second Stop returned %v; want nil (idempotent)", err)
	}
}
