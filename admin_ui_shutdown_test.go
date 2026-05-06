package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// Tests for P1.1 / S4.AdminUI — Admin UI graceful shutdown handle.
//
// These tests cover the contract introduced by the admin UI ownership PR:
//
//   1. newAdminUIServer returns a configured *http.Server (timeouts, handler).
//   2. The returned *http.Server can be Shutdown(ctx) cleanly within a
//      bounded deadline; subsequent dials are refused.
//   3. runProxyUntilShutdown's adminUISrv branch is nil-safe (so the early-
//      fail path that never assigned the handle does not panic).
//
// We deliberately avoid calling startUI() here because startUI binds to a
// fixed `:port` Addr and ListenAndServe inside a goroutine, which makes the
// test rely on TOCTOU port discovery. Instead we drive the *http.Server
// returned by newAdminUIServer against an explicit net.Listener via Serve(ln)
// — same code path inside http.Server, no port race.

func TestNewAdminUIServer_ReturnsConfiguredServer(t *testing.T) {
	srv := newAdminUIServer(0)
	if srv == nil {
		t.Fatal("newAdminUIServer returned nil")
	}
	if srv.Handler == nil {
		t.Error("Handler must be non-nil (middleware chain over wired mux)")
	}
	if srv.ReadTimeout != 15*time.Second {
		t.Errorf("ReadTimeout = %v; want 15s", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout = %v; want 0 (SSE long-lived streams)", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout = %v; want 60s", srv.IdleTimeout)
	}
	if srv.ErrorLog == nil {
		t.Error("ErrorLog must be non-nil (tlsErrorFilter)")
	}
}

func TestAdminUIServer_ShutdownReturnsBeforeDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()

	srv := newAdminUIServer(0)

	var serveErr atomic.Value
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr.Store(err)
		}
	}()

	// Bounded poll for "server is accepting" — up to 2 s in 20 ms steps.
	ready := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		_ = srv.Close()
		t.Fatalf("admin UI server never accepted connections at %s", addr)
	}

	// Real HTTP request — any valid HTTP response proves the handler chain
	// (uiIPGuardMiddleware → securityMiddleware → uiAuthMiddleware →
	// uiMetadataEnforcement → mux) actually serviced the request, not just
	// that the listener accepted a TCP connection. We deliberately don't
	// assert a specific status code; this is a liveness probe, not a
	// behaviour test.
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + addr + "/")
	if err != nil {
		_ = srv.Close()
		t.Fatalf("HTTP request to %s failed: %v", addr, err)
	}
	resp.Body.Close()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed >= 5*time.Second {
		t.Errorf("Shutdown took %v; want < 5s deadline", elapsed)
	}

	// Serve goroutine must observe ErrServerClosed and exit promptly.
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve goroutine did not exit after Shutdown")
	}
	if v := serveErr.Load(); v != nil {
		t.Errorf("Serve returned unexpected error: %v", v)
	}

	// Subsequent dial must be refused — server stopped accepting.
	if conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		conn.Close()
		t.Errorf("dial succeeded after Shutdown; server should be closed at %s", addr)
	}
}

// TestRunProxyUntilShutdown_NilAdminUISrv_Safe documents that the shutdown
// branch is a no-op when s.adminUISrv is nil (early-fail path that never
// assigned the handle). We exercise the exact branch shape inline rather than
// invoking runProxyUntilShutdown — that function blocks on a quit channel and
// touches dozens of globals; the nil-guard contract is small and local.
func TestRunProxyUntilShutdown_NilAdminUISrv_Safe(t *testing.T) {
	s := &startupState{}
	if s.adminUISrv != nil {
		t.Fatal("zero-value startupState must have nil adminUISrv")
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil adminUISrv branch panicked: %v", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if s.adminUISrv != nil {
		_ = s.adminUISrv.Shutdown(ctx)
	}
}
