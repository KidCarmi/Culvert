package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
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
	// Use net.Dialer.DialContext (not net.DialTimeout) per project policy
	// (CLAUDE.md "HTTP contexts" + golangci noctx).
	dialer := &net.Dialer{Timeout: 100 * time.Millisecond}
	ready := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		dialCtx, dialCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		conn, err := dialer.DialContext(dialCtx, "tcp", addr)
		dialCancel()
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
	// behaviour test. http.NewRequestWithContext + client.Do per project
	// policy (CLAUDE.md "HTTP contexts" + golangci noctx).
	client := &http.Client{Timeout: time.Second}
	reqCtx, reqCancel := context.WithTimeout(context.Background(), time.Second)
	defer reqCancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+addr+"/", http.NoBody)
	if err != nil {
		_ = srv.Close()
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
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
	postCtx, postCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer postCancel()
	postDialer := &net.Dialer{Timeout: 200 * time.Millisecond}
	if conn, err := postDialer.DialContext(postCtx, "tcp", addr); err == nil {
		conn.Close()
		t.Errorf("dial succeeded after Shutdown; server should be closed at %s", addr)
	}
}

// TestShutdownAdminUI_NilSrv_ReturnsNil documents that the helper is a no-op
// when srv is nil (early-fail path that never assigned the handle in
// startupState). Replaces the previous defensive panic-guard test now that
// the helper has a clean nil branch.
func TestShutdownAdminUI_NilSrv_ReturnsNil(t *testing.T) {
	if err := shutdownAdminUI(context.Background(), nil); err != nil {
		t.Errorf("shutdownAdminUI(ctx, nil) = %v; want nil", err)
	}
}

// TestShutdownAdminUI_BoundedByChildTimeout proves the Codex P1 fix on
// PR #210: when the admin UI has an in-flight handler that won't complete on
// its own (e.g. an SSE stream blocked on writes), shutdownAdminUI returns at
// the 5s child-context cap, NOT after the full parent ctx deadline. This
// preserves the parent's remaining budget for downstream shutdown steps
// (proxy drain, tunnel drain).
//
// Setup:
//   - Bare *http.Server with a handler that blocks on a release channel.
//   - Listen on 127.0.0.1:0; serve via srv.Serve(ln).
//   - Fire one in-flight request; wait until the handler is entered.
//   - Parent ctx with a 30s deadline.
//
// Assertions:
//   - shutdownAdminUI returns within ~5s (not 30s).
//   - Returned error is context.DeadlineExceeded (the child cap fired).
//   - Parent ctx is not expired and still has ≥20s remaining.
//
// Cleanup:
//   - Release the handler so the in-flight request unblocks.
//   - srv.Close() to forcibly drop any remaining connections.
//   - Join all goroutines.
func TestShutdownAdminUI_BoundedByChildTimeout(t *testing.T) {
	release := make(chan struct{})
	handlerEntered := make(chan struct{})
	var entered sync.Once

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered.Do(func() { close(handlerEntered) })
		<-release
		w.WriteHeader(http.StatusOK)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()

	srv := &http.Server{
		Handler:     handler,
		ReadTimeout: 5 * time.Second,
		// WriteTimeout: 0 mirrors the real admin UI (SSE-friendly), and is
		// what makes Shutdown block on the in-flight handler in the first place.
	}

	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(ln)
	}()

	reqDone := make(chan struct{})
	reqCtx, reqCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer reqCancel()
	go func() {
		defer close(reqDone)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+addr+"/", http.NoBody)
		if err != nil {
			return
		}
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()

	// Wait for the handler to be entered so we know Shutdown will see an
	// active request and have to wait for it.
	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		_ = srv.Close()
		t.Fatal("handler was never entered; in-flight request never reached the server")
	}

	// Parent ctx with a 30s deadline. Mirrors the 30s budget in
	// runProxyUntilShutdown, but the exact value doesn't matter — what matters
	// is that we can prove the child timeout fires first.
	parentCtx, parentCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer parentCancel()
	parentDeadline, _ := parentCtx.Deadline()

	start := time.Now()
	shutdownErr := shutdownAdminUI(parentCtx, srv)
	elapsed := time.Since(start)

	// Bounded by the 5s child cap (adminUIShutdownTimeout). The polling
	// interval inside http.Server.Shutdown means the upper bound can be
	// slightly above 5s in practice; 7s is a generous ceiling.
	if elapsed > 7*time.Second {
		t.Errorf("shutdownAdminUI returned in %v; expected ≤7s (child cap is %v)", elapsed, adminUIShutdownTimeout)
	}
	// And it must NOT have returned instantly — that would mean the in-flight
	// handler was not actually keeping Shutdown busy, invalidating the test.
	if elapsed < 4*time.Second {
		t.Errorf("shutdownAdminUI returned in %v; expected ~%v (handler should have blocked Shutdown)", elapsed, adminUIShutdownTimeout)
	}

	// The error must be the child ctx deadline, not nil and not the parent.
	if !errors.Is(shutdownErr, context.DeadlineExceeded) {
		t.Errorf("shutdownAdminUI err = %v; want context.DeadlineExceeded", shutdownErr)
	}

	// Parent ctx must still be alive and have most of its budget left.
	if err := parentCtx.Err(); err != nil {
		t.Errorf("parent ctx expired during shutdownAdminUI: %v", err)
	}
	if remaining := time.Until(parentDeadline); remaining < 20*time.Second {
		t.Errorf("parent ctx remaining = %v; expected ≥20s after 5s child cap", remaining)
	}

	// Cleanup: release the handler so the in-flight goroutine can finish,
	// then forcibly close the server (Shutdown returned with deadline
	// exceeded; in-flight handlers and listeners are still alive).
	close(release)
	_ = srv.Close()
	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Error("Serve goroutine did not exit within 2s of srv.Close()")
	}
	select {
	case <-reqDone:
	case <-time.After(2 * time.Second):
		t.Error("in-flight request goroutine did not exit within 2s of srv.Close()")
	}
}
