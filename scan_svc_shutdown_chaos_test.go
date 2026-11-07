package main

// scan_svc_shutdown_chaos_test.go — CHAOS-113 gates for the scan sidecar's
// SHUTDOWN ordering.
//
// The finding. `ScanService.server` was assigned by the goroutine running
// Start() and read by the shutdown hook (main_shutdown.go,
// "scan-svc-shutdown"), with no synchronisation. Two defects in one field:
//
//  1. A real DATA RACE, reachable from production — reproduced before the fix
//     at scan_svc.go:92 (the write) against scan_svc.go:108 and :111 (the
//     reads), 3 reports in 50 iterations under `-race`.
//  2. Worse than the race in effect: `Shutdown`'s `if ss.server == nil {
//     return nil }` reported SUCCESS to the shutdown registry when it landed
//     in the window before the assignment, having closed nothing — and the
//     registry discards the error anyway (`_ = s.scanSvc.Shutdown(ctx)`), so
//     nothing anywhere would have said otherwise. Start() then built its own
//     server and served. Measured before the fix: /health answered 200 AFTER
//     a Shutdown that returned nil, with the listening socket still held.
//
// That is a SIGTERM arriving during startup — the orchestrator cancel in the
// 2026-10-13 backlog's L-3, on the one component whose "I stopped" is a lie
// rather than a missed flush.
//
// The CONTROL matters as much as the defect gates: the cheapest way to pass
// "it did not serve after shutdown" is to make Shutdown kill the listener
// unconditionally, which would break the ordinary path it exists for.
// TestChaos113_ControlShutdownAfterServeStillDrains pins that direction.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// scanSvcProbe performs one /health request with its own transport, so a
// pooled idle connection from a previous probe can never answer for a
// listener that is already gone. Reusing http.DefaultClient here hid exactly
// that during the pre-fix reproduction: the dead sidecar "answered" from a
// warm keep-alive connection.
func scanSvcProbe(t *testing.T, addr string) (int, error) {
	t.Helper()
	tr := &http.Transport{DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+"/health", http.NoBody)
	if err != nil {
		return 0, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// TestChaos113_ShutdownBeforeServeIsHonoured is the defect gate. A Shutdown
// that lands before the serving goroutine is scheduled must be TERMINAL: the
// sidecar must never serve afterwards, whatever Start() is then asked to do.
func TestChaos113_ShutdownBeforeServeIsHonoured(t *testing.T) {
	resetScanSvcHealthForTest()
	t.Cleanup(resetScanSvcHealthForTest)
	svc := NewScanService("127.0.0.1:0")
	if err := svc.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := svc.Addr()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := svc.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	// The pre-fix shape returned nil here having done nothing, and the next
	// two assertions both failed.
	done := make(chan error, 1)
	go func() { done <- svc.Start() }()

	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Start() after Shutdown returned %v, want http.ErrServerClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Start() blocked after a completed Shutdown — the sidecar is serving")
	}

	if code, err := scanSvcProbe(t, addr); err == nil {
		t.Errorf("sidecar answered /health with %d after a successful Shutdown", code)
	}

	// The socket must be released, not merely unserved: a held port stops the
	// replacement container from binding it.
	ln, lerr := net.Listen("tcp", addr)
	if lerr != nil {
		t.Errorf("the sidecar's address %s is still held after Shutdown: %v", addr, lerr)
	} else {
		_ = ln.Close()
	}
}

// TestChaos113_ShutdownRacesTheServeGoroutine is the race gate. It reproduces
// the production interleaving (shutdown hook vs. the serving goroutine) and is
// only meaningful under `-race`, where it reported 3 data races before the fix.
func TestChaos113_ShutdownRacesTheServeGoroutine(t *testing.T) {
	resetScanSvcHealthForTest()
	t.Cleanup(resetScanSvcHealthForTest)
	for i := 0; i < 50; i++ {
		svc := NewScanService("127.0.0.1:0")
		if err := svc.Listen(); err != nil {
			t.Fatalf("listen: %v", err)
		}
		started := make(chan struct{})
		go func() {
			close(started)
			_ = svc.Start()
		}()
		<-started
		if err := svc.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		// A second Shutdown must be safe: the registry can run twice on a
		// cancelled drain, and Stopped() is the supervisor's stop signal.
		if err := svc.Shutdown(t.Context()); err != nil {
			t.Fatalf("second Shutdown: %v", err)
		}
		if !svc.stoppedByShutdown() {
			t.Fatalf("stoppedByShutdown() false after Shutdown")
		}
	}
}

// TestChaos113_ListenAfterShutdownRefuses pins that the terminal state also
// blocks a REBIND. Without it the supervisor would bind a fresh socket onto a
// server that can never serve again — a held port nothing accepts on.
func TestChaos113_ListenAfterShutdownRefuses(t *testing.T) {
	resetScanSvcHealthForTest()
	t.Cleanup(resetScanSvcHealthForTest)
	svc := NewScanService("127.0.0.1:0")
	if err := svc.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := svc.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := svc.Listen(); !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("Listen() after Shutdown returned %v, want http.ErrServerClosed", err)
	}
}

// TestChaos113_ShutdownConcurrentWithListenLeaksNoSocket pins the window the
// post-bind stopped check exists for, and it exists because this round's own
// mutation sweep found the gate missing.
//
// `Listen` checks `stopped` TWICE: once before `net.Listen` (the fast path)
// and once after, under the lock, before publishing the socket. Removing
// EITHER check alone left every other gate green — correctly for the first,
// because the second is a real second barrier, and INCORRECTLY for the second,
// because the window it guards needs concurrency to reach: a `Shutdown` that
// reads `ss.listener` as nil, followed by a `Listen` that publishes a socket
// onto an already-stopped service, leaves a BOUND LISTENER that nothing will
// ever close or accept on. The port is then held for the life of the process —
// which is Defect 2's boot case for whatever tries to bind it next.
//
// The discriminator is that a bound-but-unserved socket still completes a TCP
// handshake from the kernel backlog, while a closed one refuses. So "the dial
// was refused" is the assertion that a leaked socket cannot pass.
func TestChaos113_ShutdownConcurrentWithListenLeaksNoSocket(t *testing.T) {
	resetScanSvcHealthForTest()
	t.Cleanup(func() {
		scanSvcListenHook = nil
		resetScanSvcHealthForTest()
	})

	svc := NewScanService("127.0.0.1:0")
	entered := make(chan struct{})
	release := make(chan struct{})
	scanSvcListenHook = func() {
		close(entered)
		<-release
	}

	listenErr := make(chan error, 1)
	go func() { listenErr <- svc.Listen() }()
	<-entered // Listen is past the pre-bind check and has not bound yet

	if err := svc.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	close(release) // Listen now binds and tries to publish onto a stopped service
	err := <-listenErr

	svc.mu.Lock()
	ln := svc.listener
	svc.mu.Unlock()
	t.Cleanup(func() {
		if ln != nil {
			_ = ln.Close()
		}
	})

	if err == nil {
		t.Errorf("Listen() returned nil for a service Shutdown had already stopped")
	}
	if ln == nil {
		return // nothing was published: the strongest outcome
	}
	// A socket WAS published. It must not be left accepting.
	c, derr := net.DialTimeout("tcp", ln.Addr().String(), 500*time.Millisecond)
	if derr == nil {
		_ = c.Close()
		t.Fatalf("%s still accepts connections after Shutdown — a bound socket was published onto a stopped service and leaked for the life of the process", ln.Addr())
	}
}

// TestChaos113_ControlShutdownAfterServeStillDrains is the control. The
// ordinary path — serve, then stop — must keep working, and in-flight work
// must be allowed to finish rather than severed.
func TestChaos113_ControlShutdownAfterServeStillDrains(t *testing.T) {
	resetScanSvcHealthForTest()
	t.Cleanup(resetScanSvcHealthForTest)
	svc := NewScanService("127.0.0.1:0")
	if err := svc.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := svc.Addr()
	done := make(chan error, 1)
	go func() { done <- svc.Start() }()

	waitForScanSvc(t, addr)
	if code, err := scanSvcProbe(t, addr); err != nil || code != http.StatusOK {
		t.Fatalf("healthy sidecar: code=%d err=%v", code, err)
	}

	if err := svc.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start() returned %v after a graceful Shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Start() did not return after Shutdown")
	}
	if _, err := scanSvcProbe(t, addr); err == nil {
		t.Errorf("sidecar still answering after a graceful Shutdown")
	}
}

// waitForScanSvc blocks until the sidecar answers /health, or fails the test.
func waitForScanSvc(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if code, err := scanSvcProbe(t, addr); err == nil && code == http.StatusOK {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("sidecar never answered /health on %s", addr)
}
