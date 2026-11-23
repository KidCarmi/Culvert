package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"
	"time"
)

// resetShutdownStartedForTest restores the process-wide flag: it is never
// cleared in production, and every later /ready test would see 503.
func resetShutdownStartedForTest(t *testing.T) {
	t.Helper()
	prev := shutdownStarted.Load()
	t.Cleanup(func() { shutdownStarted.Store(prev) })
}

// TestHandleReady_NotReadyOnceShutdownBegins: between SIGTERM and the moment
// the proxy listener closes the process still answers on its port. It must not
// answer "ready": a health gate that gets a yes there passes against a process
// that is already on its way out.
func TestHandleReady_NotReadyOnceShutdownBegins(t *testing.T) {
	resetShutdownStartedForTest(t)
	shutdownStarted.Store(false)

	_, _, before := readyChecks(t, "/ready")
	if _, present := before["shutdown"]; present {
		t.Fatalf("a serving node must not carry a shutdown row: %+v", before["shutdown"])
	}

	quit := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() { awaitShutdownSignal(quit); close(done) }()

	// Negative control: nothing changes until the signal arrives.
	time.Sleep(20 * time.Millisecond)
	if _, _, c := readyChecks(t, "/ready"); c["shutdown"] != nil {
		t.Fatal("shutdown row appeared before any signal")
	}

	quit <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("awaitShutdownSignal did not return after the signal")
	}

	code, status, after := readyChecks(t, "/ready")
	if code != http.StatusServiceUnavailable || status != "not_ready" {
		t.Fatalf("/ready after SIGTERM: code=%d status=%q, want 503/not_ready", code, status)
	}
	if row := after["shutdown"]; row == nil || row.Status != "fail" {
		t.Fatalf("shutdown row = %+v, want fail", row)
	}

	// Liveness is unchanged by the flag: the compose healthcheck (/health)
	// must not start failing merely because shutdown has begun.
	w := httptest.NewRecorder()
	handleHealth(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", http.NoBody))
	if w.Code != http.StatusOK {
		t.Errorf("/health during shutdown = %d, want 200", w.Code)
	}
}
