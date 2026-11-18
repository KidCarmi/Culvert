package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// isolateRequestLogOpenRetry gives the test clean request-log engine state and
// configured path, an unopenable path (missing directory), and closes whatever
// sink the loop opened.
func isolateRequestLogOpenRetry(t *testing.T) (dir, path string) {
	t.Helper()
	restoreRing := reqlog.SwapRingForTest()
	reqlog.ResetForTest()
	prev := requestLogConfiguredPath
	t.Cleanup(func() {
		_ = reqlog.Close()
		reqlog.ResetForTest()
		restoreRing()
		requestLogConfiguredPath = prev
	})
	dir = filepath.Join(t.TempDir(), "not-yet")
	return dir, filepath.Join(dir, "requests.jsonl")
}

// The operator-visible reproduction, through the real boot path: startup could
// not open the configured request log, the operator fixes the directory, and
// the log becomes durable with no restart. The diagnostics row turns healthy
// only once the file is actually published, and the automatic open is
// attributed to system.
func TestRequestLogOpenRetry_CompletesAStartupFailureWithoutRestart(t *testing.T) {
	dir, path := isolateRequestLogOpenRetry(t)
	loadObservability(observabilityStartupConfig{RequestLogPath: path, RequestLogMaxMB: 7})
	if reqlog.PersistActive() {
		t.Fatal("precondition: the startup open must fail")
	}
	if reqlog.DeferredOpenPending() != path {
		t.Fatalf("the boot path did not arm the deferred open (pending=%q)", reqlog.DeferredOpenPending())
	}
	if c := checkRequestLogPersistence(); c.Status != diagFail {
		t.Fatalf("diagnostics = %v before the open, want fail", c.Status)
	}

	var attempts atomic.Int32
	delay := func(attempt int) time.Duration {
		attempts.Add(1)
		if attempt == 1 {
			// The first retry failed; the operator now fixes the volume. The
			// row must still be failed: an attempt was scheduled, not made good.
			if c := checkRequestLogPersistence(); c.Status != diagFail {
				t.Errorf("diagnostics = %v after a failed attempt, want fail", c.Status)
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Error(err)
			}
		}
		return 0
	}
	done := make(chan struct{})
	go func() { runRequestLogOpenRetry(context.Background(), delay); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry loop did not finish after the path became writable")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2 (one failure, one success)", got)
	}
	if !reqlog.PersistActive() || reqlog.FilePath() != path {
		t.Fatalf("the request log is not persisting to the configured path (active=%v path=%q)",
			reqlog.PersistActive(), reqlog.FilePath())
	}
	if c := checkRequestLogPersistence(); c.Status != diagOK {
		t.Fatalf("diagnostics = %v after the open, want ok", c.Status)
	}
	if _, ok := findAuditByActionObject(t, "request_log.persistence.auto_open", path); !ok {
		t.Fatal("no system audit entry for the automatic open")
	}
	e, _ := findAuditByActionObject(t, "request_log.persistence.auto_open", path)
	if e.Actor != "system" {
		t.Fatalf("automatic open attributed to %q, want system", e.Actor)
	}

	reqlog.Add(reqlog.Entry{Host: "live-after-open.example"})
	reqlog.Sync()
	data, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"live-after-open.example"`) {
		t.Fatalf("a live entry did not reach the file:\n%s", data)
	}
}

// Unchanged success path: a startup open that succeeds arms nothing, and the
// loop returns at once without waiting.
func TestRequestLogOpenRetry_SuccessfulStartupArmsNothing(t *testing.T) {
	dir, path := isolateRequestLogOpenRetry(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	loadObservability(observabilityStartupConfig{RequestLogPath: path, RequestLogMaxMB: 7})
	if !reqlog.PersistActive() {
		t.Fatal("precondition: the startup open must succeed")
	}
	if p := reqlog.DeferredOpenPending(); p != "" {
		t.Fatalf("a successful startup armed a deferred open (%q)", p)
	}
	called := false
	runRequestLogOpenRetry(context.Background(), func(int) time.Duration { called = true; return 0 })
	if called {
		t.Fatal("the loop waited although no deferred open is armed")
	}
}

// Restraint: no request log configured means nothing armed, no loop wait.
func TestRequestLogOpenRetry_IdleWhenNotConfigured(t *testing.T) {
	_, _ = isolateRequestLogOpenRetry(t)
	loadObservability(observabilityStartupConfig{})
	called := false
	runRequestLogOpenRetry(context.Background(), func(int) time.Duration { called = true; return 0 })
	if called {
		t.Fatal("the loop waited although no request log is configured")
	}
	if reqlog.PersistActive() {
		t.Fatal("a sink was published with no request log configured")
	}
}

// Shutdown: a cancelled lifecycle ends the loop while it waits, and nothing is
// published afterwards even if the path becomes writable.
func TestRequestLogOpenRetry_StopsOnCancelAndPublishesNothing(t *testing.T) {
	dir, path := isolateRequestLogOpenRetry(t)
	armRequestLogDeferredOpen(path, 0)
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		runRequestLogOpenRetry(ctx, func(int) time.Duration {
			waiting <- struct{}{}
			return time.Hour
		})
		close(done)
	}()
	<-waiting
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry loop ignored cancellation")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if !attemptRequestLogOpenRetry(ctx, 1) {
		t.Fatal("an attempt on a cancelled lifecycle must end the loop")
	}
	if reqlog.PersistActive() {
		t.Fatal("a sink was published after the lifecycle was cancelled")
	}
}

// Shutdown hook ordering: once the request-log-close hook has run, an armed
// retry does nothing and the loop ends.
func TestRequestLogOpenRetry_RefusedAfterTheShutdownHookClosedTheLog(t *testing.T) {
	dir, path := isolateRequestLogOpenRetry(t)
	armRequestLogDeferredOpen(path, 0)
	if err := reqlog.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		runRequestLogOpenRetry(context.Background(), func(int) time.Duration { return 0 })
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry loop kept running after the log was closed")
	}
	if reqlog.PersistActive() {
		t.Fatal("a sink was published after the shutdown hook closed the log")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the refused attempt created the file (stat err=%v)", err)
	}
}

// The diagnostics remedy no longer tells the operator to restart.
func TestCheckRequestLogPersistence_ActionNoLongerRequiresRestart(t *testing.T) {
	_, path := isolateRequestLogOpenRetry(t)
	requestLogConfiguredPath = path
	c := checkRequestLogPersistence()
	if c.Status != diagFail {
		t.Fatalf("status = %v, want fail while the log is not persisting", c.Status)
	}
	if strings.Contains(c.OperatorAction, "restart the proxy") {
		t.Fatalf("operator action still requires a restart: %q", c.OperatorAction)
	}
	if c.OperatorAction == "" {
		t.Fatal("the failed row lost its operator action")
	}
}
