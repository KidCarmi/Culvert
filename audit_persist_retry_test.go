package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// isolateAuditOpenRetry gives the test clean audit engine state and closes
// whatever sink the loop opened.
func isolateAuditOpenRetry(t *testing.T) (dir, path string) {
	t.Helper()
	restoreErrs := audit.ResetWriteErrorsForTest()
	restore := audit.ResetForTest()
	t.Cleanup(func() {
		_ = audit.Close()
		restore()
		restoreErrs()
	})
	dir = filepath.Join(t.TempDir(), "not-yet")
	return dir, filepath.Join(dir, "audit.jsonl")
}

// The operator-visible reproduction: startup could not open the configured
// audit log, the operator fixes the directory, and the trail becomes durable
// with no restart — the entries recorded meanwhile first, then a
// system-attributed marker, then live writes.
func TestAuditOpenRetry_CompletesAStartupFailureWithoutRestart(t *testing.T) {
	dir, path := isolateAuditOpenRetry(t)
	if err := InitAuditLog(path); err == nil {
		t.Fatal("precondition: the startup open must fail")
	}
	armAuditDeferredOpen(path)
	auditSystem("test.before_open", "obj-before", "recorded while the log was unopenable")

	var attempts atomic.Int32
	delay := func(attempt int) time.Duration {
		attempts.Add(1)
		if attempt == 1 {
			// The first retry failed; the operator now fixes the volume.
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Error(err)
			}
		}
		return 0
	}
	done := make(chan struct{})
	go func() { runAuditOpenRetry(context.Background(), delay); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the retry loop did not finish after the path became writable")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2 (one failure, one success)", got)
	}
	if !audit.PersistActive() {
		t.Fatal("the audit log is still not persisting")
	}
	auditSystem("test.after_open", "obj-after", "live write")

	data, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	before := strings.Index(s, `"test.before_open"`)
	marker := strings.Index(s, `"audit.persistence.auto_open"`)
	after := strings.Index(s, `"test.after_open"`)
	if before < 0 || marker < 0 || after < 0 || before >= marker || marker >= after {
		t.Fatalf("file order wrong (before=%d marker=%d after=%d):\n%s", before, marker, after, s)
	}
	if !strings.Contains(s, `"actor":"system"`) {
		t.Fatalf("the automatic open is not attributed to system:\n%s", s)
	}
	if audit.WriteErrors() != 0 {
		t.Fatalf("WriteErrors = %d, want 0", audit.WriteErrors())
	}
}

// Restraint: nothing armed means no loop, no timer, no file.
func TestAuditOpenRetry_IdleWhenNothingIsPending(t *testing.T) {
	_, path := isolateAuditOpenRetry(t)
	called := false
	runAuditOpenRetry(context.Background(), func(int) time.Duration { called = true; return 0 })
	if called {
		t.Fatal("the loop waited although no deferred open is armed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a file was created with nothing armed (stat err=%v)", err)
	}
}

// Shutdown: a cancelled lifecycle ends the loop while it waits, and nothing
// is published afterwards even if the path becomes writable.
func TestAuditOpenRetry_StopsOnCancelAndPublishesNothing(t *testing.T) {
	dir, path := isolateAuditOpenRetry(t)
	armAuditDeferredOpen(path)
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		runAuditOpenRetry(ctx, func(int) time.Duration {
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
	if attemptAuditOpenRetry(ctx, 1) != true {
		t.Fatal("an attempt on a cancelled lifecycle must end the loop")
	}
	if audit.PersistActive() {
		t.Fatal("a sink was published after the lifecycle was cancelled")
	}
}

// Shutdown hook ordering: once Close has run, an armed retry does nothing.
func TestAuditOpenRetry_RefusedAfterTheShutdownHookClosedTheTrail(t *testing.T) {
	dir, path := isolateAuditOpenRetry(t)
	armAuditDeferredOpen(path)
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if !attemptAuditOpenRetry(context.Background(), 1) {
		t.Fatal("an attempt after Close must report the loop finished")
	}
	if audit.PersistActive() {
		t.Fatal("a sink was published after the shutdown hook")
	}
}

// The diagnostics row no longer sends the operator to restart.
func TestCheckAuditPersistence_ActionNoLongerRequiresRestart(t *testing.T) {
	restore := audit.ResetForTest()
	t.Cleanup(restore)
	old := auditLogConfiguredPath
	auditLogConfiguredPath = "/nonexistent/audit.jsonl"
	t.Cleanup(func() { auditLogConfiguredPath = old })
	c := checkAuditPersistence()
	if c.Status != diagFail {
		t.Fatalf("status = %v, want fail while the log is not persisting", c.Status)
	}
	if strings.Contains(c.OperatorAction, "restart") && !strings.Contains(c.OperatorAction, "No restart") {
		t.Fatalf("operator action still requires a restart: %q", c.OperatorAction)
	}
}
