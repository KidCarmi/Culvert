package main

// Tests for arming the CDR health poller on a RUNTIME enable
// (ensureCDRHealthPoller / armCDRHealthPollerAtRuntime, cdr_health.go).
//
// Before the fix only loadCDR started the poller, and only when CDR was
// enabled at boot. A node that turned CDR on from the admin toggle (or by its
// first enrollment) served documents through the pool but ran no health
// probes, no client-certificate auto-renewal, no server-pin rotation and no
// re-dial until a restart.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// withCDRPollerLifecycle installs a cancellable process lifecycle context,
// resets the single-poller guard, and on cleanup cancels the context and
// waits for any poller this test started to return, so no round outlives the
// test and touches the next test's CDR globals.
func withCDRPollerLifecycle(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	resetPollerGuard := func() {
		cdrHealthPollerMu.Lock()
		cdrHealthPollerCtx = nil
		cdrHealthPollerDone = nil
		cdrHealthPollerMu.Unlock()
	}
	resetPollerGuard()
	atomic.StoreInt64(&cdrHealthFailures, 0)
	origCtx := appLifecycleCtx
	ctx, cancel := context.WithCancel(context.Background())
	appLifecycleCtx = ctx
	t.Cleanup(func() {
		cancel()
		waitCDRPollerExit(t)
		appLifecycleCtx = origCtx
		resetPollerGuard()
		atomic.StoreInt64(&cdrHealthFailures, 0)
	})
	return ctx, cancel
}

func waitCDRPollerExit(t *testing.T) {
	t.Helper()
	cdrHealthPollerMu.Lock()
	done := cdrHealthPollerDone
	cdrHealthPollerMu.Unlock()
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("CDR health poller did not exit after its lifecycle context was cancelled")
	}
}

func cdrPollerArmed() bool {
	cdrHealthPollerMu.Lock()
	defer cdrHealthPollerMu.Unlock()
	return cdrHealthPollerCtx != nil && cdrHealthPollerCtx.Err() == nil
}

func putCDRToggle(t *testing.T, enabled bool) {
	t.Helper()
	body := `{"enabled":false}`
	if enabled {
		body = `{"enabled":true}`
	}
	w := httptest.NewRecorder()
	apiCDRConfig(w, newAdminRequest(http.MethodPut, "/api/cdr/config", []byte(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/cdr/config %s: status %d; body=%s", body, w.Code, w.Body.String())
	}
}

// waitFirstHealthRound waits for the poller's immediate first round to probe
// the (unreachable) pool member and record the failure, the observable proof
// that health probing, and with it renewal and rotation, is running.
func waitFirstHealthRound(t *testing.T, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&cdrHealthFailures) > 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// TestCDRRuntimePoller_ToggleEnableStartsHealthProbing is the reproduction and
// the fix: a node that boots with CDR disabled and is enabled from the admin
// toggle now runs the health poller, whose first round probes the pool at
// once. On the baseline nothing probed the member until a restart.
func TestCDRRuntimePoller_ToggleEnableStartsHealthProbing(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	withRedialGate(t)
	withCDRPollerLifecycle(t)

	name := "rt-poller-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	dir := filepath.Join(t.TempDir(), "bundle")
	writeRedialBundle(t, dir)
	enrollRedialInstance(t, name, dir, true)

	if cdrPollerArmed() {
		t.Fatal("precondition: no poller may run while CDR is disabled")
	}
	putCDRToggle(t, true)

	if got := redialPoolNames(); len(got) != 1 || got[0] != name {
		t.Fatalf("toggle enable did not build the pool: %v", got)
	}
	if !cdrPollerArmed() {
		t.Fatal("runtime enable left the node without a health poller: no health probes, auto-renewal or re-dial until restart")
	}
	if !waitFirstHealthRound(t, 10*time.Second) {
		t.Fatal("the armed poller never probed the pool member")
	}
}

// TestCDRRuntimePoller_FirstEnrollmentAutoEnableArmsPoller: the GUI's first
// enrollment auto-enables CDR, and with it now arms the poller, so the new
// instance's client certificate will auto-renew without a restart. When the
// auto-enable cannot persist (CDR stays disabled) nothing is armed.
func TestCDRRuntimePoller_FirstEnrollmentAutoEnableArmsPoller(t *testing.T) {
	enroll := func(t *testing.T, name string) {
		t.Helper()
		dir, _ := cdrInstanceCertsDir(name)
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			t.Skipf("cannot write %s: %v", dir, err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		pemBytes, _ := tlRenewedCert(t)
		tlStubEnroll(t, func(context.Context, string, string, string, string) (*pb.EnrollResponse, error) {
			return &pb.EnrollResponse{CaCert: pemBytes, ClientCert: pemBytes, ClientKey: pemBytes}, nil
		})
		w := httptest.NewRecorder()
		apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", tl2EnrollBody(name, "127.0.0.1:1", "")))
		if w.Code != http.StatusOK {
			t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
		}
	}
	t.Run("auto-enable arms", func(t *testing.T) {
		resetCDRState(t)
		redirectSentinelToTempDir(t)
		withCDRPollerLifecycle(t)
		enroll(t, "cdr-rt-poller-enroll")
		if !cdrActiveConfig().Enabled {
			t.Fatal("precondition: first enrollment must auto-enable CDR")
		}
		if !cdrPollerArmed() {
			t.Fatal("first-enrollment auto-enable left the node without a health poller")
		}
	})
	t.Run("failed auto-enable arms nothing", func(t *testing.T) {
		resetCDRState(t)
		withCDRPollerLifecycle(t)
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		orig := cdrRuntimeEnabledPath
		cdrRuntimeEnabledPath = filepath.Join(blocker, "cdr_enabled")
		t.Cleanup(func() { cdrRuntimeEnabledPath = orig })
		enroll(t, "cdr-rt-poller-enroll-noenable")
		if cdrActiveConfig().Enabled {
			t.Fatal("precondition: the sentinel failure must leave CDR disabled")
		}
		if cdrPollerArmed() {
			t.Fatal("armed the poller although CDR stayed disabled")
		}
	})
}

// TestCDRRuntimePoller_ToggleRecoversFailedBuildViaRedial proves the armed
// poller carries the re-dial too: a toggle whose pool build skipped an
// instance (unreadable bundle) recovers on the poller's first round once the
// bundle is readable, with the toggle's config left as published.
func TestCDRRuntimePoller_ToggleRecoversFailedBuildViaRedial(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	withRedialGate(t)
	ctx, _ := withCDRPollerLifecycle(t)

	name := "rt-redial-" + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	dir := filepath.Join(t.TempDir(), "not-mounted-yet")
	enrollRedialInstance(t, name, dir, true)

	// Arm the guard under the lifecycle ctx BEFORE the toggle can, with a
	// poller started only after the bundle is readable, so the first round
	// deterministically sees a readable bundle. The toggle's own arm is then
	// the no-op second call, which is also what this asserts.
	appLifecycleCtx = nil
	putCDRToggle(t, true)
	appLifecycleCtx = ctx
	if got := redialPoolNames(); len(got) != 0 {
		t.Fatalf("precondition: unreadable bundle must leave the pool empty, got %v", got)
	}
	cfgBefore := cdrActiveConfig()
	writeRedialBundle(t, dir)
	if !ensureCDRHealthPoller(appLifecycleCtx) {
		t.Fatal("first arm under a live lifecycle must start the poller")
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(redialPoolNames()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := redialPoolNames(); len(got) != 1 || got[0] != name {
		t.Fatalf("armed poller did not re-dial the skipped instance: %v", got)
	}
	if cdrActiveConfig() != cfgBefore {
		t.Fatalf("re-dial changed the active config: before %+v after %+v", cfgBefore, cdrActiveConfig())
	}
	// A further toggle enable is a no-op for the poller.
	putCDRToggle(t, true)
	if ensureCDRHealthPoller(appLifecycleCtx) {
		t.Fatal("a second poller was started under the same live lifecycle")
	}
}

// TestCDRRuntimePoller_Refusals: the arm starts nothing outside a live
// lifecycle, on a disable, or a second time.
func TestCDRRuntimePoller_Refusals(t *testing.T) {
	t.Run("toggle disable arms nothing", func(t *testing.T) {
		resetCDRState(t)
		redirectSentinelToTempDir(t)
		withCDRPollerLifecycle(t)
		putCDRToggle(t, false)
		if cdrPollerArmed() {
			t.Fatal("a runtime DISABLE started the health poller")
		}
	})
	t.Run("no lifecycle context wired", func(t *testing.T) {
		resetCDRState(t)
		redirectSentinelToTempDir(t)
		withCDRPollerLifecycle(t)
		appLifecycleCtx = nil
		putCDRToggle(t, true)
		if cdrPollerArmed() {
			t.Fatal("armed a poller with no lifecycle context to stop it")
		}
	})
	t.Run("lifecycle already cancelled (shutdown in progress)", func(t *testing.T) {
		resetCDRState(t)
		redirectSentinelToTempDir(t)
		_, cancel := withCDRPollerLifecycle(t)
		cancel()
		putCDRToggle(t, true)
		if cdrPollerArmed() {
			t.Fatal("armed a poller after the lifecycle was cancelled")
		}
		cdrHealthPollerMu.Lock()
		started := cdrHealthPollerDone != nil
		cdrHealthPollerMu.Unlock()
		if started {
			t.Fatal("a poller goroutine was started under a cancelled lifecycle")
		}
	})
}

// TestCDRRuntimePoller_OnePollerPerLifecycle: concurrent enables, a
// boot-armed node toggled again, and disable/enable cycles never start a
// second poller; a NEW lifecycle (after the old one ended) may start one.
func TestCDRRuntimePoller_OnePollerPerLifecycle(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	ctx, cancel := withCDRPollerLifecycle(t)

	// Boot path: loadCDR's arm.
	if !ensureCDRHealthPoller(ctx) {
		t.Fatal("boot arm did not start the poller")
	}
	var started atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ensureCDRHealthPoller(ctx) {
				started.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := started.Load(); n != 0 {
		t.Fatalf("%d extra pollers started under one live lifecycle", n)
	}
	putCDRToggle(t, true)
	putCDRToggle(t, false)
	putCDRToggle(t, true)
	if ensureCDRHealthPoller(ctx) {
		t.Fatal("disable/enable cycle left the guard re-armable under the same lifecycle")
	}

	// The lifecycle ends: the poller exits, and a fresh lifecycle may arm.
	cancel()
	waitCDRPollerExit(t)
	next, nextCancel := context.WithCancel(context.Background())
	defer func() { nextCancel(); waitCDRPollerExit(t) }()
	if !ensureCDRHealthPoller(next) {
		t.Fatal("a new lifecycle could not start a poller after the previous one ended")
	}
}
