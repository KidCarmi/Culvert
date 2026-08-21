package main

// CHAOS-50 — the Root-CA load failure must have a RECOVERY path.
//
// CHAOS-06 made the failure visible and CHAOS-28 made an EXPIRED CA fail closed.
// Neither gave a failed LOAD a way back: the bundle was read once at startup, the
// recorded failure was never cleared, and the auto-rotation loop — which drives
// the cluster CA too — was skipped entirely when the inspection CA did not load.
// These tests pin each half.

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// swapInspectionCA isolates the process-global inspection CA and the recorded
// load failure for one test.
func swapInspectionCA(t *testing.T) {
	t.Helper()
	prev := certMgr
	prevErr := sslInspectionLoadFailure()
	// loadRootCA publishes caRuntime; restore it so a shuffled run cannot leave
	// another test's persistRotatedCA pointed at this test's temp dir.
	prevRuntime := caRuntime
	certMgr = ca.New()
	sslInspectionLoadError.Store("")
	resetCALoadRecoveryForTest()
	resetCAUsabilityHealthForTest()
	t.Cleanup(func() {
		certMgr = prev
		caRuntime = prevRuntime
		sslInspectionLoadError.Store(prevErr)
		resetCALoadRecoveryForTest()
		resetCAUsabilityHealthForTest()
	})
}

// fastCARetries compresses the retry schedule so a test exercises the campaign
// without sleeping the real one.
//
// The loop SNAPSHOTS these on the caller's goroutine (see caRetrySchedule), so
// restoring them in cleanup cannot race a still-running loop. Every test that
// arms the loop must still call awaitCARecoveryTerminal before returning — the
// loop reads OTHER process globals (certMgr) that cleanup also restores.
func fastCARetries(t *testing.T, budget int) {
	t.Helper()
	pi, pm, pb := caLoadRetryInitial, caLoadRetryMax, caLoadRetryBudget
	caLoadRetryInitial = 5 * time.Millisecond
	caLoadRetryMax = 20 * time.Millisecond
	caLoadRetryBudget = budget
	t.Cleanup(func() {
		caLoadRetryInitial, caLoadRetryMax, caLoadRetryBudget = pi, pm, pb
	})
}

// awaitCARecoveryTerminal blocks until the recovery campaign has reached a state
// after which it touches no swapped global — it has either recovered or given up,
// and both are set after the last certMgr access.
func awaitCARecoveryTerminal(t *testing.T) {
	t.Helper()
	waitForCA(t, "the recovery campaign to reach a terminal state", 15*time.Second, func() bool {
		rec := caLoadRecoveryStatus()
		return rec.Recovered || rec.GaveUp
	})
}

// awaitFirstRotationRound arms the round observer BEFORE the loop starts (it is
// snapshotted at StartCAAutoRotation) and returns a wait function. Without it a
// test that swaps globalClusterCA/certMgr would restore them while the round is
// still reading them.
func awaitFirstRotationRound(t *testing.T) func() {
	t.Helper()
	prev := caRotationRoundObserver
	done := make(chan struct{})
	var once sync.Once
	caRotationRoundObserver = func() { once.Do(func() { close(done) }) }
	t.Cleanup(func() { caRotationRoundObserver = prev })
	return func() {
		t.Helper()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatal("auto-rotation round did not complete")
		}
	}
}

func writeCorruptBundle(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.bundle")
	if err := os.WriteFile(path, []byte("not a PEM bundle"), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

func writeGoodBundle(t *testing.T, path string) {
	t.Helper()
	src := ca.New()
	if err := src.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if err := src.SaveCA(path, ""); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}
}

func waitForCA(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestChaos50_RotationLoopStartsDespiteInspectionCAFailure is the coupling gate.
// StartCAAutoRotation drives BOTH the inspection CA and the CLUSTER CA; gating it
// on certMgr.Ready() meant a corrupt inspection bundle silently disabled cluster
// CA rotation (enrollment / CP↔DP mTLS) for the life of the process.
func TestChaos50_RotationLoopStartsDespiteInspectionCAFailure(t *testing.T) {
	swapInspectionCA(t)
	captureStartupAlerts(t)
	fastCARetries(t, 1)

	cca := installGlobalClusterCA(t)
	awaitRound := awaitFirstRotationRound(t)
	// A cluster CA inside its 30-day rotation window: the loop must rotate it.
	certPEM, keyPEM, cert := newClusterCAPair(t, "Culvert Cluster CA", 10*24*time.Hour)
	key, err := parseAndValidateCAKey(keyPEM, cert.PublicKey.(*ecdsa.PublicKey))
	if err != nil {
		t.Fatalf("parse cluster CA key: %v", err)
	}
	cca.mu.Lock()
	cca.cert, cca.certPEM, cca.key = cert, certPEM, key
	was := cert.NotAfter
	cca.mu.Unlock()

	loadRootCA(rootCAStartupConfig{Path: writeCorruptBundle(t)}, t.Context())

	if certMgr.Ready() {
		t.Fatal("precondition: the corrupt bundle must fail to load")
	}
	waitForCA(t, "cluster CA auto-rotation", 15*time.Second, func() bool {
		cca.mu.RLock()
		defer cca.mu.RUnlock()
		return !cca.cert.NotAfter.Equal(was)
	})
	// Both spawned loops must be done touching the swapped globals before this
	// test returns and cleanup restores them.
	awaitRound()
	awaitCARecoveryTerminal(t)
}

// TestChaos50_TransientLoadFailureSelfHeals: the bundle becomes readable again
// (volume attached late, permissions fixed, disk freed) and the appliance
// re-reads it instead of waiting for a restart.
func TestChaos50_TransientLoadFailureSelfHeals(t *testing.T) {
	swapInspectionCA(t)
	captureStartupAlerts(t)
	fastCARetries(t, 20)

	path := writeCorruptBundle(t)
	loadRootCA(rootCAStartupConfig{Path: path}, t.Context())
	if certMgr.Ready() {
		t.Fatal("precondition: load must fail")
	}
	if sslInspectionLoadFailure() == "" {
		t.Fatal("precondition: the failure must be recorded")
	}

	writeGoodBundle(t, path) // the fault clears

	waitForCA(t, "inspection CA recovery", 10*time.Second, certMgr.Ready)
	waitForCA(t, "recorded failure to clear", 10*time.Second, func() bool {
		return sslInspectionLoadFailure() == ""
	})
	awaitCARecoveryTerminal(t)
	if rec := caLoadRecoveryStatus(); !rec.Recovered || rec.Attempts == 0 {
		t.Errorf("recovery not recorded: %+v", rec)
	}
}

// TestChaos50_RecoveryNeverMintsANewRoot is the security half. LoadOrInitCA
// GENERATES a root when the path is absent, which is right on first boot and
// catastrophic on a retry: if the fault is an unmounted volume, a minting retry
// silently replaces the fleet's trust anchor with one no client trusts and writes
// it to ephemeral storage. Recovery must re-read the configured bundle only.
func TestChaos50_RecoveryNeverMintsANewRoot(t *testing.T) {
	swapInspectionCA(t)
	captureStartupAlerts(t)
	fastCARetries(t, 3)

	dir := t.TempDir()
	path := filepath.Join(dir, "ca.bundle")
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadRootCA(rootCAStartupConfig{Path: path}, t.Context())
	if certMgr.Ready() {
		t.Fatal("precondition: load must fail")
	}

	// The "volume disappeared" shape: the bundle path is now absent.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	waitForCA(t, "recovery to give up", 10*time.Second, func() bool {
		return caLoadRecoveryStatus().GaveUp
	})
	if certMgr.Ready() {
		t.Error("recovery MINTED a new Root CA against a missing bundle — the fleet's trust anchor must never be replaced by a timer")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("recovery wrote a new bundle to a path whose volume is gone (stat err = %v)", err)
	}
	if sslInspectionLoadFailure() == "" {
		t.Error("an unrecovered load failure must stay recorded")
	}
}

// TestChaos50_RecoveryIsBounded: no infinite retries.
func TestChaos50_RecoveryIsBounded(t *testing.T) {
	swapInspectionCA(t)
	captureStartupAlerts(t)
	fastCARetries(t, 4)

	loadRootCA(rootCAStartupConfig{Path: writeCorruptBundle(t)}, t.Context())

	waitForCA(t, "recovery to give up", 10*time.Second, func() bool {
		return caLoadRecoveryStatus().GaveUp
	})
	rec := caLoadRecoveryStatus()
	if rec.Attempts != 4 {
		t.Errorf("attempts = %d, want exactly the budget (4)", rec.Attempts)
	}
	// And it must STAY stopped.
	time.Sleep(200 * time.Millisecond)
	if got := caLoadRecoveryStatus().Attempts; got != 4 {
		t.Errorf("attempts kept climbing after the budget: %d", got)
	}
}

// TestChaos50_HealthClearsOnRecoveryEvidence: the recorded failure used to be
// write-only, so /healthz, /readyz?strict=1 and the support-telemetry readiness
// row stayed red after the operator had actually fixed the CA — a probe that
// outlives its fault. Recovery must be reported on evidence, and evidence must
// clear it.
func TestChaos50_HealthClearsOnRecoveryEvidence(t *testing.T) {
	swapInspectionCA(t)
	captureStartupAlerts(t)

	noteSSLInspectionUnavailable("/data/ca.bundle", os.ErrPermission)
	if got := computeHealth().SSLInspection; got != "load_failed" {
		t.Fatalf("precondition: ssl_inspection = %q, want load_failed", got)
	}

	if err := certMgr.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	noteSSLInspectionRecovered("test recovery")

	if got := computeHealth().SSLInspection; got != "ready" {
		t.Errorf("/healthz ssl_inspection = %q after recovery, want ready", got)
	}
	// Assert on the `ca` ROW, not on the overall strict verdict: other rows
	// (ClamAV, policy) legitimately fail in a unit-test process, and the claim
	// here is specifically that the CA row stops failing. Pre-fix it stayed
	// "fail" — which is what made /readyz?strict=1 a permanent 503.
	report, _ := computeReadiness()
	caRow, ok := report.Checks["ca"]
	if !ok {
		t.Fatal("no ca readiness row after recovery")
	}
	if caRow.Status != "ok" {
		t.Errorf("readiness ca row = %q (%s) after recovery, want ok", caRow.Status, caRow.Detail)
	}

	// The pre-fix state, for contrast: while the failure is recorded the row
	// fails and the strict verdict is 503.
	noteSSLInspectionUnavailable("/data/ca.bundle", os.ErrPermission)
	report, _ = computeReadiness()
	if report.Checks["ca"].Status != "fail" {
		t.Error("a recorded load failure must fail the ca readiness row")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz?strict=1", http.NoBody)
	handleReady(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz?strict=1 = %d with a live CA load failure, want 503", rec.Code)
	}
}

// TestChaos50_RecoveryClearsOnlyOnRealEvidence: silence is not recovery. Nothing
// may clear the latch except an observed success.
func TestChaos50_RecoveryClearsOnlyOnRealEvidence(t *testing.T) {
	swapInspectionCA(t)
	captureStartupAlerts(t)

	noteSSLInspectionUnavailable("/data/ca.bundle", os.ErrPermission)
	// A no-op caller must not clear it.
	if sslInspectionLoadFailure() == "" {
		t.Fatal("precondition")
	}
	if got := computeHealth().SSLInspection; got != "load_failed" {
		t.Errorf("ssl_inspection = %q, want load_failed", got)
	}
	// And clearing when there is nothing recorded must not fabricate a recovery.
	sslInspectionLoadError.Store("")
	resetCALoadRecoveryForTest()
	noteSSLInspectionRecovered("no fault to recover from")
	if caLoadRecoveryStatus().Recovered {
		t.Error("recovery recorded with no prior failure")
	}
}

// TestChaos50_InspectMatchedBypassIsCounted: the fail-OPEN direction. An expired
// CA moves culvert_ca_inspect_blocked_total; a CA that never loaded moved nothing
// at all, even though that is the direction where DLP/AV/YARA/CDR/DPI are off.
func TestChaos50_InspectMatchedBypassIsCounted(t *testing.T) {
	swapInspectionCA(t) // no CA installed => certMgr.Ready() == false
	resetCALoadRecoveryForTest()

	before := caInspectBypassCount()
	dec := sslResolution{Action: SSLInspect, Source: decryptobs.DecisionPolicyInspect}
	id := ProxyIdentity{ClientIP: "198.51.100.9"}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://chaos50.invalid:443", http.NoBody)
	r.Host = "chaos50.invalid:443"
	w := httptest.NewRecorder()

	// The counter is incremented at the dispatch decision, BEFORE the bypass
	// relay tries to reach the (deliberately unresolvable) origin — so assert on
	// the decision without waiting for the dial to fail.
	go handleTunnel(w, r, dec, nil, id)
	waitForCA(t, "the fail-open bypass to be counted", 10*time.Second, func() bool {
		return caInspectBypassCount() == before+1
	})

	if got := caInspectBypassCount(); got != before+1 {
		t.Errorf("inspect-matched bypass counter = %d, want %d", got, before+1)
	}
	if got := caUsabilityFailures().Blocks; got != 0 {
		t.Errorf("a CA that never loaded must not be counted as a fail-CLOSED block: %d", got)
	}
}

// TestChaos50_MetricsExposeLoadPosture: `ready:false` alone cannot distinguish
// "no CA configured here" from "the configured CA failed and traffic is leaving
// uninspected". The load series must say which.
func TestChaos50_MetricsExposeLoadPosture(t *testing.T) {
	swapInspectionCA(t)
	captureStartupAlerts(t)

	var sb strings.Builder
	caWriteLoadFailurePrometheus(&sb)
	if !strings.Contains(sb.String(), "culvert_ca_load_failed 0") {
		t.Errorf("healthy node should report culvert_ca_load_failed 0:\n%s", sb.String())
	}

	noteSSLInspectionUnavailable("/data/ca.bundle", os.ErrPermission)
	noteCAInspectUnavailableBypass()

	sb.Reset()
	caWriteLoadFailurePrometheus(&sb)
	out := sb.String()
	for _, want := range []string{
		"culvert_ca_load_failed 1",
		"culvert_ca_inspect_bypassed_total 1",
		"culvert_ca_load_recovery_attempts_total",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestChaos50_CAStatusSurfacesLoadPosture pins the admin-API half of the same
// distinction (the CA panel keys on these fields).
func TestChaos50_CAStatusSurfacesLoadPosture(t *testing.T) {
	swapInspectionCA(t)
	captureStartupAlerts(t)
	noteSSLInspectionUnavailable("/data/ca.bundle", os.ErrPermission)
	noteCAInspectUnavailableBypass()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/ca/status", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	apiCAStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`"loadFailed":true`, `"loadFailureReason"`, `"inspectBypassed":1`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in /api/ca/status:\n%s", want, body)
		}
	}
}

// TestChaos50_ManualRecoveryIsNotOverwrittenByRetry is the review follow-up
// (Codex P1). Installing a CA is a multi-step operation — read/generate, install,
// persist, clear the latch — and the automatic retry and the admin force-rotate
// both perform it. Un-serialized, the retry can read the OLD bundle, the admin
// can install and persist a NEW one, and the retry then installs its buffered old
// CA on top: the API reports "persisted: true" (true, on disk) while the LIVE
// process signs with the superseded root, so every client the operator just
// provisioned with the new root rejects every leaf until a restart.
//
// The invariant asserted here is exactly that disagreement: the in-memory CA and
// the on-disk bundle must never diverge, however the two paths interleave.
func TestChaos50_ManualRecoveryIsNotOverwrittenByRetry(t *testing.T) {
	swapInspectionCA(t)
	captureStartupAlerts(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "ca.bundle")
	writeGoodBundle(t, path) // a readable bundle, so LoadCA succeeds and can race
	cfg := rootCAStartupConfig{Path: path}
	caRuntime.path = path
	caRuntime.passphrase = ""

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Keep a fault recorded so the attempt is never short-circuited.
			noteSSLInspectionUnavailable(path, os.ErrPermission)
			_, _ = tryInspectionCARecovery(cfg, 1)
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := installAndPersistRotatedCA(); err != nil {
				t.Errorf("installAndPersistRotatedCA: %v", err)
			}
		}()
	}
	wg.Wait()

	// Whatever won, the process and its disk must agree.
	onDisk := ca.New()
	if err := onDisk.LoadCA(path, ""); err != nil {
		t.Fatalf("bundle unreadable after the race: %v", err)
	}
	live := certMgr.CACertInfo()["fingerprint"]
	persisted := onDisk.CACertInfo()["fingerprint"]
	if live != persisted {
		t.Errorf("live Root CA %v != persisted Root CA %v — a recovery attempt overwrote a manual one "+
			"(the admin was told the rotation landed; the process is signing with a different root)",
			live, persisted)
	}
}
