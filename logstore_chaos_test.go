package main

// logstore_chaos_test.go — CHAOS-57 gates for the composition root's half of
// the request-history recovery.
//
// The engine gates (internal/logstore) prove the store recovers. These prove
// the appliance NOTICES: a degradation nobody can see is the failure mode the
// register's §1 theme is about, and this store's degradations were previously
// a single WARN line in a log an operator has no reason to be reading.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/logstore"
)

const chaosHistoryPass = "history chaos passphrase"

// withHistoryStore isolates the process-wide history singleton and the health
// record for one test.
func withHistoryStore(t *testing.T) string {
	t.Helper()
	oldStore := globalLogStore.Load()
	oldDir, oldPass := logStoreDir, logStorePassphrase
	dir := filepath.Join(t.TempDir(), "history")
	logStoreDir = dir
	logStorePassphrase = chaosHistoryPass
	t.Cleanup(func() {
		disableLogStore()
		globalLogStore.Store(oldStore)
		logStoreDir, logStorePassphrase = oldDir, oldPass
		resetLogStoreHealthForTest()
	})
	resetLogStoreHealthForTest()
	return dir
}

// seedRootHistory creates a populated, cleanly-closed store at dir.
func seedRootHistory(t *testing.T, dir string) {
	t.Helper()
	if err := enableLogStore(context.Background(), dir, 0, 0); err != nil {
		t.Fatalf("seed enable: %v", err)
	}
	if ls := globalLogStore.Load(); ls != nil {
		for i := 0; i < 200; i++ {
			ls.Add(LogEntry{Host: "example.com", Method: "GET", Status: "OK"})
		}
	}
	disableLogStore()
	resetLogStoreHealthForTest()
}

// A damaged store must not stop the admin turning history on: it self-heals,
// the outcome is recorded, and every surface says so.
func TestChaos57_EnableRecoversDamagedStoreAndSurfacesIt(t *testing.T) {
	dir := withHistoryStore(t)
	seedRootHistory(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("scramble manifest: %v", err)
	}

	if err := enableLogStore(context.Background(), dir, 0, 0); err != nil {
		t.Fatalf("enable against a damaged store failed: %v", err)
	}
	if globalLogStore.Load() == nil {
		t.Fatal("store was not published after recovery")
	}

	h := logStoreHealthState()
	if !h.SaveRequested || !h.Available || !h.Recovered {
		t.Fatalf("health record after a recovery = %+v, want requested+available+recovered", h)
	}
	if h.ResidualCopies != 1 {
		t.Errorf("residual copies = %d, want 1", h.ResidualCopies)
	}
	if got := logstore.QuarantinedCopies(dir); len(got) != 1 {
		t.Errorf("quarantined copies on disk = %v, want exactly 1 (moved aside, never deleted)", got)
	}

	row := checkRequestHistory()
	if row.Code != "request_history" || row.Status != diagWarn {
		t.Errorf("diagnostics row = %+v, want a request_history warn", row)
	}
	if row.OperatorAction == "" {
		t.Error("a warn row carries no operator action")
	}
	if !strings.Contains(renderMetrics(t), "culvert_logstore_recovered 1") {
		t.Error("culvert_logstore_recovered did not report the recovery")
	}
}

// A store that cannot be opened at all must DEGRADE — history off, process
// alive, traffic unaffected — and be visible on every surface. Before this
// change the visibility was one WARN log line.
func TestChaos57_UnopenableStoreDegradesAndStaysVisible(t *testing.T) {
	dir := withHistoryStore(t)
	seedRootHistory(t, dir)

	// A changed passphrase: intact data the configured key cannot open. It must
	// NOT be quarantined (that would destroy history over a config change) and
	// therefore cannot self-heal — the degradation is the whole outcome.
	logStorePassphrase = "a different passphrase"

	err := enableLogStore(context.Background(), dir, 0, 0)
	if err == nil {
		t.Fatal("enable succeeded with the wrong passphrase")
	}
	if globalLogStore.Load() != nil {
		t.Fatal("a store was published despite the failure")
	}
	if got := logstore.QuarantinedCopies(dir); len(got) != 0 {
		t.Fatalf("a passphrase change quarantined the history store: %v", got)
	}

	h := logStoreHealthState()
	if !h.SaveRequested || h.Available {
		t.Fatalf("health record = %+v, want requested but unavailable", h)
	}
	if h.Detail == "" {
		t.Error("no detail recorded for an unavailable store")
	}

	row := checkRequestHistory()
	if row.Status != diagWarn {
		t.Errorf("diagnostics row status = %v, want warn (never fail — the gateway is serving)", row.Status)
	}
	body := renderMetrics(t)
	if !strings.Contains(body, "culvert_logstore_available 0") {
		t.Error("culvert_logstore_available did not report the store as down")
	}
}

// The salt-loss condition reaches the admin as its OWN actionable message: the
// history is recoverable by restoring one file, which is a different remedy
// from the passphrase mismatch it used to be indistinguishable from.
func TestChaos57_LostSaltIsReportedWithItsOwnRemedy(t *testing.T) {
	dir := withHistoryStore(t)
	seedRootHistory(t, dir)
	if err := os.Remove(dir + ".salt"); err != nil {
		t.Fatalf("remove salt: %v", err)
	}

	err := enableLogStore(context.Background(), dir, 0, 0)
	if err == nil {
		t.Fatal("enable succeeded with no salt sidecar")
	}
	if !strings.Contains(err.Error(), "salt") {
		t.Errorf("err = %v, does not name the salt", err)
	}
	if _, serr := os.Stat(dir + ".salt"); serr == nil {
		t.Fatal("a fresh salt was minted over an existing store — the history is now unreadable")
	}
	if h := logStoreHealthState(); h.Available {
		t.Errorf("health record reports the store available: %+v", h)
	}
}

// A healthy enable must stay byte-identical to the pre-change behaviour: no
// recovery reported, nothing on disk, an ok row.
func TestChaos57_HealthyEnableReportsNothing(t *testing.T) {
	dir := withHistoryStore(t)

	if err := enableLogStore(context.Background(), dir, 0, 0); err != nil {
		t.Fatalf("enable: %v", err)
	}
	h := logStoreHealthState()
	if !h.Available || h.Recovered || h.ResidualCopies != 0 || h.Detail != "" {
		t.Fatalf("health record on a clean enable = %+v", h)
	}
	if row := checkRequestHistory(); row.Status != diagOK {
		t.Errorf("diagnostics row = %+v, want ok", row)
	}
}

// History saving off is a healthy posture, not a degradation — but an
// unreconciled quarantine from an earlier incident still occupies the volume
// and must stay visible after the admin turns saving off.
func TestChaos57_DisabledIsOKButUnreconciledEvidenceStillWarns(t *testing.T) {
	dir := withHistoryStore(t)

	if err := enableLogStore(context.Background(), dir, 0, 0); err != nil {
		t.Fatalf("enable: %v", err)
	}
	disableLogStore()
	if row := checkRequestHistory(); row.Status != diagOK {
		t.Errorf("row with saving off and a clean volume = %+v, want ok", row)
	}

	// Plant the evidence an earlier incident would have left.
	if err := os.MkdirAll(dir+".corrupt.1700000000000000000", 0o700); err != nil {
		t.Fatalf("plant quarantine: %v", err)
	}
	noteLogStoreDisabled(dir)
	row := checkRequestHistory()
	if row.Status != diagWarn {
		t.Errorf("row with an unreconciled quarantined copy = %+v, want warn", row)
	}
	if !strings.Contains(row.OperatorAction, "reclaim disk") {
		t.Errorf("operator action does not say what to do: %q", row.OperatorAction)
	}
}
