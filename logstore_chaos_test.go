package main

// logstore_chaos_test.go — CHAOS-57 gates for the request-history store's open
// path at the composition root.
//
// internal/logstore/resilient_test.go proves the engine recovers. These gates
// prove the two things only the root can prove, and they are the actual defect:
//
//  1. the ADMIN-API path goes through the guard. openLogStore is shared by boot
//     and by `POST /api/logs/retention`, so an unguarded open meant a damaged
//     store could kill a SERVING gateway from an HTTP handler — and, because
//     `LogStoreEnabled` is durable in admin_settings.json, replay that death on
//     every subsequent boot with no admin UI left to switch it off.
//  2. the recovery is VISIBLE. Resetting searchable history silently would
//     trade a crash loop for an invisible evidence loss, which is not a fix.
//
// Every scenario was reproduced against the pre-fix tree: with openLogStore
// calling logstore.OpenTTL directly, TestChaos57_AdminEnableSurvivesAPoisonedStore
// leaves the poisoned directory in place and the process depends on badger not
// panicking; the observability gates fail outright because nothing records an
// outcome.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/badgerguard"
	"github.com/KidCarmi/Culvert/internal/logstore"
)

// withHistoryStoreDir points the process-global history-store location at a
// temp dir and restores it, so these gates cannot leak into other tests.
func withHistoryStoreDir(t *testing.T) string {
	t.Helper()
	prevDir, prevPass := logStoreDir, logStorePassphrase
	dir := filepath.Join(t.TempDir(), "logstore")
	logStoreDir, logStorePassphrase = dir, ""
	resetLogStoreHealthForTest()
	t.Cleanup(func() {
		disableLogStore()
		logStoreDir, logStorePassphrase = prevDir, prevPass
		resetLogStoreHealthForTest()
	})
	return dir
}

// plantPoisonMarker writes the on-disk state a process that died inside
// badger.Open leaves behind: the marker file survives, and the kernel released
// its flock when the owner died.
func plantPoisonMarker(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	p := badgerguard.StoreBase(dir) + badgerguard.MarkerSuffix + "4242-1"
	if err := os.WriteFile(p, []byte("pid=4242\n"), 0o600); err != nil {
		t.Fatalf("plant marker: %v", err)
	}
	return p
}

// seedHistoryStore creates a populated, cleanly-closed store at dir.
func seedHistoryStore(t *testing.T, dir string) {
	t.Helper()
	s, _, err := openLogStore(dir, 1, 0)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	for i := 0; i < 20; i++ {
		s.Add(LogEntry{Host: "seed.example.com", Method: "GET"})
	}
	if err := s.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
	resetLogStoreHealthForTest()
}

// ── the defect ───────────────────────────────────────────────────────────────

// The headline gate. An admin enabling history on a store a previous process
// died inside of must recover, not re-enter the fault. Before the fix this call
// reached badger.Open on a poisoned directory — on the HTTP handler's goroutine.
func TestChaos57_AdminEnableSurvivesAPoisonedStore(t *testing.T) {
	dir := withHistoryStoreDir(t)
	seedHistoryStore(t, dir)
	marker := plantPoisonMarker(t, dir)

	if err := enableLogStore(context.Background(), dir, 1, 0); err != nil {
		t.Fatalf("enable on a poisoned store failed: %v", err)
	}
	if globalLogStore.Load() == nil {
		t.Fatal("history is not serving after recovery")
	}
	h := logStoreOpenState()
	if !h.Recovered {
		t.Fatalf("the poisoned store was not recovered: %+v", h)
	}
	if _, err := os.Stat(h.QuarantinePath); err != nil {
		t.Errorf("quarantined copy is not on disk — evidence was destroyed, not moved aside: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("the acted-on marker survived; the next enable would quarantine a healthy store")
	}
	if logStoreQuarantines.Load() != 1 {
		t.Errorf("culvert_logstore_quarantines_total = %d, want 1", logStoreQuarantines.Load())
	}
}

// The boot half of the same fault: the durable `LogStoreEnabled` setting is
// replayed on every start, so an unguarded open turns one damaged store into a
// permanent crash loop under `restart: unless-stopped`. Recovery must complete
// within a single start — a fix that needed two would still leave one boot in
// which the appliance does not come up.
func TestChaos57_BootReplayOfTheDurableEnableRecoversInOneStart(t *testing.T) {
	dir := withHistoryStoreDir(t)
	seedHistoryStore(t, dir)
	plantPoisonMarker(t, dir)

	loadLogStore(logStoreStartupConfig{
		Dir:            dir,
		SeedEnable:     true,
		RetentionDays:  1,
		RetentionMaxGB: 0,
	}, context.Background())

	if globalLogStore.Load() == nil {
		t.Fatal("history did not come up on the boot path after recovery")
	}
	if !logStoreOpenState().Recovered {
		t.Error("the boot path did not record the recovery")
	}
}

// A store nothing is wrong with must be left completely alone. A resilience
// feature that disturbs healthy data is worse than the fault it prevents.
func TestChaos57_HealthyStoreIsNeverDisturbed(t *testing.T) {
	dir := withHistoryStoreDir(t)
	seedHistoryStore(t, dir)

	if err := enableLogStore(context.Background(), dir, 1, 0); err != nil {
		t.Fatalf("enable: %v", err)
	}
	h := logStoreOpenState()
	if h.Recovered || h.Failure != "" {
		t.Errorf("a healthy store was reported as damaged: %+v", h)
	}
	if n := logStoreResidualQuarantines(); n != 0 {
		t.Errorf("quarantined copies after a clean enable = %d, want 0", n)
	}
	if got := checkHistoryStore(); got.Status != diagOK {
		t.Errorf("contract row = %q (%s), want ok", got.Status, got.Message)
	}
}

// ── the recovery must be visible ─────────────────────────────────────────────

// Resetting searchable history is an evidence-affecting act, so it goes in the
// audit record alongside logstore.purge and logstore.cleanup. Asserting on
// CONTENT rather than on a ring-length delta is required: the audit ring is
// bounded at 500 and saturates under `-count=2 -shuffle=on`.
func TestChaos57_QuarantineIsAudited(t *testing.T) {
	dir := withHistoryStoreDir(t)
	seedHistoryStore(t, dir)
	plantPoisonMarker(t, dir)
	before := time.Now().UnixMilli()

	if err := enableLogStore(context.Background(), dir, 1, 0); err != nil {
		t.Fatalf("enable: %v", err)
	}

	found := false
	for _, e := range auditGet() {
		if e.Action == "logstore.quarantine" && e.Object == "history" && e.TS >= before {
			found = true
			if !strings.Contains(e.Detail, "durable request log") {
				t.Errorf("audit detail does not tell the operator what survived: %q", e.Detail)
			}
		}
	}
	if !found {
		t.Error("no logstore.quarantine audit entry — history was reset with no record of it")
	}
}

// The contract row must key on evidence that is STILL PRESENT, not on the
// cumulative counter. A counter-keyed row latches until process restart even
// after the operator has done exactly what it asked, which is the defect
// ca_health.go's persistence warning was fixed for.
func TestChaos57_ContractRowClearsWhenTheOperatorReclaimsTheDisk(t *testing.T) {
	dir := withHistoryStoreDir(t)
	seedHistoryStore(t, dir)
	plantPoisonMarker(t, dir)

	if err := enableLogStore(context.Background(), dir, 1, 0); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got := checkHistoryStore(); got.Status != diagWarn {
		t.Fatalf("contract row after a quarantine = %q, want warn", got.Status)
	}
	copies := logstore.QuarantinedCopies(dir)
	if len(copies) == 0 {
		t.Fatal("no quarantined copy to reclaim")
	}

	// The operator does what OperatorAction told them to.
	for _, c := range copies {
		if err := os.RemoveAll(c); err != nil {
			t.Fatalf("reclaim %s: %v", c, err)
		}
	}
	if n := logStoreResidualQuarantines(); n != 0 {
		t.Errorf("residual quarantines after reclaim = %d, want 0 — the metric cannot clear", n)
	}
	// The row must clear RIGHT NOW: no restart, no history toggle, no second
	// open. The first draft keyed this branch on the historical `Recovered`
	// flag, so it kept warning after the copies were gone — and said "0
	// quarantined copy/copies on disk" while doing it (Codex review, PR #1242).
	// Asserting only after a disable/re-enable, as this test first did, hid
	// that: re-enabling resets the flag, so the row cleared for the wrong
	// reason and the gate proved less than it claimed.
	if got := checkHistoryStore(); got.Status != diagOK {
		t.Errorf("contract row immediately after the operator reconciled = %q (%s), want ok", got.Status, got.Message)
	}
	// The cumulative counter is deliberately NOT cleared: "did this ever
	// happen?" must survive the cleanup that clears "is there still evidence?".
	if logStoreQuarantines.Load() == 0 {
		t.Error("the cumulative quarantine counter was reset by the cleanup; the incident is now invisible")
	}
	// And it stays ok across a toggle.
	disableLogStore()
	if err := enableLogStore(context.Background(), dir, 1, 0); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if got := checkHistoryStore(); got.Status != diagOK {
		t.Errorf("contract row after a re-enable = %q (%s), want ok", got.Status, got.Message)
	}
}

// A failed open must degrade, never take the process or the proxy with it, and
// must say so on the operator surfaces.
func TestChaos57_UnopenableStoreDegradesVisibly(t *testing.T) {
	dir := withHistoryStoreDir(t)
	// A regular file where the store directory belongs: badger cannot open it,
	// and it is an ENVIRONMENTAL fault, so nothing may be renamed.
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	if err := os.WriteFile(dir, []byte("not a store"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	err := enableLogStore(context.Background(), dir, 1, 0)
	if err == nil {
		t.Fatal("enable succeeded against a non-directory; the fixture no longer fails")
	}
	if globalLogStore.Load() != nil {
		t.Error("a failed open published a store")
	}
	h := logStoreOpenState()
	if h.Failure == "" {
		t.Error("the failure was not recorded; an operator cannot see why history is off")
	}
	if h.Recovered {
		t.Error("an environmental fault was reported as a recovery")
	}
	if n := logStoreResidualQuarantines(); n != 0 {
		t.Errorf("an environmental fault produced %d quarantined copies; nothing should have been renamed", n)
	}
	if got := checkHistoryStore(); got.Status != diagWarn {
		t.Errorf("contract row = %q, want warn (never fail — history is an enhancement)", got.Status)
	}
}

// ── anti-regression ──────────────────────────────────────────────────────────

// The guard is only worth anything if every path that opens this store goes
// through it. This is structural rather than behavioural on purpose: the fault
// it prevents is an uncatchable panic, so a test that waits to observe the
// regression at runtime would have to survive the process dying.
func TestChaos57_NoRootPathOpensTheHistoryStoreUnguarded(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	guarded := false
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(b)
		if strings.Contains(src, "logstore.OpenTTL(") {
			t.Errorf("%s calls logstore.OpenTTL directly — a corrupt store there panics out of a "+
				"goroutine badger spawns and kills the process; use logstore.OpenResilientTTL", f)
		}
		if strings.Contains(src, "logstore.OpenResilientTTL(") {
			guarded = true
		}
	}
	if !guarded {
		t.Error("no root file opens the history store through the guard; the CHAOS-57 fix has been removed")
	}
}

// Codex review, PR #1242 (P2). "Open" is a claim about the present, so it must
// be read from the published store. Keyed on "an enable was once attempted",
// the row went on reporting an open history store after every disable — a
// runtime toggle, or persisted admin settings switching off a YAML-seeded
// store — which is a monitoring blind spot in the direction that looks healthy.
func TestChaos57_ContractRowReportsADisabledStoreAsDisabled(t *testing.T) {
	dir := withHistoryStoreDir(t)
	seedHistoryStore(t, dir)

	if err := enableLogStore(context.Background(), dir, 1, 0); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if got := checkHistoryStore(); got.Message != "request-history store open" {
		t.Fatalf("row while enabled = %q, want the open message", got.Message)
	}

	disableLogStore()
	got := checkHistoryStore()
	if got.Status != diagOK {
		t.Errorf("row after disable = %q, want ok (a disabled store is not a fault)", got.Status)
	}
	if got.Message == "request-history store open" {
		t.Error("the row still reports history as open after disableLogStore closed and unpublished it")
	}
}
