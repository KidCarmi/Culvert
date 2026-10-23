//go:build linux

package main

// catfeeddb_runtime_fault_chaos_test.go — CHAOS-74 gates for the OPERATOR
// SURFACES of a Layer-2 community category store that opened cleanly and then
// stopped being readable.
//
// CHAOS-50 made the boot path survivable and visible. Every field it records is
// written once by loadCommunityFeedDB, which left the surfaces blind to the
// larger window: the store is open and serving on the proxy data path for the
// whole life of the process, and the volume under it can fail at any point in
// that window. Before this fix `culvert_catfeeddb_available` reported 1 — while
// promising in its own HELP text to mean "open and serving lookups" — for a
// store whose every lookup had stopped answering.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catdb"
)

// degradedCommunityStore returns a store that has taken a real, contained
// memory fault: seeded, closed so the tables land on disk, reopened cleanly,
// then truncated underneath the live mapping and probed once.
//
// The fault is produced, not simulated. A test that only set a flag would pin
// the plumbing while leaving the thing the plumbing reports unverified.
func degradedCommunityStore(t *testing.T) *catdb.CommunityDB {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	db, err := catdb.Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	entries := make(map[string]string, 20000)
	for i := 0; i < 20000; i++ {
		entries[fmt.Sprintf("evil%d.example", i)] = "Malware"
	}
	if err := db.BulkWrite(entries); err != nil {
		t.Fatalf("bulkwrite: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	ssts, err := filepath.Glob(filepath.Join(dir, "*.sst"))
	if err != nil || len(ssts) == 0 {
		t.Fatalf("expected flushed tables, got %v (%v)", ssts, err)
	}
	reopened, err := catdb.Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	for _, f := range ssts {
		if err := os.Truncate(f, 0); err != nil {
			t.Fatalf("truncate: %v", err)
		}
	}
	reopened.Lookup("evil19999.example")
	if _, mem, degraded := reopened.LookupFaults(); mem == 0 || !degraded {
		t.Fatalf("store did not latch degraded: mem=%d degraded=%v", mem, degraded)
	}
	return reopened
}

// The gauge must stop contradicting its own HELP text, and the two new counters
// must be present so an alerting rule can key on them.
func TestMetrics_CatFeedDBRuntimeDegradationIsVisible(t *testing.T) {
	swapCommunityDBGlobals(t)

	// A healthy boot record with no store attached: the baseline the old code
	// emitted forever regardless of what the store was doing.
	noteCatFeedDBState(catFeedDBHealth{Configured: true, Available: true})
	body := renderMetrics(t)
	for _, want := range []string{
		"culvert_catfeeddb_available 1",
		"culvert_catfeeddb_lookup_errors_total 0",
		"culvert_catfeeddb_memory_faults_total 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%q missing from /metrics for a healthy store", want)
		}
	}

	// Same boot record. The store is now dead.
	communityDB = degradedCommunityStore(t)
	body = renderMetrics(t)
	if !strings.Contains(body, "culvert_catfeeddb_available 0") {
		t.Error("culvert_catfeeddb_available still reports 1 for a store that stopped serving lookups")
	}
	if strings.Contains(body, "culvert_catfeeddb_memory_faults_total 0") {
		t.Error("culvert_catfeeddb_memory_faults_total still 0 after a contained memory fault")
	}
	if !strings.Contains(body, "culvert_catfeeddb_memory_faults_total 1") {
		t.Errorf("expected exactly one accounted memory fault; /metrics says:\n%s", catFeedDBMetricLines(body))
	}
}

// The diagnostics row must name the impact and give the operator the action,
// and must not be silent just because the BOOT went fine.
func TestCheckCategoryFeedDB_RuntimeDegradationWarns(t *testing.T) {
	swapCommunityDBGlobals(t)

	noteCatFeedDBState(catFeedDBHealth{Configured: true, Available: true})
	if row := checkCategoryFeedDB(); row.Status != diagOK {
		t.Fatalf("a healthy store should be ok, got %q: %s", row.Status, row.Message)
	}

	communityDB = degradedCommunityStore(t)
	row := checkCategoryFeedDB()
	if row.Status != diagWarn {
		t.Fatalf("a store that stopped serving must warn, got %q: %s", row.Status, row.Message)
	}
	if row.Code != "category_feed_db" {
		t.Errorf("row code drifted: %q", row.Code)
	}
	// The operator needs to know the impact is Layer-1-only and that a restart
	// is what re-opens (and quarantines) the store.
	for _, want := range []string{"admin-managed list only", "restart"} {
		if !strings.Contains(row.Message+" "+row.OperatorAction, want) {
			t.Errorf("row does not mention %q: %s / %s", want, row.Message, row.OperatorAction)
		}
	}
	if row.OperatorAction == "" {
		t.Error("a warn row with no operator action is a dead end")
	}
}

// Negative control: a healthy store attached to a healthy boot record must not
// trip any of the new signals. Without this, a surface that warned
// unconditionally would pass every assertion above.
func TestCheckCategoryFeedDB_HealthyStoreTripsNothing(t *testing.T) {
	swapCommunityDBGlobals(t)

	dir := filepath.Join(t.TempDir(), "catfeeddb")
	db, err := catdb.Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.BulkWrite(map[string]string{"evil.example": "Malware"}); err != nil {
		t.Fatalf("bulkwrite: %v", err)
	}
	// Resolve a hit and a miss: neither is store trouble.
	if cat, ok := db.Lookup("evil.example"); !ok || cat != "Malware" {
		t.Fatalf("hit: cat=%q ok=%v", cat, ok)
	}
	db.Lookup("absent.example")

	communityDB = db
	noteCatFeedDBState(catFeedDBHealth{Configured: true, Available: true})

	if row := checkCategoryFeedDB(); row.Status != diagOK {
		t.Errorf("healthy store warns: %q %s", row.Status, row.Message)
	} else if strings.Contains(row.Message, "containment: unavailable") {
		t.Errorf("Linux build reports containment unavailable: %s", row.Message)
	}
	body := renderMetrics(t)
	for _, want := range []string{
		"culvert_catfeeddb_available 1",
		"culvert_catfeeddb_lookup_errors_total 0",
		"culvert_catfeeddb_memory_faults_total 0",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%q missing for a healthy, serving store", want)
		}
	}
}

// catFeedDBMetricLines extracts the store's exposition lines for a failure
// message, so a broken assertion reports the actual series instead of the whole
// metrics body.
func catFeedDBMetricLines(body string) string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "culvert_catfeeddb_") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
