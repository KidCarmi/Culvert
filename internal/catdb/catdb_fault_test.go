package catdb

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// seedOnDisk fills a store, closes it so the memtable is flushed into `.sst`
// tables, and returns the reopened store plus the table paths. The reopen is
// the part that matters: it is a HEALTHY open, the one the boot-health record
// (catfeeddb_health.go) observes and reports as Available=true.
func seedOnDisk(t *testing.T, n int) (store *CommunityDB, tables []string) {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	entries := make(map[string]string, n)
	for i := 0; i < n; i++ {
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
		t.Fatalf("expected flushed .sst tables on disk, got %v (err %v)", ssts, err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	return reopened, ssts
}

// TestLookup_VolumeDamageAfterHealthyOpenIsContained is CHAOS-74's gate.
//
// Measured pre-fix behavior, against this exact sequence: the final Lookup
// raised
//
//	unexpected fault address 0x...
//	fatal error: fault
//	[signal SIGBUS: bus error code=0x2 ...]
//	github.com/google/flatbuffers/go.GetInt32(...)
//	github.com/dgraph-io/badger/v4/fb.(*TableIndex).BloomFilterBytes(...)
//	github.com/dgraph-io/badger/v4/table.(*Table).DoesNotHave(...)
//	...
//	github.com/KidCarmi/Culvert/internal/catdb.(*CommunityDB).getExact
//
// and killed the process. `fatal error: fault` is not a panic, so neither
// recover() nor crashguard.go could see it: on the proxy data path, where this
// lookup runs for every request that resolves a host category, one damaged
// table was a total gateway outage with no log line. This test passing is the
// containment working — it cannot pass in a process that died.
func TestLookup_VolumeDamageAfterHealthyOpenIsContained(t *testing.T) {
	db, ssts := seedOnDisk(t, 20000)

	// The store is healthy and serving. This is the state the boot record saw.
	if cat, ok := db.Lookup("evil7.example"); !ok || cat != "Malware" {
		t.Fatalf("healthy lookup before damage: cat=%q ok=%v", cat, ok)
	}
	if faults, mem, degraded := db.LookupFaults(); faults != 0 || mem != 0 || degraded {
		t.Fatalf("healthy store already reports trouble: faults=%d mem=%d degraded=%v", faults, mem, degraded)
	}

	// The data volume damages the tables underneath the live mapping.
	for _, f := range ssts {
		if err := os.Truncate(f, 0); err != nil {
			t.Fatalf("truncate %s: %v", f, err)
		}
	}

	cat, ok := db.Lookup("evil19999.example")
	if ok || cat != "" {
		t.Fatalf("a damaged store must not claim a category: cat=%q ok=%v", cat, ok)
	}

	faults, mem, degraded := db.LookupFaults()
	if mem == 0 {
		t.Fatalf("the mapping fault was not accounted: faults=%d mem=%d degraded=%v", faults, mem, degraded)
	}
	if !degraded {
		t.Fatal("the store must latch degraded after a mapping fault")
	}

	// Latched: further lookups are refused without touching badger again, so
	// the fault count does not grow with request volume.
	for i := 0; i < 50; i++ {
		if _, ok := db.Lookup(fmt.Sprintf("evil%d.example", i)); ok {
			t.Fatal("a degraded store answered a lookup")
		}
	}
	if _, memAfter, _ := db.LookupFaults(); memAfter != mem {
		t.Fatalf("degraded store kept re-entering badger: mem went %d -> %d", mem, memAfter)
	}
}

// TestLookup_OrdinaryMissIsNotAFault is the negative control. The fix now
// classifies lookup errors, and the overwhelmingly common one —
// badger.ErrKeyNotFound for a host that is simply not in the feed — must stay a
// clean miss. If it were counted, every uncategorised host on the internet
// would report as store damage and the new signal would be worthless.
func TestLookup_OrdinaryMissIsNotAFault(t *testing.T) {
	db, _ := seedOnDisk(t, 2000)

	for _, host := range []string{
		"not-in-the-feed.example",
		"deep.sub.domain.absent.example",
		"localhost",
		"single",
	} {
		if cat, ok := db.Lookup(host); ok || cat != "" {
			t.Fatalf("Lookup(%q) = (%q, %v), want a clean miss", host, cat, ok)
		}
	}
	// A present host still resolves, so the walk itself is intact.
	if cat, ok := db.Lookup("sub.evil3.example"); !ok || cat != "Malware" {
		t.Fatalf("subdomain walk broken: cat=%q ok=%v", cat, ok)
	}

	faults, mem, degraded := db.LookupFaults()
	if faults != 0 || mem != 0 || degraded {
		t.Fatalf("ordinary misses were counted as store trouble: faults=%d mem=%d degraded=%v", faults, mem, degraded)
	}
}
