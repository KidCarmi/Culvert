//go:build linux

// Real mapping faults are contained on Linux only (storeguard.FaultContainmentSupported);
// elsewhere they re-panic by design, so these gates run where containment exists.

package catdb

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/storeguard"
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

// TestOpenResilient_RuntimeFaultQuarantinesOnNextOpen closes CHAOS-74's
// fault-to-restart path. Containing the fault keeps the process alive, but the
// diagnostics row tells the operator to restart, and the restart is the only
// point at which this derived store can be rebuilt. Measured before the fault
// was persisted: the reopen returned badger's unclassified
// `mmapping ... size: 0` error with Trigger="" and Quarantined=false, so every
// later start stayed Layer-1-only and never rebuilt the store.
func TestOpenResilient_RuntimeFaultQuarantinesOnNextOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	db, err := Open(dir)
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
	ssts, _ := filepath.Glob(filepath.Join(dir, "*.sst"))
	if len(ssts) == 0 {
		t.Fatal("expected flushed .sst tables on disk")
	}

	live, rec, err := OpenResilient(dir)
	if err != nil || rec.Trigger != TriggerNone {
		t.Fatalf("healthy open: err=%v rec=%+v", err, rec)
	}
	for _, f := range ssts {
		if err := os.Truncate(f, 0); err != nil {
			t.Fatalf("truncate %s: %v", f, err)
		}
	}
	live.Lookup("evil19999.example")
	if _, mem, degraded := live.LookupFaults(); mem == 0 || !degraded {
		t.Fatalf("store did not latch degraded: mem=%d degraded=%v", mem, degraded)
	}
	_ = live.Close() // the operator's restart; a damaged store may refuse a clean close

	next, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("restart after a contained fault must rebuild the store, got err=%v rec=%+v", err, rec)
	}
	t.Cleanup(func() { _ = next.Close() })
	if rec.Trigger != TriggerRuntimeFault || !rec.Quarantined || rec.QuarantinePath == "" {
		t.Fatalf("restart did not quarantine the faulted store: %+v", rec)
	}
	if _, err := os.Stat(rec.QuarantinePath); err != nil {
		t.Fatalf("quarantined evidence missing: %v", err)
	}
	// The rebuilt store is empty and serving; the policy outcome stays
	// "uncategorised" until the feed repopulates it.
	if cat, ok := next.Lookup("evil7.example"); ok || cat != "" {
		t.Fatalf("rebuilt store answered from quarantined data: cat=%q ok=%v", cat, ok)
	}
	if err := next.BulkWrite(map[string]string{"evil.example": "Malware"}); err != nil {
		t.Fatalf("rebuilt store not writable: %v", err)
	}
	if cat, ok := next.Lookup("evil.example"); !ok || cat != "Malware" {
		t.Fatalf("rebuilt store not serving: cat=%q ok=%v", cat, ok)
	}

	// The signal is consumed: a third start is a plain healthy open.
	_ = next.Close()
	third, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("third open: %v", err)
	}
	_ = third.Close()
	if rec.Trigger != TriggerNone || rec.Quarantined {
		t.Fatalf("fault signal was not cleared after quarantine: %+v", rec)
	}
}

// TestOpenResilient_RuntimeFaultThroughASymlinkRecoversTheTarget pins the
// restart path for a configured path that is an alias onto the data volume
// (`/var/lib/catdb -> /mnt/data/catdb`). Before the path was resolved once at
// open, the marker went beside the alias and the next start renamed the
// SYMLINK aside. badger then created a plain directory at the alias, so the
// rebuilt feed left the volume and the damaged target was left in place.
func TestOpenResilient_RuntimeFaultThroughASymlinkRecoversTheTarget(t *testing.T) {
	volume := t.TempDir()
	target := filepath.Join(volume, "catfeeddb")
	alias := filepath.Join(t.TempDir(), "catfeeddb")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	seed, err := Open(alias)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	entries := make(map[string]string, 20000)
	for i := 0; i < 20000; i++ {
		entries[fmt.Sprintf("evil%d.example", i)] = "Malware"
	}
	if err := seed.BulkWrite(entries); err != nil {
		t.Fatalf("bulkwrite: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	ssts, _ := filepath.Glob(filepath.Join(target, "*.sst"))
	if len(ssts) == 0 {
		t.Fatal("expected flushed .sst tables in the target")
	}

	live, rec, err := OpenResilient(alias)
	if err != nil || rec.Trigger != TriggerNone {
		t.Fatalf("healthy open through the alias: err=%v rec=%+v", err, rec)
	}
	for _, f := range ssts {
		if err := os.Truncate(f, 0); err != nil {
			t.Fatalf("truncate %s: %v", f, err)
		}
	}
	live.Lookup("evil19999.example")
	if _, mem, degraded := live.LookupFaults(); mem == 0 || !degraded {
		t.Fatalf("fault through the alias was not contained: mem=%d degraded=%v", mem, degraded)
	}
	_ = live.Close()

	if _, err := os.Stat(target + storeguard.FaultMarkerSuffix); err != nil {
		t.Fatalf("fault marker not beside the real target: %v", err)
	}
	if _, err := os.Lstat(alias + storeguard.FaultMarkerSuffix); err == nil {
		t.Fatal("fault marker written beside the alias")
	}

	next, rec, err := OpenResilient(alias)
	if err != nil {
		t.Fatalf("restart through the alias: err=%v rec=%+v", err, rec)
	}
	t.Cleanup(func() { _ = next.Close() })
	if rec.Trigger != TriggerRuntimeFault || !rec.Quarantined {
		t.Fatalf("restart did not quarantine: %+v", rec)
	}

	// The alias is untouched: still a symlink, still onto the same target.
	fi, err := os.Lstat(alias)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the configured alias was replaced: fi=%v err=%v", fi, err)
	}
	if got, err := os.Readlink(alias); err != nil || got != target {
		t.Fatalf("alias now points at %q (err %v), want %q", got, err, target)
	}
	// The damaged target was moved aside BESIDE THE TARGET, on the volume.
	if filepath.Dir(rec.QuarantinePath) != volume {
		t.Fatalf("quarantine landed at %q, want beside the target in %q", rec.QuarantinePath, volume)
	}
	if strays, _ := filepath.Glob(alias + storeguard.QuarantineSuffix + "*"); len(strays) != 0 {
		t.Fatalf("something was quarantined beside the alias: %v", strays)
	}
	// The fresh store lives under the target and serves through the alias.
	if err := next.BulkWrite(map[string]string{"evil.example": "Malware"}); err != nil {
		t.Fatalf("rebuilt store not writable: %v", err)
	}
	if cat, ok := next.Lookup("evil.example"); !ok || cat != "Malware" {
		t.Fatalf("rebuilt store not serving: cat=%q ok=%v", cat, ok)
	}
	if fi, err := os.Lstat(target); err != nil || !fi.IsDir() {
		t.Fatalf("fresh store is not a directory at the target: fi=%v err=%v", fi, err)
	}
	if got := QuarantinedCopies(alias); len(got) != 1 || got[0] != rec.QuarantinePath {
		t.Fatalf("QuarantinedCopies(alias) = %v, want [%s]", got, rec.QuarantinePath)
	}
}
