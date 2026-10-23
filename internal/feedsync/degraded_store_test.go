//go:build linux

// Real mapping faults are contained on Linux only (storeguard.FaultContainmentSupported).

package feedsync

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
	"github.com/KidCarmi/Culvert/internal/feedsched"
)

// degradedStore returns a community store that has taken a REAL contained
// memory fault and latched degraded. It is seeded and flushed, reopened
// healthy, has its tables truncated under the live mapping, and is then
// probed once.
func degradedStore(t *testing.T) *catdb.CommunityDB {
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
	ssts, _ := filepath.Glob(filepath.Join(dir, "*.sst"))
	if len(ssts) == 0 {
		t.Fatal("expected flushed tables")
	}
	live, err := catdb.Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = live.Close() })
	for _, f := range ssts {
		if err := os.Truncate(f, 0); err != nil {
			t.Fatalf("truncate: %v", err)
		}
	}
	live.Lookup("evil19999.example")
	if _, _, degraded := live.LookupFaults(); !degraded {
		t.Fatal("store did not latch degraded")
	}
	return live
}

// TestSyncer_DegradedStoreFailsTheRoundWithoutFetchingOrCrashing is the
// syncer-level CHAOS-74 gate. Before every data method went through the
// guarded choke point, the syncer's own goroutine reached the damaged store
// through Stats (SIGBUS in getTableInfo) and BulkWrite after the latch, which
// undid the containment. Now a round against a degraded store must:
//   - not crash (this test passing at all shows that),
//   - not fetch the 50+ MB feed only to have the write refused,
//   - fail as a bounded "write" round, so the scheduler backs off rather than
//     hot-looping, and
//   - leave the RunNow probe (Stats) answerable.
func TestSyncer_DegradedStoreFailsTheRoundWithoutFetchingOrCrashing(t *testing.T) {
	db := degradedStore(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	fs := New(db, srv.URL, time.Hour)
	before := SyncFailures()
	for i := 1; i <= 3; i++ {
		if fs.syncRound() {
			t.Fatal("a round against a degraded store reported success")
		}
		h := fs.Health()
		if h.LastFailure != failWrite || h.ConsecutiveFailures != int64(i) {
			t.Fatalf("round %d: health = %+v, want LastFailure=%q and %d consecutive failures", i, h, failWrite, i)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("degraded store still cost %d feed download(s)", n)
	}
	if SyncFailures() != before+3 {
		t.Fatalf("SyncFailures = %d, want %d", SyncFailures(), before+3)
	}

	// The scheduler's view: the RunNow probe answers without touching badger,
	// and a failed round backs off by minutes, not a hot loop.
	cfg := fs.schedulerConfig()
	_ = cfg.RunNow()
	if d := feedsched.New(cfg).NextDelay(false); d < time.Minute {
		t.Fatalf("delay after a degraded round = %s, want a backoff", d)
	}

	// And a live loop over the degraded store neither crashes nor spins.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	attemptsBefore := fs.Health().ConsecutiveFailures
	fs.Start(ctx)
	<-ctx.Done()
	fs.Wait()
	if extra := fs.Health().ConsecutiveFailures - attemptsBefore; extra > 1 {
		t.Fatalf("the loop ran %d rounds in 200ms against a degraded store; that is a hot loop", extra)
	}
}
