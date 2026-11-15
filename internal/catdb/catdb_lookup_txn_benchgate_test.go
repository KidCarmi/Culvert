//go:build benchgate

package catdb

// catdb_lookup_txn_benchgate_test.go — the allocation gate for the Layer-2
// community-category domain walk's single read transaction.
//
// `benchgate`-tagged, like every other gate in this repository, and registered
// in the Fast gate's `benchgate` job (plus the QA gate and the weekly stress
// run) in the same change that added it: a gate CI does not run is not a gate.
//
// The correctness guards for this change — the differential oracle against the
// frozen per-label walk, the key-reuse test, and the structural
// one-transaction-per-walk wall — are deliberately NOT here. They are cheap and
// load-independent, so they belong in the default suite where every run
// executes them: see catdb_lookup_txn_test.go.

import "testing"

// TestBenchGate_CommunityLookupAllocs bounds the per-request allocation count
// of the deep uncategorised walk — the shape a real feed answers most often.
//
// The bound is the measured 27 allocs/op plus headroom for badger's own
// per-read machinery (getMemTables, getTableForKey, KeyWithTs, the Item), which
// is the majority of what remains and is not ours to remove. The frozen
// comparison is the load-bearing half: it fails if the per-label transaction
// (or a per-label key conversion) comes back, whatever the absolute number has
// drifted to.
func TestBenchGate_CommunityLookupAllocs(t *testing.T) {
	const (
		host      = "a.b.c.cdn.example.com"
		maxAllocs = 31
	)
	db := benchCommunityStore(t)

	current := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = db.Lookup(host)
		}
	})
	frozen := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = lookupPerLabelTxn(db, host)
		}
	})

	curAllocs, oldAllocs := current.AllocsPerOp(), frozen.AllocsPerOp()
	t.Logf("one-transaction walk: %d allocs/op, %d B/op (bound %d)", curAllocs, current.AllocedBytesPerOp(), maxAllocs)
	t.Logf("per-label walk:       %d allocs/op, %d B/op", oldAllocs, frozen.AllocedBytesPerOp())

	if curAllocs > maxAllocs {
		t.Errorf("the community-category walk allocates %d/op for a 5-label host, bound %d — per-label badger machinery is back on the data path",
			curAllocs, maxAllocs)
	}
	if curAllocs >= oldAllocs {
		t.Errorf("the one-transaction walk (%d allocs/op) is no cheaper than the frozen per-label shape (%d allocs/op); the optimization has been undone",
			curAllocs, oldAllocs)
	}
}
