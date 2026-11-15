package catdb

// catdb_lookup_txn_bench_test.go — before/after evidence for the Layer-2
// community-category domain walk.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkCommunityLookup' -benchmem -count=6 ./internal/catdb
//	go test -run '^$' -bench 'BenchmarkCommunityLookupParallel' -benchmem -count=6 -cpu 1,4 ./internal/catdb
//
// What is being measured. Lookup walks the destination authority label by
// label: it probes the full host, then strips the leftmost label and retries,
// stopping before a bare TLD. A 5-label host therefore issues up to four point
// reads, and an UNCATEGORISED host — the overwhelmingly common outcome, since
// the feed covers a small slice of the namespace — always runs the walk to
// completion.
//
// The walk used to open one badger read transaction PER LABEL. Each
// db.View costs, inside badger:
//
//   - a heap-allocated *badger.Txn,
//   - oracle.readTs(): the global oracle mutex, plus readMark.Begin, which
//     SENDS on the watermark goroutine's single channel,
//   - txn.Discard() → doneRead → readMark.Done, a second send on that same
//     single channel.
//
// Those two channel sends are the load-bearing term under concurrency: every
// concurrent lookup in the process funnels through one watermark goroutine, so
// the walk multiplied a process-wide serialization point by the destination's
// label count.
//
// lookupPerLabelTxn below is the FROZEN pre-change shape, kept in-tree so the
// comparison stays reproducible rather than living only in a commit message.
// It is a verbatim copy of the removed code; it is not called by production and
// must NOT be "kept in sync" with Lookup — its whole value is that it does not
// move.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	badger "github.com/dgraph-io/badger/v4"

	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/storeguard"
)

// benchCommunityStore opens a real on-disk store holding a feed-shaped slice of
// entries. The hit entry is at the registrable domain, which is where a real
// community feed carries it.
func benchCommunityStore(tb testing.TB) *CommunityDB {
	tb.Helper()
	db, err := Open(tb.TempDir())
	if err != nil {
		tb.Fatalf("Open: %v", err)
	}
	tb.Cleanup(func() { _ = db.Close() })
	entries := map[string]string{
		"facebook.com": "Social Media",
		"malware.io":   "Malicious",
	}
	// Pad the store so the point reads are not all served from one tiny table.
	for i := 0; i < 2000; i++ {
		entries[fmt.Sprintf("site%04d.example", i)] = "News"
	}
	if err := db.BulkWrite(entries); err != nil {
		tb.Fatalf("BulkWrite: %v", err)
	}
	return db
}

// ── frozen pre-change shape: one badger transaction per label ───────────────

// lookupPerLabelTxn is the pre-change Lookup. Do not update it.
func lookupPerLabelTxn(c *CommunityDB, host string) (string, bool) {
	if c.degraded.Load() {
		return "", false
	}
	host = hostutil.NormalizeHost(host)
	var (
		cat   string
		found bool
	)
	err := c.access(func() error {
		var walkErr error
		cat, found, walkErr = walkPerLabelTxn(c, host)
		return walkErr
	})
	switch {
	case err == nil:
		return cat, found
	case storeguard.IsStoreFault(err), errors.Is(err, ErrDegraded):
		return "", false
	default:
		if c.faults.Add(1) == 1 {
			obs.Printf("CatFeedDB: community category lookup failed (host treated as uncategorised): %q", obs.Sanitize(err.Error()))
		}
		return "", false
	}
}

// walkPerLabelTxn is the pre-change walk. Do not update it.
func walkPerLabelTxn(c *CommunityDB, host string) (category string, found bool, err error) {
	for {
		cat, hit, lookupErr := getExactOwnTxn(c, host)
		if lookupErr != nil {
			return "", false, lookupErr
		}
		if hit {
			return cat, true, nil
		}
		dot := strings.Index(host, ".")
		if dot < 0 {
			break
		}
		parent := host[dot+1:]
		if !strings.Contains(parent, ".") {
			break
		}
		host = parent
	}
	return "", false, nil
}

// getExactOwnTxn is the pre-change point read: its own db.View per label.
// Do not update it.
func getExactOwnTxn(c *CommunityDB, domain string) (category string, found bool, err error) {
	var cat string
	viewErr := c.db.View(func(txn *badger.Txn) error {
		item, getErr := txn.Get([]byte(domain))
		if getErr != nil {
			return getErr
		}
		return item.Value(func(val []byte) error {
			cat = string(val)
			return nil
		})
	})
	switch {
	case viewErr == nil:
		return cat, true, nil
	case errors.Is(viewErr, badger.ErrKeyNotFound):
		return "", false, nil
	default:
		return "", false, viewErr
	}
}

// ── scenarios ───────────────────────────────────────────────────────────────

// benchLookupHosts are the three shapes that matter, with the number of point
// reads each one costs.
var benchLookupHosts = []struct {
	name  string
	host  string
	reads int
	hit   bool
}{
	// Hit at the registrable domain: the shape a categorised request takes.
	{"HitAtParent", "www.facebook.com", 2, true},
	// Uncategorised 3-label host: the common outcome on a real feed.
	{"MissShallow", "unknown.example.com", 2, false},
	// Uncategorised deep host (CDN/bucket shapes): the walk runs to completion.
	{"MissDeep", "a.b.c.cdn.example.com", 5, false},
}

func BenchmarkCommunityLookup_Current(b *testing.B) {
	db := benchCommunityStore(b)
	for _, tc := range benchLookupHosts {
		b.Run(tc.name, func(b *testing.B) {
			if _, ok := db.Lookup(tc.host); ok != tc.hit {
				b.Fatalf("Lookup(%q) hit=%v, want %v", tc.host, ok, tc.hit)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = db.Lookup(tc.host)
			}
		})
	}
}

func BenchmarkCommunityLookup_PerLabelTxn(b *testing.B) {
	db := benchCommunityStore(b)
	for _, tc := range benchLookupHosts {
		b.Run(tc.name, func(b *testing.B) {
			if _, ok := lookupPerLabelTxn(db, tc.host); ok != tc.hit {
				b.Fatalf("lookupPerLabelTxn(%q) hit=%v, want %v", tc.host, ok, tc.hit)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = lookupPerLabelTxn(db, tc.host)
			}
		})
	}
}

// The parallel pair is the one that shows the watermark channel. Run with
// -cpu 1,4 to see the per-label shape degrade with concurrency.
func BenchmarkCommunityLookupParallel_Current(b *testing.B) {
	db := benchCommunityStore(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = db.Lookup("a.b.c.cdn.example.com")
		}
	})
}

func BenchmarkCommunityLookupParallel_PerLabelTxn(b *testing.B) {
	db := benchCommunityStore(b)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = lookupPerLabelTxn(db, "a.b.c.cdn.example.com")
		}
	})
}
