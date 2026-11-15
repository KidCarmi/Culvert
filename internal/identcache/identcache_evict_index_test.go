package identcache

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This file is the correctness case for PERF-IDENTCACHE-1, which replaced
// evictOneLocked's scan over every bucket with two incrementally maintained
// heaps. The optimisation is only admissible if it selects the SAME victim the
// scan did, so the scan is kept here as an executable oracle and the index's
// structural invariants are checked against the data they are derived from.

// referenceVictim is the pre-PERF-IDENTCACHE-1 selection, verbatim apart from
// not mutating the cache: the full scan over c.buckets, applying BetterVictim
// to each bucket's front. It reports the key the old implementation would have
// evicted and whether that key was chosen on the expired-front fast path.
//
// It calls frontLocked, which advances b.head past consumed slots. That is the
// same lazy cleanup the production path performs and does not change which
// entry is any bucket's front.
func referenceVictim[T any](c *Cache[T], now time.Time) (key string, expired, found bool) {
	var (
		victimKey    string
		victimClient string
		victimLive   int
		victimAdded  time.Time
		haveVictim   bool
	)
	for client, b := range c.buckets {
		k, e, okFront := c.frontLocked(client, b)
		if !okFront {
			continue
		}
		if !now.Before(e.expiry) {
			// The scan took whichever expired front Go's map order reached
			// first, so the identity of this key is not reproducible — only
			// the fact that an expired front existed is.
			return k, true, true
		}
		if !haveVictim || BetterVictim(b.live, e.added, client, victimLive, victimAdded, victimClient) {
			victimKey, victimClient, victimLive, victimAdded, haveVictim = k, client, b.live, e.added, true
		}
	}
	return victimKey, false, haveVictim
}

// checkEvictionIndex asserts every invariant evictOneLocked relies on when it
// trusts a heap root without re-validating it.
func checkEvictionIndex[T any](t *testing.T, c *Cache[T], stage string) {
	t.Helper()

	if len(c.victims) != len(c.buckets) || len(c.expiries) != len(c.buckets) {
		t.Fatalf("%s: index covers %d victims / %d expiries, want %d in each",
			stage, len(c.victims), len(c.expiries), len(c.buckets))
	}

	for _, h := range []struct {
		name string
		slot int
		s    []*bucket
		less func(a, b *bucket) bool
	}{
		{"victims", slotVictim, c.victims, victimLess},
		{"expiries", slotExpiry, c.expiries, expiryLess},
	} {
		seen := map[*bucket]bool{}
		for i, b := range h.s {
			if b == nil {
				t.Fatalf("%s: %s[%d] is nil", stage, h.name, i)
			}
			if b.pos[h.slot] != i {
				t.Fatalf("%s: %s[%d] records position %d", stage, h.name, i, b.pos[h.slot])
			}
			if seen[b] {
				t.Fatalf("%s: %s holds client %q twice", stage, h.name, b.client)
			}
			seen[b] = true
			if c.buckets[b.client] != b {
				t.Fatalf("%s: %s holds client %q, absent from c.buckets", stage, h.name, b.client)
			}
			if i > 0 && h.less(b, h.s[(i-1)/2]) {
				t.Fatalf("%s: %s violates the heap order at %d (client %q)", stage, h.name, i, b.client)
			}
		}
	}

	// The memo the ordering reads must still describe the bucket's real front.
	for client, b := range c.buckets {
		k, e, ok := c.frontLocked(client, b)
		if !ok {
			t.Fatalf("%s: bucket %q is indexed with live=%d but has no front", stage, client, b.live)
		}
		if k != b.frontKey || !e.added.Equal(b.frontAdded) || !e.expiry.Equal(b.frontExpiry) {
			t.Fatalf("%s: bucket %q memo is %q/%v, front is %q/%v",
				stage, client, b.frontKey, b.frontAdded, k, e.added)
		}
	}
}

// indexVictim reports the entry evictOneLocked would drop, read from the two
// heap roots exactly as it reads them.
func indexVictim[T any](c *Cache[T], now time.Time) (key string, expired bool) {
	if b := heapPeek(c.expiries); b != nil && !now.Before(b.frontExpiry) {
		return b.frontKey, true
	}
	if b := heapPeek(c.victims); b != nil {
		return b.frontKey, false
	}
	return "", false
}

// assertSameVictim requires the eviction index to choose what the scan it
// replaced would have chosen, on the state the cache is in right now.
func assertSameVictim[T any](t *testing.T, c *Cache[T], now time.Time, step int) {
	t.Helper()
	wantKey, wantExpired, wantFound := referenceVictim(c, now)
	gotKey, gotExpired := indexVictim(c, now)
	switch {
	case !wantFound:
		if gotKey != "" {
			t.Fatalf("step %d: index chose %q where the scan found no victim", step, gotKey)
		}
	case wantExpired:
		// The scan took whichever expired front Go's map order reached first,
		// so "an expired front" is reproducible but its identity is not.
		if !gotExpired {
			t.Fatalf("step %d: scan found an expired front, index chose live %q", step, gotKey)
		}
		if e, present := c.entries[gotKey]; !present || now.Before(e.expiry) {
			t.Fatalf("step %d: index chose %q, which is not an expired front", step, gotKey)
		}
	case gotExpired:
		t.Fatalf("step %d: index chose expired %q where the scan found none", step, gotKey)
	case gotKey != wantKey:
		t.Fatalf("step %d: index chose %q, scan chose %q", step, gotKey, wantKey)
	}
}

// TestChaos76_EvictionIndexSelectsTheSameVictimAsTheFullScan is the
// differential oracle: over randomised workloads the heap-indexed
// evictOneLocked must drop exactly the entry the scan it replaced would have
// dropped, or — on the expired-front path, where the scan's own choice was map
// order and so unreproducible — an entry that was likewise an expired front.
func TestChaos76_EvictionIndexSelectsTheSameVictimAsTheFullScan(t *testing.T) {
	for _, tc := range []struct {
		name            string
		cap, clients    int
		ttlJitterMillis int
	}{
		{"one client", 16, 1, 0},
		{"few clients, all live", 24, 4, 0},
		{"one entry each", 32, 32, 0},
		{"skewed holdings", 32, 6, 0},
		{"mixed expiry", 32, 8, 40},
		{"wide and expiring", 64, 48, 25},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(1)) //nolint:gosec // G404: deterministic seeded workload, not security
			c := New[int](Options{MaxEntries: tc.cap})
			base := time.Now()

			for step := 0; step < 4000; step++ {
				now := base.Add(time.Duration(step) * time.Millisecond)
				client := "client-" + strconv.Itoa(rng.Intn(tc.clients))
				key := "key-" + strconv.Itoa(rng.Intn(tc.cap*2))

				switch {
				case rng.Intn(8) == 0 && len(c.entries) > 0:
					// Reads reclaim expired entries, which moves fronts.
					c.Get("key-" + strconv.Itoa(rng.Intn(tc.cap*2)))
				default:
					ttl := time.Second
					if tc.ttlJitterMillis > 0 {
						ttl = time.Duration(rng.Intn(tc.ttlJitterMillis)+1) * time.Millisecond
					}
					c.store(key, client, step, true, now, now.Add(ttl))
				}

				if len(c.entries) < tc.cap {
					continue
				}
				// At the cap, compare the two selections on the SAME state.
				assertSameVictim(t, c, now, step)
				checkEvictionIndex(t, c, "step "+strconv.Itoa(step))
			}
		})
	}
}

// TestChaos76_EvictionPrefersTheEarliestExpiredFront pins the one deliberate
// refinement PERF-IDENTCACHE-1 made. The scan dropped whichever expired front
// Go's randomised map iteration reached first; the index drops the one that
// expired soonest, which satisfies the same policy and is reproducible — the
// property BetterVictim exists to give the live path.
func TestChaos76_EvictionPrefersTheEarliestExpiredFront(t *testing.T) {
	const cap_ = 4
	now := time.Now()
	for attempt := 0; attempt < 32; attempt++ {
		c := New[int](Options{MaxEntries: cap_})
		// Three single-entry clients whose entries are already dead, with
		// distinct deadlines, plus one live entry.
		c.store("dead-late", "c-late", 1, true, now.Add(-3*time.Second), now.Add(-time.Second))
		c.store("dead-early", "c-early", 2, true, now.Add(-3*time.Second), now.Add(-3*time.Second))
		c.store("dead-mid", "c-mid", 3, true, now.Add(-3*time.Second), now.Add(-2*time.Second))
		c.store("live", "c-live", 4, true, now, now.Add(time.Hour))

		c.store("fresh", "c-fresh", 5, true, now, now.Add(time.Hour))

		if _, present := c.entries["dead-early"]; present {
			t.Fatalf("attempt %d: the earliest-expiring front survived", attempt)
		}
		for _, kept := range []string{"dead-late", "dead-mid", "live", "fresh"} {
			if _, present := c.entries[kept]; !present {
				t.Fatalf("attempt %d: %q was evicted ahead of the earliest-expiring front", attempt, kept)
			}
		}
	}
}

// TestChaos76_EvictionIndexSurvivesRefreshAndCompaction exercises the paths
// that move a bucket's front without removing an entry — re-verifying a
// credential, which re-attributes and re-appends a key, and the compaction
// that renumbers every surviving position.
func TestChaos76_EvictionIndexSurvivesRefreshAndCompaction(t *testing.T) {
	c := New[int](Options{MaxEntries: 40})
	base := time.Now()
	rng := rand.New(rand.NewSource(7)) //nolint:gosec // G404: deterministic seeded workload, not security
	for step := 0; step < 3000; step++ {
		now := base.Add(time.Duration(step) * time.Millisecond)
		// A small key space over a small client space forces refreshes of keys
		// the bucket already lists, and re-attribution across clients.
		key := "key-" + strconv.Itoa(rng.Intn(24))
		client := "client-" + strconv.Itoa(rng.Intn(5))
		c.store(key, client, step, true, now, now.Add(time.Minute))
		checkEvictionIndex(t, c, "refresh step "+strconv.Itoa(step))
	}
	if c.Len() > 40 {
		t.Fatalf("cap exceeded: %d entries", c.Len())
	}
}

// ── Cost-shape guards (PERF-IDENTCACHE-1) ───────────────────────────────────
//
// The WALL-CLOCK ratio gate lives in identcache_evict_shape_benchgate_test.go,
// behind the `benchgate` tag, because a timing comparison is not a property an
// ordinary, race or determinism run can decide — the repo's standing rule, and
// the reason internal/catgroup's equivalent gate is tagged. What stays here is
// deterministic and fails under any load.

// TestChaos76_WallNoBucketScanSurvivesInEviction is the load-independent guard
// on the regression PERF-IDENTCACHE-1 closed: it fails the build if victim
// selection goes back to iterating the bucket map, whatever the machine is
// doing at the time.
//
// The scan was linear in the number of distinct fairness keys — which is the
// number of active client addresses — and it ran under c.mu once per insertion
// for as long as the cache sat at its cap, so its return is a throughput and
// latency regression on the proxy credential path, not a cosmetic one.
func TestChaos76_WallNoBucketScanSurvivesInEviction(t *testing.T) {
	src, err := os.ReadFile("identcache.go")
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := functionBody(t, src, "evictOneLocked")
	if !ok {
		t.Fatal("not-vacuous check: evictOneLocked is gone, so this wall guards nothing")
	}
	if regexp.MustCompile(`range\s+c\.buckets`).MatchString(fn) {
		t.Error("evictOneLocked iterates c.buckets again: victim selection must come " +
			"from the c.victims / c.expiries roots, which are O(log clients), not from " +
			"a scan that is linear in the active client count")
	}
	// Not vacuous: the roots the selection is supposed to read must be there.
	for _, want := range []string{"heapPeek(c.expiries)", "heapPeek(c.victims)"} {
		if !strings.Contains(fn, want) {
			t.Errorf("not-vacuous check: evictOneLocked no longer reads %s", want)
		}
	}
}

// functionBody returns the source text of the named top-level func or method.
func functionBody(t *testing.T, src []byte, name string) (string, bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "identcache.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		fn, isFunc := decl.(*ast.FuncDecl)
		if !isFunc || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		return string(src[fset.Position(fn.Body.Pos()).Offset:fset.Position(fn.Body.End()).Offset]), true
	}
	return "", false
}
