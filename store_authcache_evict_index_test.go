package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This file is the correctness case for PERF-AUTHCACHE-1, which replaced
// evictOneLocked's scan over every bucket with two incrementally maintained
// heaps. The optimisation is only admissible if it selects the SAME victim the
// scan did, so the scan is kept here as an executable oracle and the index's
// structural invariants are checked against the data they are derived from.
//
// This matters more than it would for an ordinary cache: the eviction policy is
// a security control (CHAOS-57 — the cache is populated by UNAUTHENTICATED
// requests, so a flood that could displace honest clients' cached positives
// turns bcrypt's cost onto legitimate traffic). A faster selection that picked
// a different victim would be a security regression, not a speed-up.

// referenceAuthVictim is the pre-PERF-AUTHCACHE-1 selection, verbatim apart
// from not mutating the store: the full scan over a.buckets, applying
// betterAuthCacheVictim to each bucket's front. It reports the key the old
// implementation would have evicted and whether that key was chosen on the
// expired-front fast path.
//
// It calls frontLocked, which advances b.head past consumed slots. That is the
// same lazy cleanup the production path performs and does not change which
// entry is any bucket's front.
//
// The expiry test is `now.After(e.expiry)`, exactly as the replaced scan wrote
// it — NOT `!now.Before(...)`. The two differ at the instant now == expiry, and
// copying the original keeps the oracle an oracle.
func referenceAuthVictim(a *authCacheStore, now time.Time) (key string, expired, found bool) {
	var (
		victimKey    string
		victimClient string
		victimLive   int
		victimAdded  time.Time
		haveVictim   bool
	)
	for client, b := range a.buckets {
		k, e, okFront := a.frontLocked(client, b)
		if !okFront {
			continue
		}
		if now.After(e.expiry) {
			// The scan took whichever expired front Go's map order reached
			// first, so the identity of this key is not reproducible — only
			// the fact that an expired front existed is.
			return k, true, true
		}
		if !haveVictim || betterAuthCacheVictim(b.live, e.added, client, victimLive, victimAdded, victimClient) {
			victimKey, victimClient, victimLive, victimAdded, haveVictim = k, client, b.live, e.added, true
		}
	}
	return victimKey, false, haveVictim
}

// checkAuthEvictionIndex asserts every invariant evictOneLocked relies on when
// it trusts a heap root without re-validating it.
func checkAuthEvictionIndex(t *testing.T, a *authCacheStore, stage string) {
	t.Helper()

	if len(a.victims) != len(a.buckets) || len(a.expiries) != len(a.buckets) {
		t.Fatalf("%s: index covers %d victims / %d expiries, want %d in each",
			stage, len(a.victims), len(a.expiries), len(a.buckets))
	}

	for _, h := range []struct {
		name string
		slot int
		s    []*authCacheBucket
		less func(x, y *authCacheBucket) bool
	}{
		{"victims", authSlotVictim, a.victims, authVictimLess},
		{"expiries", authSlotExpiry, a.expiries, authExpiryLess},
	} {
		seen := map[*authCacheBucket]bool{}
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
			if a.buckets[b.client] != b {
				t.Fatalf("%s: %s holds client %q, absent from a.buckets", stage, h.name, b.client)
			}
			if i > 0 && h.less(b, h.s[(i-1)/2]) {
				t.Fatalf("%s: %s violates the heap order at %d (client %q)", stage, h.name, i, b.client)
			}
		}
	}

	// The memo the ordering reads must still describe the bucket's real front.
	for client, b := range a.buckets {
		k, e, ok := a.frontLocked(client, b)
		if !ok {
			t.Fatalf("%s: bucket %q is indexed with live=%d but has no front", stage, client, b.live)
		}
		if k != b.frontKey || !e.added.Equal(b.frontAdded) || !e.expiry.Equal(b.frontExpiry) {
			t.Fatalf("%s: bucket %q memo is key=%q added=%v expiry=%v, front is key=%q added=%v expiry=%v",
				stage, client, b.frontKey, b.frontAdded, b.frontExpiry, k, e.added, e.expiry)
		}
	}
}

// indexAuthVictim reports the entry evictOneLocked would drop, read from the
// two heap roots exactly as it reads them.
func indexAuthVictim(a *authCacheStore, now time.Time) (key string, expired bool) {
	if b := authHeapPeek(a.expiries); b != nil && now.After(b.frontExpiry) {
		return b.frontKey, true
	}
	if b := authHeapPeek(a.victims); b != nil {
		return b.frontKey, false
	}
	return "", false
}

// assertSameAuthVictim requires the eviction index to choose what the scan it
// replaced would have chosen, on the state the store is in right now.
func assertSameAuthVictim(t *testing.T, a *authCacheStore, now time.Time, step int) {
	t.Helper()
	wantKey, wantExpired, wantFound := referenceAuthVictim(a, now)
	gotKey, gotExpired := indexAuthVictim(a, now)
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
		if e, present := a.entries[gotKey]; !present || !now.After(e.expiry) {
			t.Fatalf("step %d: index chose %q, which is not an expired front", step, gotKey)
		}
	case gotExpired:
		t.Fatalf("step %d: index chose expired %q where the scan found none", step, gotKey)
	case gotKey != wantKey:
		t.Fatalf("step %d: index chose %q, scan chose %q", step, gotKey, wantKey)
	}
}

// TestPerfAuthCache1_EvictionIndexSelectsTheSameVictimAsTheFullScan is the
// differential oracle: over randomised workloads the heap-indexed
// evictOneLocked must drop exactly the entry the scan it replaced would have
// dropped, or — on the expired-front path, where the scan's own choice was map
// order and so unreproducible — an entry that was likewise an expired front.
//
// The cap is lowered from maxAuthCacheSize so eviction is reached in a test-
// sized workload; the selection under test does not read the cap.
func TestPerfAuthCache1_EvictionIndexSelectsTheSameVictimAsTheFullScan(t *testing.T) {
	const (
		clients = 17
		steps   = 1500
	)
	for _, seed := range []int64{1, 2, 3, 5, 8, 13} {
		rng := rand.New(rand.NewSource(seed)) //nolint:gosec // G404: deterministic seeded workload, not security
		a := &authCacheStore{}
		for step := 0; step < steps; step++ {
			client := "client-" + strconv.Itoa(rng.Intn(clients))
			// A small password space so refreshes of an existing key happen
			// often: that is the path that re-attributes and re-appends a key.
			pass := "p-" + strconv.Itoa(rng.Intn(60))
			a.set(client, "user", pass, rng.Intn(2) == 0)

			a.mu.Lock()
			now := time.Now()
			// Age one entry so the expired-front path is exercised alongside
			// the fairness path rather than only after a full TTL.
			//
			// Reaching past set() to rewrite an expiry must re-run
			// syncBucketLocked, which is the ONLY writer of the memo the heaps
			// are ordered on. Production never needs this: set writes an
			// entry's expiry once, at insertion, and every later change to a
			// bucket's front goes through syncBucketLocked already.
			if rng.Intn(6) == 0 && len(a.entries) > 0 {
				keys := make([]string, 0, len(a.entries))
				for k := range a.entries {
					keys = append(keys, k)
				}
				sort.Strings(keys) // map order must not steer the workload
				victim := a.entries[keys[rng.Intn(len(keys))]]
				victim.expiry = now.Add(-time.Minute)
				if b := a.buckets[victim.client]; b != nil {
					a.syncBucketLocked(victim.client, b)
				}
			}
			checkAuthEvictionIndex(t, a, "seed "+strconv.FormatInt(seed, 10)+" step "+strconv.Itoa(step))
			assertSameAuthVictim(t, a, now, step)
			// Drive a real eviction through the production path so the index is
			// checked against the state evictions leave behind, not only
			// insertions.
			if len(a.entries) > 40 {
				a.evictOneLocked(now)
				checkAuthEvictionIndex(t, a, "post-evict step "+strconv.Itoa(step))
			}
			a.mu.Unlock()
		}
		if a.Evictions() == 0 {
			t.Fatal("not-vacuous check: no eviction ran, so the oracle compared nothing")
		}
	}
}

// TestPerfAuthCache1_EvictionPrefersTheEarliestExpiredFront pins the one
// deliberate refinement PERF-AUTHCACHE-1 made. The scan dropped whichever
// expired front Go's randomised map iteration reached first; the index drops
// the one that expired soonest, which satisfies the same policy and is
// reproducible — the property betterAuthCacheVictim exists to give the live
// path.
func TestPerfAuthCache1_EvictionPrefersTheEarliestExpiredFront(t *testing.T) {
	a := &authCacheStore{}
	for i := 0; i < 6; i++ {
		a.set("client-"+strconv.Itoa(i), "user", "p-"+strconv.Itoa(i), true)
	}
	now := time.Now()
	a.mu.Lock()
	// Expire three fronts at distinct instants; the earliest must go first.
	// syncBucketLocked is the only writer of the memo the heaps are ordered
	// on, so a test that reaches past set() to age an entry must re-run it.
	for i, age := range []time.Duration{3 * time.Minute, time.Minute, 2 * time.Minute} {
		client := "client-" + strconv.Itoa(i)
		a.entries[cacheKey("user", "p-"+strconv.Itoa(i))].expiry = now.Add(-age)
		a.syncBucketLocked(client, a.buckets[client])
	}
	order := []string{
		cacheKey("user", "p-0"), // -3m, earliest deadline
		cacheKey("user", "p-2"), // -2m
		cacheKey("user", "p-1"), // -1m
	}
	for i, wantKey := range order {
		gotKey, expired := indexAuthVictim(a, now)
		if !expired {
			t.Fatalf("eviction %d: index took the live path with expired fronts present", i)
		}
		if gotKey != wantKey {
			t.Errorf("eviction %d: index chose %q, want the earliest-expiring front %q", i, gotKey, wantKey)
		}
		a.evictOneLocked(now)
		checkAuthEvictionIndex(t, a, "after expired eviction "+strconv.Itoa(i))
	}
	a.mu.Unlock()
}

// TestPerfAuthCache1_EvictionIndexSurvivesRefreshAndCompaction exercises the
// paths that move a bucket's front without removing an entry — re-verifying a
// credential, which re-appends a key, and the compaction that rebuilds a
// bucket's key slice and resets its head.
func TestPerfAuthCache1_EvictionIndexSurvivesRefreshAndCompaction(t *testing.T) {
	a := &authCacheStore{}
	// One client holding several credentials, each re-verified repeatedly: the
	// shape that grows a bucket's key slice past the compaction threshold.
	for round := 0; round < 40; round++ {
		for i := 0; i < 5; i++ {
			a.set("office", "user", "p-"+strconv.Itoa(i), true)
			a.mu.Lock()
			checkAuthEvictionIndex(t, a, "refresh round "+strconv.Itoa(round))
			a.mu.Unlock()
		}
	}
	a.mu.Lock()
	b := a.buckets["office"]
	if b == nil {
		t.Fatal("not-vacuous check: the office bucket is gone")
	}
	if b.live != 5 {
		t.Errorf("office holds live=%d, want 5 distinct credentials", b.live)
	}
	a.mu.Unlock()
}

// TestPerfAuthCache1_WallNoBucketScanSurvivesInEviction is the load-independent
// guard on the regression PERF-AUTHCACHE-1 closed: it fails the build if victim
// selection goes back to iterating the bucket map, whatever the machine is
// doing at the time.
//
// The scan was linear in the number of distinct fairness keys — which is the
// number of active client addresses — and it ran under a.mu once per insertion
// for as long as the cache sat at its cap, so its return is a throughput and
// latency regression on the local credential path, not a cosmetic one.
// Measured before the index: 345,745 ns per insertion at 5,000 clients.
func TestPerfAuthCache1_WallNoBucketScanSurvivesInEviction(t *testing.T) {
	// Anchored to the package source dir, never CWD-relative: a concurrent
	// os.Chdir would otherwise make this wall read the wrong file
	// (TestTestFileReadsAreCWDIndependent enforces this).
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "store.go"))
	if err != nil {
		t.Fatal(err)
	}
	fn, ok := authFunctionBody(t, src, "evictOneLocked")
	if !ok {
		t.Fatal("not-vacuous check: evictOneLocked is gone, so this wall guards nothing")
	}
	if regexp.MustCompile(`range\s+a\.buckets`).MatchString(fn) {
		t.Error("evictOneLocked iterates a.buckets again: victim selection must come " +
			"from the a.victims / a.expiries roots, which are O(log clients), not from " +
			"a scan that is linear in the active client count")
	}
	// Not vacuous: the roots the selection is supposed to read must be there.
	for _, want := range []string{"authHeapPeek(a.expiries)", "authHeapPeek(a.victims)"} {
		if !strings.Contains(fn, want) {
			t.Errorf("not-vacuous check: evictOneLocked no longer reads %s", want)
		}
	}
}

// authFunctionBody returns the source text of the named top-level func or
// method in src.
func authFunctionBody(t *testing.T, src []byte, name string) (string, bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "store.go", src, 0)
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
