package main

// threatfeed_savetodisk_race_test.go — focused race investigation
// for the ThreatFeed.saveToDisk capture pattern (PR #247 non-
// blocking review note).
//
// Surface under examination
// =========================
// saveToDisk (threatfeed.go:416–440) reads tf.urls / tf.domains
// under RLock and captures them into a feedDB struct by *reference*
// (the maps are not deep-copied). It then RUnlocks BEFORE
// json.Marshal walks those references:
//
//	tf.mu.RLock()
//	allowlist := make([]string, 0, len(tf.domainAllowlist))
//	for d := range tf.domainAllowlist { allowlist = append(allowlist, d) }
//	sort.Strings(allowlist)
//	db := feedDB{
//	    LastSync:        tf.lastSync,
//	    URLs:            tf.urls,           // reference, not deep copy
//	    Domains:         tf.domains,        // reference, not deep copy
//	    DomainAllowlist: allowlist,         // slice copy
//	}
//	tf.mu.RUnlock()
//	data, err := json.Marshal(db)            // walks references unlocked
//
// The PR #247 review note flagged this as a future-fragility item.
// This test investigates whether the pattern actually trips
// `go test -race` under concurrent mutator activity.
//
// Static analysis (recorded for context)
// ======================================
// Grep `tf.urls\b|tf.domains\b|tf.domainAllowlist\b` returns:
//   - urls written only at :150 (Sync), :398 (loadFromDisk init),
//     :495 (ImportFeedData) — all REASSIGNMENTS to fresh maps under
//     tf.mu.Lock(); the OLD map is never mutated in place.
//   - domains: same pattern (:151, :399, :496).
//   - domainAllowlist: REASSIGNED at :89 (Init), :257
//     (SetDomainAllowlist), :403 (loadFromDisk); but ALSO mutated
//     in place at :279 (AddDomainAllowlist add) and :292
//     (RemoveDomainAllowlist delete).
//
// Predictions
// ===========
// - urls/domains: saveToDisk after RUnlock walks the OLD map; the
//   field reassignment doesn't mutate the old map, so json.Marshal
//   sees a stable snapshot. No race expected on these.
// - domainAllowlist: saveToDisk DEEP-COPIES into a []string slice
//   under RLock, so no reference is held past RUnlock. The in-place
//   mutations at :279 / :292 cannot race with the slice walk. No
//   race expected.
//
// Result (recorded after running this harness under -race -count=1
// on the PR #247 baseline, May 2026)
// ====================================================================
// `-race` DID NOT FIRE under 4 saveToDisk goroutines × 50 iterations
// concurrent with 4 mutator goroutines × 50 iterations cycling
// through ImportFeedData / SetDomainAllowlist /
// AddDomainAllowlist / RemoveDomainAllowlist.
//
// The shallow-map capture pattern in saveToDisk is **theoretically
// fragile** (capturing a reference and using it post-RUnlock is a
// recognised footgun in general Go) but **safe under the current
// invariant set**:
//
//	(i)  tf.urls / tf.domains are only ever REASSIGNED wholesale
//	     (lines 150–151 in Sync, 495–496 in ImportFeedData) under
//	     tf.mu.Lock — the old map captured by saveToDisk is
//	     unreachable from any writer after the reassignment, so the
//	     unlocked json.Marshal walk iterates an immutable snapshot.
//	     Grep `tf.urls\[|tf.domains\[` returns only READS (lines
//	     177, 182, 199); no per-key WRITE site exists.
//	(ii) tf.domainAllowlist IS mutated in place at :279 / :292, but
//	     saveToDisk DEEP-COPIES it into a []string slice under
//	     RLock before RUnlock; the in-place mutators cannot reach
//	     the slice.
//
// No production fix is warranted. This test stays as a forward
// regression guard:
//   - if a future change adds a per-key write site on tf.urls or
//     tf.domains (e.g. `tf.urls[k] = v` outside a wholesale
//     reassignment), the harness will trip `-race` because
//     saveToDisk's unlocked walk would race the in-place mutation;
//   - if a future change replaces the domainAllowlist slice copy
//     with a direct reference, the AddDomainAllowlist /
//     RemoveDomainAllowlist mutators will race the same way.
//
// The test runs in CI on every -race gate by default. No env-var
// gate; no t.Skip.

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestThreatFeed_SaveToDisk_ConcurrentMutators_Race(t *testing.T) {
	ensureClusterPersistTestLogger(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "threatfeed.json")

	tf := &ThreatFeed{
		dbPath:          path,
		urls:            map[string]feedEntry{},
		domains:         map[string]feedEntry{},
		domainAllowlist: map[string]bool{},
	}

	// Seed initial state so saveToDisk has something non-trivial to
	// marshal on every iteration.
	seedURLs := make(map[string]int64, 128)
	seedDomains := make(map[string]int64, 128)
	for i := 0; i < 128; i++ {
		seedURLs[fmt.Sprintf("http://race-test-%d.example/x", i)] = int64(1700000000 + i)
		seedDomains[fmt.Sprintf("race-test-%d.example", i)] = int64(1700000000 + i)
	}
	tf.ImportFeedData(seedURLs, seedDomains)
	tf.SetDomainAllowlist([]string{"seed-allow-1.example", "seed-allow-2.example"})

	const (
		saveGoroutines     = 4
		mutatorGoroutines  = 4
		savesPerGoroutine  = 50
		mutatorsPerGoroutine = 50
	)

	// startBarrier releases all goroutines simultaneously to maximise
	// concurrent overlap from the first iteration. No sleeps; no
	// timing-based assertions. The race detector is the assertion.
	startBarrier := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(saveGoroutines + mutatorGoroutines)

	// Save goroutines: hot-loop saveToDisk via the public Save()
	// wrapper. Each call:
	//   1. RLocks, reads tf.urls / tf.domains by reference,
	//      deep-copies tf.domainAllowlist into a slice.
	//   2. RUnlocks.
	//   3. json.Marshal walks the held references.
	//   4. atomicWriteFile commits to disk.
	for i := 0; i < saveGoroutines; i++ {
		go func() {
			defer wg.Done()
			<-startBarrier
			for j := 0; j < savesPerGoroutine; j++ {
				tf.Save()
			}
		}()
	}

	// Mutator goroutines: cycle through the four public mutator
	// surfaces — two that REASSIGN (ImportFeedData,
	// SetDomainAllowlist) and two that MUTATE IN PLACE
	// (AddDomainAllowlist, RemoveDomainAllowlist).
	for i := 0; i < mutatorGoroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-startBarrier
			for j := 0; j < mutatorsPerGoroutine; j++ {
				switch (i + j) % 4 {
				case 0:
					// Reassign urls + domains (Lock'd in
					// threatfeed.go:149–153).
					newURLs := map[string]int64{
						fmt.Sprintf("http://mut-%d-%d.example/x", i, j): 1700000000,
					}
					newDomains := map[string]int64{
						fmt.Sprintf("mut-%d-%d.example", i, j): 1700000000,
					}
					tf.ImportFeedData(newURLs, newDomains)
				case 1:
					// Reassign domainAllowlist (Lock'd in
					// threatfeed.go:255–270).
					tf.SetDomainAllowlist([]string{
						fmt.Sprintf("allow-mut-%d-%d.example", i, j),
					})
				case 2:
					// In-place ADD to domainAllowlist (Lock'd
					// in threatfeed.go:273–287).
					tf.AddDomainAllowlist(fmt.Sprintf("add-mut-%d-%d.example", i, j))
				case 3:
					// In-place DELETE from domainAllowlist
					// (Lock'd in threatfeed.go:289–301).
					tf.RemoveDomainAllowlist(fmt.Sprintf("add-mut-%d-%d.example", i, j))
				}
			}
		}()
	}

	close(startBarrier)
	wg.Wait()

	// Final sanity: the file exists. The actual assertion is the
	// race detector — if any unsynchronized access on tf.urls /
	// tf.domains / tf.domainAllowlist happened during the
	// saveToDisk windows, this test fails AT THE RACE SITE
	// (not in this function).
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("threatfeed.json missing after race harness: %v", err)
	}
}
