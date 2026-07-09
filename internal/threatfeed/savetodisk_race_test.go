package threatfeed

// savetodisk_race_test.go is a focused race guard for Feed.saveToDisk.
//
// Production invariant: saveToDisk must not expose live tf.urls,
// tf.domains, or tf.domainAllowlist data to json.Marshal after releasing
// tf.mu. That was historically a future-fragility item; it became a real race
// risk once allowlist updates started pruning allowlisted domains from
// tf.domains in place.
//
// The fix is to deep-copy every collection under RLock, then marshal those
// copies after RUnlock. This test hot-loops Save() while the public mutators
// reassign URL/domain maps, replace the allowlist, and mutate the allowlist in
// place. The race detector is the assertion.

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestThreatFeed_SaveToDisk_ConcurrentMutators_Race(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "threatfeed.json")

	tf := &Feed{
		dbPath:          path,
		urls:            map[string]entry{},
		domains:         map[string]entry{},
		domainAllowlist: map[string]bool{},
	}

	seedURLs := make(map[string]int64, 128)
	seedDomains := make(map[string]int64, 128)
	for i := 0; i < 128; i++ {
		seedURLs[fmt.Sprintf("http://race-test-%d.example/x", i)] = int64(1700000000 + i)
		seedDomains[fmt.Sprintf("race-test-%d.example", i)] = int64(1700000000 + i)
	}
	tf.ImportFeedData(seedURLs, seedDomains)
	tf.SetDomainAllowlist([]string{"seed-allow-1.example", "seed-allow-2.example"})

	const (
		saveGoroutines       = 4
		mutatorGoroutines    = 4
		savesPerGoroutine    = 50
		mutatorsPerGoroutine = 50
	)

	startBarrier := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(saveGoroutines + mutatorGoroutines)

	for i := 0; i < saveGoroutines; i++ {
		go func() {
			defer wg.Done()
			<-startBarrier
			for j := 0; j < savesPerGoroutine; j++ {
				tf.Save()
			}
		}()
	}

	for i := 0; i < mutatorGoroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			<-startBarrier
			for j := 0; j < mutatorsPerGoroutine; j++ {
				switch (i + j) % 4 {
				case 0:
					newURLs := map[string]int64{
						fmt.Sprintf("http://mut-%d-%d.example/x", i, j): 1700000000,
					}
					newDomains := map[string]int64{
						fmt.Sprintf("mut-%d-%d.example", i, j): 1700000000,
					}
					tf.ImportFeedData(newURLs, newDomains)
				case 1:
					tf.SetDomainAllowlist([]string{
						fmt.Sprintf("allow-mut-%d-%d.example", i, j),
					})
				case 2:
					tf.AddDomainAllowlist(fmt.Sprintf("add-mut-%d-%d.example", i, j))
				case 3:
					tf.RemoveDomainAllowlist(fmt.Sprintf("add-mut-%d-%d.example", i, j))
				}
			}
		}()
	}

	close(startBarrier)
	wg.Wait()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("threatfeed.json missing after race harness: %v", err)
	}
}
