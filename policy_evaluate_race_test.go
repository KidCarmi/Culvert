package main

// policy_evaluate_race_test.go — proves PolicyStore snapshot readers (List,
// Save) do not race with Evaluate's lock-free shared-cell counter bumps.
//
// Evaluate scans an immutable definition revision and updates its stable atomic
// accounting cell after releasing the store lock. List and Save detach nested
// definition data and atomic-load that cell, so snapshots remain race-free
// without holding a store lock across request evaluation.

import (
	"sync"
	"testing"
)

func TestEvaluate_NoRaceWithListAndSave(t *testing.T) {
	snapshotPolicyForIDTest(t) // isolate + reset the store
	// Save is a no-op when path=="" (snapshotPolicyForIDTest sets path=""), but
	// the snapshot copy still runs when a path is set — point it at a temp file
	// so Save exercises the real snapshot-copy path under load.
	policyStore.path = t.TempDir() + "/rules.json"

	policyStore.Add(PolicyRule{Priority: 1, Name: "race-A", Action: ActionAllow, DestFQDN: "a.example.com"})
	policyStore.Add(PolicyRule{Priority: 2, Name: "race-B", Action: ActionAllow, DestFQDN: "b.example.com"})

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer: hammer Evaluate (bumps the shared accounting cell on match).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				policyStore.Evaluate("1.2.3.4", "", "", "a.example.com", nil)
			}
		}
	}()

	// Readers: List and Save concurrently snapshot-copy the rules.
	for r := 0; r < 2; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = policyStore.List()
					_ = policyStore.Save() // race stress; persistence outcome is not under test
				}
			}
		}()
	}

	// Let the goroutines interleave for a bit.
	for i := 0; i < 3000; i++ {
		_ = policyStore.List()
	}
	close(stop)
	wg.Wait()
}
