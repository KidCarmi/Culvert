package main

// policy_evaluate_race_test.go — proves the PolicyStore snapshot readers
// (List, Save) no longer race with Evaluate's lock-free counter bumps.
//
// Evaluate bumps rule.HitCount/lastHitUnix via atomics under a shared RLock;
// List() and Save() snapshot-copy the whole rule (a plain read of those two
// fields). Before the fix the readers held only RLock (shared with Evaluate's
// RLock), so the plain copy raced with the atomic writes. The readers now take
// the exclusive Lock, which serializes them against the writers. Under -race
// the pre-fix code fails here; the fixed code is clean.

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

	// Writer: hammer Evaluate (bumps HitCount/lastHitUnix on match).
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
					policyStore.Save()
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
