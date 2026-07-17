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

// TestCascadeRename_NoRaceWithEvaluate proves the Cascade*Rename mutators no
// longer race Evaluate's lock-free backing-array scan. Evaluate snapshots the
// slice header under RLock then scans lock-free; the pre-fix cascade wrote
// pointer slots into that same shared backing array in place (ps.rules[i]=&nr),
// which -race flags as a write concurrent with Evaluate's read. The copy-on-
// write cascade rebuilds ps.rules into a fresh slice, leaving the array a
// concurrent Evaluate is still scanning untouched. Under -race the pre-fix code
// fails here; the fixed code is clean.
func TestCascadeRename_NoRaceWithEvaluate(t *testing.T) {
	snapshotPolicyForIDTest(t)
	prof := "prof-" + t.Name()
	grp := "grp-" + t.Name()
	// Rules that reference a decryption profile and a category group by ID, so
	// both cascade methods touch them.
	a := policyStore.Add(PolicyRule{Priority: 1, Name: "race-A", Action: ActionAllow, DestFQDN: "a.example.com", DecryptionProfile: prof, DecryptionProfileID: "01ARZ3NDEKTSV4RRFFQ69G5FAV"})
	policyStore.Add(PolicyRule{Priority: 2, Name: "race-B", Action: ActionAllow, DestFQDN: "b.example.com", DestCategoryGroup: grp, DestCategoryGroupID: "01ARZ3NDEKTSV4RRFFQ69G5FAW"})
	_ = a

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Reader: hammer Evaluate (lock-free backing-array scan).
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

	// Writers: alternate the two cascade renames so the denormalized name flips
	// back and forth (each call touches ≥1 rule → rebuilds ps.rules).
	for i := 0; i < 4000; i++ {
		if i%2 == 0 {
			policyStore.CascadeDecryptionProfileRename("01ARZ3NDEKTSV4RRFFQ69G5FAV", prof, prof+"-x")
			policyStore.CascadeDecryptionProfileRename("01ARZ3NDEKTSV4RRFFQ69G5FAV", prof+"-x", prof)
		} else {
			policyStore.CascadeDestCategoryGroupRename("01ARZ3NDEKTSV4RRFFQ69G5FAW", grp, grp+"-x")
			policyStore.CascadeDestCategoryGroupRename("01ARZ3NDEKTSV4RRFFQ69G5FAW", grp+"-x", grp)
		}
	}
	close(stop)
	wg.Wait()
}
