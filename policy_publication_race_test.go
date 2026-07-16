package main

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPolicyStore_EvaluateConcurrentMutationNoRace(t *testing.T) {
	ps := &PolicyStore{}
	for i := 1; i <= 32; i++ {
		ps.Add(PolicyRule{
			Priority: i,
			Name:     fmt.Sprintf("race-rule-%d", i),
			DestFQDN: fmt.Sprintf("host-%d.example", i),
			Action:   ActionAllow,
		})
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = ps.Evaluate("203.0.113.1", "alice", "local", "host-32.example", nil)
				}
			}
		}()
	}

	for i := 0; i < 3000; i++ {
		if !ps.Delete(16) {
			t.Fatal("delete of replacement slot failed")
		}
		ps.Add(PolicyRule{
			Priority: 16,
			Name:     fmt.Sprintf("replacement-%d", i),
			DestFQDN: "replacement.example",
			Action:   ActionAllow,
		})
	}
	close(stop)
	wg.Wait()
}

func TestPolicyStore_EvaluateConcurrentAllPublicationMutatorsNoRace(t *testing.T) {
	ps := &PolicyStore{path: filepath.Join(t.TempDir(), "policy.json")}
	a := ps.Add(PolicyRule{
		Priority: 1, Name: "all-mutators-a", DestFQDN: "*", Action: ActionAllow,
		DecryptionProfileID: "decrypt-id", DecryptionProfile: "decrypt-a",
		DestCategoryGroupID: "category-id", DestCategoryGroup: "category-a",
	})
	b := ps.Add(PolicyRule{Priority: 2, Name: "all-mutators-b", DestFQDN: "never.example", Action: ActionAllow})

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = ps.Evaluate("203.0.113.1", "alice", "local", "example.com", nil)
					_ = ps.List()
				}
			}
		}()
	}

	for i := range 100 {
		var byID PolicyRule
		for _, rule := range ps.List() {
			if rule.ID == a.ID {
				byID = rule
				break
			}
		}
		if byID.ID == "" {
			t.Fatal("stable rule disappeared")
		}
		byID.Name = fmt.Sprintf("all-mutators-a-%d", i)
		if !ps.UpdateByID(a.ID, byID) {
			t.Fatal("UpdateByID failed")
		}
		current := ps.List()
		byPriority := current[1]
		if !ps.Update(byPriority.Priority, byPriority) {
			t.Fatal("Update failed")
		}
		current = ps.List()
		if !ps.Reorder([]int{current[1].Priority, current[0].Priority}) {
			t.Fatal("Reorder failed")
		}
		current = ps.List()
		if !ps.PermutePriorities([]int{current[1].Priority, current[0].Priority}) {
			t.Fatal("PermutePriorities failed")
		}
		ps.CascadeDecryptionProfileRename("decrypt-id", "", fmt.Sprintf("decrypt-%d", i))
		ps.CascadeDestCategoryGroupRename("category-id", "", fmt.Sprintf("category-%d", i))
		_ = ps.Save() // this in-memory stress store has no persistence path
		if i%10 == 0 {
			ps.ReplaceAll(ps.List())
		}
	}
	close(stop)
	wg.Wait()

	ids := map[string]bool{}
	for _, rule := range ps.List() {
		ids[rule.ID] = true
	}
	if !ids[a.ID] || !ids[b.ID] {
		t.Fatalf("publication mutators changed stable IDs: %+v", ids)
	}
}

func TestPolicyStore_PublicationPreservesRuleIdentityAndHits(t *testing.T) {
	ps := &PolicyStore{}
	added := ps.Add(PolicyRule{Priority: 1, Name: "stable", DestFQDN: "example.com", Action: ActionAllow})
	if added.ID == "" {
		t.Fatal("Add did not assign a stable rule ID")
	}
	if match := ps.Evaluate("203.0.113.1", "alice", "local", "example.com", nil); match == nil {
		t.Fatal("initial rule did not match")
	}

	updated := added
	updated.Name = "stable-renamed"
	if !ps.UpdateByID(added.ID, updated) {
		t.Fatal("UpdateByID failed")
	}
	match := ps.Evaluate("203.0.113.1", "alice", "local", "example.com", nil)
	if match == nil || match.Rule.ID != added.ID || match.Rule.Name != "stable-renamed" {
		t.Fatalf("updated match = %#v; want renamed rule with stable ID %q", match, added.ID)
	}
	got := ps.List()
	if len(got) != 1 || got[0].ID != added.ID || got[0].HitCount != 2 {
		t.Fatalf("published rule = %#v; want stable ID and two cumulative hits", got)
	}
}

func TestPolicyStore_PublicationPreservesFirstMatchReorder(t *testing.T) {
	ps := &PolicyStore{}
	block := ps.Add(PolicyRule{Priority: 1, Name: "block-first", DestFQDN: "*", Action: ActionBlockPage})
	allow := ps.Add(PolicyRule{Priority: 2, Name: "allow-second", DestFQDN: "*", Action: ActionAllow})

	if match := ps.Evaluate("203.0.113.1", "", "unauth", "example.com", nil); match == nil || match.Rule.ID != block.ID {
		t.Fatalf("initial first match = %#v; want block rule %q", match, block.ID)
	}
	if !ps.Reorder([]int{allow.Priority, block.Priority}) {
		t.Fatal("Reorder failed")
	}
	if match := ps.Evaluate("203.0.113.1", "", "unauth", "example.com", nil); match == nil || match.Rule.ID != allow.ID {
		t.Fatalf("reordered first match = %#v; want allow rule %q", match, allow.ID)
	}
}

func TestPolicyStore_ReplaceAllPreservesAccountingByStableID(t *testing.T) {
	ps := &PolicyStore{}
	added := ps.Add(PolicyRule{Priority: 1, Name: "before", DestFQDN: "*", Action: ActionAllow})
	if match := ps.Evaluate("203.0.113.1", "", "unauth", "example.com", nil); match == nil {
		t.Fatal("rule did not match")
	}
	snapshot := ps.List()
	if snapshot[0].HitCount != 1 || snapshot[0].lastHitUnix == 0 {
		t.Fatalf("precondition: accounting = (%d,%d), want (1,nonzero)", snapshot[0].HitCount, snapshot[0].lastHitUnix)
	}
	snapshot[0].Name = "after"
	snapshot[0].Action = ActionDrop
	ps.ReplaceAll(snapshot)
	preserved := ps.List()[0]
	if preserved.ID != added.ID || preserved.HitCount != 1 || preserved.lastHitUnix != snapshot[0].lastHitUnix {
		t.Fatalf("same-ID ReplaceAll accounting = (%q,%d,%d), want (%q,1,%d)", preserved.ID, preserved.HitCount, preserved.lastHitUnix, added.ID, snapshot[0].lastHitUnix)
	}

	fresh := snapshot[0]
	fresh.ID = newRuleID()
	ps.ReplaceAll([]PolicyRule{fresh})
	if got := ps.List()[0]; got.HitCount != 0 || got.lastHitUnix != 0 {
		t.Fatalf("new-ID ReplaceAll retained accounting = (%d,%d), want zero", got.HitCount, got.lastHitUnix)
	}
}

func TestPolicyStore_ListCannotMutatePublishedDefinition(t *testing.T) {
	enabled := true
	logTraffic := true
	stripALPN := true
	countries := []string{"US"}
	days := []string{"monday"}
	ps := &PolicyStore{}
	ps.Add(PolicyRule{
		Priority:    1,
		Name:        "immutable-list",
		DestFQDN:    "*",
		Action:      ActionAllow,
		Enabled:     &enabled,
		LogTraffic:  &logTraffic,
		StripALPN:   &stripALPN,
		DestCountry: countries,
		Schedule:    &PolicySchedule{Days: days},
	})

	// Add must detach caller-owned nested data before returning.
	enabled = false
	logTraffic = false
	stripALPN = false
	countries[0] = "GB"
	days[0] = "friday"
	added := ps.List()[0]
	if !ruleIsEnabled(&added) || !ruleLogsTraffic(&added) || !*added.StripALPN || added.DestCountry[0] != "US" || added.Schedule.Days[0] != "monday" {
		t.Fatalf("Add caller mutation escaped into published rule: %+v", added)
	}

	listed := ps.List()
	*listed[0].Enabled = false
	*listed[0].LogTraffic = false
	*listed[0].StripALPN = false
	listed[0].DestCountry[0] = "CA"
	listed[0].Schedule.Days[0] = "tuesday"

	got := ps.List()[0]
	if !ruleIsEnabled(&got) || !ruleLogsTraffic(&got) || !*got.StripALPN || got.DestCountry[0] != "US" || got.Schedule.Days[0] != "monday" {
		t.Fatalf("List mutation escaped into published rule: %+v", got)
	}
}

func TestPolicyStore_ListClonesAuthNestedData(t *testing.T) {
	ps := &PolicyStore{}
	ps.mu.Lock()
	ps.rules = []*PolicyRule{{
		Priority: 1,
		Name:     "auth-nested",
		SubjectMatch: &SubjectMatch{All: []SubjectPredicate{{
			Type:   subjectPredicateCIDR,
			Values: []string{"10.0.0.0/8"},
		}}},
		Auth:     &AuthRuleSpec{ProviderRefs: []string{"primary"}},
		counters: &policyRuleCounters{},
	}}
	ps.sortLocked()
	ps.mu.Unlock()

	listed := ps.List()
	listed[0].SubjectMatch.All[0].Values[0] = "mallory"
	listed[0].Auth.ProviderRefs[0] = "attacker"

	got := ps.List()[0]
	if got.SubjectMatch.All[0].Values[0] != "10.0.0.0/8" || got.Auth.ProviderRefs[0] != "primary" {
		t.Fatalf("List auth mutation escaped into published rule: %+v", got)
	}
}

func TestPolicyStore_PolicyMatchCannotMutatePublishedDefinition(t *testing.T) {
	enabled := true
	logTraffic := true
	stripALPN := true
	ps := &PolicyStore{}
	ps.Add(PolicyRule{
		Priority:   1,
		Name:       "immutable-match",
		DestFQDN:   "*",
		Action:     ActionAllow,
		Enabled:    &enabled,
		LogTraffic: &logTraffic,
		StripALPN:  &stripALPN,
		Schedule:   &PolicySchedule{},
	})

	match := ps.Evaluate("203.0.113.1", "alice", "local", "example.com", nil)
	if match == nil {
		t.Fatal("rule did not match")
	}
	match.Rule.Name = "mutated"
	match.Rule.Action = ActionBlockPage
	*match.Rule.Enabled = false
	*match.Rule.LogTraffic = false
	*match.Rule.StripALPN = false
	match.Rule.Schedule.TimeStart = "23:59"

	listed := ps.List()[0]
	if listed.Name != "immutable-match" || listed.Action != ActionAllow || !ruleIsEnabled(&listed) || !ruleLogsTraffic(&listed) || !*listed.StripALPN || listed.Schedule.TimeStart != "" {
		t.Fatalf("PolicyMatch mutation escaped into published rule: %+v", listed)
	}
	if next := ps.Evaluate("203.0.113.1", "alice", "local", "example.com", nil); next == nil || next.Action != ActionAllow {
		t.Fatalf("PolicyMatch mutation changed the next decision: %+v", next)
	}
}

func TestPolicyStore_PolicyMatchMaterializesLiveAccounting(t *testing.T) {
	ps := &PolicyStore{}
	ps.Add(PolicyRule{Priority: 1, Name: "match-accounting", DestFQDN: "*", Action: ActionAllow})

	match := ps.Evaluate("203.0.113.1", "alice", "local", "example.com", nil)
	if match == nil {
		t.Fatal("rule did not match")
	}
	if match.Rule.HitCount != 1 {
		t.Fatalf("PolicyMatch HitCount = %d, want 1", match.Rule.HitCount)
	}
	if match.Rule.lastHitUnix == 0 {
		t.Fatal("PolicyMatch lastHitUnix is zero after a match")
	}
}

func TestRestoreHitCountsConcurrentEvaluateNoRace(t *testing.T) {
	withCleanRuleMet(t)
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })
	ruleMet.restoreRecords(map[string]persistedRuleCounter{"restore-race": {Hits: 1}})

	for range 1000 {
		// Exercise the compatibility path for a directly installed rule with no
		// accounting cell. Restore must publish a detached definition rather than
		// filling the pointer on a revision an evaluator may already hold.
		policyStore.mu.Lock()
		policyStore.rules = []*PolicyRule{{Priority: 1, Name: "restore-race", DestFQDN: "*", Action: ActionAllow}}
		policyStore.mu.Unlock()

		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		go func() {
			defer wg.Done()
			<-start
			_ = policyStore.Evaluate("203.0.113.1", "alice", "local", "example.com", nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			RestoreHitCounts()
		}()
		close(start)
		wg.Wait()
	}
}

func TestRestoreHitCountsPreservesLiveHitAndNewerLastHit(t *testing.T) {
	withCleanRuleMet(t)
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })

	persistedHits := int64(10)
	persistedLast := time.Now().Add(-time.Hour).Unix()
	ruleMet.restoreRecords(map[string]persistedRuleCounter{
		"restore-logical-race": {Hits: persistedHits, LastHit: persistedLast},
	})
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "restore-logical-race", DestFQDN: "*", Action: ActionAllow}})
	if match := policyStore.Evaluate("203.0.113.1", "alice", "local", "example.com", nil); match == nil {
		t.Fatal("rule did not match")
	}
	liveLast := policyStore.List()[0].lastHitUnix

	RestoreHitCounts()
	got := policyStore.List()[0]
	if got.HitCount != persistedHits+1 {
		t.Fatalf("restored HitCount = %d, want persisted %d + one live hit", got.HitCount, persistedHits)
	}
	if got.lastHitUnix < liveLast {
		t.Fatalf("restored lastHitUnix = %d, want at least live timestamp %d", got.lastHitUnix, liveLast)
	}
	RestoreHitCounts()
	if got := policyStore.List()[0].HitCount; got != persistedHits+1 {
		t.Fatalf("repeated restore changed HitCount to %d, want %d", got, persistedHits+1)
	}
}

func TestPolicyStoreListDoesNotExposeCounterCell(t *testing.T) {
	ps := &PolicyStore{}
	ps.Add(PolicyRule{Priority: 1, Name: "detached-accounting", DestFQDN: "*", Action: ActionAllow})
	if match := ps.Evaluate("203.0.113.1", "alice", "local", "example.com", nil); match == nil {
		t.Fatal("rule did not match")
	}
	listed := ps.List()
	if listed[0].counters != nil {
		t.Fatal("List exposed the live private accounting cell")
	}
	if listed[0].HitCount != 1 || listed[0].lastHitUnix == 0 {
		t.Fatalf("List did not materialize accounting: %+v", listed[0])
	}
}

func TestPolicyStore_UpdatePreservesStableID(t *testing.T) {
	ps := &PolicyStore{}
	added := ps.Add(PolicyRule{Priority: 1, Name: "stable-id", DestFQDN: "*", Action: ActionAllow})
	updated := added
	updated.Name = "stable-id-renamed"
	updated.ID = newRuleID()

	if !ps.Update(added.Priority, updated) {
		t.Fatal("Update failed")
	}
	if got := ps.List()[0].ID; got != added.ID {
		t.Fatalf("Update changed stable ID from %q to %q", added.ID, got)
	}
}

func TestBackfillIDsConcurrentEvaluateNoRace(t *testing.T) {
	ps := &PolicyStore{}
	for range 1000 {
		ps.mu.Lock()
		ps.rules = []*PolicyRule{{Priority: 1, Name: "backfill-race", DestFQDN: "*", Action: ActionAllow, counters: &policyRuleCounters{}}}
		ps.mu.Unlock()

		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		go func() {
			defer wg.Done()
			<-start
			_ = ps.Evaluate("203.0.113.1", "alice", "local", "example.com", nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			ps.mu.Lock()
			ps.backfillIDsLocked()
			ps.mu.Unlock()
		}()
		close(start)
		wg.Wait()
	}
}
