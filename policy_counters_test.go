package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// policy_counters_test.go — lastHit tracking + its persistence via the
// existing metrics-layer hit-counter system (policy-metadata P1; authority
// docs/design/POLICY-ARCHITECTURE-FUTURE.md §6 row E). HitCount already
// persists (metrics.go); this slice adds lastHit through the SAME path (no
// second persistence system).

func TestPolicyCounters_LastHitStampedOnMatch(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "any-allow", Action: ActionAllow, ID: "R-HIT"}})

	before := ps.List()[0]
	if before.HitCount != 0 || before.LastHit != "" {
		t.Fatalf("precondition: fresh rule should have 0 hits and no lastHit, got %+v", before)
	}
	if m := ps.Evaluate("10.0.0.1", "", "", "example.com", nil); m == nil {
		t.Fatal("expected the any-allow rule to match")
	}
	got := ps.List()[0]
	if got.HitCount != 1 {
		t.Errorf("HitCount = %d after one match; want 1", got.HitCount)
	}
	if got.LastHit == "" {
		t.Error("LastHit not stamped after a match")
	}
	if _, err := time.Parse(time.RFC3339, got.LastHit); err != nil {
		t.Errorf("LastHit %q is not RFC3339: %v", got.LastHit, err)
	}
}

// TestPolicyCounters_ListNeverReportsStaleLastHit pins the fix for the
// DP-after-snapshot staleness bug: LastHit is a computed display field, so a
// value that leaked onto a stored rule (e.g. a CP snapshot built from List(),
// re-applied via ReplaceAll which zeros lastHitUnix) must never be reported
// for a rule that has not actually matched on this node.
func TestPolicyCounters_ListNeverReportsStaleLastHit(t *testing.T) {
	ps := &PolicyStore{}
	// A rule carrying a computed LastHit string but no live timestamp.
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "leaked", Action: ActionAllow, ID: "L", LastHit: "2020-01-01T00:00:00Z"}})
	if got := ps.List()[0]; got.LastHit != "" {
		t.Errorf("ReplaceAll left a stale LastHit %q; want cleared", got.LastHit)
	}
	// Even if a stale string somehow arrives in a newly published definition,
	// List recomputes it from the accounting cell.
	ps.mu.Lock()
	nr := clonePolicyRuleForPublication(ps.rules[0])
	nr.LastHit = "2020-01-01T00:00:00Z"
	nr.lastHitUnix = 0
	ps.rules = []*PolicyRule{nr}
	ps.sortLocked()
	ps.mu.Unlock()
	if got := ps.List()[0]; got.LastHit != "" {
		t.Errorf("List reported stale LastHit %q for a never-hit rule; want empty", got.LastHit)
	}
}

// withCleanRuleMet swaps in a fresh global ruleMet for the test and restores
// the real one afterward, so mutating the shared counter map can't leak across
// tests (important under -shuffle).
func withCleanRuleMet(t *testing.T) {
	t.Helper()
	ruleMet.mu.Lock()
	oh, ol, oi, on, oa, oo := ruleMet.hits, ruleMet.last, ruleMet.byID, ruleMet.loadedByName, ruleMet.appliedByName, ruleMet.order
	ruleMet.hits = make(map[string]*int64)
	ruleMet.last = make(map[string]*int64)
	ruleMet.byID = make(map[string]persistedRuleCounter)
	ruleMet.loadedByName = make(map[string]persistedRuleCounter)
	ruleMet.appliedByName = make(map[string]int64)
	ruleMet.order = nil
	ruleMet.mu.Unlock()
	t.Cleanup(func() {
		ruleMet.mu.Lock()
		ruleMet.hits, ruleMet.last, ruleMet.byID, ruleMet.loadedByName, ruleMet.appliedByName, ruleMet.order = oh, ol, oi, on, oa, oo
		ruleMet.mu.Unlock()
	})
}

func withEmptyPolicyStore(t *testing.T) {
	t.Helper()
	policyStore.mu.Lock()
	savedRules, savedPath := policyStore.rules, policyStore.path
	savedVersion, savedUpdatedAt := policyStore.version, policyStore.updatedAt
	policyStore.rules = nil
	policyStore.path = ""
	policyStore.version = 0
	policyStore.updatedAt = ""
	policyStore.mu.Unlock()
	t.Cleanup(func() {
		policyStore.mu.Lock()
		policyStore.rules, policyStore.path = savedRules, savedPath
		policyStore.version, policyStore.updatedAt = savedVersion, savedUpdatedAt
		policyStore.mu.Unlock()
	})
}

func replacePolicyRulesAsFreshProcess(rules []PolicyRule) {
	policyStore.mu.Lock()
	policyStore.rules = nil
	policyStore.mu.Unlock()
	policyStore.ReplaceAll(rules)
}

func readPersistedRuleCounterFile(t *testing.T, path string) persistedRuleCounterFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file persistedRuleCounterFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if file.Version != hitCounterFormatVersion || file.Rules == nil {
		t.Fatalf("counter file header = version %d, rules nil=%v", file.Version, file.Rules == nil)
	}
	return file
}

func persistedRuleCountersByName(file persistedRuleCounterFile) map[string]persistedRuleCounter {
	recs := make(map[string]persistedRuleCounter, len(file.Rules))
	for _, rec := range file.Rules {
		recs[rec.Name] = rec
	}
	return recs
}

func TestStartHitCounterPersistenceRestoresBeforeCancelledSave(t *testing.T) {
	withCleanRuleMet(t)
	withEmptyPolicyStore(t)
	rule := policyStore.Add(PolicyRule{Name: "startup-restore", Action: ActionAllow})
	path := filepath.Join(t.TempDir(), "hit_counters.json")
	want := persistedRuleCounter{ID: rule.ID, Hits: 7, LastHit: 1_700_000_000}
	b, err := json.Marshal(map[string]persistedRuleCounter{rule.Name: want})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	startHitCounterPersistence(ctx, path)

	got := policyStore.List()[0]
	if got.HitCount != want.Hits || got.lastHitUnix != want.LastHit {
		t.Fatalf("restored telemetry = (%d,%d), want (%d,%d)", got.HitCount, got.lastHitUnix, want.Hits, want.LastHit)
	}
	saved := persistedRuleCountersByName(readPersistedRuleCounterFile(t, path))
	want.Name = rule.Name
	if saved[rule.Name] != want {
		t.Fatalf("shutdown-safe persisted telemetry = %+v, want %+v", saved[rule.Name], want)
	}
}

func TestStartHitCounterPersistencePreservesMalformedEvidence(t *testing.T) {
	withCleanRuleMet(t)
	withEmptyPolicyStore(t)
	policyStore.ReplaceAll([]PolicyRule{
		{ID: newRuleID(), Priority: 1, Name: "version", Action: ActionAllow},
		{ID: newRuleID(), Priority: 2, Name: "malformed-evidence", Action: ActionAllow},
	})

	duplicateID := newRuleID()
	duplicateStableID, err := json.Marshal(persistedRuleCounterFile{Version: hitCounterFormatVersion, Rules: []persistedRuleCounter{
		{Name: "a", ID: duplicateID, Hits: 1},
		{Name: "b", ID: duplicateID, Hits: 2},
	}})
	if err != nil {
		t.Fatal(err)
	}
	oversized := make([]persistedRuleCounter, maxRuleMetrics+1)
	for i := range oversized {
		oversized[i] = persistedRuleCounter{Name: fmt.Sprintf("rule-%03d", i)}
	}
	tooMany, err := json.Marshal(persistedRuleCounterFile{Version: hitCounterFormatVersion, Rules: oversized})
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string][]byte{
		"truncated":            []byte(`{"version":2,"rules":`),
		"top-level-null":       []byte(`null`),
		"null-historical":      []byte(`{"rule":null}`),
		"unknown-historical":   []byte(`{"rule":{"hits":1,"extra":true}}`),
		"missing-historical":   []byte(`{"rule":{"lastHit":1700000000}}`),
		"null-historical-hits": []byte(`{"rule":{"hits":null}}`),
		"null-v2-record":       []byte(`{"version":2,"rules":[null]}`),
		"missing-v2-hits":      []byte(`{"version":2,"rules":[{"name":"rule","lastHit":1700000000}]}`),
		"null-v2-hits":         []byte(`{"version":2,"rules":[{"name":"rule","hits":null}]}`),
		"duplicate-legacy-key": []byte(`{"same":1,"same":2}`),
		"duplicate-v2-key":     []byte(`{"version":2,"version":2,"rules":[]}`),
		"duplicate-record-key": []byte(`{"version":2,"rules":[{"name":"same","name":"other","hits":1}]}`),
		"missing-rules":        []byte(`{"version":2}`),
		"null-rules":           []byte(`{"version":2,"rules":null}`),
		"unsupported-version":  []byte(`{"version":3,"rules":[]}`),
		"unknown-envelope-key": []byte(`{"version":2,"rules":[],"extra":true}`),
		"unknown-record-key":   []byte(`{"version":2,"rules":[{"name":"unknown","hits":1,"extra":true}]}`),
		"negative-v2":          []byte(`{"version":2,"rules":[{"name":"negative","hits":-1}]}`),
		"malformed-v2-id":      []byte(`{"version":2,"rules":[{"name":"bad-id","id":"not-a-ulid","hits":1}]}`),
		"duplicate-stable-id":  duplicateStableID,
		"ambiguous-name-only":  []byte(`{"version":2,"rules":[{"name":"same","hits":1},{"name":"same","hits":2}]}`),
		"too-many-records":     tooMany,
		"negative-historical":  []byte(`{"negative":-1}`),
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hit_counters.json")
			if err := os.WriteFile(path, want, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			startHitCounterPersistence(ctx, path)
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("malformed counter evidence was overwritten: got %q, want %q", got, want)
			}
			for _, rule := range policyStore.List() {
				if rule.HitCount != 0 || rule.lastHitUnix != 0 {
					t.Fatalf("invalid evidence restored into policy %q: hits=%d lastHit=%d", rule.Name, rule.HitCount, rule.lastHitUnix)
				}
			}
			ruleMet.mu.RLock()
			loaded := len(ruleMet.hits) + len(ruleMet.byID) + len(ruleMet.loadedByName)
			ruleMet.mu.RUnlock()
			if loaded != 0 {
				t.Fatalf("invalid evidence mutated rule metrics: loaded cardinality=%d", loaded)
			}
		})
	}
}

func TestHistoricalCounterNameFallbackRequiresInvalidID(t *testing.T) {
	t.Run("malformed ID falls back for a unique current name", func(t *testing.T) {
		withCleanRuleMet(t)
		withEmptyPolicyStore(t)
		policyStore.ReplaceAll([]PolicyRule{{ID: newRuleID(), Priority: 1, Name: "legacy-name", Action: ActionAllow}})
		path := filepath.Join(t.TempDir(), "hit_counters.json")
		if err := os.WriteFile(path, []byte(`{"legacy-name":{"id":"not-a-ulid","hits":4}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if status := loadHitCounters(path); status != hitCounterLoadOK {
			t.Fatalf("load status = %v, want OK", status)
		}
		RestoreHitCounts()
		if got := policyStore.List()[0].HitCount; got != 4 {
			t.Fatalf("restored malformed-ID historical hits = %d, want 4", got)
		}
	})

	t.Run("valid unmatched ID never falls back by name", func(t *testing.T) {
		withCleanRuleMet(t)
		withEmptyPolicyStore(t)
		policyStore.ReplaceAll([]PolicyRule{{ID: newRuleID(), Priority: 1, Name: "reused-name", Action: ActionAllow}})
		path := filepath.Join(t.TempDir(), "hit_counters.json")
		data, err := json.Marshal(map[string]persistedRuleCounter{
			"reused-name": {ID: newRuleID(), Hits: 9},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if status := loadHitCounters(path); status != hitCounterLoadOK {
			t.Fatalf("load status = %v, want OK", status)
		}
		RestoreHitCounts()
		if got := policyStore.List()[0].HitCount; got != 0 {
			t.Fatalf("valid unmatched stable ID restored by name: got %d hits", got)
		}
	})
}

func TestHitCountersRoundTripDuplicateNamesByStableID(t *testing.T) {
	withCleanRuleMet(t)
	withEmptyPolicyStore(t)
	idA, idB := newRuleID(), newRuleID()
	replacePolicyRulesAsFreshProcess([]PolicyRule{
		{ID: idA, Priority: 1, Name: "duplicate", Action: ActionAllow},
		{ID: idB, Priority: 2, Name: "duplicate", Action: ActionDrop},
	})
	policyStore.mu.RLock()
	atomic.StoreInt64(&policyStore.rules[0].counters.hitCount, 3)
	atomic.StoreInt64(&policyStore.rules[0].counters.lastHitUnix, 1_700_000_001)
	atomic.StoreInt64(&policyStore.rules[1].counters.hitCount, 7)
	atomic.StoreInt64(&policyStore.rules[1].counters.lastHitUnix, 1_700_000_002)
	policyStore.mu.RUnlock()
	path := filepath.Join(t.TempDir(), "hit_counters.json")
	saveHitCounters(path)
	file := readPersistedRuleCounterFile(t, path)
	if len(file.Rules) != 2 || file.Rules[0].ID == file.Rules[1].ID {
		t.Fatalf("duplicate-name persistence collapsed identities: %+v", file.Rules)
	}

	replacePolicyRulesAsFreshProcess([]PolicyRule{
		{ID: idA, Priority: 1, Name: "duplicate", Action: ActionAllow},
		{ID: idB, Priority: 2, Name: "duplicate", Action: ActionDrop},
	})
	if status := loadHitCounters(path); status != hitCounterLoadOK {
		t.Fatalf("load status = %v, want OK", status)
	}
	RestoreHitCounts()
	byID := make(map[string]PolicyRule)
	for _, rule := range policyStore.List() {
		byID[rule.ID] = rule
	}
	if byID[idA].HitCount != 3 || byID[idB].HitCount != 7 {
		t.Fatalf("restored duplicate-name hits = (%d,%d), want (3,7)", byID[idA].HitCount, byID[idB].HitCount)
	}
	if byID[idA].lastHitUnix != 1_700_000_001 || byID[idB].lastHitUnix != 1_700_000_002 {
		t.Fatalf("restored duplicate-name last-hit = (%d,%d)", byID[idA].lastHitUnix, byID[idB].lastHitUnix)
	}
}

func TestReplaceAllPreservedAccountingPersistsByStableID(t *testing.T) {
	withCleanRuleMet(t)
	withEmptyPolicyStore(t)
	id := newRuleID()
	policyStore.ReplaceAll([]PolicyRule{{ID: id, Priority: 1, Name: "before-replace", DestFQDN: "*", Action: ActionAllow}})
	if match := policyStore.Evaluate("203.0.113.1", "", "unauth", "example.com", nil); match == nil {
		t.Fatal("rule did not match")
	}
	replacement := policyStore.List()[0]
	replacement.Name = "after-replace"
	policyStore.ReplaceAll([]PolicyRule{replacement})

	path := filepath.Join(t.TempDir(), "hit_counters.json")
	saveHitCounters(path)
	file := readPersistedRuleCounterFile(t, path)
	if len(file.Rules) != 1 || file.Rules[0].ID != id || file.Rules[0].Name != "after-replace" || file.Rules[0].Hits != 1 || file.Rules[0].LastHit == 0 {
		t.Fatalf("persisted post-ReplaceAll accounting = %+v", file.Rules)
	}
}

func TestHitCounters_LastHitPersistRoundTrip(t *testing.T) {
	withCleanRuleMet(t)
	withEmptyPolicyStore(t)
	path := filepath.Join(t.TempDir(), "hit_counters.json")

	ruleMet.RecordHit("persist-rule")
	ruleMet.RecordHit("persist-rule")
	saveHitCounters(path)

	// Wipe in-memory, reload from disk.
	ruleMet.mu.Lock()
	ruleMet.hits = make(map[string]*int64)
	ruleMet.last = make(map[string]*int64)
	ruleMet.byID = make(map[string]persistedRuleCounter)
	ruleMet.loadedByName = make(map[string]persistedRuleCounter)
	ruleMet.appliedByName = make(map[string]int64)
	ruleMet.order = nil
	ruleMet.mu.Unlock()

	loadHitCounters(path)

	ruleMet.mu.RLock()
	h := ruleMet.hits["persist-rule"]
	l := ruleMet.last["persist-rule"]
	ruleMet.mu.RUnlock()
	if h == nil || atomic.LoadInt64(h) != 2 {
		t.Errorf("hits not restored: %v", h)
	}
	if l == nil || atomic.LoadInt64(l) == 0 {
		t.Error("lastHit not persisted/restored")
	}
}

func TestHitCounters_LegacyFormatStillLoads(t *testing.T) {
	withCleanRuleMet(t)
	path := filepath.Join(t.TempDir(), "hit_counters.json")
	// Legacy bare-count file (pre-lastHit): {"old-rule": 9}
	if err := atomicWriteFile(path, []byte(`{"old-rule": 9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	loadHitCounters(path)
	ruleMet.mu.RLock()
	h := ruleMet.hits["old-rule"]
	ruleMet.mu.RUnlock()
	if h == nil || atomic.LoadInt64(h) != 9 {
		t.Errorf("legacy count not restored: %v", h)
	}
}

func TestRestoreHitCounts_AppliesHitsAndLastHit(t *testing.T) {
	withCleanRuleMet(t)
	withEmptyPolicyStore(t)
	// Simulate the immutable snapshot loaded from the persistence file.
	ruleMet.restoreRecords(map[string]persistedRuleCounter{
		"restore-rule": {Hits: 3, LastHit: time.Now().Unix()},
	})

	// …a fresh store loads the rule with zero live counters…
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "restore-rule", Action: ActionAllow, ID: "RID"}})
	if policyStore.List()[0].HitCount != 0 {
		t.Fatal("precondition: freshly-replaced rule should have 0 hits")
	}

	// …and RestoreHitCounts copies both hits and lastHit onto it.
	RestoreHitCounts()
	got := policyStore.List()[0]
	if got.HitCount != 3 {
		t.Errorf("HitCount = %d after restore; want 3", got.HitCount)
	}
	if got.LastHit == "" {
		t.Error("LastHit not restored onto the rule")
	}
}

func TestSaveHitCountersTracksRenamedRule(t *testing.T) {
	withCleanRuleMet(t)
	withEmptyPolicyStore(t)
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "before-rename", DestFQDN: "*", Action: ActionAllow, ID: newRuleID()}})

	for range 2 {
		if match := policyStore.Evaluate("203.0.113.1", "alice", "local", "example.com", nil); match == nil {
			t.Fatal("rule did not match")
		}
		ruleMet.RecordHit("before-rename")
	}
	current := policyStore.List()[0]
	current.Name = "after-rename"
	if !policyStore.UpdateByID(current.ID, current) {
		t.Fatal("rename update failed")
	}

	path := filepath.Join(t.TempDir(), "hit_counters.json")
	saveHitCounters(path)
	ruleMet.mu.Lock()
	ruleMet.hits = make(map[string]*int64)
	ruleMet.last = make(map[string]*int64)
	ruleMet.byID = make(map[string]persistedRuleCounter)
	ruleMet.loadedByName = make(map[string]persistedRuleCounter)
	ruleMet.appliedByName = make(map[string]int64)
	ruleMet.order = nil
	ruleMet.mu.Unlock()
	current = policyStore.List()[0]
	replacePolicyRulesAsFreshProcess([]PolicyRule{current}) // simulate freshly loaded rules with reset live accounting
	loadHitCounters(path)
	ruleMet.mu.RLock()
	_, staleNamePersisted := ruleMet.hits["before-rename"]
	ruleMet.mu.RUnlock()
	if staleNamePersisted {
		t.Fatal("pre-rename telemetry alias was persisted")
	}
	RestoreHitCounts()

	got := policyStore.List()[0]
	if got.HitCount != 2 {
		t.Fatalf("renamed rule restored HitCount = %d, want 2", got.HitCount)
	}
	if got.LastHit == "" {
		t.Fatal("renamed rule lost LastHit across persistence")
	}
}

func TestHitCountersStableIDSurvivesRenameBeforeCounterResave(t *testing.T) {
	withCleanRuleMet(t)
	withEmptyPolicyStore(t)
	id := newRuleID()
	policyStore.ReplaceAll([]PolicyRule{{ID: id, Priority: 1, Name: "old-name", DestFQDN: "*", Action: ActionAllow}})
	for range 2 {
		if match := policyStore.Evaluate("203.0.113.1", "alice", "local", "example.com", nil); match == nil {
			t.Fatal("rule did not match")
		}
	}
	path := filepath.Join(t.TempDir(), "hit_counters.json")
	saveHitCounters(path) // persisted before the policy rename

	renamed := policyStore.List()[0]
	renamed.Name = "new-name"
	if !policyStore.UpdateByID(id, renamed) {
		t.Fatal("rename update failed")
	}
	replacePolicyRulesAsFreshProcess(policyStore.List()) // simulate restart from renamed policy
	ruleMet.mu.Lock()
	ruleMet.hits = make(map[string]*int64)
	ruleMet.last = make(map[string]*int64)
	ruleMet.byID = make(map[string]persistedRuleCounter)
	ruleMet.loadedByName = make(map[string]persistedRuleCounter)
	ruleMet.appliedByName = make(map[string]int64)
	ruleMet.order = nil
	ruleMet.mu.Unlock()
	loadHitCounters(path) // still keyed by old name, joined by stable ID
	RestoreHitCounts()

	got := policyStore.List()[0]
	if got.Name != "new-name" || got.ID != id || got.HitCount != 2 {
		t.Fatalf("restored renamed rule = %+v, want ID %q, name new-name, hits 2", got, id)
	}
}

func TestRestoreRecordsCapsStableIDIndex(t *testing.T) {
	rm := &ruleMetrics{hits: make(map[string]*int64), last: make(map[string]*int64)}
	recs := make(map[string]persistedRuleCounter, maxRuleMetrics+5)
	for i := 0; i < maxRuleMetrics+5; i++ {
		recs[fmt.Sprintf("rule-%03d", i)] = persistedRuleCounter{ID: newRuleID(), Hits: 1}
	}
	rm.restoreRecords(recs)
	if len(rm.hits) != maxRuleMetrics || len(rm.byID) != maxRuleMetrics || len(rm.loadedByName) != 0 || len(rm.appliedByName) != maxRuleMetrics {
		t.Fatalf("restored cardinality hits=%d ids=%d legacy-names=%d applied=%d, want (%d,%d,0,%d)", len(rm.hits), len(rm.byID), len(rm.loadedByName), len(rm.appliedByName), maxRuleMetrics, maxRuleMetrics, maxRuleMetrics)
	}
}

func TestLegacyCounterSnapshotUpgradesToStableID(t *testing.T) {
	withCleanRuleMet(t)
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })
	id := newRuleID()
	policyStore.ReplaceAll([]PolicyRule{{ID: id, Priority: 1, Name: "legacy-name", Action: ActionAllow}})
	path := filepath.Join(t.TempDir(), "hit_counters.json")
	if err := os.WriteFile(path, []byte(`{"legacy-name":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	loadHitCounters(path)
	RestoreHitCounts()
	saveHitCounters(path)
	recs := persistedRuleCountersByName(readPersistedRuleCounterFile(t, path))
	if rec := recs["legacy-name"]; rec.ID != id || rec.Hits != 2 {
		t.Fatalf("upgraded record = %+v, want ID %q and 2 hits", rec, id)
	}
}

func TestRepeatedRestoreDoesNotDoubleCountLiveTelemetryAfterLegacyLoad(t *testing.T) {
	withCleanRuleMet(t)
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })
	policyStore.ReplaceAll([]PolicyRule{{ID: newRuleID(), Priority: 1, Name: "legacy-live", DestFQDN: "*", Action: ActionAllow}})
	ruleMet.restoreRecords(map[string]persistedRuleCounter{"legacy-live": {Hits: 10}})
	RestoreHitCounts()
	if match := policyStore.Evaluate("203.0.113.1", "alice", "local", "example.com", nil); match == nil {
		t.Fatal("rule did not match")
	}
	ruleMet.RecordHit("legacy-live") // production telemetry mirrors the evaluation hit
	RestoreHitCounts()
	if got := policyStore.List()[0].HitCount; got != 11 {
		t.Fatalf("HitCount after repeated restore = %d, want 11 (persisted 10 + one live hit)", got)
	}
}

func TestPolicyLoadPreservesLiveCountersByStableID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	id := newRuleID()
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{
		ID: id, Priority: 1, Name: "hot-reload-rule", DestFQDN: "*", Action: ActionAllow,
	}})
	if match := ps.Evaluate("203.0.113.1", "alice", "local", "example.com", nil); match == nil {
		t.Fatal("precondition: rule did not match")
	}
	rules := ps.List()
	rules[0].Name = "hot-reload-renamed"
	rules[0].HitCount = 0
	rules[0].LastHit = ""
	raw, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ps.Load(path); err != nil {
		t.Fatal(err)
	}
	got := ps.List()[0]
	if got.ID != id || got.Name != "hot-reload-renamed" {
		t.Fatalf("loaded identity = (%q, %q), want (%q, %q)", got.ID, got.Name, id, "hot-reload-renamed")
	}
	if got.HitCount != 1 || got.LastHit == "" {
		t.Fatalf("accounting after hot reload = (hits=%d, lastHit=%q), want preserved", got.HitCount, got.LastHit)
	}
}

func TestRestoreRecordsPreservesLiveTelemetryAcrossReloads(t *testing.T) {
	rm := &ruleMetrics{
		hits:          make(map[string]*int64),
		last:          make(map[string]*int64),
		byID:          make(map[string]persistedRuleCounter),
		loadedByName:  make(map[string]persistedRuleCounter),
		appliedByName: make(map[string]int64),
	}
	old := time.Now().Add(-time.Hour).Unix()
	future := time.Now().Add(time.Hour).Unix()
	rm.restoreRecords(map[string]persistedRuleCounter{"reload": {Hits: 10, LastHit: old}})
	rm.RecordHit("reload")
	atomic.StoreInt64(rm.last["reload"], future)

	// Repeating or temporarily omitting a snapshot cannot erase live telemetry.
	rm.restoreRecords(map[string]persistedRuleCounter{"reload": {Hits: 10, LastHit: old}})
	rm.restoreRecords(map[string]persistedRuleCounter{})
	rm.restoreRecords(map[string]persistedRuleCounter{"reload": {Hits: 10, LastHit: old}})
	if got := atomic.LoadInt64(rm.hits["reload"]); got != 11 {
		t.Fatalf("hits after repeated/omitted reload = %d, want persisted 10 + one live hit", got)
	}
	if got := atomic.LoadInt64(rm.last["reload"]); got != future {
		t.Fatalf("lastHit after older reload = %d, want newer live timestamp %d", got, future)
	}

	// A genuinely newer persisted baseline contributes only its positive delta.
	rm.restoreRecords(map[string]persistedRuleCounter{"reload": {Hits: 12, LastHit: old}})
	if got := atomic.LoadInt64(rm.hits["reload"]); got != 13 {
		t.Fatalf("hits after baseline growth = %d, want persisted 12 + one live hit", got)
	}
}

func TestLastHitWritersAreMonotonic(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{ID: newRuleID(), Priority: 1, Name: "future-hit", DestFQDN: "*", Action: ActionAllow}})
	atomic.StoreInt64(&ps.rules[0].counters.lastHitUnix, future)
	if match := ps.Evaluate("203.0.113.1", "alice", "local", "example.com", nil); match == nil {
		t.Fatal("rule did not match")
	}
	if got := atomic.LoadInt64(&ps.rules[0].counters.lastHitUnix); got != future {
		t.Fatalf("Evaluate reduced lastHitUnix from %d to %d", future, got)
	}

	rm := &ruleMetrics{hits: make(map[string]*int64), last: make(map[string]*int64)}
	zero, last := int64(0), future
	rm.hits["future-hit"] = &zero
	rm.last["future-hit"] = &last
	rm.RecordHit("future-hit")
	if got := atomic.LoadInt64(&last); got != future {
		t.Fatalf("RecordHit reduced last timestamp from %d to %d", future, got)
	}
}
