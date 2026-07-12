package main

import (
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
	// Even if a stale string somehow sits on a stored rule, List recomputes.
	ps.mu.Lock()
	ps.rules[0].LastHit = "2020-01-01T00:00:00Z"
	ps.rules[0].lastHitUnix = 0
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
	oh, ol, oo := ruleMet.hits, ruleMet.last, ruleMet.order
	ruleMet.hits = make(map[string]*int64)
	ruleMet.last = make(map[string]*int64)
	ruleMet.order = nil
	ruleMet.mu.Unlock()
	t.Cleanup(func() {
		ruleMet.mu.Lock()
		ruleMet.hits, ruleMet.last, ruleMet.order = oh, ol, oo
		ruleMet.mu.Unlock()
	})
}

func TestHitCounters_LastHitPersistRoundTrip(t *testing.T) {
	withCleanRuleMet(t)
	path := filepath.Join(t.TempDir(), "hit_counters.json")

	ruleMet.RecordHit("persist-rule")
	ruleMet.RecordHit("persist-rule")
	saveHitCounters(path)

	// Wipe in-memory, reload from disk.
	ruleMet.mu.Lock()
	ruleMet.hits = make(map[string]*int64)
	ruleMet.last = make(map[string]*int64)
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
	// Persisted counters live in ruleMet keyed by name…
	ruleMet.RecordHit("restore-rule")
	ruleMet.RecordHit("restore-rule")
	ruleMet.RecordHit("restore-rule")

	// …a fresh store loads the rule with zero live counters…
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })
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
