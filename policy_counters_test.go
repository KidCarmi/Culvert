package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	// Both directions go through setCountersLocked so the lock-free read view is
	// republished with the maps it is derived from. Assigning the fields directly
	// leaves the view pointing at the previous run's counter cells, and RecordHit
	// would then silently increment those instead of these (see ruleCounterState).
	ruleMet.mu.Lock()
	saved := ruleMet.countersLocked()
	ruleMet.setCountersLocked(emptyRuleCounterState())
	ruleMet.mu.Unlock()
	t.Cleanup(func() {
		ruleMet.mu.Lock()
		ruleMet.setCountersLocked(saved)
		ruleMet.mu.Unlock()
	})
}

func withEmptyPolicyStore(t *testing.T) {
	t.Helper()
	saved := policyStore.List()
	policyStore.ReplaceAll(nil)
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })
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
	ruleMet.setCountersLocked(emptyRuleCounterState())
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
	// Simulate the immutable snapshot loaded from the persistence file.
	ruleMet.restoreRecords(map[string]persistedRuleCounter{
		"restore-rule": {Hits: 3, LastHit: time.Now().Unix()},
	})

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

func TestSaveHitCountersTracksRenamedRule(t *testing.T) {
	withCleanRuleMet(t)
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })
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
	ruleMet.setCountersLocked(emptyRuleCounterState())
	ruleMet.mu.Unlock()
	current = policyStore.List()[0]
	policyStore.ReplaceAll([]PolicyRule{current}) // simulate freshly loaded rules with reset live accounting
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
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })
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
	policyStore.ReplaceAll(policyStore.List()) // simulate restart from renamed policy
	ruleMet.mu.Lock()
	ruleMet.setCountersLocked(emptyRuleCounterState())
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
	if len(rm.hits) != maxRuleMetrics || len(rm.byID) != maxRuleMetrics || len(rm.loadedByName) != maxRuleMetrics || len(rm.appliedByName) != maxRuleMetrics {
		t.Fatalf("restored cardinality hits=%d ids=%d names=%d applied=%d, want all %d", len(rm.hits), len(rm.byID), len(rm.loadedByName), len(rm.appliedByName), maxRuleMetrics)
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
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recs map[string]persistedRuleCounter
	if err := json.Unmarshal(data, &recs); err != nil {
		t.Fatal(err)
	}
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

// TestPersistentAdminState_RestoreBeforePersistenceLoop pins the startup
// ordering that closes the metrics.go:96 window (Codex #738 P2): the hit-counter
// baseline must be loaded and merged into the per-rule cells (loadHitCounters →
// RestoreHitCounts) BEFORE the periodic/shutdown saver goroutine
// (startHitCounterPersistence) starts. If the saver starts first, a save racing
// the load→restore window (e.g. ctx cancelled mid-startup) persists still-zero
// cells over a non-empty hit_counters.json. Source-scanned so a future reorder
// of loadPersistentAdminState re-fails here.
func TestPersistentAdminState_RestoreBeforePersistenceLoop(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "persistent_admin_state_startup.go"))
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	body := string(src)
	iLoad := strings.Index(body, "loadHitCounters(cfg.HitCountersPath)")
	iRestore := strings.Index(body, "RestoreHitCounts()")
	iStart := strings.Index(body, "startHitCounterPersistence(ctx, cfg.HitCountersPath)")
	if iLoad < 0 || iRestore < 0 || iStart < 0 {
		t.Fatalf("expected all three calls in loadPersistentAdminState (load=%d restore=%d start=%d)", iLoad, iRestore, iStart)
	}
	if !(iLoad < iRestore && iRestore < iStart) {
		t.Fatalf("startup order must be loadHitCounters(%d) < RestoreHitCounts(%d) < startHitCounterPersistence(%d)", iLoad, iRestore, iStart)
	}
}

// TestStartHitCounterPersistence_DoesNotLoad proves the saver goroutine starter
// no longer loads the baseline itself — that responsibility moved to the caller
// so it can run before RestoreHitCounts. If a refactor folds loading back in,
// the load→restore ordering guarantee silently breaks; this catches it.
func TestStartHitCounterPersistence_DoesNotLoad(t *testing.T) {
	withCleanRuleMet(t)
	withEmptyPolicyStore(t)
	path := filepath.Join(t.TempDir(), "hit_counters.json")
	if err := os.WriteFile(path, []byte(`{"decoupled-rule":{"hits":9}}`), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel AND wait for the saver goroutine's final on-cancel save to finish
	// before t.TempDir()'s RemoveAll runs (registered earlier ⇒ runs after this
	// in LIFO order); otherwise that save races the cleanup and recreates a file
	// in the temp dir ("directory not empty").
	done := startHitCounterPersistence(ctx, path)
	t.Cleanup(func() { cancel(); <-done })

	ruleMet.mu.RLock()
	_, loaded := ruleMet.hits["decoupled-rule"]
	ruleMet.mu.RUnlock()
	if loaded {
		t.Fatal("startHitCounterPersistence loaded the baseline itself; load must be caller-driven (before RestoreHitCounts)")
	}
}

// TestHitCounterPersistence_StartupOrderPreservesCounts runs the exact
// production sequence (load → restore → start → immediate save) against a
// non-empty seed and asserts the persisted count survives — i.e. restore has
// populated the cells before any save, so the file is never clobbered to zero.
func TestHitCounterPersistence_StartupOrderPreservesCounts(t *testing.T) {
	withCleanRuleMet(t)
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })

	id := newRuleID()
	policyStore.ReplaceAll([]PolicyRule{{ID: id, Priority: 1, Name: "guard-rule", DestFQDN: "*", Action: ActionAllow}})

	path := filepath.Join(t.TempDir(), "hit_counters.json")
	lastHit := time.Now().Add(-time.Minute).Unix()
	seed := fmt.Sprintf(`{"guard-rule":{"id":%q,"hits":7,"lastHit":%d}}`, id, lastHit)
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	// Production order (see loadPersistentAdminState).
	loadHitCounters(path)
	RestoreHitCounts()
	if got := policyStore.List()[0].HitCount; got != 7 {
		t.Fatalf("after restore, cell HitCount = %d, want 7 (restore must populate cells before any save)", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel AND wait for the saver goroutine's final on-cancel save to finish
	// before t.TempDir()'s RemoveAll runs; otherwise that save races the cleanup
	// and recreates a file in the temp dir ("directory not empty").
	done := startHitCounterPersistence(ctx, path)
	t.Cleanup(func() { cancel(); <-done })
	saveHitCounters(path)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var counts map[string]persistedRuleCounter
	if err := json.Unmarshal(data, &counts); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if counts["guard-rule"].Hits != 7 {
		t.Fatalf("persisted guard-rule hits = %d, want 7 (startup-window save clobbered the count)", counts["guard-rule"].Hits)
	}
}
