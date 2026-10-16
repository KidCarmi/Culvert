package main

// Contract tests for the evaluationSnapshot publication marker.
//
// The marker is a PERFORMANCE shortcut over a CORRECTNESS walk: the walk
// guarantees no evaluator ever reaches a definition with a nil accounting cell.
// These tests pin both halves — the shortcut must fire on exactly the revisions
// sortLocked published, and the walk must still run (and still normalize) on
// every slice the marker does not name.

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestEvaluationSnapshot_PublishedRevisionSkipsTheWalk pins that a revision
// published by a mutator is recognised by identity, so the snapshot returns
// that exact slice without re-walking it.
func TestEvaluationSnapshot_PublishedRevisionSkipsTheWalk(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "a", DestFQDN: "*", Action: ActionAllow},
		{Priority: 2, Name: "b", DestFQDN: "b.example.com", Action: ActionDrop},
	})

	ps.mu.RLock()
	live := ps.rules
	published := ps.isPublished(live)
	ps.mu.RUnlock()
	if !published {
		t.Fatal("ReplaceAll's revision is not recognised as published; the hot path would re-walk every request")
	}
	snap := ps.evaluationSnapshot()
	if len(snap) != len(live) || &snap[0] != &live[0] {
		t.Fatalf("snapshot returned a different slice than the published revision (len %d vs %d)", len(snap), len(live))
	}
	for i, r := range snap {
		if r.counters == nil {
			t.Fatalf("published rule %d (%q) has a nil accounting cell", i, r.Name)
		}
	}
}

// TestEvaluationSnapshot_EveryMutatorRepublishesTheMarker pins that the marker
// tracks the CURRENT revision. A marker left naming a superseded slice would
// send every later request down the walk (a silent perf regression); a marker
// naming a slice that is no longer ps.rules must never be reported published.
func TestEvaluationSnapshot_EveryMutatorRepublishesTheMarker(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "a", DestFQDN: "*", Action: ActionAllow}})
	ps.mu.RLock()
	stale := ps.rules
	ps.mu.RUnlock()

	for _, step := range []struct {
		name   string
		mutate func()
	}{
		{"Add", func() { ps.Add(PolicyRule{Priority: 2, Name: "b", DestFQDN: "b.example.com", Action: ActionDrop}) }},
		{"Update", func() {
			ps.Update(2, PolicyRule{Priority: 2, Name: "b2", DestFQDN: "b2.example.com", Action: ActionDrop})
		}},
		{"Delete", func() { ps.Delete(2) }},
		{"ReplaceAll", func() {
			ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "z", DestFQDN: "*", Action: ActionAllow}})
		}},
	} {
		step.mutate()
		ps.mu.RLock()
		current := ps.rules
		currentOK := ps.isPublished(current)
		staleOK := len(stale) > 0 && ps.isPublished(stale)
		ps.mu.RUnlock()
		if !currentOK {
			t.Errorf("after %s the live revision is not marked published", step.name)
		}
		if staleOK && len(stale) == len(current) && &stale[0] == &current[0] {
			continue // the mutator genuinely republished the same slice
		}
		if staleOK {
			t.Errorf("after %s a superseded revision is still marked published", step.name)
		}
	}
}

// TestEvaluationSnapshot_DirectInstallStillNormalizes pins the compatibility
// contract the marker must not weaken: a slice installed around the mutators
// (internal callers, tests) is NOT named by the marker, so the walk runs and
// publishes initialized cells before any evaluator can touch them.
func TestEvaluationSnapshot_DirectInstallStillNormalizes(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "published", DestFQDN: "*", Action: ActionAllow}})

	// Install a raw definition with no accounting cell, exactly as a test or an
	// internal caller that bypasses the mutators would.
	ps.mu.Lock()
	ps.rules = []*PolicyRule{{Priority: 1, Name: "raw", DestFQDN: "*", Action: ActionAllow, ID: "RAW"}}
	raw := ps.rules
	ps.mu.Unlock()

	ps.mu.RLock()
	marked := ps.isPublished(raw)
	ps.mu.RUnlock()
	if marked {
		t.Fatal("a directly installed slice must never be mistaken for a published revision")
	}

	snap := ps.evaluationSnapshot()
	if len(snap) != 1 {
		t.Fatalf("snapshot length %d, want 1", len(snap))
	}
	if snap[0].counters == nil {
		t.Fatal("evaluationSnapshot returned a definition with a nil accounting cell; Evaluate would panic")
	}

	// And the hit still lands on that cell.
	m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
	if m == nil || m.Rule.Name != "raw" {
		t.Fatalf("expected the installed rule to match, got %v", m)
	}
	if got := atomic.LoadInt64(&snap[0].counters.hitCount); got != 1 {
		t.Errorf("hitCount %d after one match, want 1", got)
	}
}

// TestEvaluationSnapshot_SameFirstRuleDifferentSliceIsNotPublished pins the
// defect the first draft of the marker shipped with (Codex review, PR #1643):
// it stored rules[0] — the rule POINTER in slot 0 — rather than &rules[0], the
// address OF slot 0. A caller can install a same-length slice that reuses the
// published slice's first rule and replaces a later one, and the stored rule
// pointer compares equal across those two genuinely different revisions. The
// walk was then skipped over a definition carrying no accounting cell, and the
// Evaluate that matched it dereferenced a nil counters — a panic on the proxy
// hot path, reached through exactly the compatibility path the marker was
// supposed to leave untouched.
func TestEvaluationSnapshot_SameFirstRuleDifferentSliceIsNotPublished(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "keep", DestFQDN: "keep.example.com", Action: ActionAllow},
		{Priority: 2, Name: "replaced", DestFQDN: "replaced.example.com", Action: ActionDrop},
	})

	// Same length, SAME first rule pointer, second slot swapped for a raw
	// definition with no accounting cell — a fresh slice, so a fresh array.
	raw := &PolicyRule{Priority: 2, Name: "raw", DestFQDN: "*", Action: ActionAllow, ID: "RAW"}
	ps.mu.Lock()
	installed := []*PolicyRule{ps.rules[0], raw}
	ps.rules = installed
	ps.mu.Unlock()

	ps.mu.RLock()
	marked := ps.isPublished(installed)
	ps.mu.RUnlock()
	if marked {
		t.Fatal("a slice that merely REUSES the published first rule must not be recognised as that revision")
	}

	snap := ps.evaluationSnapshot()
	for i, r := range snap {
		if r.counters == nil {
			t.Fatalf("rule %d (%q) reached the evaluator with a nil accounting cell", i, r.Name)
		}
	}

	// The match lands on the raw rule, and accounting it must not panic.
	m := ps.Evaluate("203.0.113.7", "", "unauth", "anything.example.com", nil)
	if m == nil || m.Rule.Name != "raw" {
		t.Fatalf("expected the raw catch-all to match, got %v", m)
	}
}

// TestEvaluationSnapshot_EmptyStoreIsSafe pins the degenerate shapes: a store
// that never published, and a published-then-emptied one. Neither may index
// into a zero-length slice.
func TestEvaluationSnapshot_EmptyStoreIsSafe(t *testing.T) {
	var fresh PolicyStore
	if got := len(fresh.evaluationSnapshot()); got != 0 {
		t.Fatalf("fresh store snapshot length %d, want 0", got)
	}
	ps := &PolicyStore{}
	ps.ReplaceAll(nil)
	if got := len(ps.evaluationSnapshot()); got != 0 {
		t.Fatalf("emptied store snapshot length %d, want 0", got)
	}
}

// TestEvaluationSnapshot_ConcurrentMutationIsRaceFree runs the hot-path read
// against continuous republication. Every snapshot must be internally
// consistent — no nil cell reaches an evaluator — under -race.
func TestEvaluationSnapshot_ConcurrentMutationIsRaceFree(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "a", DestFQDN: "*", Action: ActionAllow}})

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			ps.ReplaceAll([]PolicyRule{
				{Priority: 1, Name: "a", DestFQDN: "*", Action: ActionAllow},
				{Priority: 2, Name: "b", DestFQDN: "b.example.com", Action: ActionDrop},
			})
		}
	}()
	for i := 0; i < 2000; i++ {
		for j, r := range ps.evaluationSnapshot() {
			if r.counters == nil {
				t.Fatalf("iteration %d: rule %d has a nil accounting cell", i, j)
			}
		}
		if m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil); m == nil {
			t.Fatalf("iteration %d: catch-all did not match", i)
		}
	}
	stop.Store(true)
	wg.Wait()
}
