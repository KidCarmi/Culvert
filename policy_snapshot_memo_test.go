package main

// Per-request cost of the policy-rule publication check (Performance Guardian).
//
// PolicyStore.Evaluate runs on EVERY proxied request — HTTP, CONNECT,
// WebSocket and SOCKS5 alike — and its first act is evaluationSnapshot. That
// function used to scan every rule in the rulebase looking for a nil counters
// cell before it returned. Production rules always carry one, so the scan never
// short-circuited: it ran to completion on every request to prove a negative.
//
// Measured on a 4-core Xeon @2.10GHz (medians of n=3), snapshot alone:
//
//	rules      10        100       1 000     10 000
//	before     14.1 ns   52.3 ns   471 ns    28 985 ns
//	after      13.2 ns   12.8 ns    12.3 ns      13.2 ns
//
// It is superlinear before, not merely linear: the scan is a pointer chase, so
// once the rulebase no longer fits in cache each rule costs a miss.
//
// The scan ran BEFORE evaluation, so it taxed even requests the engine decides
// in O(1). A request matching the HIGHEST-priority rule — one comparison of
// real policy work — measured 465 ns at 10 rules and 30 900 ns at 10 000, i.e.
// at 10 000 rules roughly 98% of Evaluate was the pre-scan and 2% was the
// policy decision. After the change that request is flat at ~390 ns.
//
// EVERYTHING BELOW MEASURES THE PRODUCTION FUNCTION. The one exception is
// legacyEvaluationSnapshot, which deliberately freezes the PRE-CHANGE shape so
// the before/after comparison stays reproducible in-tree on any runner — the
// convention plLegacyAllowLine and BenchmarkHTTPForward_LegacyClientPerRequest
// already follow. It is the baseline and the differential oracle, never the
// thing under test.
//
//	go test -run '^$' -bench 'BenchmarkPolicySnapshot' -benchmem -count=6 .

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
)

// legacyEvaluationSnapshot is the pre-change body verbatim: an O(rulebase) scan
// for a nil counters cell on every call, with the same conditional
// normalization behind it. It is the oracle the differential test below
// compares against, so it must keep matching the semantics the production
// function had before the memo — not the memo.
func legacyEvaluationSnapshot(ps *PolicyStore) []*PolicyRule {
	ps.mu.RLock()
	rules := ps.rules
	needsPublication := false
	for _, rule := range rules {
		if rule.counters == nil {
			needsPublication = true
			break
		}
	}
	ps.mu.RUnlock()
	if !needsPublication {
		return rules
	}
	ps.mu.Lock()
	for _, rule := range ps.rules {
		if rule.counters == nil {
			ps.sortLocked()
			break
		}
	}
	rules = ps.rules
	ps.mu.Unlock()
	return rules
}

// ── Before vs after ─────────────────────────────────────────────────────────

var snapSink []*PolicyRule

// snapSinkParallel is the keep-alive sink for the PARALLEL benchmark. It is
// atomic because every RunParallel worker publishes into it, and a plain
// package-level assignment from several workers is a data race that fails
// `go test -race -bench` (Codex review). Keeping each worker's result in a
// LOCAL for the duration of the loop is still what matters for the
// measurement — a shared sink written every iteration turns false sharing into
// the thing being measured, the trap recorded on internal/blocklist's hot-read
// benchmark — so the local stays and only the one publish per worker is
// synchronized.
var snapSinkParallel atomic.Pointer[[]*PolicyRule]

func BenchmarkPolicySnapshot_Legacy(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				snapSink = legacyEvaluationSnapshot(ps)
			}
		})
	}
}

func BenchmarkPolicySnapshot_Current(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				snapSink = ps.evaluationSnapshot()
			}
		})
	}
}

// BenchmarkPolicySnapshot_CurrentParallel is the figure a gateway actually
// pays: every core evaluating policy at once. Each worker accumulates into its
// own local and publishes once, so the benchmark measures the snapshot rather
// than false sharing on one shared package variable — the trap recorded on
// internal/blocklist's hot-read benchmark, where a shared sink flattened the
// result and hid the finding. See snapSinkParallel for why that one publish is
// atomic rather than a plain assignment.
func BenchmarkPolicySnapshot_CurrentParallel(b *testing.B) {
	for _, n := range []int{100, 1000} {
		ps := buildPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				var local []*PolicyRule
				for pb.Next() {
					local = ps.evaluationSnapshot()
				}
				snapSinkParallel.Store(&local)
			})
		})
	}
}

// buildFirstMatchPolicyStore puts the matching rule at the TOP of the rulebase,
// so evaluation itself is O(1) and any growth with rule count is the snapshot's
// tax rather than the policy scan's.
func buildFirstMatchPolicyStore(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, 0, n+1)
	rules = append(rules, PolicyRule{Priority: 0, Name: "hit", DestFQDN: "target.example.com", Action: ActionAllow})
	for i := 0; i < n; i++ {
		rules = append(rules, PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("rule-%d", i),
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		})
	}
	ps.ReplaceAll(rules)
	return ps
}

// BenchmarkPolicyEvaluate_FirstMatch is the end-to-end statement of the
// finding: an O(1) policy decision must not get more expensive as the rulebase
// grows around it.
func BenchmarkPolicyEvaluate_FirstMatch(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		ps := buildFirstMatchPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil); m == nil {
					b.Fatal("expected the top-priority rule to match")
				}
			}
		})
	}
}

// ── Regression gate control ─────────────────────────────────────────────────

// TestBenchGate_SnapshotControl_StillReturnsTheWholeRulebase is the CONTROL for
// the gate above. The cheapest way to make evaluationSnapshot flat in rule
// count is to stop returning the rules — which would disable the policy engine
// entirely while passing every timing assertion. So pin that the snapshot still
// hands back the complete, priority-ordered rulebase, and that an evaluation
// against it still reaches a rule at the far end.
func TestBenchGate_SnapshotControl_StillReturnsTheWholeRulebase(t *testing.T) {
	const n = 500
	ps := buildPolicyStore(n)
	ps.Add(PolicyRule{Priority: n + 1, Name: "last", DestFQDN: "target.example.com", Action: ActionAllow})

	got := ps.evaluationSnapshot()
	if len(got) != n+1 {
		t.Fatalf("snapshot returned %d rules, want %d — the engine would be evaluating a truncated rulebase", len(got), n+1)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Priority > got[i].Priority {
			t.Fatalf("snapshot is not priority-ordered at %d: %d before %d", i, got[i-1].Priority, got[i].Priority)
		}
	}
	m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
	if m == nil || m.Rule.Name != "last" {
		t.Fatalf("the lowest-priority rule is no longer reachable through the snapshot: %+v", m)
	}
}

// ── Correctness ─────────────────────────────────────────────────────────────

// TestEvaluationSnapshot_DifferentialAgainstLegacy is the correctness spine.
// The memo is only acceptable if it hands every caller exactly what the
// pre-change scan would have handed them, so drive a randomized sequence of
// real mutations and compare the two implementations rule for rule after each
// one — including the direct-install shape that the compatibility path exists
// for, which no ordinary mutator produces.
func TestEvaluationSnapshot_DifferentialAgainstLegacy(t *testing.T) {
	// #nosec G404 -- deterministic seeded generator for reproducible test data
	rng := rand.New(rand.NewSource(20260922))
	ps := &PolicyStore{}
	next := 1

	sameRules := func(step string, a, b []*PolicyRule) {
		t.Helper()
		if len(a) != len(b) {
			t.Fatalf("%s: legacy returned %d rules, current %d", step, len(a), len(b))
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("%s: rule %d differs: legacy %p (%q) vs current %p (%q)", step, i, a[i], a[i].Name, b[i], b[i].Name)
			}
		}
	}

	for step := 0; step < 400; step++ {
		switch rng.Intn(7) {
		case 0: // Add
			ps.Add(PolicyRule{Priority: next, Name: fmt.Sprintf("r-%d", next), DestFQDN: fmt.Sprintf("h%d.example.com", next), Action: ActionAllow})
			next++
		case 1: // Delete an existing priority
			if list := ps.List(); len(list) > 0 {
				ps.Delete(list[rng.Intn(len(list))].Priority)
			}
		case 2: // Update in place
			if list := ps.List(); len(list) > 0 {
				victim := list[rng.Intn(len(list))]
				victim.Action = ActionDrop
				ps.Update(victim.Priority, victim)
			}
		case 3: // Bulk replace
			size := rng.Intn(5)
			rules := make([]PolicyRule, size)
			for i := range rules {
				rules[i] = PolicyRule{Priority: next, Name: fmt.Sprintf("b-%d", next), DestFQDN: fmt.Sprintf("b%d.example.com", next), Action: ActionAllow}
				next++
			}
			ps.ReplaceAll(rules)
		case 4: // DeleteByID
			if list := ps.List(); len(list) > 0 {
				ps.DeleteByID(list[rng.Intn(len(list))].ID)
			}
		case 5: // Direct install, bypassing every mutator — the compatibility path.
			ps.mu.Lock()
			ps.rules = []*PolicyRule{{Priority: next, Name: fmt.Sprintf("d-%d", next), DestFQDN: fmt.Sprintf("d%d.example.com", next), Action: ActionAllow}}
			ps.mu.Unlock()
			next++
		case 6: // Repeated reads: the memo is warm here and must stay honest.
		}

		legacy := legacyEvaluationSnapshot(ps)
		current := ps.evaluationSnapshot()
		sameRules(fmt.Sprintf("step %d", step), legacy, current)

		// And again, with the memo now definitely warm.
		sameRules(fmt.Sprintf("step %d (warm)", step), legacyEvaluationSnapshot(ps), ps.evaluationSnapshot())
	}
}

// TestEvaluationSnapshot_EveryMutationIsVisibleImmediately is the
// security-critical half. A memo that outlived the slice it described would
// serve a stale rulebase — a deleted deny rule that keeps allowing, or an added
// one that never takes effect — so pin that the very next evaluation after each
// kind of mutation sees the new state. Failing this is a wrong verdict, not a
// slow one.
func TestEvaluationSnapshot_EveryMutationIsVisibleImmediately(t *testing.T) {
	const host = "target.example.com"
	probe := func(ps *PolicyStore) *PolicyMatch {
		return ps.Evaluate("203.0.113.7", "", "unauth", host, nil)
	}

	mutators := map[string]func(ps *PolicyStore) (wantAction PolicyAction, wantMatch bool){
		"Add": func(ps *PolicyStore) (PolicyAction, bool) {
			ps.Add(PolicyRule{Priority: 1, Name: "added", DestFQDN: host, Action: ActionDrop})
			return ActionDrop, true
		},
		"Update": func(ps *PolicyStore) (PolicyAction, bool) {
			ps.Add(PolicyRule{Priority: 1, Name: "seed", DestFQDN: host, Action: ActionAllow})
			_ = probe(ps) // warm the memo on the pre-update slice
			ps.Update(1, PolicyRule{Priority: 1, Name: "seed", DestFQDN: host, Action: ActionDrop})
			return ActionDrop, true
		},
		"Delete": func(ps *PolicyStore) (PolicyAction, bool) {
			ps.Add(PolicyRule{Priority: 1, Name: "seed", DestFQDN: host, Action: ActionAllow})
			_ = probe(ps)
			ps.Delete(1)
			return "", false
		},
		"DeleteByID": func(ps *PolicyStore) (PolicyAction, bool) {
			added := ps.Add(PolicyRule{Priority: 1, Name: "seed", DestFQDN: host, Action: ActionAllow})
			_ = probe(ps)
			ps.DeleteByID(added.ID)
			return "", false
		},
		"ReplaceAll": func(ps *PolicyStore) (PolicyAction, bool) {
			ps.Add(PolicyRule{Priority: 1, Name: "seed", DestFQDN: host, Action: ActionAllow})
			_ = probe(ps)
			ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "replaced", DestFQDN: host, Action: ActionDrop}})
			return ActionDrop, true
		},
		"ReplaceAllToEmpty": func(ps *PolicyStore) (PolicyAction, bool) {
			ps.Add(PolicyRule{Priority: 1, Name: "seed", DestFQDN: host, Action: ActionAllow})
			_ = probe(ps)
			ps.ReplaceAll(nil)
			return "", false
		},
		"DirectInstall": func(ps *PolicyStore) (PolicyAction, bool) {
			ps.Add(PolicyRule{Priority: 1, Name: "seed", DestFQDN: host, Action: ActionAllow})
			_ = probe(ps)
			ps.mu.Lock()
			ps.rules = []*PolicyRule{{Priority: 1, Name: "direct", DestFQDN: host, Action: ActionDrop}}
			ps.mu.Unlock()
			return ActionDrop, true
		},
	}

	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			ps := &PolicyStore{}
			wantAction, wantMatch := mutate(ps)
			got := probe(ps)
			switch {
			case wantMatch && got == nil:
				t.Fatalf("%s: the mutation is invisible to the next evaluation — a stale snapshot is being served", name)
			case !wantMatch && got != nil:
				t.Fatalf("%s: removed rule %q still matches — a stale snapshot is being served", name, got.Rule.Name)
			case wantMatch && got.Action != wantAction:
				t.Fatalf("%s: got action %q, want %q", name, got.Action, wantAction)
			}
		})
	}
}

// TestEvaluationSnapshot_DirectInstallIsStillNormalized pins the compatibility
// path the memo must not swallow: rules installed straight onto ps.rules have
// no counters cell and none of the precomputed matching state sortLocked
// derives, so the first evaluation after such an install must still normalize
// them. The memo names a different slice at that point, which is what routes
// the call to the slow path.
func TestEvaluationSnapshot_DirectInstallIsStillNormalized(t *testing.T) {
	ps := &PolicyStore{}
	ps.mu.Lock()
	ps.rules = []*PolicyRule{{Priority: 1, Name: "raw", DestFQDN: "Target.Example.COM", Action: ActionAllow}}
	ps.mu.Unlock()

	rules := ps.evaluationSnapshot()
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if rules[0].counters == nil {
		t.Error("counters cell was not published — hit accounting would nil-panic on the request path")
	}
	if rules[0].normFQDN == "" {
		t.Error("normFQDN was not precomputed — the rule would be matched against an un-normalized destination")
	}
	// And the normalization must actually make the rule match the canonical host.
	if m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil); m == nil {
		t.Error("a directly installed rule does not match after normalization")
	}
}

// TestEvaluationSnapshot_MemoDoesNotSurviveItsSlice pins the fail-safe property
// the memo rests on: it is compared by slice identity, so any assignment to
// ps.rules stops it matching without the writer having to remember anything.
// This is the difference between this memo and an atomic.Pointer read view —
// there is no "mutator forgot to republish" failure mode, because a stale memo
// costs one scan rather than a wrong verdict.
func TestEvaluationSnapshot_MemoDoesNotSurviveItsSlice(t *testing.T) {
	ps := &PolicyStore{}
	ps.Add(PolicyRule{Priority: 1, Name: "a", DestFQDN: "a.example.com", Action: ActionAllow})
	_ = ps.evaluationSnapshot() // warm

	ps.mu.RLock()
	warm := sameRuleSlice(ps.verified, ps.rules)
	ps.mu.RUnlock()
	if !warm {
		t.Fatal("memo did not warm after a publication")
	}

	ps.mu.Lock()
	ps.rules = []*PolicyRule{{Priority: 1, Name: "b", DestFQDN: "b.example.com", Action: ActionAllow}}
	stale := sameRuleSlice(ps.verified, ps.rules)
	ps.mu.Unlock()
	if stale {
		t.Fatal("memo still matched a slice it never verified — an unpublished rulebase could reach the evaluator")
	}
}

// TestSameRuleSlice pins the memo key itself, including the empty-slice case
// (where there is no element address to compare) and the shared-backing-array
// case a reslice produces.
func TestSameRuleSlice(t *testing.T) {
	a := []*PolicyRule{{Name: "0"}, {Name: "1"}, {Name: "2"}}
	if !sameRuleSlice(a, a) {
		t.Error("a slice is not the same as itself")
	}
	if sameRuleSlice(a, a[:2]) {
		t.Error("a shorter reslice of the same array must not be accepted")
	}
	if sameRuleSlice(a, a[1:]) {
		t.Error("a reslice starting elsewhere in the same array must not be accepted")
	}
	if sameRuleSlice(a, append([]*PolicyRule(nil), a...)) {
		t.Error("a copy with identical contents must not be accepted — the key is identity, not equality")
	}
	if !sameRuleSlice(nil, nil) || !sameRuleSlice(nil, []*PolicyRule{}) {
		t.Error("two empty rulebases must compare equal — an empty store is a legitimate published state")
	}
	if sameRuleSlice(nil, a) {
		t.Error("empty must not match non-empty")
	}
}

// TestEvaluationSnapshot_ConcurrentReadersAndMutators runs the real evaluator
// against the real mutators under the race detector. It is the half that proves
// the memo is read and written under the same lock that already guards
// ps.rules, so adding it introduced no new data race.
func TestEvaluationSnapshot_ConcurrentReadersAndMutators(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "seed", DestFQDN: "*", Action: ActionAllow}})

	var stop atomic.Bool
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil); m != nil {
					_ = m.Rule.Name
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			ps.Add(PolicyRule{Priority: i + 2, Name: fmt.Sprintf("r-%d", i), DestFQDN: fmt.Sprintf("h%d.example.com", i), Action: ActionAllow})
			if i%5 == 0 {
				ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "seed", DestFQDN: "*", Action: ActionAllow}})
			}
			if i%7 == 0 {
				ps.mu.Lock()
				ps.rules = append([]*PolicyRule(nil), ps.rules...)
				ps.mu.Unlock()
			}
		}
		stop.Store(true)
	}()

	wg.Wait()
}
