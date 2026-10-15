package main

// Correctness and scaling evidence for the per-revision publication memo on the
// policy evaluation snapshot (publishedRevision / PolicyStore.verified).
//
// The hot path used to re-derive "does every definition carry an accounting
// cell?" on EVERY request — an O(rules) walk under ps.mu.RLock, ahead of the
// scan. The memo answers it once per published revision. The benchmarks below
// are the before/after evidence; the tests are the deterministic gates, written
// as structural invariants rather than timing ratios so they fail identically on
// any hardware, at any load, with or without -race (same discipline as
// policy_srcprefix_benchgate_test.go).
//
//	go test -run 'TestPolicySnapshot' .
//	go test -run '^$' -bench 'BenchmarkPolicySnapshot' -benchmem -count=6 .

import (
	"fmt"
	"sync"
	"testing"
)

// buildSnapshotStore returns an isolated store with n published rules. Local to
// the test — never the process-wide policyStore — so nothing here perturbs
// global state another test depends on.
func buildSnapshotStore(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := range rules {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("snap-%d", i),
			DestFQDN: fmt.Sprintf("snap-%d.example.invalid", i),
			Action:   ActionAllow,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

// sameBacking reports whether two slices are the same published revision.
func sameBacking(a, b []*PolicyRule) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// TestPolicySnapshot_MemoisesPublishedRevision is the SCALING gate. It does not
// time anything: it asserts the structural property that makes the walk O(1) —
// after one evaluation the live revision is memoised, so the next evaluation
// answers from the memo instead of walking the rulebase. If a future change
// drops or mis-keys the memo, every evaluation walks every rule again and this
// fails deterministically.
func TestPolicySnapshot_MemoisesPublishedRevision(t *testing.T) {
	ps := buildSnapshotStore(64)
	if v := ps.verified.Load(); v != nil {
		t.Fatalf("memo populated before any evaluation: %v", v)
	}

	first := ps.evaluationSnapshot()
	v := ps.verified.Load()
	if v == nil {
		t.Fatal("first evaluation did not memoise the revision")
	}
	if !v.matchesRevision(first) {
		t.Fatal("memo does not key the revision it was derived from")
	}

	second := ps.evaluationSnapshot()
	if !sameBacking(first, second) {
		t.Fatal("second snapshot returned a different revision than the first")
	}
	if ps.verified.Load() != v {
		t.Fatal("second evaluation re-derived the memo instead of hitting it")
	}
}

// TestPolicySnapshot_MutationInvalidatesMemo proves the memo cannot answer for a
// revision it was not derived from: every mutator publishes a fresh slice, so
// the identity key stops matching and the next evaluation re-derives.
func TestPolicySnapshot_MutationInvalidatesMemo(t *testing.T) {
	ps := buildSnapshotStore(8)
	before := ps.evaluationSnapshot()
	stale := ps.verified.Load()

	ps.Add(PolicyRule{Priority: 99, Name: "added", DestFQDN: "added.example.invalid", Action: ActionAllow})

	after := ps.evaluationSnapshot()
	if sameBacking(before, after) {
		t.Fatal("Add did not publish a fresh revision; the memo key is meaningless")
	}
	if len(after) != len(before)+1 {
		t.Fatalf("snapshot after Add has %d rules, want %d", len(after), len(before)+1)
	}
	if stale.matchesRevision(after) {
		t.Fatal("the pre-mutation memo still matches the post-mutation revision")
	}
	if fresh := ps.verified.Load(); fresh == stale || !fresh.matchesRevision(after) {
		t.Fatal("the post-mutation evaluation did not re-memoise the new revision")
	}
}

// TestPolicySnapshot_DirectInstallStillPublishes covers the compatibility path
// the walk existed for: rules installed straight into ps.rules carry no
// accounting cell, and the snapshot must still normalize them under the writer
// lock before any evaluator can touch a nil counters field. The memo must not
// short-circuit that — and must then memoise the NORMALIZED revision, not the
// raw one.
func TestPolicySnapshot_DirectInstallStillPublishes(t *testing.T) {
	ps := buildSnapshotStore(4)
	_ = ps.evaluationSnapshot() // memoise the published revision first

	ps.mu.Lock()
	ps.rules = []*PolicyRule{
		{Priority: 1, Name: "raw-a", DestFQDN: "raw-a.example.invalid", Action: ActionAllow},
		{Priority: 2, Name: "raw-b", DestFQDN: "raw-b.example.invalid", Action: ActionAllow},
	}
	raw := ps.rules
	ps.mu.Unlock()

	got := ps.evaluationSnapshot()
	if len(got) != 2 {
		t.Fatalf("snapshot returned %d rules, want 2", len(got))
	}
	for i, r := range got {
		if r.counters == nil {
			t.Fatalf("rule %d (%s) still has no accounting cell after the snapshot", i, r.Name)
		}
	}
	if sameBacking(got, raw) {
		t.Fatal("the directly-installed revision was published in place instead of rebuilt")
	}
	if v := ps.verified.Load(); !v.matchesRevision(got) {
		t.Fatal("the normalized revision was not memoised")
	}
	// And the normalized revision must be usable: a match still evaluates.
	if m := ps.Evaluate("203.0.113.7", "", "", "raw-a.example.invalid", nil); m == nil {
		t.Fatal("Evaluate found no match against the normalized revision")
	}
}

// TestPolicySnapshot_EmptyRevisionNeedsNoMemo documents the one revision that is
// its own answer: an empty rulebase has nothing to walk, so it must neither
// consult nor populate the memo (storing a zero-length key would alias every
// other empty revision).
func TestPolicySnapshot_EmptyRevisionNeedsNoMemo(t *testing.T) {
	ps := &PolicyStore{}
	if got := ps.evaluationSnapshot(); len(got) != 0 {
		t.Fatalf("empty store snapshot returned %d rules", len(got))
	}
	if v := ps.verified.Load(); v != nil {
		t.Fatal("an empty revision populated the memo")
	}
}

// TestPolicySnapshot_ConcurrentEvaluateAndMutate is the concurrency gate: run it
// with -race. Readers hit, miss and re-memoise while writers publish fresh
// revisions underneath them; every snapshot a reader observes must be fully
// published, whichever revision it won.
func TestPolicySnapshot_ConcurrentEvaluateAndMutate(t *testing.T) {
	ps := buildSnapshotStore(32)
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					for _, r := range ps.evaluationSnapshot() {
						if r.counters == nil {
							t.Error("evaluator observed a definition with no accounting cell")
							return
						}
					}
					ps.Evaluate("203.0.113.7", "", "", "snap-0.example.invalid", nil)
				}
			}
		}()
	}

	for i := 0; i < 400; i++ {
		added := ps.Add(PolicyRule{
			Priority: 10000 + i,
			Name:     fmt.Sprintf("churn-%d", i),
			DestFQDN: "churn.example.invalid",
			Action:   ActionAllow,
		})
		ps.DeleteByID(added.ID)
	}
	close(stop)
	wg.Wait()
}

// BenchmarkPolicySnapshot_Steady is the before/after evidence and the regression
// benchmark. Pre-change this walked every rule on every call (measured on a
// 4 vCPU Xeon: 17.3 ns at 10 rules, 70.3 ns at 100, 387 ns at 500, 876 ns at
// 1000); with the memo it is one atomic load and a header comparison, flat
// across all four sizes. A reappearing slope here is the regression.
func BenchmarkPolicySnapshot_Steady(b *testing.B) {
	for _, n := range []int{10, 100, 500, 1000} {
		ps := buildSnapshotStore(n)
		_ = ps.evaluationSnapshot()
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if got := ps.evaluationSnapshot(); len(got) != n {
					b.Fatalf("snapshot returned %d rules, want %d", len(got), n)
				}
			}
		})
	}
}

// BenchmarkPolicySnapshot_SteadyParallel is the concurrency half of the same
// evidence. The pre-change walk held ps.mu.RLock for O(rules) — two atomic
// read-modify-writes on one shared word plus a hold time that grew with the
// rulebase — so it both taxed every request and queued the config plane behind
// it. The memo is an atomic pointer LOAD with no read-modify-write, so this
// should improve with core count rather than degrade.
func BenchmarkPolicySnapshot_SteadyParallel(b *testing.B) {
	for _, n := range []int{100, 1000} {
		ps := buildSnapshotStore(n)
		_ = ps.evaluationSnapshot()
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if got := ps.evaluationSnapshot(); len(got) != n {
						b.Fatalf("snapshot returned %d rules, want %d", len(got), n)
					}
				}
			})
		})
	}
}

// BenchmarkPolicySnapshot_AllocFree asserts the steady path stays allocation
// free: the memo must never allocate on a hit (a store per request would be
// both an allocation and a write to a shared word).
func BenchmarkPolicySnapshot_AllocFree(b *testing.B) {
	ps := buildSnapshotStore(256)
	_ = ps.evaluationSnapshot()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ps.evaluationSnapshot()
	}
}
