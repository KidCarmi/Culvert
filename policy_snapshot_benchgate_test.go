//go:build benchgate

package main

// Cost gate for the evaluationSnapshot publication marker.
//
//	go test -tags benchgate -run 'TestBenchGate_PolicyEvaluationSnapshot' -v .
//
// GATE DESIGN — STRUCTURAL, NOT TIMED, following this repo's standing answer to
// runner noise (see policy_srcprefix_benchgate_test.go): the claim is proven by
// a VERDICT, never by a duration or a ratio, so the gate fails identically on
// any hardware, at any load, with or without -race.
//
// The claim: on a revision a mutator published, evaluationSnapshot must NOT
// re-walk the rule set. That walk ran on every request — twice, since Stage-1's
// resolveAuthOutcome takes the same snapshot — and it is O(number of rules) of
// pointer-chasing across as many separate heap objects, so it dominated a
// request that matched an early rule: measured on a 4-core Xeon at 10 001
// rules, 32.03 µs/op of which 30.8 µs was the walk.
//
// The probe below is the one OBSERVABLE difference between walking and not
// walking, and it is deliberately something no mutator ever does: it clears the
// accounting cells of an already-published revision IN PLACE. A snapshot that
// walks sees the nil cells and republishes (a new slice); a snapshot that
// trusts the marker returns the same slice it was given. Nothing about that
// in-place clear is a supported mutation — the production mutators always
// publish a fresh clone through copyPolicyRuleForPublication, which is exactly
// why the marker may trust them — it is simply the only way to ask the hot path
// which branch it took without measuring a clock.

import (
	"fmt"
	"testing"
)

// TestBenchGate_PolicyEvaluationSnapshotIsConstantCost pins that a published
// revision is recognised by identity instead of re-walked, at every rule count.
func TestBenchGate_PolicyEvaluationSnapshotIsConstantCost(t *testing.T) {
	for _, n := range []int{1, 10, 100, 1000} {
		t.Run(fmt.Sprintf("rules=%d", n), func(t *testing.T) {
			ps := buildPolicyStore(n)

			first := ps.evaluationSnapshot()
			if len(first) != n {
				t.Fatalf("snapshot length %d, want %d", len(first), n)
			}
			for i, r := range first {
				if r.counters == nil {
					t.Fatalf("published rule %d has a nil accounting cell", i)
				}
			}

			// Probe only (see the file comment): make every definition look
			// unpublished to a walk, without going through a mutator.
			for _, r := range first {
				r.counters = nil
			}

			again := ps.evaluationSnapshot()
			if len(again) != n || &again[0] != &first[0] {
				t.Fatalf("rules=%d: evaluationSnapshot re-walked and republished a revision a mutator had already published — "+
					"the O(number of rules) compatibility walk is back on the per-request policy hot path", n)
			}

			// Leave the store usable for anything that runs after this probe.
			ps.mu.Lock()
			ps.sortLocked()
			ps.mu.Unlock()
			for i, r := range ps.evaluationSnapshot() {
				if r.counters == nil {
					t.Fatalf("rule %d still has a nil accounting cell after republication", i)
				}
			}
		})
	}
}
