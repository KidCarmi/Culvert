//go:build benchgate

package main

// Perf-regression gate for the per-request policy publication check.
//
// Lives with the other benchgate tests because it is a PERFORMANCE contract,
// not a correctness one — the correctness contracts (the differential against
// the pre-change scan, per-mutator visibility, the compatibility path) are in
// policy_snapshot_memo_test.go and run in the normal suite, as does this
// gate's CONTROL (TestBenchGate_SnapshotControl_StillReturnsTheWholeRulebase),
// which is a structural assertion and is worth running unconditionally.
//
//	go test -tags benchgate -run 'TestBenchGate_EvaluationSnapshot' -v .

import "testing"

// snapshotNsPerOp times evaluationSnapshot on a warm store.
func snapshotNsPerOp(ps *PolicyStore) float64 {
	res := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			snapSink = ps.evaluationSnapshot()
		}
	})
	return float64(res.NsPerOp())
}

// TestBenchGate_EvaluationSnapshotIsFlatInRuleCount is a RATIO gate, and
// therefore machine-independent: it times 10 rules against 10 000 in the SAME
// run and requires the large rulebase to cost no more than a small multiple of
// the small one. Post-change the ratio is ~1.0x; with the per-request scan
// reintroduced it is ~2 000x, so the 4x bound has three orders of magnitude of
// separation and cannot flake on a loaded runner or under -race.
//
// A timing gate was chosen over a structural one here because the property is
// genuinely about cost scaling and the separation is enormous; the repository's
// structural-gate preference exists for cases where the margin is thin (see
// internal/connlimit and the latency histogram), which this is not.
func TestBenchGate_EvaluationSnapshotIsFlatInRuleCount(t *testing.T) {
	small := snapshotNsPerOp(buildPolicyStore(10))
	large := snapshotNsPerOp(buildPolicyStore(10000))
	if small <= 0 || large <= 0 {
		t.Skip("benchmark produced no timing signal")
	}
	const bound = 4.0
	if ratio := large / small; ratio > bound {
		t.Errorf("evaluationSnapshot scales with rule count: 10 rules %.1f ns/op, 10000 rules %.1f ns/op (%.1fx, bound %.1fx).\n"+
			"The per-request publication check must be O(1) — see the memo contract on evaluationSnapshot.", small, large, ratio, bound)
	}
}
