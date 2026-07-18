package blocklist

import "testing"

// TestApplyDelta_AddRemove covers the basic incremental semantics.
func TestApplyDelta_AddRemove(t *testing.T) {
	b := New()
	b.ApplyDelta([]string{"a.example", "*.ads.example", "B.EXAMPLE"}, nil)
	if !b.IsBlocked("a.example") || !b.IsBlocked("x.ads.example") || !b.IsBlocked("b.example") {
		t.Fatal("added hosts (incl. wildcard + case-fold) should be blocked")
	}
	b.ApplyDelta(nil, []string{"a.example", "*.ads.example"})
	if b.IsBlocked("a.example") || b.IsBlocked("x.ads.example") {
		t.Error("removed hosts should no longer be blocked")
	}
	if !b.IsBlocked("b.example") {
		t.Error("unrelated host must remain blocked")
	}
}

// TestApplyDelta_NeverRemovesManual is the security invariant: a delta cannot
// delete an admin-managed manual block (mirrors the ReplaceFeedEntries /
// PR #249 re-injection guarantee). A compromised or buggy CP delta must not be
// able to silently unblock an operator's manual block.
func TestApplyDelta_NeverRemovesManual(t *testing.T) {
	b := New()
	b.AddManual("c2.evil.example") // admin manual block
	if !b.IsBlocked("c2.evil.example") {
		t.Fatal("manual block not in effect")
	}
	// A delta attempts to remove it.
	b.ApplyDelta(nil, []string{"c2.evil.example"})
	if !b.IsBlocked("c2.evil.example") {
		t.Fatal("a CP delta deleted an admin manual block — PR #249 regression on the delta path")
	}
}

// TestApplyDelta_ReaddWins covers the precedence when a host is in both sets.
func TestApplyDelta_ReaddWins(t *testing.T) {
	b := New()
	b.Add("h.example")
	b.ApplyDelta([]string{"h.example"}, []string{"h.example"})
	if !b.IsBlocked("h.example") {
		t.Error("a host in both added and removed should end up added (re-add wins)")
	}
}

// TestContentHash_DeterministicAndSensitive: the hash is order-independent and
// changes exactly when the enforcement set changes.
func TestContentHash_DeterministicAndSensitive(t *testing.T) {
	b1 := New()
	b1.ApplyDelta([]string{"a.example", "b.example", "*.c.example"}, nil)
	b2 := New()
	// Same set, different insertion order.
	b2.ApplyDelta([]string{"*.c.example", "b.example", "a.example"}, nil)
	if b1.ContentHash() != b2.ContentHash() {
		t.Fatal("ContentHash must be independent of insertion order")
	}

	before := b1.ContentHash()
	b1.ApplyDelta([]string{"d.example"}, nil)
	if b1.ContentHash() == before {
		t.Error("ContentHash must change when a host is added")
	}
	b1.ApplyDelta(nil, []string{"d.example"})
	if b1.ContentHash() != before {
		t.Error("ContentHash must return to the prior value when the change is reverted")
	}
}

// TestApplyDelta_ConvergesToSameHash proves the delta path is equivalent to a
// full rebuild: applying a sequence of deltas yields the same ContentHash as
// building the final set directly — the convergence guarantee the DP relies on.
func TestApplyDelta_ConvergesToSameHash(t *testing.T) {
	// Target set built directly.
	full := New()
	full.ApplyDelta([]string{"a.example", "c.example", "*.d.example"}, nil)

	// Same set reached incrementally: add a,b,c → remove b → add wildcard.
	inc := New()
	inc.ApplyDelta([]string{"a.example", "b.example", "c.example"}, nil)
	inc.ApplyDelta([]string{"*.d.example"}, []string{"b.example"})

	if inc.ContentHash() != full.ContentHash() {
		t.Fatalf("incremental deltas did not converge to the full-build hash:\n inc=%s\nfull=%s",
			inc.ContentHash(), full.ContentHash())
	}
}
