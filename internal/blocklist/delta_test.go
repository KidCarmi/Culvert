package blocklist

import "testing"

// TestApplyDelta_AddRemove covers the basic incremental enforcement semantics.
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

// TestFeedSetFingerprint_OrderIndependent: the fingerprint is a pure function of
// the set, independent of insertion/iteration order, and changes exactly when
// the set changes.
func TestFeedSetFingerprint_OrderIndependent(t *testing.T) {
	a := FeedSetFingerprint([]string{"a.example", "b.example", "*.c.example"})
	b := FeedSetFingerprint([]string{"*.c.example", "B.EXAMPLE", "a.example"}) // reordered + case
	if a != b {
		t.Fatalf("fingerprint must be order- and case-independent: %s != %s", a, b)
	}
	if a == FeedSetFingerprint([]string{"a.example", "b.example"}) {
		t.Error("fingerprint must change when the set changes")
	}
	if FeedSetFingerprint(nil) != FeedSetFingerprint([]string{"", "  "}) {
		t.Error("empty/blank tokens must not affect the fingerprint")
	}
}

// TestApplyDelta_ConvergesToFingerprint proves the delta path converges to the
// same synced fingerprint as a direct full build: applying a sequence of deltas
// yields the SyncedFingerprint the CP advertises via FeedSetFingerprint over the
// final set — the convergence guarantee the DP relies on.
func TestApplyDelta_ConvergesToFingerprint(t *testing.T) {
	// Target CP set + the fingerprint the CP would advertise for it.
	final := []string{"a.example", "c.example", "*.d.example"}
	target := FeedSetFingerprint(final)

	// Same set reached incrementally: add a,b,c → remove b → add wildcard.
	inc := New()
	inc.ApplyDelta([]string{"a.example", "b.example", "c.example"}, nil)
	inc.ApplyDelta([]string{"*.d.example"}, []string{"b.example"})

	if inc.SyncedFingerprint() != target {
		t.Fatalf("incremental deltas did not converge to the CP fingerprint:\n inc=%s\n cp=%s",
			inc.SyncedFingerprint(), target)
	}
}

// TestReplaceFeedEntries_EstablishesFingerprint: a full apply sets the synced
// fingerprint to the CP list's fingerprint (ground-truth reset), healing any
// prior delta drift.
func TestReplaceFeedEntries_EstablishesFingerprint(t *testing.T) {
	b := New()
	// Corrupt the synced fingerprint with a duplicate-toggling bad delta.
	b.ApplyDelta([]string{"x.example", "x.example"}, nil)
	hosts := []string{"a.example", "b.example", "*.c.example"}
	b.ReplaceFeedEntries(hosts)
	if b.SyncedFingerprint() != FeedSetFingerprint(hosts) {
		t.Fatal("ReplaceFeedEntries must reset the synced fingerprint to the CP list's fingerprint")
	}
}

// TestSyncedFingerprint_DecoupledFromLocalManual is the key P1 invariant that
// makes drift detection loop-free: a DP with its own local manual blocks (that
// the CP set never contained) still converges to EXACTLY the fingerprint the CP
// advertises over its BlockedHosts. Without this decoupling, a hash over the
// DP's enforcement set would diverge on every apply and trigger a perpetual
// resync storm (red-team break #1).
func TestSyncedFingerprint_DecoupledFromLocalManual(t *testing.T) {
	cpHosts := []string{"feed1.example", "feed2.example", "*.feedwild.example"}
	cpFingerprint := FeedSetFingerprint(cpHosts)

	dp := New()
	dp.AddManual("local-admin-block.example") // DP-local manual, NOT in the CP set
	dp.ReplaceFeedEntries(cpHosts)            // apply the CP set

	if dp.SyncedFingerprint() != cpFingerprint {
		t.Fatal("DP synced fingerprint must equal the CP fingerprint despite a DP-local manual block")
	}
	// Enforcement still carries BOTH the CP feed and the local manual.
	if !dp.IsBlocked("feed1.example") || !dp.IsBlocked("local-admin-block.example") {
		t.Fatal("enforcement must carry both the CP feed set and the DP-local manual block")
	}

	// A subsequent CP delta that adds/removes feed hosts keeps the DP in
	// lockstep with the CP fingerprint, still ignoring the local manual block.
	cpHosts2 := []string{"feed1.example", "*.feedwild.example", "feed3.example"} // -feed2 +feed3
	dp.ApplyDelta([]string{"feed3.example"}, []string{"feed2.example"})
	if dp.SyncedFingerprint() != FeedSetFingerprint(cpHosts2) {
		t.Fatal("after a delta, DP synced fingerprint must track the CP set, not DP-local manual")
	}
}

// TestApplyDelta_ManualRemoveDropsFingerprint: when a CP delta removes a host
// that is ALSO a DP-local manual block, enforcement keeps it (invariant 1) but
// the synced fingerprint drops it (invariant 2) so the DP still matches the CP's
// advertised fingerprint for the new version.
func TestApplyDelta_ManualRemoveDropsFingerprint(t *testing.T) {
	dp := New()
	// CP version has [shared.example, other.example]; the DP admin ALSO manually
	// blocked shared.example.
	dp.ReplaceFeedEntries([]string{"shared.example", "other.example"})
	dp.AddManual("shared.example")

	// CP publishes a new version that drops shared.example from the feed.
	dp.ApplyDelta(nil, []string{"shared.example"})

	if !dp.IsBlocked("shared.example") {
		t.Fatal("a manually-blocked host must stay enforced even after the CP feed drops it")
	}
	if dp.SyncedFingerprint() != FeedSetFingerprint([]string{"other.example"}) {
		t.Fatal("synced fingerprint must drop a CP-removed host even when it is locally manual-protected")
	}
}
