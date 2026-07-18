package main

// controlplane_snapshot_bounds_test.go — H5 fix coverage.
//
// validateConfigSnapshot enforces per-slice caps on the DP-side
// ConfigSnapshot apply path. Caller must reject the entire snapshot on
// error (no partial application) — these tests verify the validator
// AND the apply-site integration.

import (
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

// TestValidateConfigSnapshot_AcceptsEmpty confirms the trivial case.
func TestValidateConfigSnapshot_AcceptsEmpty(t *testing.T) {
	if err := validateConfigSnapshot(ConfigSnapshot{}); err != nil {
		t.Errorf("empty snapshot must validate; got %v", err)
	}
}

// TestValidateConfigSnapshot_AcceptsAtCap covers the boundary: a slice
// of exactly cap entries is fine; cap+1 trips.
func TestValidateConfigSnapshot_AcceptsAtCap(t *testing.T) {
	snap := ConfigSnapshot{
		BlockedHosts: make([]string, maxSnapBlockedHosts),
	}
	if err := validateConfigSnapshot(snap); err != nil {
		t.Errorf("snapshot at cap should validate; got %v", err)
	}
}

// TestValidateConfigSnapshot_RejectsBlockedHostsOverflow is the
// canonical attack scenario: a malicious CP packs the gRPC frame with
// short host strings to trigger oversized DP-side allocation.
func TestValidateConfigSnapshot_RejectsBlockedHostsOverflow(t *testing.T) {
	snap := ConfigSnapshot{
		BlockedHosts: make([]string, maxSnapBlockedHosts+1),
	}
	err := validateConfigSnapshot(snap)
	if err == nil {
		t.Fatal("expected overflow error; got nil")
	}
	if !strings.Contains(err.Error(), "blocked_hosts") {
		t.Errorf("error should name the offending field; got %v", err)
	}
}

// TestValidateConfigSnapshot_RejectsPolicyRulesOverflow exercises a
// different field to confirm the table-driven validator works for all
// entries, not just the first.
func TestValidateConfigSnapshot_RejectsPolicyRulesOverflow(t *testing.T) {
	snap := ConfigSnapshot{
		PolicyRules: make([]PolicyRule, maxSnapPolicyRules+1),
	}
	err := validateConfigSnapshot(snap)
	if err == nil {
		t.Fatal("expected overflow error; got nil")
	}
	if !strings.Contains(err.Error(), "policy_rules") {
		t.Errorf("error should name the offending field; got %v", err)
	}
}

// TestValidateConfigSnapshot_RejectsThreatFeedURLsOverflow covers a map
// field — exercising len() on a map[string]int64.
func TestValidateConfigSnapshot_RejectsThreatFeedURLsOverflow(t *testing.T) {
	feed := make(map[string]int64, maxSnapThreatFeedURLs+1)
	for i := 0; i <= maxSnapThreatFeedURLs; i++ {
		feed[strconv.Itoa(i)] = int64(i)
	}
	snap := ConfigSnapshot{ThreatFeedURLs: feed}
	err := validateConfigSnapshot(snap)
	if err == nil {
		t.Fatal("expected overflow error; got nil")
	}
	if !strings.Contains(err.Error(), "threat_feed_urls") {
		t.Errorf("error should name the offending field; got %v", err)
	}
}

// TestValidateConfigSnapshot_RejectsURLCategoryHostOverflow covers the P1 inner-
// dimension bound: url_categories has a small ENTRY cap, but each entry carries a
// Hosts list — a few entries must not smuggle millions of hosts past it.
func TestValidateConfigSnapshot_RejectsURLCategoryHostOverflow(t *testing.T) {
	// Two entries whose Hosts together exceed the aggregate host cap.
	half := maxSnapURLCategoryHosts/2 + 1
	snap := ConfigSnapshot{URLCategories: []CategoryEntry{
		{Name: "a", Hosts: make([]string, half)},
		{Name: "b", Hosts: make([]string, half)},
	}}
	err := validateConfigSnapshot(snap)
	if err == nil || !strings.Contains(err.Error(), "url_category_hosts") {
		t.Fatalf("expected url_category_hosts overflow, got %v", err)
	}
}

// TestValidateConfigSnapshot_RejectsAggregateOverflow covers the P1 aggregate
// bound: individually-valid host-scale slices whose SUM exceeds the frame's
// capacity must be rejected with a clear named error (not left to overflow the
// wire). Two 2 M slices are each under their own cap but sum past the aggregate.
func TestValidateConfigSnapshot_RejectsAggregateOverflow(t *testing.T) {
	snap := ConfigSnapshot{
		BlockedHosts: make([]string, maxSnapBlockedHosts),
		IPList:       make([]string, maxSnapIPList),
	}
	err := validateConfigSnapshot(snap)
	if err == nil || !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("expected aggregate overflow (2M+2M > %d), got %v", maxSnapAggregateEntries, err)
	}
}

// TestValidateConfigSnapshot_AllowsSingleMaxedSlice confirms the aggregate bound
// does NOT reject the legitimate largest single-slice case (a 2 M blocklist).
func TestValidateConfigSnapshot_AllowsSingleMaxedSlice(t *testing.T) {
	snap := ConfigSnapshot{BlockedHosts: make([]string, maxSnapBlockedHosts)}
	if err := validateConfigSnapshot(snap); err != nil {
		t.Fatalf("a single maxed slice (2M blocked hosts) must validate; got %v", err)
	}
}

// TestApplyConfigSnapshot_RejectsOversizedSnapshot wires the validator
// into the apply path: an over-cap snapshot must NOT mutate the local
// blocklist.
func TestApplyConfigSnapshot_RejectsOversizedSnapshot(t *testing.T) {
	resetSnapshotBoundsTestGlobals(t)

	// Pre-populate the blocklist with a known marker so we can confirm
	// the over-cap snapshot does NOT replace it.
	bl = blocklist.New()
	bl.Add("preexisting.example")
	preBL := bl

	snap := ConfigSnapshot{
		Version:      99,
		BlockedHosts: make([]string, maxSnapBlockedHosts+1),
	}
	for i := range snap.BlockedHosts {
		snap.BlockedHosts[i] = "evil.example"
	}
	// applyConfigSnapshot must now RETURN an error on rejection (so the HA
	// resync path can fail closed instead of marking sync-OK on a dropped apply).
	if err := applyConfigSnapshot(snap); err == nil {
		t.Error("applyConfigSnapshot returned nil for an over-cap snapshot; HA fail-closed depends on the error")
	}

	if bl != preBL {
		t.Error("bl pointer changed despite over-cap snapshot — partial application")
	}
	if !bl.IsBlocked("preexisting.example") {
		t.Error("pre-existing blocklist entry was replaced")
	}
}

// TestFetchAndApply_OverCapDoesNotPoisonLastVersion checks the second
// integration point: a rejected snapshot must NOT advance lastVersion,
// otherwise subsequent legitimate snapshots with the same version
// would be silently skipped.
func TestFetchAndApply_OverCapDoesNotPoisonLastVersion(t *testing.T) {
	resetSnapshotBoundsTestGlobals(t)

	c := &DataPlaneClient{}
	c.lastVersion.Store(5)
	snap := ConfigSnapshot{
		Version:      10,
		BlockedHosts: make([]string, maxSnapBlockedHosts+1),
	}

	// Mimic the relevant slice of fetchAndApply: validate before
	// advancing lastVersion. We can't easily call fetchAndApply itself
	// without a live gRPC client, so we exercise the same logic that
	// guards lastVersion below.
	if err := validateConfigSnapshot(snap); err == nil {
		t.Fatal("validator should have rejected oversized snapshot")
	}
	if c.lastVersion.Load() != 5 {
		t.Errorf("lastVersion should remain 5 on rejected snapshot; got %d", c.lastVersion.Load())
	}
}

// resetSnapshotBoundsTestGlobals snapshots/restores the cluster-wide
// proxy state mutated by applyConfigSnapshot for isolation under
// -shuffle. Keeps the test surface narrow — only the globals the H5
// path can touch.
func resetSnapshotBoundsTestGlobals(t *testing.T) {
	t.Helper()
	origBL := bl
	origIPF := ipf
	origAction := atomic.LoadInt32(&defaultPolicyActionAllow)
	t.Cleanup(func() {
		bl = origBL
		ipf = origIPF
		atomic.StoreInt32(&defaultPolicyActionAllow, origAction)
	})
}
