package main

// controlplane_delta_apply_test.go — T3 P1 slice 5: DP-side delta apply.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/KidCarmi/Culvert/internal/blocklist"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestApplyBlocklistDeltaSnapshot_ConvergesAndAppliesRemainder: the DP delta
// apply advances the blocklist incrementally, verifies convergence, and applies
// the non-blocklist remainder.
func TestApplyBlocklistDeltaSnapshot_ConvergesAndAppliesRemainder(t *testing.T) {
	origRules := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(origRules) })

	v1 := []string{"a.example", "b.example"}
	v3 := []string{"a.example", "c.example", "*.d.example"}
	bl.ReplaceFeedEntries(v1)

	chain := []blocklistDelta{
		{Added: []string{"c.example", "*.d.example"}, Removed: []string{"b.example"}},
	}
	remainder := ConfigSnapshot{
		PolicyRules: []PolicyRule{{Priority: 1, Name: "delta-remainder-rule", DestFQDN: "x.com", Action: "allow"}},
	}
	if err := applyBlocklistDeltaSnapshot(remainder, chain, blocklist.FeedSetFingerprint(v3)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !bl.IsBlocked("c.example") || !bl.IsBlocked("x.d.example") || bl.IsBlocked("b.example") {
		t.Fatal("blocklist did not converge to v3 via the delta")
	}
	if bl.SyncedFingerprint() != blocklist.FeedSetFingerprint(v3) {
		t.Fatal("synced fingerprint mismatch after delta apply")
	}
	found := false
	for _, r := range policyStore.List() {
		if r.Name == "delta-remainder-rule" {
			found = true
		}
	}
	if !found {
		t.Fatal("non-blocklist remainder (policy rule) was not applied")
	}
}

// TestApplyBlocklistDeltaSnapshot_DriftRejected: a wrong target fingerprint (a
// missed/misapplied delta) is detected and returns an error WITHOUT applying the
// remainder — the caller then full-resyncs.
func TestApplyBlocklistDeltaSnapshot_DriftRejected(t *testing.T) {
	origRules := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(origRules) })

	bl.ReplaceFeedEntries([]string{"a.example"})
	remainder := ConfigSnapshot{
		PolicyRules: []PolicyRule{{Priority: 1, Name: "should-not-apply", DestFQDN: "x.com", Action: "allow"}},
	}
	err := applyBlocklistDeltaSnapshot(remainder, []blocklistDelta{{Added: []string{"z.example"}}}, "deadbeefdeadbeef")
	if err == nil {
		t.Fatal("expected a drift error for a wrong target fingerprint")
	}
	for _, r := range policyStore.List() {
		if r.Name == "should-not-apply" {
			t.Fatal("remainder must NOT be applied when the blocklist fails its drift check")
		}
	}
}

// TestDataPlaneClient_DeltaSyncApplies drives the full client path: fetchAndApply
// tries the delta first, applies it, and advances lastVersion.
func TestDataPlaneClient_DeltaSyncApplies(t *testing.T) {
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDataDir })

	v1 := []string{"a.example", "b.example"}
	v2 := []string{"a.example", "b.example", "c.example"}
	bl.ReplaceFeedEntries(v1)

	c := &DataPlaneClient{lastVersion: 5}
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		if method != methodGetConfigDelta {
			return nil, fmt.Errorf("unexpected method %s (should not fall through to full sync)", method)
		}
		reply := getConfigDeltaReply{
			Mode:          "delta",
			BaseVersion:   5,
			TargetVersion: 6,
			Deltas:        []blocklistDelta{{Added: []string{"c.example"}}},
			TargetFP:      blocklist.FeedSetFingerprint(v2),
			Remainder:     &ConfigSnapshot{},
		}
		b, _ := json.Marshal(reply)
		return b, nil
	}
	c.fetchAndApply(context.Background())
	if c.lastVersion != 6 {
		t.Fatalf("lastVersion=%d, want 6 (delta applied)", c.lastVersion)
	}
	if !bl.IsBlocked("c.example") {
		t.Fatal("delta add not applied to the blocklist")
	}
	if bl.SyncedFingerprint() != blocklist.FeedSetFingerprint(v2) {
		t.Fatal("synced fingerprint mismatch after client delta apply")
	}
}

// TestDataPlaneClient_DeltaUnchanged: an unchanged reply advances nothing and
// does not fall through to a full pull.
func TestDataPlaneClient_DeltaUnchanged(t *testing.T) {
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)
	c := &DataPlaneClient{lastVersion: 7}
	calls := 0
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		calls++
		if method != methodGetConfigDelta {
			return nil, fmt.Errorf("unexpected method %s", method)
		}
		b, _ := json.Marshal(getConfigDeltaReply{Mode: "unchanged", TargetVersion: 7})
		return b, nil
	}
	c.fetchAndApply(context.Background())
	if c.lastVersion != 7 {
		t.Fatalf("lastVersion changed to %d on unchanged", c.lastVersion)
	}
	if calls != 1 {
		t.Fatalf("unchanged should be a single delta call, got %d calls", calls)
	}
}

// TestDataPlaneClient_DeltaResyncFallsThrough: a resync directive makes the DP
// fall through to the full GetConfig path, which applies the full snapshot.
func TestDataPlaneClient_DeltaResyncFallsThrough(t *testing.T) {
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDataDir })

	full := []string{"full1.example", "full2.example"}
	bl.ReplaceFeedEntries([]string{"stale.example"})

	c := &DataPlaneClient{lastVersion: 3}
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		switch method {
		case methodGetConfigDelta:
			b, _ := json.Marshal(getConfigDeltaReply{Mode: "resync", TargetVersion: 9})
			return b, nil
		case methodGetConfig:
			b, _ := json.Marshal(ConfigSnapshot{Version: 9, BlockedHosts: full})
			return b, nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	c.fetchAndApply(context.Background())
	if c.lastVersion != 9 {
		t.Fatalf("lastVersion=%d, want 9 (full resync applied)", c.lastVersion)
	}
	if !bl.IsBlocked("full1.example") || bl.IsBlocked("stale.example") {
		t.Fatal("full resync did not replace the blocklist")
	}
}

// TestDataPlaneClient_DeltaUnsupportedFallsThrough: an old CP that returns
// Unimplemented for GetConfigDelta makes the DP mark delta unsupported and use
// the full path (both this cycle and without re-probing until reconnect).
func TestDataPlaneClient_DeltaUnsupportedFallsThrough(t *testing.T) {
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDataDir })
	bl.ReplaceFeedEntries([]string{"stale.example"})

	c := &DataPlaneClient{lastVersion: 2}
	deltaCalls := 0
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		switch method {
		case methodGetConfigDelta:
			deltaCalls++
			return nil, status.Errorf(codes.Unimplemented, "unknown method GetConfigDelta")
		case methodGetConfig:
			b, _ := json.Marshal(ConfigSnapshot{Version: 4, BlockedHosts: []string{"new.example"}})
			return b, nil
		default:
			return nil, fmt.Errorf("unexpected method %s", method)
		}
	}
	c.fetchAndApply(context.Background())
	if c.lastVersion != 4 || !bl.IsBlocked("new.example") {
		t.Fatalf("full path did not apply after Unimplemented delta (lastVersion=%d)", c.lastVersion)
	}
	// Second cycle: delta must NOT be re-probed (deltaUnsupported latched).
	c.fetchAndApply(context.Background())
	if deltaCalls != 1 {
		t.Fatalf("delta was re-probed after Unimplemented; got %d delta calls", deltaCalls)
	}
}
