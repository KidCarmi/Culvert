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

// mustRemainder marshals a remainder snapshot to the wire RawMessage form.
func mustRemainder(t *testing.T, snap ConfigSnapshot) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal remainder: %v", err)
	}
	return b
}

// restoreBlAndIPF snapshots the shared blocklist + IP-filter globals the client
// apply tests mutate, restoring them on cleanup so the determinism gate
// (-shuffle -count=2) can't observe wiped state in a later test.
func restoreBlAndIPF(t *testing.T) {
	t.Helper()
	feed := bl.FeedList()
	oldIPF := ipf
	t.Cleanup(func() {
		bl.ReplaceFeedEntries(feed)
		ipf = oldIPF
	})
}

// TestApplyBlocklistDeltaSnapshot_ConvergesAndAppliesRemainder: the DP delta
// apply advances the blocklist incrementally, verifies convergence, and applies
// the non-blocklist remainder.
func TestApplyBlocklistDeltaSnapshot_ConvergesAndAppliesRemainder(t *testing.T) {
	restoreBlAndIPF(t)
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
	restoreBlAndIPF(t)
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
	restoreBlAndIPF(t)
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
			Remainder:     mustRemainder(t, ConfigSnapshot{}),
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
	restoreBlAndIPF(t)
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
	restoreBlAndIPF(t)
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

// TestDataPlaneClient_DeltaFencedRejected: a delta stamped with an epoch BELOW
// the DP's ratchet (a fenced-out zombie CP) is rejected before any mutation and
// does not advance lastVersion. (Roll-F2 coverage: the delta-path epoch fence.)
func TestDataPlaneClient_DeltaFencedRejected(t *testing.T) {
	restoreBlAndIPF(t)
	restore := resetDPLastSeenEpochForTest()
	dpLastSeenEpoch.Store(5) // DP has seen epoch 5 from the real leader
	t.Cleanup(restore)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDataDir })

	bl.ReplaceFeedEntries([]string{"a.example"})
	before := bl.SyncedFingerprint()
	c := &DataPlaneClient{lastVersion: 5}
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		if method != methodGetConfigDelta {
			return nil, fmt.Errorf("fenced delta must NOT fall through to %s", method)
		}
		reply := getConfigDeltaReply{
			Mode: "delta", BaseVersion: 5, TargetVersion: 6, Epoch: 3, // stale epoch
			Deltas:    []blocklistDelta{{Added: []string{"evil.example"}}},
			TargetFP:  blocklist.FeedSetFingerprint([]string{"a.example", "evil.example"}),
			Remainder: mustRemainder(t, ConfigSnapshot{}),
		}
		b, _ := json.Marshal(reply)
		return b, nil
	}
	c.fetchAndApply(context.Background())
	if c.lastVersion != 5 {
		t.Fatalf("fenced delta advanced lastVersion to %d", c.lastVersion)
	}
	if bl.IsBlocked("evil.example") || bl.SyncedFingerprint() != before {
		t.Fatal("fenced delta mutated the blocklist")
	}
}

// TestDataPlaneClient_DeltaBaseMovedFallsThrough: a delta whose BaseVersion does
// not match the DP's lastVersion forces the full path. (Roll-F2 coverage.)
func TestDataPlaneClient_DeltaBaseMovedFallsThrough(t *testing.T) {
	restoreBlAndIPF(t)
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDataDir })
	bl.ReplaceFeedEntries([]string{"stale.example"})

	c := &DataPlaneClient{lastVersion: 3}
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		switch method {
		case methodGetConfigDelta:
			reply := getConfigDeltaReply{Mode: "delta", BaseVersion: 99, TargetVersion: 100, // base != 3
				Deltas: []blocklistDelta{{Added: []string{"x.example"}}}, Remainder: mustRemainder(t, ConfigSnapshot{})}
			b, _ := json.Marshal(reply)
			return b, nil
		case methodGetConfig:
			b, _ := json.Marshal(ConfigSnapshot{Version: 5, BlockedHosts: []string{"fresh.example"}})
			return b, nil
		default:
			return nil, fmt.Errorf("unexpected %s", method)
		}
	}
	c.fetchAndApply(context.Background())
	if c.lastVersion != 5 || !bl.IsBlocked("fresh.example") {
		t.Fatalf("base-moved delta did not fall through to the full path (lastVersion=%d)", c.lastVersion)
	}
}

// TestDataPlaneClient_DeltaDriftHealsViaFull: a delta whose TargetFP does not
// match after apply (missed/misapplied) falls through to the full path, which
// heals the blocklist wholesale. (Roll-F2: client-level drift→resync contract.)
func TestDataPlaneClient_DeltaDriftHealsViaFull(t *testing.T) {
	restoreBlAndIPF(t)
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDataDir })
	bl.ReplaceFeedEntries([]string{"v1.example"})

	full := []string{"healed1.example", "healed2.example"}
	c := &DataPlaneClient{lastVersion: 4}
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		switch method {
		case methodGetConfigDelta:
			reply := getConfigDeltaReply{Mode: "delta", BaseVersion: 4, TargetVersion: 5,
				Deltas:   []blocklistDelta{{Added: []string{"partial.example"}}},
				TargetFP: "wrongfp-triggers-drift", Remainder: mustRemainder(t, ConfigSnapshot{})}
			b, _ := json.Marshal(reply)
			return b, nil
		case methodGetConfig:
			b, _ := json.Marshal(ConfigSnapshot{Version: 5, BlockedHosts: full})
			return b, nil
		default:
			return nil, fmt.Errorf("unexpected %s", method)
		}
	}
	c.fetchAndApply(context.Background())
	if c.lastVersion != 5 {
		t.Fatalf("drift did not heal via full resync (lastVersion=%d)", c.lastVersion)
	}
	if !bl.IsBlocked("healed1.example") || bl.IsBlocked("partial.example") {
		t.Fatal("full resync did not replace the drifted blocklist")
	}
}

// TestApplyBlocklistDeltaSnapshot_ManualSurvivesEndToEnd is the F3 end-to-end
// invariant: a CP delta that removes a host which is ALSO a DP-local manual block
// keeps it enforced AND still converges the fingerprint to the CP's feed-only
// target — verified on the real bl through the actual apply path (not just the
// primitive), including the SyncedFingerprint()==targetFP gate.
func TestApplyBlocklistDeltaSnapshot_ManualSurvivesEndToEnd(t *testing.T) {
	restoreBlAndIPF(t)
	origRules := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(origRules) })

	bl.ReplaceFeedEntries([]string{"shared.example", "other.example"})
	bl.AddManual("shared.example") // also a DP-local manual block
	// CP publishes a version that drops shared.example from the feed.
	chain := []blocklistDelta{{Removed: []string{"shared.example"}}}
	targetFP := blocklist.FeedSetFingerprint([]string{"other.example"})
	if err := applyBlocklistDeltaSnapshot(ConfigSnapshot{}, chain, targetFP); err != nil {
		t.Fatalf("apply must converge (manual host dropped from fp, kept in enforcement): %v", err)
	}
	if !bl.IsBlocked("shared.example") {
		t.Fatal("a CP delta removed a DP-local manual block through the real apply path")
	}
}

// TestDataPlaneClient_DeltaReprobeAfterCooldown: after latching deltaUnsupported,
// the DP re-probes exactly once every deltaReprobeInterval polls (covers the
// in-place-CP-upgrade case where connect() never runs). (Roll-F1 coverage.)
func TestDataPlaneClient_DeltaReprobeAfterCooldown(t *testing.T) {
	c := &DataPlaneClient{lastVersion: 3, deltaUnsupported: true}
	deltaCalls := 0
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		if method == methodGetConfigDelta {
			deltaCalls++
			return nil, status.Errorf(codes.Unimplemented, "still old")
		}
		return nil, fmt.Errorf("unexpected %s", method)
	}
	for i := 0; i < deltaReprobeInterval; i++ {
		_ = c.tryDeltaSync(context.Background())
	}
	if deltaCalls != 1 {
		t.Fatalf("want exactly 1 re-probe over %d polls, got %d", deltaReprobeInterval, deltaCalls)
	}
}
