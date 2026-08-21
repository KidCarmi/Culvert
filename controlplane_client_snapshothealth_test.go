package main

// controlplane_client_snapshothealth_test.go — integration tests proving
// configSnapshotApplyFailing (configsnapshot_apply_health.go) is updated by
// the REAL control-plane processing paths (fetchAndApply / applyDeltaReply),
// not merely by direct calls to markConfigSnapshotApplyRejected/OK. Covers
// every payload-content rejection point named in the outcome model
// (received → parsed → validated → fenced(excluded) → synchronized →
// applied) plus recovery.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

// TestFetchAndApply_MalformedFullSnapshotMarksRejected drives the REAL
// fetchAndApply full-snapshot path with a GetConfig response that isn't
// valid JSON at all — the parse step of the outcome model.
func TestFetchAndApply_MalformedFullSnapshotMarksRejected(t *testing.T) {
	resetConfigSnapshotApplyHealth(t)
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)

	c := &DataPlaneClient{}
	c.lastVersion.Store(0) // skip the delta path entirely
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		if method != methodGetConfig {
			t.Fatalf("unexpected method %s", method)
		}
		return json.RawMessage(`{not valid json`), nil
	}

	c.fetchAndApply(context.Background())
	if lastConfigSnapshotApplyOK() {
		t.Fatal("a malformed full-snapshot response must mark the real path rejected")
	}
}

// TestFetchAndApply_OverCapSnapshotMarksRejectedThroughRealPath drives the
// REAL fetchAndApply path with a structurally-valid-JSON but over-cap
// snapshot — the validate step of the outcome model.
func TestFetchAndApply_OverCapSnapshotMarksRejectedThroughRealPath(t *testing.T) {
	resetConfigSnapshotApplyHealth(t)
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)

	c := &DataPlaneClient{}
	c.lastVersion.Store(0)
	snap := ConfigSnapshot{Version: 1, BlockedHosts: make([]string, maxSnapBlockedHosts+1)}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		return raw, nil
	}

	c.fetchAndApply(context.Background())
	if lastConfigSnapshotApplyOK() {
		t.Fatal("an over-cap full snapshot must mark the real path rejected")
	}
}

// TestFetchAndApply_SuccessfulApplyRecoversThroughRealPath proves a prior
// real-path rejection clears on the next successful real-path apply — the
// "successful recovery" case the review demanded.
func TestFetchAndApply_SuccessfulApplyRecoversThroughRealPath(t *testing.T) {
	resetConfigSnapshotApplyHealth(t)
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)
	restoreBlAndIPF(t)
	origRules := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(origRules) })
	oldDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDataDir })

	markConfigSnapshotApplyRejected() // start from a rejected state
	if lastConfigSnapshotApplyOK() {
		t.Fatal("setup: expected rejected state before the real apply")
	}

	c := &DataPlaneClient{}
	c.lastVersion.Store(0)
	raw, err := json.Marshal(ConfigSnapshot{Version: 1})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c.callForTest = func(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
		return raw, nil
	}

	c.fetchAndApply(context.Background())
	if !lastConfigSnapshotApplyOK() {
		t.Fatal("a successful full-snapshot apply through the real path must recover the signal")
	}
	if c.lastVersion.Load() != 1 {
		t.Fatalf("lastVersion=%d, want 1 (the snapshot must have actually applied)", c.lastVersion.Load())
	}
}

// TestApplyDeltaReply_MalformedRemainderMarksRejected drives the REAL
// applyDeltaReply path with a delta reply whose Remainder is not valid
// JSON — the parse step of the outcome model, delta side.
func TestApplyDeltaReply_MalformedRemainderMarksRejected(t *testing.T) {
	resetConfigSnapshotApplyHealth(t)
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)

	c := &DataPlaneClient{}
	c.lastVersion.Store(4)
	reply := getConfigDeltaReply{
		Mode: "delta", BaseVersion: 4, TargetVersion: 5, Epoch: 0,
		Deltas:    []blocklistDelta{{Added: []string{"z.example"}}},
		Remainder: json.RawMessage(`{not valid json`),
	}
	if c.applyDeltaReply(reply) {
		t.Fatal("a malformed delta remainder must return false (resync)")
	}
	if lastConfigSnapshotApplyOK() {
		t.Fatal("a malformed delta remainder must mark the real path rejected")
	}
}

// TestApplyDeltaReply_DriftMarksRejectedThroughRealPath drives the REAL
// applyDeltaReply path with a wrong target blocklist fingerprint — the
// apply step of the outcome model, delta side (mirrors
// TestApplyDeltaReply_RejectedBlocklistLeavesRemainderUnapplied's setup).
func TestApplyDeltaReply_DriftMarksRejectedThroughRealPath(t *testing.T) {
	resetConfigSnapshotApplyHealth(t)
	restoreBlAndIPF(t)
	origRules := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(origRules) })
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDataDir })

	bl.ReplaceFeedEntries([]string{"a.example"})
	c := &DataPlaneClient{}
	c.lastVersion.Store(4)
	reply := getConfigDeltaReply{
		Mode: "delta", BaseVersion: 4, TargetVersion: 5, Epoch: 0,
		Deltas:    []blocklistDelta{{Added: []string{"z.example"}}},
		TargetFP:  "wrongfp-forces-reject",
		Remainder: mustRemainder(t, ConfigSnapshot{}),
	}
	if c.applyDeltaReply(reply) {
		t.Fatal("a delta with a bad blocklist fingerprint must return false (resync)")
	}
	if lastConfigSnapshotApplyOK() {
		t.Fatal("a delta apply (blocklist drift) rejection must mark the real path rejected")
	}
}

// TestApplyDeltaReply_SuccessRecoversThroughRealPath proves a successful
// real delta apply clears a prior rejection.
func TestApplyDeltaReply_SuccessRecoversThroughRealPath(t *testing.T) {
	resetConfigSnapshotApplyHealth(t)
	restoreBlAndIPF(t)
	origRules := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(origRules) })
	restore := resetDPLastSeenEpochForTest()
	t.Cleanup(restore)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDataDir })

	markConfigSnapshotApplyRejected()

	v1 := []string{"a.example"}
	v2 := []string{"a.example", "c.example"}
	bl.ReplaceFeedEntries(v1)
	c := &DataPlaneClient{}
	c.lastVersion.Store(4)
	reply := getConfigDeltaReply{
		Mode: "delta", BaseVersion: 4, TargetVersion: 5, Epoch: 0,
		Deltas:    []blocklistDelta{{Added: []string{"c.example"}}},
		TargetFP:  blocklist.FeedSetFingerprint(v2),
		Remainder: mustRemainder(t, ConfigSnapshot{}),
	}
	if !c.applyDeltaReply(reply) {
		t.Fatal("a well-formed, converging delta must apply (return true)")
	}
	if !lastConfigSnapshotApplyOK() {
		t.Fatal("a successful delta apply through the real path must recover the signal")
	}
}
