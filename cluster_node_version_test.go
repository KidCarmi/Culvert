package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestMetricsReport_VersionFields_WireRoundTrip pins the M5 PR-A additive
// contract: the new version facts survive a marshal/unmarshal round-trip, an
// OLD report (JSON without the keys) degrades to zero-value rather than
// erroring, and a zero-valued report omits the keys entirely (omitempty), so a
// mixed-version cluster never trips a decoder.
func TestMetricsReport_VersionFields_WireRoundTrip(t *testing.T) {
	in := MetricsReport{
		NodeID:         "dp-1",
		Total:          100,
		ConfigVersion:  42,
		PolicyVersion:  7,
		Epoch:          3,
		CulvertVersion: "v1.2.3",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out MetricsReport
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ConfigVersion != 42 || out.PolicyVersion != 7 || out.Epoch != 3 || out.CulvertVersion != "v1.2.3" {
		t.Fatalf("version facts did not round-trip: got %+v", out)
	}

	// Backward compat: a report from an older DP omits the new keys entirely.
	var legacy MetricsReport
	if err := json.Unmarshal([]byte(`{"node_id":"dp-old","total":5}`), &legacy); err != nil {
		t.Fatalf("legacy unmarshal: %v", err)
	}
	if legacy.ConfigVersion != 0 || legacy.CulvertVersion != "" {
		t.Fatalf("legacy report should decode to zero-value version facts; got %+v", legacy)
	}

	// omitempty: a zero-valued report must not emit the new keys.
	empty, _ := json.Marshal(MetricsReport{NodeID: "dp-z"})
	for _, key := range []string{"config_version", "policy_version", "epoch", "culvert_version"} {
		if strings.Contains(string(empty), key) {
			t.Errorf("zero-valued report should omit %q; got %s", key, empty)
		}
	}
}

// TestPushMetrics_StampsVersionFacts exercises the full CP-side consume path:
// a DP heartbeat carrying version facts lands in nodeMetrics (PR-A) and the
// reported build version is copied onto the enrolled node (PR-B), so both the
// metrics list and the node list surface it.
func TestPushMetrics_StampsVersionFacts(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "disconnected", CertSerial: "s1"})

	origInsecure := clusterInsecure
	defer func() { clusterInsecure = origInsecure }()
	clusterInsecure = true // no mTLS peer in the test context

	// Isolate the process-global metrics map.
	nodeMetricsMu.Lock()
	origMetrics := nodeMetrics
	nodeMetrics = map[string]MetricsReport{}
	nodeMetricsMu.Unlock()
	defer func() {
		nodeMetricsMu.Lock()
		nodeMetrics = origMetrics
		nodeMetricsMu.Unlock()
	}()

	report := MetricsReport{
		NodeID:         "dp-1",
		Total:          10,
		ConfigVersion:  42,
		PolicyVersion:  7,
		Epoch:          3,
		CulvertVersion: "v9.9.9",
	}
	raw, _ := json.Marshal(report)
	if _, err := (&controlPlaneServer{}).PushMetrics(testBGCtx(), raw); err != nil {
		t.Fatalf("PushMetrics: %v", err)
	}

	// PR-A: metrics list carries the version facts.
	var stored *MetricsReport
	for _, m := range NodeMetricsList() {
		if m.NodeID == "dp-1" {
			mm := m
			stored = &mm
			break
		}
	}
	if stored == nil {
		t.Fatal("dp-1 not present in NodeMetricsList")
	}
	if stored.ConfigVersion != 42 || stored.PolicyVersion != 7 || stored.Epoch != 3 || stored.CulvertVersion != "v9.9.9" {
		t.Fatalf("stored metrics missing version facts: %+v", *stored)
	}

	// PR-B: the enrolled node picked up the reported build version.
	var node *EnrolledNode
	for _, n := range globalClusterStore.ListNodes() {
		if n.NodeID == "dp-1" {
			nn := n
			node = &nn
			break
		}
	}
	if node == nil {
		t.Fatal("dp-1 not present in ListNodes")
	}
	if node.Version != "v9.9.9" {
		t.Fatalf("enrolled node version = %q, want v9.9.9", node.Version)
	}
}

// TestBuildMetricsReport_StampsAppliedSnapshotFacts pins that the heartbeat
// reports the APPLIED snapshot's version facts (Codex P2): ConfigVersion and
// PolicyVersion come from the client's applied-snapshot tracking — which is
// seeded from the last-known-good snapshot at startup — not from a live poll
// or the DP-local policyStore apply counter.
func TestBuildMetricsReport_StampsAppliedSnapshotFacts(t *testing.T) {
	origEpoch := dpLastSeenEpoch.Load()
	defer dpLastSeenEpoch.Store(origEpoch)
	dpLastSeenEpoch.Store(11)

	c := &DataPlaneClient{nodeID: "dp-1"}
	// Simulate startup seeding from a cached snapshot at config v5 / policy v9,
	// with no successful CP poll yet.
	c.lastVersion.Store(5)
	c.lastPolicyVersion.Store(9)

	report := c.buildMetricsReport()
	if report.NodeID != "dp-1" {
		t.Fatalf("node_id = %q, want dp-1", report.NodeID)
	}
	if report.ConfigVersion != 5 {
		t.Errorf("config_version = %d, want 5 (applied snapshot version)", report.ConfigVersion)
	}
	if report.PolicyVersion != 9 {
		t.Errorf("policy_version = %d, want 9 (applied snapshot policy generation, not local counter)", report.PolicyVersion)
	}
	if report.Epoch != 11 {
		t.Errorf("epoch = %d, want 11", report.Epoch)
	}
	if report.CulvertVersion != version {
		t.Errorf("culvert_version = %q, want %q", report.CulvertVersion, version)
	}
}

// TestUpdateNodeSeen_EmptyVersionPreservesExisting guards the skip-on-empty
// contract: an older DP heartbeat that omits the version must not wipe a
// version previously recorded from a newer report.
func TestUpdateNodeSeen_EmptyVersionPreservesExisting(t *testing.T) {
	cs := newTestClusterStore(t)
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "disconnected"})

	cs.UpdateNodeSeen("dp-1", "", "v1.0.0")
	if n, _ := cs.GetNode("dp-1"); n.Version != "v1.0.0" {
		t.Fatalf("version = %q, want v1.0.0 after first report", n.Version)
	}
	// A subsequent heartbeat with no version reported must preserve it.
	cs.UpdateNodeSeen("dp-1", "10.0.0.1", "")
	if n, _ := cs.GetNode("dp-1"); n.Version != "v1.0.0" {
		t.Fatalf("version = %q, want v1.0.0 preserved on empty report", n.Version)
	}
}
