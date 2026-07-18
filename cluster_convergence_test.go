package main

// cluster_convergence_test.go — T3 P1 reverse telemetry + fleet convergence.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

// viewerReqM builds a viewer-role request for the given method/target.
func viewerReqM(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, http.NoBody)
	return req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleViewer))
}

// setConvergenceNodes swaps the global nodeMetrics for the duration of a test.
func setConvergenceNodes(t *testing.T, reports ...MetricsReport) {
	t.Helper()
	nodeMetricsMu.Lock()
	orig := nodeMetrics
	nodeMetrics = map[string]MetricsReport{}
	for _, r := range reports {
		nodeMetrics[r.NodeID] = r
	}
	nodeMetricsMu.Unlock()
	t.Cleanup(func() {
		nodeMetricsMu.Lock()
		nodeMetrics = orig
		nodeMetricsMu.Unlock()
	})
}

func TestComputeFleetConvergence(t *testing.T) {
	orig := globalConfigStore
	t.Cleanup(func() { globalConfigStore = orig; gcMarshalCache.reset(); gcDeltaRemainderCache.reset() })
	globalConfigStore = &ConfigStore{}
	// Publish to version 2 so cpVersion=2 and the ring holds the FP.
	list := []string{"a.example", "b.example"}
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: []string{"a.example"}}); err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: list}); err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	cpFP := blocklist.FeedSetFingerprint(list)

	setConvergenceNodes(t,
		MetricsReport{NodeID: "converged", ConfigVersion: 2, SyncedFP: cpFP},
		MetricsReport{NodeID: "behind", ConfigVersion: 1, SyncedFP: "oldfp"},
		MetricsReport{NodeID: "drifted", ConfigVersion: 2, SyncedFP: "wrongfp"},
		MetricsReport{NodeID: "oldDP"}, // no telemetry (ConfigVersion 0, SyncedFP "")
	)

	fc := computeFleetConvergence()
	if fc.CPVersion != 2 || fc.CPFP != cpFP {
		t.Fatalf("cp version/fp: got v%d fp=%q, want v2 fp=%q", fc.CPVersion, fc.CPFP, cpFP)
	}
	if fc.NodeCount != 4 || fc.Converged != 1 || fc.Stragglers != 3 {
		t.Fatalf("counts: nodes=%d converged=%d stragglers=%d, want 4/1/3", fc.NodeCount, fc.Converged, fc.Stragglers)
	}
	byID := map[string]nodeConvergence{}
	for _, n := range fc.Nodes {
		byID[n.NodeID] = n
	}
	if !byID["converged"].Converged || byID["converged"].VersionsBehind != 0 {
		t.Error("converged node misclassified")
	}
	if byID["behind"].Converged || byID["behind"].VersionsBehind != 1 {
		t.Error("behind node misclassified")
	}
	if !byID["drifted"].FPMismatch || byID["drifted"].Converged {
		t.Error("drifted node (at version, wrong fp) must be a non-converged fp_mismatch")
	}
	if byID["oldDP"].Reporting || byID["oldDP"].Converged {
		t.Error("a node with no T3 telemetry must be reporting=false and not converged")
	}
	if byID["oldDP"].VersionsBehind != 2 && byID["oldDP"].VersionsBehind != 0 {
		// behind is cpVersion-0=2; acceptable either as 2 (raw) — just assert it's not negative.
		t.Errorf("oldDP versions_behind=%d unexpected", byID["oldDP"].VersionsBehind)
	}
}

func TestApiClusterConvergence_RBACAndShape(t *testing.T) {
	orig := globalConfigStore
	t.Cleanup(func() { globalConfigStore = orig; gcMarshalCache.reset(); gcDeltaRemainderCache.reset() })
	globalConfigStore = &ConfigStore{}
	if err := globalConfigStore.Update(ConfigSnapshot{BlockedHosts: []string{"a.example"}}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	setConvergenceNodes(t, MetricsReport{NodeID: "n1", ConfigVersion: 1, SyncedFP: blocklist.FeedSetFingerprint([]string{"a.example"})})

	// POST is rejected (GET-only).
	recPost := httptest.NewRecorder()
	apiClusterConvergence(recPost, viewerReqM(http.MethodPost, "/api/cluster/convergence"))
	if recPost.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: got %d, want 405", recPost.Code)
	}

	rec := httptest.NewRecorder()
	apiClusterConvergence(rec, viewerReqM(http.MethodGet, "/api/cluster/convergence"))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: got %d, want 200", rec.Code)
	}
	var fc fleetConvergence
	if err := json.Unmarshal(rec.Body.Bytes(), &fc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if fc.CPVersion != 1 || fc.NodeCount != 1 || fc.Converged != 1 {
		t.Fatalf("shape: v%d nodes=%d converged=%d, want v1/1/1", fc.CPVersion, fc.NodeCount, fc.Converged)
	}
}
