package main

// cluster_convergence.go — T3 P1 reverse telemetry + fleet-convergence surface.
//
// Delta sync is transparent (no config knobs), but its correctness contract —
// "every DP converges to the CP's authoritative version" — is only observable if
// the fleet reports back. DP heartbeats (MetricsReport) now carry the config
// version + blocklist synced fingerprint each node enforces; the CP aggregates
// them into a convergence view (which nodes are current, which lag, which have a
// fingerprint mismatch), surfaced read-only on /api/cluster/convergence and the
// Cluster panel, plus Prometheus counters for delta modes served.

import (
	"net/http"
	"sync/atomic"
)

// Delta-mode served counters (Prometheus). Incremented in GetConfigDelta so an
// operator can see the delta-vs-resync mix — a high resync rate means DPs keep
// falling out of the ring window (too small, or churny publishes).
var (
	statConfigDeltaServed     atomic.Int64 // mode=delta
	statConfigDeltaUnchanged  atomic.Int64 // mode=unchanged
	statConfigDeltaResync     atomic.Int64 // mode=resync
	statConfigDeltaFrameSkips atomic.Int64 // reply would exceed the frame → downgraded to resync
)

// nodeConvergence is one DP's convergence state relative to the CP.
type nodeConvergence struct {
	NodeID         string `json:"node_id"`
	ConfigVersion  int64  `json:"config_version"`
	VersionsBehind int64  `json:"versions_behind"`
	Converged      bool   `json:"converged"`
	FPMismatch     bool   `json:"fp_mismatch"` // at the CP version but a different fingerprint (drift)
	Reporting      bool   `json:"reporting"`   // node sent T3 telemetry (old DPs omit it)
	Uptime         string `json:"uptime,omitempty"`
}

// fleetConvergence is the CP-side aggregate.
type fleetConvergence struct {
	CPVersion  int64             `json:"cp_version"`
	CPFP       string            `json:"cp_fp,omitempty"` // "" when the ring has no FP for the current version
	NodeCount  int               `json:"node_count"`
	Converged  int               `json:"converged"`
	Stragglers int               `json:"stragglers"`
	Nodes      []nodeConvergence `json:"nodes"`
}

// computeFleetConvergence builds the convergence view from the reported node
// metrics + the CP's current published version/fingerprint. A node is converged
// when it is at (or ahead of) the CP version AND — if both sides have a
// fingerprint — the fingerprints match. A node that never reported T3 telemetry
// (old DP: ConfigVersion 0, SyncedFP "") is counted as non-converged/reporting=false
// rather than falsely "behind by cpVersion".
func computeFleetConvergence() fleetConvergence {
	cpVersion := globalConfigStore.Version()
	cpFP, _ := globalConfigStore.deltaRing.newestFP(cpVersion)

	fc := fleetConvergence{CPVersion: cpVersion, CPFP: cpFP}
	nodeMetricsMu.RLock()
	fc.Nodes = make([]nodeConvergence, 0, len(nodeMetrics))
	for nid, m := range nodeMetrics {
		reporting := m.ConfigVersion > 0 || m.SyncedFP != ""
		behind := cpVersion - m.ConfigVersion
		if behind < 0 {
			behind = 0 // a node briefly ahead (raced a fresh publish) is not "behind"
		}
		atVersion := reporting && m.ConfigVersion >= cpVersion
		fpMismatch := atVersion && cpFP != "" && m.SyncedFP != "" && m.SyncedFP != cpFP
		converged := atVersion && !fpMismatch
		nc := nodeConvergence{
			NodeID:         nid,
			ConfigVersion:  m.ConfigVersion,
			VersionsBehind: behind,
			Converged:      converged,
			FPMismatch:     fpMismatch,
			Reporting:      reporting,
			Uptime:         m.Uptime,
		}
		fc.Nodes = append(fc.Nodes, nc)
		if converged {
			fc.Converged++
		} else {
			fc.Stragglers++
		}
	}
	nodeMetricsMu.RUnlock()
	fc.NodeCount = len(fc.Nodes)
	return fc
}

// apiClusterConvergence (GET, viewer) exposes fleet config-sync convergence:
// which DPs are current, which lag, which drifted. Read-only, side-effect-free.
func apiClusterConvergence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	jsonOK(w, computeFleetConvergence())
}
