package main

// bandwidth.go — package-main glue for the bandwidth/QoS policy engine, moved
// to internal/bandwidth (ADR-0002). The alias shim keeps the ConfigSnapshot
// field, the startup slice, and the test suite using the original unqualified
// names; the admin API handler stays here (requireRole/auditEvent/jsonOK are
// main-owned).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/KidCarmi/Culvert/internal/bandwidth"
)

// BandwidthPolicy / BandwidthPolicyInfo / BandwidthManager re-exposed
// unqualified (engine types are bandwidth.Policy / .PolicyInfo / .Manager).
type (
	BandwidthPolicy     = bandwidth.Policy
	BandwidthPolicyInfo = bandwidth.PolicyInfo
	BandwidthManager    = bandwidth.Manager
)

// NewBandwidthManager / humanRate re-exposed for the startup slice, the
// handler below, and the test suite.
var (
	NewBandwidthManager = bandwidth.NewManager
	humanRate           = bandwidth.HumanRate
)

// globalBandwidth is the process-wide bandwidth manager.
var globalBandwidth *BandwidthManager

// apiBandwidthPolicies handles CRUD for bandwidth/QoS policies.
//
//	GET    /api/cluster/bandwidth          — list all policies (viewer)
//	POST   /api/cluster/bandwidth          — create a new policy (admin)
//	DELETE /api/cluster/bandwidth?name=X   — delete a policy (admin)
func apiBandwidthPolicies(w http.ResponseWriter, r *http.Request) {
	if globalBandwidth == nil {
		http.Error(w, "bandwidth manager not initialised", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		policies := globalBandwidth.List()
		infos := make([]BandwidthPolicyInfo, len(policies))
		for i, p := range policies {
			infos[i] = BandwidthPolicyInfo{
				Policy:    p,
				HumanRate: humanRate(p.MaxBytesPerSec),
			}
		}
		jsonOK(w, infos)

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var p BandwidthPolicy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		added, err := globalBandwidth.Add(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEvent(r, "bandwidth.add",
			sanitizeLog(added.Name),
			fmt.Sprintf("priority=%s rate=%s",
				strings.ReplaceAll(fmt.Sprintf("%d", added.Priority), "\n", ""),
				humanRate(added.MaxBytesPerSec)))
		jsonOK(w, BandwidthPolicyInfo{
			Policy:    added,
			HumanRate: humanRate(added.MaxBytesPerSec),
		})

	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name parameter is required", http.StatusBadRequest)
			return
		}
		if !globalBandwidth.Delete(name) {
			http.Error(w, "policy not found", http.StatusNotFound)
			return
		}
		auditEvent(r, "bandwidth.delete", sanitizeLog(name), "deleted")
		jsonOK(w, map[string]any{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
