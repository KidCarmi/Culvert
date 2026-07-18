package main

// pac_posture_api.go — PAC Exception Intelligence P0: the read-only PAC
// posture surface. apiPACPostureInventory serves the config-derived DIRECT
// (full security-path bypass) inventory. Viewer-readable, side-effect-free,
// Observable evidence class only — it reports what the configuration makes
// reachable, NEVER that a bypass was used (the proxy cannot observe DIRECT
// traffic; usage is deferred to a future endpoint-agent evidence source).

import (
	"net/http"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// apiPACPostureInventory handles GET /api/pac/posture/inventory (viewer).
// It inventories every DIRECT path across the legacy default profile and all
// custom steering profiles.
func apiPACPostureInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := pacProfiles.Get()
	// Inventory the synthesized legacy default profile alongside the custom
	// ones, so /proxy.pac's exclusions + private-direct bypass are surfaced
	// through the same read-model. The synthetic default leads the list.
	full := pac.ProfilesConfig{Pools: cfg.Pools}
	full.Profiles = append(full.Profiles, pacSyntheticDefaultProfile())
	full.Profiles = append(full.Profiles, cfg.Profiles...)
	jsonOK(w, pac.BuildDirectInventory(full))
}
