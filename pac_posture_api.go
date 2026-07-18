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
	jsonOK(w, pacDirectInventory())
}

// pacDirectInventory is the single source of the config-derived DIRECT
// inventory over the synthesized legacy default profile + all custom profiles
// (the synthetic default leads the list). It also augments the default with
// the legacy fail-open terminal: when no proxy host is configured, the legacy
// /proxy.pac fails OPEN to DIRECT for all traffic if the fetching client
// supplies no resolvable Host. The static Profile model (balanced, no
// availability terminal) cannot express that request-dependent branch, so the
// under-report is injected here rather than mis-modeling the profile mode
// (which would also skew the simulator).
func pacDirectInventory() pac.DirectInventory {
	cfg := pacProfiles.Get()
	full := pac.ProfilesConfig{Pools: cfg.Pools}
	full.Profiles = append(full.Profiles, pacSyntheticDefaultProfile())
	full.Profiles = append(full.Profiles, cfg.Profiles...)
	inv := pac.BuildDirectInventory(full)
	if n := pac.NormalizeLenient(pacStore.Get()); n.ProxyHost == "" {
		for i := range inv.Profiles {
			if inv.Profiles[i].ProfileID != pac.DefaultProfileID {
				continue
			}
			inv.Profiles[i].DirectPaths = append(inv.Profiles[i].DirectPaths, pac.DirectEntry{
				Kind:   pac.BypassFailOpen,
				Detail: "no proxy host configured — the legacy /proxy.pac fails OPEN to DIRECT for all traffic when the client supplies no resolvable Host",
				Broad:  true,
			})
			// The default is already DIRECT-capable (plain_host), so the profile
			// counts are unchanged; only the path counts move. No break: the loop
			// scans the whole (small) slice, so the non-default skip above is
			// exercised rather than being dead behind an early break.
			inv.TotalDirectPaths++
			inv.BroadDirectPaths++
		}
	}
	return inv
}
