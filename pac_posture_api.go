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

// pacDirectInventory is the config-derived DIRECT inventory for the CURRENT
// steering config (custom profiles + the synthesized legacy default).
func pacDirectInventory() pac.DirectInventory {
	return pacDirectInventoryFor(pacProfiles.Get())
}

// pacDirectInventoryFor builds the DIRECT inventory over the synthesized legacy
// default profile + the given custom profiles (the synthetic default leads the
// list). It augments the default with the legacy fail-open terminal: when no
// proxy host is configured, the legacy /proxy.pac fails OPEN to DIRECT for all
// traffic if the fetching client supplies no resolvable Host — the static
// Profile model (balanced, no availability terminal) cannot express that
// request-dependent branch, so the under-report is injected here rather than
// mis-modeling the profile mode (which would also skew the simulator).
//
// The fail-open decision reads the CURRENT pacStore proxy host, so a candidate
// (P3 change-diff) is compared apples-to-apples: only the profiles differ, the
// proxy-host context is held constant across before/after.
func pacDirectInventoryFor(cfg pac.ProfilesConfig) pac.DirectInventory {
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

// apiPACPostureDiff handles POST /api/pac/posture/diff (viewer, read-only): the
// P3 DIRECT-surface change-diff. The body is a candidate steering config
// {profiles, pools}; the response reports which DIRECT (full-security-path)
// bypasses that candidate would ADD / REMOVE / BROADEN vs the current active
// config. Config-derived (Observable) — it never claims a bypass was used, only
// how the reachable DIRECT surface would change.
//
// Viewer-reachable and it replays a caller-supplied candidate through the
// inventory builder, so the candidate is validated + bounded (same guard as the
// analyze/simulate routes) to keep a low-privilege user from driving unbounded
// work from the management plane.
func apiPACPostureDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var candidate pac.ProfilesConfig
	if err := decodeJSON(r, &candidate); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if issues := pac.ValidateProfilesConfig(candidate); len(issues) > 0 {
		writePACIssues(w, "invalid candidate config", issues)
		return
	}
	before := pacDirectInventory()
	after := pacDirectInventoryFor(candidate)
	jsonOK(w, pac.DiffDirectInventory(before, after))
}
