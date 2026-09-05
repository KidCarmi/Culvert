package main

// pac_publish_api.go — simulator + safe-publishing admin API (initiative
// PR 3). Endpoints:
//   POST /api/pac/simulate                     — viewer: explain one URL/host
//   GET  /api/pac/profiles/{id}/lifecycle      — viewer: draft/active/history
//   POST /api/pac/profiles/{id}/lifecycle      — admin: save-draft/diff/impact/publish/rollback
//
// The lifecycle store is node-local operator metadata; publish/rollback drive
// the ACTIVE pacProfiles store (which cluster-syncs via the PR2 surface) and
// go through the same validate→persist→audit→saveConfigVersion→republish path
// as a direct mutation. The simulator/diff/impact reuse the engine evaluator,
// never a second rule engine.

import (
	"net/http"
	"strings"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// pacLifecycle is the process-wide draft/revision store (node-local),
// loaded by the startup slice from <dataDir>/pac_profiles_lifecycle.json.
var pacLifecycle = &pac.LifecycleStore{}

// apiPACSimulate handles POST /api/pac/simulate — explain what a profile
// would return for a URL/host. Viewer-readable; performs no live DNS.
func apiPACSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ProfileID string       `json:"profileId"`
		Input     pac.SimInput `json:"input"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	profile, pools, ok := pacResolveProfileForEval(req.ProfileID)
	if !ok {
		http.Error(w, "profile not found: "+sanitizeLog(req.ProfileID), http.StatusNotFound)
		return
	}
	jsonOK(w, pac.Simulate(profile, pools, req.Input))
}

// pacResolveProfileForEval returns the profile spec + current pool map for a
// profile ID. "default" resolves to the legacy-backed default profile
// synthesized from pacStore so the simulator can explain it too.
func pacResolveProfileForEval(id string) (pac.Profile, map[string]pac.Pool, bool) {
	pools := pacProfiles.PoolMap() // fresh copy — safe to augment
	if id == "" || id == pac.DefaultProfileID {
		// The synthesized default profile routes non-excluded traffic through
		// the legacy single-proxy config under the reserved "__legacy__" pool
		// ID. Inject that pool from pacStore so the simulator resolves the real
		// ProxyHost:ProxyPort; otherwise profileTerminal treats the pool as
		// missing and returns the fail-closed placeholder, misrepresenting the
		// live default PAC for every non-DIRECT destination.
		// Resolve host + port the same way CompileConfig does so the simulated
		// terminal matches the served /proxy.pac: lenient-normalized host, and
		// port 0 → 8080 (the compiler's final fallback). Empty ProxyHost is the
		// request-host-fallback case the simulator cannot model, so we leave the
		// pool absent (terminal shows the fail-closed placeholder as a signal).
		if n := pac.NormalizeLenient(pacStore.Get()); n.ProxyHost != "" {
			port := n.ProxyPort
			if port == 0 {
				port = 8080
			}
			pools["__legacy__"] = pac.Pool{
				ID: "__legacy__", Name: "Legacy PAC proxy",
				Endpoints: []pac.PoolEndpoint{{Host: n.ProxyHost, Port: port}},
			}
		}
		return pacSyntheticDefaultProfile(), pools, true
	}
	p, ok := pacProfiles.ProfileByID(id)
	return p, pools, ok
}

// pacSyntheticDefaultProfile expresses the legacy default config as a Profile
// so the simulator/diff can operate on it uniformly. Its exclusions become
// DIRECT domain/wildcard/cidr rules; balanced + private-direct mirrors the
// legacy generator (see pacDefaultView).
func pacSyntheticDefaultProfile() pac.Profile {
	c := pacStore.Get()
	n := pac.NormalizeLenient(c)
	p := pac.Profile{
		ID: pac.DefaultProfileID, Name: "Default (legacy PAC config)", Enabled: true,
		PoolID: "__legacy__", PrivateNetworks: pac.PrivateDirect, AvailabilityMode: pac.ModeBalanced,
	}
	for _, e := range n.Exclusions {
		switch e.Kind {
		case pac.KindWildcard:
			p.Rules = append(p.Rules, pac.Rule{Kind: pac.RuleKindSuffix, Pattern: e.Host, Action: pac.ActionDirect})
		case pac.KindCIDR:
			p.Rules = append(p.Rules, pac.Rule{Kind: pac.RuleKindCIDR4, Pattern: e.Canonical(), Action: pac.ActionDirect})
		default:
			p.Rules = append(p.Rules, pac.Rule{Kind: pac.RuleKindDomain, Pattern: e.Host, Action: pac.ActionDirect})
		}
	}
	return p
}

// apiPACProfileLifecycle handles GET/POST /api/pac/profiles/{id}/lifecycle.
func apiPACProfileLifecycle(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/pac/profiles/")
	id = strings.TrimSuffix(id, "/lifecycle")
	if id == "" || strings.Contains(id, "/") || id == pac.DefaultProfileID {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		pacLifecycleGet(w, r, id)
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) || !pacProfilesMutationAllowed(w) {
			return
		}
		pacLifecyclePost(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func apiPACAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ProfileID   string      `json:"profileId"`
		Action      string      `json:"action"` // diff | impact
		Draft       pac.Profile `json:"draft"`
		Sample      []string    `json:"sample"`
		UseObserved bool        `json:"useObserved"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ProfileID == "" || strings.Contains(req.ProfileID, "/") || req.ProfileID == pac.DefaultProfileID {
		http.NotFound(w, r)
		return
	}
	req.Draft.ID = req.ProfileID
	// This route is viewer-reachable and replays a caller-supplied draft +
	// sample through the evaluator. Validate the draft (bounds rules/patterns)
	// and cap the sample so a low-privilege user cannot drive unbounded
	// evaluation work from the management plane.
	if issues := pac.ValidateProfilesConfig(pac.ProfilesConfig{Profiles: []pac.Profile{req.Draft}, Pools: pacProfiles.Get().Pools}); len(issues) > 0 {
		writePACIssues(w, "invalid draft", issues)
		return
	}
	if len(req.Sample) > pacMaxAnalyzeSample {
		req.Sample = req.Sample[:pacMaxAnalyzeSample]
	}
	for i := range req.Sample {
		if len(req.Sample[i]) > pac.MaxEntryLen {
			req.Sample[i] = req.Sample[i][:pac.MaxEntryLen] // no legitimate host exceeds this
		}
	}
	active, hasActive := pacProfiles.ProfileByID(req.ProfileID)
	switch req.Action {
	case "diff":
		jsonOK(w, pac.DiffProfiles(active, hasActive, req.Draft))
	case "impact":
		sample := req.Sample
		source := "test_vectors"
		if req.UseObserved {
			sample = append(sample, pacObservedDestinations()...)
			source = "observed"
		}
		jsonOK(w, pac.AnalyzeImpact(active, hasActive, req.Draft, pacProfiles.PoolMap(), sample, source))
	default:
		http.Error(w, "unknown analyze action: "+sanitizeLog(req.Action)+" (diff|impact)", http.StatusBadRequest)
	}
}

// pacObservedDestinations returns a bounded sample of recently-seen
// destination hosts from the in-memory top-hosts counter (no live DNS, no
// telemetry fabrication — real observed hostnames only).
func pacObservedDestinations() []string {
	// Cap at 100 to match the established viewer disclosure limit on
	// /api/top-hosts (observed destinations are cross-user browsing telemetry).
	const maxSample = 100
	stats := topHosts.Top(maxSample)
	out := make([]string, 0, len(stats))
	for i := range stats {
		out = append(out, stats[i].Host)
	}
	return out
}
