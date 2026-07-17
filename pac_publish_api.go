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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

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
		if c := pacStore.Get(); c.ProxyHost != "" {
			pools["__legacy__"] = pac.Pool{
				ID: "__legacy__", Name: "Legacy PAC proxy",
				Endpoints: []pac.PoolEndpoint{{Host: c.ProxyHost, Port: c.ProxyPort}},
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
		pacLifecycleGet(w, id)
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) || !pacProfilesMutationAllowed(w) {
			return
		}
		pacLifecyclePost(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func pacLifecycleGet(w http.ResponseWriter, id string) {
	active, activeOK := pacProfiles.ProfileByID(id)
	lc, _ := pacLifecycle.Get(id)
	var diff *pac.ProfileDiff
	if lc.DraftDirty && activeOK {
		d := pac.DiffProfiles(active, true, lc.Draft)
		diff = &d
	}
	prev, hasPrev := lc.PreviousRevision()
	resp := map[string]any{
		"profileId":    id,
		"activeExists": activeOK,
		"active":       active,
		"draft":        lc.Draft,
		"draftDirty":   lc.DraftDirty,
		"activeN":      lc.ActiveN,
		"revisions":    lc.Revisions,
		"draftDiff":    diff,
	}
	if hasPrev {
		resp["previousRevision"] = prev.N
	}
	jsonOK(w, resp)
}

func pacLifecyclePost(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Action        string      `json:"action"` // save_draft | diff | impact | publish | rollback
		Draft         pac.Profile `json:"draft"`
		ConfirmDirect string      `json:"confirmDirect"` // must equal id to publish new DIRECT paths
		TargetN       int64       `json:"targetN"`       // rollback target
		Sample        []string    `json:"sample"`        // impact test vectors
		UseObserved   bool        `json:"useObserved"`   // impact: sample from topHosts
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Only mutating actions live here — the lifecycle POST route is
	// AuditExpected, so every action must emit an audit event (C2c). The
	// read-only analysis actions (diff/impact) live on the viewer
	// /api/pac/analyze route instead.
	switch req.Action {
	case "save_draft":
		pacLifecycleSaveDraft(w, r, id, req.Draft)
	case "publish":
		pacLifecyclePublish(w, r, id, req.Draft, req.ConfirmDirect)
	case "rollback":
		pacLifecycleRollback(w, r, id, req.TargetN)
	default:
		http.Error(w, "unknown or non-mutating action: "+sanitizeLog(req.Action)+" (use /api/pac/analyze for diff/impact)", http.StatusBadRequest)
	}
}

func pacLifecycleSaveDraft(w http.ResponseWriter, r *http.Request, id string, draft pac.Profile) {
	draft.ID = id
	lc, _ := pacLifecycle.Get(id)
	lc.TouchDraft(draft)
	if err := pacLifecycle.Put(lc); err != nil {
		http.Error(w, "save error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Draft persistence is a (node-local) state change — audit it so the
	// AuditExpected lifecycle POST route always emits an event (C2c).
	auditEvent(r, "pac.profile_draft", id, fmt.Sprintf("dirty=%t rules=%d", lc.DraftDirty, len(lc.Draft.Rules)))
	jsonOK(w, map[string]any{"draftDirty": lc.DraftDirty, "draft": lc.Draft})
}

// apiPACAnalyze handles POST /api/pac/analyze — read-only diff/impact for a
// candidate draft against the active revision. Viewer-accessible, no
// mutation, no audit (kept OFF the AuditExpected lifecycle route so C2c's
// audit-completion signal stays meaningful).
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
	const maxSample = 500
	stats := topHosts.Top(maxSample)
	out := make([]string, 0, len(stats))
	for i := range stats {
		out = append(out, stats[i].Host)
	}
	return out
}

func pacLifecyclePublish(w http.ResponseWriter, r *http.Request, id string, draft pac.Profile, confirmDirect string) {
	draft.ID = id

	// Serialize the guardrail evaluation WITH the write under the profile
	// mutation mutex: read the active state/pools, evaluate EvaluatePublish, and
	// commit the replacement while holding the lock. Evaluating before taking
	// the lock is a TOCTOU — a concurrent mutation could change the active
	// profile or pools between the guardrail decision and the write, letting a
	// publish slip past the typed-DIRECT confirmation or record a digest
	// computed against stale pool endpoints.
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()

	pools := pacProfiles.PoolMap()
	active, hasActive := pacProfiles.ProfileByID(id)
	chk := pac.EvaluatePublish(draft, pools, active, hasActive)
	if !chk.OK && !chk.RequiresConfirmation {
		writePACIssues(w, "publish blocked by guardrails", chk.Issues)
		return
	}
	if chk.RequiresConfirmation && confirmDirect != id {
		// High-friction typed confirmation for new DIRECT paths.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort body
			"error":          "publish introduces new DIRECT paths; retype the profile ID in confirmDirect to proceed",
			"newDirectPaths": chk.NewDirectPaths,
			"confirmField":   "confirmDirect",
			"confirmValue":   id,
		})
		return
	}

	before := pacProfiles.Get()
	candidate := pacProfiles.Get()
	ts := time.Now().UTC().Format(time.RFC3339)
	actor := sessionAdmin(r)

	lc, _ := pacLifecycle.Get(id)
	n := lc.Publish(draft, chk.Digest, actor, "", ts)
	published := lc.Draft // carries the assigned revision

	replaced := false
	for i := range candidate.Profiles {
		if candidate.Profiles[i].ID == id {
			candidate.Profiles[i] = published
			replaced = true
			break
		}
	}
	if !replaced {
		candidate.Profiles = append(candidate.Profiles, published)
	}
	if !pacApplyProfilesMutation(w, r, "pac.profile_publish", id, before, candidate) {
		return
	}
	if err := pacLifecycle.Put(lc); err != nil {
		logger.Printf("PAC: lifecycle persist after publish: %v", err)
	}
	jsonOK(w, map[string]any{"published": true, "revision": n, "digest": chk.Digest})
}

func pacLifecycleRollback(w http.ResponseWriter, r *http.Request, id string, targetN int64) {
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	lc, ok := pacLifecycle.Get(id)
	if !ok {
		http.Error(w, "no publish history for profile: "+sanitizeLog(id), http.StatusNotFound)
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	actor := sessionAdmin(r)
	n, ok := lc.Rollback(targetN, actor, ts)
	if !ok {
		http.Error(w, fmt.Sprintf("revision %d not found for profile %s", targetN, sanitizeLog(id)), http.StatusNotFound)
		return
	}
	restored := lc.Draft // rollback set Draft to the target spec at revision n

	before := pacProfiles.Get()
	candidate := pacProfiles.Get()
	replaced := false
	for i := range candidate.Profiles {
		if candidate.Profiles[i].ID == id {
			candidate.Profiles[i] = restored
			replaced = true
			break
		}
	}
	if !replaced {
		candidate.Profiles = append(candidate.Profiles, restored)
	}
	if !pacApplyProfilesMutation(w, r, "pac.profile_rollback", id, before, candidate) {
		return
	}
	if err := pacLifecycle.Put(lc); err != nil {
		logger.Printf("PAC: lifecycle persist after rollback: %v", err)
	}
	jsonOK(w, map[string]any{"rolledBack": true, "toRevision": targetN, "newRevision": n})
}
