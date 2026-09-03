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
	// Read the active profile and the lifecycle record under the mutation
	// mutex so a concurrent publish/rollback — which updates pacProfiles
	// before pacLifecycle — cannot present a torn cross-store view (a stale
	// draft diffed against the new active spec, i.e. a spurious dirty/diff).
	// Both accessors return deep copies, so the lock is released before use.
	pacProfilesAPIMu.Lock()
	cfg := pacProfiles.Get()
	active, activeOK := pacProfiles.ProfileByID(id)
	lc, _ := pacLifecycle.Get(id)
	pacProfilesAPIMu.Unlock()
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
		// 2F-A tokens: save_draft echoes draftRevision; publish/rollback echo
		// activeRevision (the active profile's revision) when a profile is
		// active, else collectionEtag (a first publish is a collection create).
		"draftRevision":  lc.DraftRevision,
		"activeRevision": active.Revision,
		"collectionEtag": pac.ConfigETag(cfg),
	}
	if hasPrev {
		resp["previousRevision"] = prev.N
	}
	jsonOK(w, resp)
}

func pacLifecyclePost(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Action        string      `json:"action"` // save_draft | publish | rollback
		Draft         pac.Profile `json:"draft"`
		ConfirmDirect string      `json:"confirmDirect"` // must equal id to publish new DIRECT paths
		TargetN       int64       `json:"targetN"`       // rollback target
		Reason        string      `json:"reason"`        // optional change-reason recorded on the revision
		// 2F-A fence tokens (see pac_fence.go).
		DraftRevision          int64  `json:"draftRevision"`          // save_draft: the draft token loaded
		ExpectedActiveRevision int64  `json:"expectedActiveRevision"` // publish/rollback: the active profile's revision loaded
		CollectionEtag         string `json:"collectionEtag"`         // publish/rollback with NO active profile: the collection token loaded
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	reason := req.Reason
	if len(reason) > pacMaxReasonLen {
		reason = reason[:pacMaxReasonLen]
	}
	// Only mutating actions live here — the lifecycle POST route is
	// AuditExpected, so every action must emit an audit event (C2c). The
	// read-only analysis actions (diff/impact) live on the viewer
	// /api/pac/analyze route instead.
	switch req.Action {
	case "save_draft":
		pacLifecycleSaveDraft(w, r, id, req.Draft, pacFenceInt(r, "draftRevision", req.DraftRevision))
	case "publish":
		pacLifecyclePublish(w, r, id, req.Draft, req.ConfirmDirect, reason,
			pacFenceInt(r, "expectedActiveRevision", req.ExpectedActiveRevision), pacFenceStr(r, "collectionEtag", req.CollectionEtag))
	case "rollback":
		pacLifecycleRollback(w, r, id, req.TargetN, req.ConfirmDirect,
			pacFenceInt(r, "expectedActiveRevision", req.ExpectedActiveRevision), pacFenceStr(r, "collectionEtag", req.CollectionEtag))
	default:
		http.Error(w, "unknown or non-mutating action: "+sanitizeLog(req.Action)+" (use /api/pac/analyze for diff/impact)", http.StatusBadRequest)
	}
}

func pacLifecycleSaveDraft(w http.ResponseWriter, r *http.Request, id string, draft pac.Profile, token int64) {
	draft.ID = id
	// Serialize the lifecycle read-modify-write under the same mutex as
	// publish/rollback. Without it, a save_draft that reads the record before a
	// concurrent publish and writes it back after would clobber the published
	// revision (lost update) and let the next publish re-mint that revision
	// number — breaking the monotonic, never-reused revision invariant.
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	lc, found := pacLifecycle.Get(id)
	// 2F-A fence: an existing draft must be echoed by the draftRevision it
	// was loaded at (428 absent, 409 stale). The FIRST save_draft for a
	// profile creates the record and takes no token; a non-zero token for a
	// record that no longer exists means the draft vanished (404).
	switch {
	case found && lc.DraftRevision > 0:
		if !pacCheckRevision(w, "draftRevision", token, lc.DraftRevision) {
			return
		}
	case token != 0:
		http.NotFound(w, r)
		return
	}
	lc.TouchDraft(draft)
	if err := pacLifecycle.Put(lc); err != nil {
		http.Error(w, "save error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Draft persistence is a (node-local) state change — audit it so the
	// AuditExpected lifecycle POST route always emits an event (C2c).
	auditEvent(r, "pac.profile_draft", id, fmt.Sprintf("dirty=%t rules=%d", lc.DraftDirty, len(lc.Draft.Rules)))
	jsonOK(w, map[string]any{"draftDirty": lc.DraftDirty, "draft": lc.Draft, "draftRevision": lc.DraftRevision})
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

func pacLifecyclePublish(w http.ResponseWriter, r *http.Request, id string, draft pac.Profile, confirmDirect, reason string, expectedActive int64, collectionEtag string) {
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
	// 2F-A fence, before the guardrail: the caller must echo the active
	// profile's revision (or, for a first publish, the collection token).
	if !pacLifecycleFence(w, active, hasActive, expectedActive, collectionEtag) {
		return
	}
	chk := pac.EvaluatePublish(draft, pools, active, hasActive)
	if !chk.OK && !chk.RequiresConfirmation {
		// Guardrail block is a security-relevant attempt (fail-closed on a bad
		// or DIRECT-widening draft); count + log it so a SOC/SRE can alert —
		// non-2xx, so it must NOT audit on the AuditExpected route.
		pacPublishBlockedTotal.Add(1)
		logger.Printf("PAC: publish blocked by guardrails for %q", sanitizeLog(id))
		writePACIssues(w, "publish blocked by guardrails", chk.Issues)
		return
	}
	if chk.RequiresConfirmation && confirmDirect != id {
		pacPublishConfirmRequiredTotal.Add(1)
		logger.Printf("PAC: publish of %q requires typed DIRECT confirmation", sanitizeLog(id))
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
	n := lc.Publish(draft, chk.Digest, actor, reason, ts)
	published := lc.Draft // carries the assigned lifecycle revision
	// The active profile's Revision is the PR2 PUT optimistic-concurrency token
	// (monotonic +1 per mutation), a DIFFERENT counter from the lifecycle
	// revision N. Advance it monotonically instead of aliasing it to N —
	// aliasing moves the token backwards and defeats stale-write detection.
	published.Revision = 1
	if hasActive {
		published.Revision = active.Revision + 1
	}

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
	pacLifecycleStage("intent_persisted")
	if !pacApplyProfilesMutation(w, r, "pac.profile_publish", id, before, candidate) {
		return
	}
	pacLifecycleStage("active_committed")
	err := pacLifecyclePersist("finalize")
	if err == nil {
		err = pacLifecycle.Put(lc)
	}
	if err != nil {
		// The active spec is already published (traffic is correct), but the
		// node-local revision history did not persist. Report failure rather
		// than a false 200 so the operator knows the timeline is inconsistent
		// and can re-publish (silent success here would let nextRevisionN
		// re-issue N after a restart).
		logger.Printf("PAC: lifecycle persist after publish failed for %q: %v", sanitizeLog(id), err)
		http.Error(w, "profile published but revision-history persistence failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	pacLifecycleStage("finalized")
	logger.Printf("PAC: published profile %q revision %d (digest %s)", sanitizeLog(id), n, chk.Digest)
	pacPublishesTotal.Add(1)
	jsonOK(w, map[string]any{"published": true, "revision": n, "digest": chk.Digest,
		"activeRevision": published.Revision, "draftRevision": lc.DraftRevision})
}

func pacLifecycleRollback(w http.ResponseWriter, r *http.Request, id string, targetN int64, confirmDirect string, expectedActive int64, collectionEtag string) {
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	lc, ok := pacLifecycle.Get(id)
	if !ok {
		http.Error(w, "no publish history for profile: "+sanitizeLog(id), http.StatusNotFound)
		return
	}
	active, hasActive := pacProfiles.ProfileByID(id)
	// 2F-A fence (same contract as publish), before any lifecycle mutation.
	if !pacLifecycleFence(w, active, hasActive, expectedActive, collectionEtag) {
		return
	}
	pools := pacProfiles.PoolMap()
	ts := time.Now().UTC().Format(time.RFC3339)
	actor := sessionAdmin(r)
	n, ok := lc.Rollback(targetN, actor, ts)
	if !ok {
		http.Error(w, fmt.Sprintf("revision %d not found for profile %s", targetN, sanitizeLog(id)), http.StatusNotFound)
		return
	}
	restored := lc.Draft // rollback set Draft to the target spec at revision n

	// A rollback that re-introduces DIRECT relative to the CURRENTLY-active
	// revision must pass the same typed confirmation as a forward publish —
	// "previously published" is not sufficient because the threat posture (and
	// the operator) may differ now, and skipping it would make the publish
	// confirmation launderable through a rollback.
	chk := pac.EvaluatePublish(restored, pools, active, hasActive)
	if !chk.OK && !chk.RequiresConfirmation {
		pacPublishBlockedTotal.Add(1)
		logger.Printf("PAC: rollback of %q blocked by guardrails", sanitizeLog(id))
		writePACIssues(w, "rollback blocked by guardrails", chk.Issues)
		return
	}
	if chk.RequiresConfirmation && confirmDirect != id {
		pacPublishConfirmRequiredTotal.Add(1)
		logger.Printf("PAC: rollback of %q requires typed DIRECT confirmation", sanitizeLog(id))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort body
			"error":          "rollback re-introduces new DIRECT paths; retype the profile ID in confirmDirect to proceed",
			"newDirectPaths": chk.NewDirectPaths,
			"confirmField":   "confirmDirect",
			"confirmValue":   id,
		})
		return
	}

	// Advance the PUT optimistic-concurrency token monotonically (see publish).
	restored.Revision = 1
	if hasActive {
		restored.Revision = active.Revision + 1
	}

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
	pacLifecycleStage("intent_persisted")
	if !pacApplyProfilesMutation(w, r, "pac.profile_rollback", id, before, candidate) {
		return
	}
	pacLifecycleStage("active_committed")
	err := pacLifecyclePersist("finalize")
	if err == nil {
		err = pacLifecycle.Put(lc)
	}
	if err != nil {
		logger.Printf("PAC: lifecycle persist after rollback failed for %q: %v", sanitizeLog(id), err)
		http.Error(w, "profile rolled back but revision-history persistence failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// targetN is a user-supplied body value; route it through sanitizeLog so
	// CodeQL sees the sanitiser on the log sink (CWE-117). n is engine-derived.
	pacLifecycleStage("finalized")
	logger.Printf("PAC: rolled back profile %q to revision %s (new revision %d)", sanitizeLog(id), sanitizeLog(fmt.Sprintf("%d", targetN)), n)
	pacRollbacksTotal.Add(1)
	jsonOK(w, map[string]any{"rolledBack": true, "toRevision": targetN, "newRevision": n,
		"activeRevision": restored.Revision, "draftRevision": lc.DraftRevision})
}

// pacLifecycleFence applies the 2F-A precondition to publish and rollback,
// under pacProfilesAPIMu: with an active profile the caller echoes its
// revision (key "revision", so the refusal names the same token the profile
// surfaces carry); without one — a first publish creates the profile — the
// caller echoes the collection token. Returns false after writing the refusal.
func pacLifecycleFence(w http.ResponseWriter, active pac.Profile, hasActive bool, expectedActive int64, collectionEtag string) bool {
	if hasActive {
		return pacCheckRevision(w, "revision", expectedActive, active.Revision)
	}
	return pacCheckEtag(w, "collectionEtag", collectionEtag, pac.ConfigETag(pacProfiles.Get()))
}
