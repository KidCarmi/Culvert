package main

// pac_profiles_api.go — admin API for PAC steering profiles and proxy pools
// (initiative PR 2). Strict validation at this boundary only (the
// ProfileStore itself stays tolerant for replay paths). Every mutation
// audits (auditEventDiff) and snapshots config (saveConfigVersion), then
// republishes the cluster ConfigSnapshot so DP nodes converge.
//
// Routes (registered in registerPACRoutes, metadata in ui_routes_meta.go):
//   GET  /api/pac/profiles        — viewer: profiles + pools + default view
//   POST /api/pac/profiles        — admin: create profile
//   GET/PUT/DELETE /api/pac/profiles/{id} — admin mutations, viewer reads
//   POST /api/pac/pools           — admin: create pool
//   GET/PUT/DELETE /api/pac/pools/{id}    — admin mutations, viewer reads

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// pacDefaultProfileView is the synthesized, read-only description of the
// legacy-backed default profile shown alongside custom profiles.
type pacDefaultProfileView struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	LegacyManaged    bool   `json:"legacyManaged"`
	AvailabilityMode string `json:"availabilityMode"`
	PrivateNetworks  string `json:"privateNetworks"`
	ProxyHost        string `json:"proxyHost"`
	ProxyPort        int    `json:"proxyPort"`
	Exclusions       int    `json:"exclusions"`
	PACPath          string `json:"pacPath"`
}

func pacDefaultView() pacDefaultProfileView {
	c := pacStore.Get()
	port := c.ProxyPort
	if port == 0 {
		if def := pacStore.DefaultPort(); def > 0 {
			port = def
		} else {
			port = 8080
		}
	}
	return pacDefaultProfileView{
		ID: pac.DefaultProfileID, Name: "Default (legacy PAC config)", Enabled: true,
		// By PR-2 vocabulary the legacy default is BALANCED (its exclusions
		// are explicit DIRECT carve-outs; the terminal has no DIRECT), with
		// the legacy private-network bypass.
		LegacyManaged: true, AvailabilityMode: pac.ModeBalanced, PrivateNetworks: pac.PrivateDirect,
		ProxyHost: c.ProxyHost, ProxyPort: port, Exclusions: len(c.Exclusions),
		PACPath: "/pac/default.pac",
	}
}

// writePACIssues writes a structured 400 with validation issues.
func writePACIssues(w http.ResponseWriter, msg string, issues []pac.ValidationIssue) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort error body
		"error":  msg,
		"issues": issues,
	})
}

// pacProfilesAPIMu serializes the read-modify-write of every profile/pool
// mutation (Get → modify → Set replaces the WHOLE config): without it two
// concurrent admin mutations lose one update and can mint duplicate
// revisions. Mirrors the saveConfigVersionMu precedent (configversion.go).
var pacProfilesAPIMu sync.Mutex

// pacProfilesMutationAllowed gates mutations to CP/standalone nodes: a
// data-plane node's profile store is CP-managed (snapshot-synced) — a local
// edit would silently diverge until the next CP version bump, then be
// obliterated without trace (Panorama managed-object semantics).
func pacProfilesMutationAllowed(w http.ResponseWriter) bool {
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	if role == "data-plane" {
		http.Error(w, "PAC profiles are managed by the control plane on this node", http.StatusConflict)
		return false
	}
	return true
}

// pacApplyProfilesMutation validates the candidate config strictly, persists
// it, audits, versions, and republishes the cluster snapshot. Returns false
// after writing the error response when the mutation is rejected.
func pacApplyProfilesMutation(w http.ResponseWriter, r *http.Request, action, object string, before, candidate pac.ProfilesConfig) bool {
	if issues := pac.ValidateProfilesConfig(candidate); len(issues) > 0 {
		writePACIssues(w, "validation failed", issues)
		return false
	}
	if err := pacProfiles.Set(candidate); err != nil {
		http.Error(w, "save error: "+err.Error(), http.StatusInternalServerError)
		return false
	}
	pacAfterActiveCommit(r, action, object, before, candidate)
	return true
}

// pacAfterActiveCommit runs the post-commit side effects of a PROVEN active
// store mutation: audit, config version, cluster republish, alert reset.
// Nothing here may run before the durable write succeeded (2F-B, C1).
func pacAfterActiveCommit(r *http.Request, action, object string, before, candidate pac.ProfilesConfig) {
	auditEventDiff(r, action, object,
		fmt.Sprintf("profiles=%d pools=%d", len(candidate.Profiles), len(candidate.Pools)),
		before, candidate)
	saveConfigVersion(sessionAdmin(r), action)
	_ = publishCurrentConfigSnapshot()
	pacResetProfileAlert(object)
}

// pacGuardDirectCRUD enforces the SAME safe-publish guardrail on the direct
// CRUD create/update path as the publish lifecycle (pac_publish_api.go), so the
// typed-DIRECT confirmation cannot be bypassed by saving a profile through the
// editor/API instead of the lifecycle. A candidate that introduces a NEW
// full-security-path bypass (DIRECT) — a DIRECT rule, availability mode, or
// private-networks=direct that the active revision did not have — is refused
// with 409 until the caller retypes the profile ID in the ?confirmDirect=
// query parameter. Hard guardrail failures (missing/empty pool, secure-mode
// could-emit-DIRECT, compile/digest) block with 400 regardless of confirmation.
// Returns true if the mutation may proceed. Must be called under
// pacProfilesAPIMu, on the candidate being committed.
func pacGuardDirectCRUD(w http.ResponseWriter, candidate pac.ProfilesConfig, p, active pac.Profile, hasActive bool, action string, confirm *pacConfirm) bool {
	// Structural validation runs first so an invalid candidate (e.g. unknown
	// pool) returns the canonical validation issues rather than a spurious
	// DIRECT-confirmation prompt. pacApplyProfilesMutation validates again
	// (the lifecycle path reaches it without this guard) — the repeat is
	// idempotent.
	if issues := pac.ValidateProfilesConfig(candidate); len(issues) > 0 {
		writePACIssues(w, "validation failed", issues)
		return false
	}
	// A disabled candidate serves nothing (servePACProfileFile 404s a disabled
	// profile), so it cannot make any DIRECT path reachable — no confirmation.
	if !p.Enabled {
		return true
	}
	// A disabled active spec is NOT a live DIRECT baseline: enabling a dormant
	// DIRECT profile (disabled → enabled, e.g. one created pre-guard or via a
	// tolerant import) makes its DIRECT path reachable to clients for the first
	// time, so treat it as introducing DIRECT with no prior footprint.
	if hasActive && !active.Enabled {
		active, hasActive = pac.Profile{}, false
	}
	pools := make(map[string]pac.Pool, len(candidate.Pools))
	for i := range candidate.Pools {
		pools[candidate.Pools[i].ID] = candidate.Pools[i]
	}
	chk := pac.EvaluatePublish(p, pools, active, hasActive)
	if !chk.RequiresConfirmation {
		return true
	}
	// 2F-B (C2): the SAME candidate-bound challenge as the lifecycle —
	// the legacy ?confirmDirect=<profile id> query parameter no longer
	// authorizes anything.
	expectedSpec := ""
	if hasActive {
		expectedSpec = pac.ProfileSpecDigest(active)
	}
	binding := pacChallengeBinding{
		ProfileID: p.ID, Action: action, CandidateSpecDigest: pac.ProfileSpecDigest(p),
		ExpectedActiveRevision: active.Revision, ExpectedActiveSpecDigest: expectedSpec,
		PoolDigest: pac.PoolDigest(pac.ReferencedPools(p, pools)), ArtifactDigest: chk.Digest, NewDirectPaths: chk.NewDirectPaths,
	}
	return pacVerifyConfirm(w, binding, confirm, nil)
}

// apiPACProfiles handles GET (list) and POST (create) /api/pac/profiles.
func apiPACProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg := pacProfiles.Get()
		jsonOK(w, map[string]any{
			"defaultProfile": pacDefaultView(),
			"profiles":       cfg.Profiles,
			"pools":          cfg.Pools,
			// 2F-A tokens: the collection token every CREATE must echo, and
			// the per-pool token every pool PUT/DELETE must echo.
			"collectionEtag": pac.ConfigETag(cfg),
			"poolEtags":      pacPoolEtags(cfg),
		})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) || !pacProfilesMutationAllowed(w) {
			return
		}
		var in struct {
			pac.Profile
			CollectionEtag string      `json:"collectionEtag"`
			Confirm        *pacConfirm `json:"confirm"`
		}
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		p := in.Profile
		token := pacFenceStr(r, "collectionEtag", in.CollectionEtag)
		pacWriteStateDecision(r, "resolved")
		pacProfilesAPIMu.Lock()
		defer pacProfilesAPIMu.Unlock()
		// 2F-A fence, decided inside the mutex against the authoritative
		// collection: a create issued from a stale listing is refused.
		if !pacCheckEtag(w, "collectionEtag", token, pac.ConfigETag(pacProfiles.Get())) {
			pacWriteStateDecision(r, "fence")
			return
		}
		pacWriteStateDecision(r, "fence")
		if _, exists := pacProfiles.ProfileByID(p.ID); exists {
			http.Error(w, "profile already exists: "+sanitizeLog(p.ID), http.StatusConflict)
			return
		}
		p.Revision = 1
		before := pacProfiles.Get()
		candidate := pacProfiles.Get() // independent deep copy (audit diff keeps before intact)
		candidate.Profiles = append(candidate.Profiles, p)
		// A brand-new profile has no active spec, so any DIRECT capability is
		// "new" and requires the typed confirmation — same gate as publish.
		if !pacGuardDirectCRUD(w, candidate, p, pac.Profile{}, false, "create", in.Confirm) {
			return
		}
		// 2F-E correction round 2/3: a (re)created profile starts a NEW
		// node-local history epoch. The fresh record is made durable BEFORE
		// the active create (persist-before-swap on both sides): whatever
		// record may survive under this id — a delete whose record removal
		// failed or crashed, a stale epoch — is replaced first, so a
		// recreated profile can never be exposed beside the old epoch; a
		// failed epoch write refuses the create with nothing changed.
		if _, err := pacLifecycle.Recreate(p.ID, p.Revision, pac.ProfileSpecDigest(p)); err != nil {
			logger.Printf("PAC: history epoch for %q could not be recorded at create: %v", sanitizeLog(p.ID), err)
			http.Error(w, "the profile's history epoch could not be recorded; nothing was changed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if pacApplyProfilesMutation(w, r, "pac.profile_create", p.ID, before, candidate) {
			jsonOK(w, p)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiPACProfileItem handles GET/PUT/DELETE /api/pac/profiles/{id} and, for
// the "/lifecycle" sub-resource, delegates to the safe-publishing handler
// (initiative PR 3) — one registered prefix, one uiRoutes entry.
func apiPACProfileItem(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/lifecycle") {
		apiPACProfileLifecycle(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/pac/profiles/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	if id == pac.DefaultProfileID {
		// GET returns the synthesized view; the legacy default is managed
		// via /api/pac-config, so mutations are refused here.
		if r.Method == http.MethodGet {
			jsonOK(w, pacDefaultView())
			return
		}
		http.Error(w, `the "default" profile is managed via /api/pac-config`, http.StatusConflict)
		return
	}
	switch r.Method {
	case http.MethodGet:
		p, ok := pacProfiles.ProfileByID(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		jsonOK(w, p)
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) || !pacProfilesMutationAllowed(w) {
			return
		}
		pacProfilePut(w, r, id)
	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) || !pacProfilesMutationAllowed(w) {
			return
		}
		pacProfileDelete(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func pacProfileDelete(w http.ResponseWriter, r *http.Request, id string) {
	token := pacFenceInt(r, "revision", 0)
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	before := pacProfiles.Get()
	existing, ok := pacProfiles.ProfileByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// 2F-A fence: a DELETE must echo the revision it loaded.
	if !pacCheckRevision(w, "revision", token, existing.Revision) {
		return
	}
	candidate, removed := pacRemoveProfile(pacProfiles.Get(), id)
	if !removed {
		http.NotFound(w, r)
		return
	}
	// 2F-E correction round 3: the delete transition is recorded DURABLY
	// before the active profile is removed. A crash or a failed record
	// removal after the active delete then leaves a record that the next
	// access (or boot) finishes — never one whose old epoch looks valid for
	// a profile recreated under the same id. A failed first write refuses
	// the delete with nothing changed.
	if err := pacLifecycle.MarkDeletePending(id); err != nil {
		logger.Printf("PAC: delete transition for %s could not be recorded: %v", sanitizeLog(id), err)
		http.Error(w, "the delete could not be recorded in the node-local history; nothing was changed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if pacApplyProfilesMutation(w, r, "pac.profile_delete", id, before, candidate) {
		// Drop the node-local lifecycle history for the deleted profile. A
		// failure here is finished by the next access/boot (the flag above);
		// the active mutation is committed and is reported as such.
		if err := pacLifecycle.Delete(id); err != nil {
			logger.Printf("PAC: lifecycle delete for %s: %v (finished at the next access)", sanitizeLog(id), err)
		}
		// Drop the node-local DIRECT-exception governance too, so a later
		// profile recreated under the SAME id cannot silently inherit the old
		// owner/reason/expiry and show a newly introduced bypass as governed
		// without fresh attestation.
		pacExceptionsMu.Lock()
		if err := pacExceptions.Delete(id); err != nil {
			logger.Printf("PAC: exception delete for %s: %v", sanitizeLog(id), err)
		}
		pacExceptionsMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}
}

func pacProfilePut(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		pac.Profile
		Confirm *pacConfirm `json:"confirm"`
	}
	if err := decodeJSON(r, &in); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	p := in.Profile
	if p.ID != "" && p.ID != id {
		http.Error(w, "profile ID in body must match URL", http.StatusBadRequest)
		return
	}
	p.ID = id
	token := pacFenceInt(r, "revision", p.Revision)
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	before := pacProfiles.Get()
	candidate := pacProfiles.Get() // independent deep copy (audit diff keeps before intact)
	var activeSpec pac.Profile
	found := false
	for i := range candidate.Profiles {
		if candidate.Profiles[i].ID != id {
			continue
		}
		// 2F-A fence: the client MUST echo the revision it loaded — an
		// absent/zero token is 428 and a stale one a structured 409, never
		// silent last-writer-wins (the pre-2F-A "revision 0 skips the
		// check" path is gone; stored profiles never carry 0 any more).
		if !pacCheckRevision(w, "revision", token, candidate.Profiles[i].Revision) {
			return
		}
		activeSpec = candidate.Profiles[i] // the spec being replaced, for the DIRECT-delta guardrail
		p.Revision = candidate.Profiles[i].Revision + 1
		candidate.Profiles[i] = p
		found = true
		break
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	// Same guardrail as publish: an update that introduces a new DIRECT path
	// vs the spec it replaces requires the typed confirmation.
	if !pacGuardDirectCRUD(w, candidate, p, activeSpec, true, "update", in.Confirm) {
		return
	}
	if pacApplyProfilesMutation(w, r, "pac.profile_update", id, before, candidate) {
		jsonOK(w, p)
	}
}

func pacRemoveProfile(cfg pac.ProfilesConfig, id string) (pac.ProfilesConfig, bool) {
	for i := range cfg.Profiles {
		if cfg.Profiles[i].ID == id {
			cfg.Profiles = append(cfg.Profiles[:i:i], cfg.Profiles[i+1:]...)
			return cfg, true
		}
	}
	return cfg, false
}

// apiPACPools handles GET (list) and POST (create) /api/pac/pools.
func apiPACPools(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOK(w, pacPoolViews(pacProfiles.Get().Pools))
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) || !pacProfilesMutationAllowed(w) {
			return
		}
		var in struct {
			pac.Pool
			CollectionEtag string `json:"collectionEtag"`
		}
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		p := in.Pool
		token := pacFenceStr(r, "collectionEtag", in.CollectionEtag)
		pacWriteStateDecision(r, "resolved")
		pacProfilesAPIMu.Lock()
		defer pacProfilesAPIMu.Unlock()
		if !pacCheckEtag(w, "collectionEtag", token, pac.ConfigETag(pacProfiles.Get())) {
			pacWriteStateDecision(r, "fence")
			return
		}
		pacWriteStateDecision(r, "fence")
		if _, exists := pacProfiles.PoolByID(p.ID); exists {
			http.Error(w, "pool already exists: "+sanitizeLog(p.ID), http.StatusConflict)
			return
		}
		before := pacProfiles.Get()
		candidate := pacProfiles.Get() // independent deep copy (audit diff keeps before intact)
		candidate.Pools = append(candidate.Pools, p)
		if pacApplyProfilesMutation(w, r, "pac.pool_create", p.ID, before, candidate) {
			jsonOK(w, p)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiPACPoolItem handles GET/PUT/DELETE /api/pac/pools/{id}.
func apiPACPoolItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/pac/pools/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		p, ok := pacProfiles.PoolByID(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		jsonOK(w, pacPoolView{Pool: p, ETag: pac.PoolETag(p)})
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) || !pacProfilesMutationAllowed(w) {
			return
		}
		pacPoolPut(w, r, id)
	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) || !pacProfilesMutationAllowed(w) {
			return
		}
		pacPoolDelete(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func pacPoolPut(w http.ResponseWriter, r *http.Request, id string) {
	var in struct {
		pac.Pool
		ETag string `json:"etag"`
	}
	if err := decodeJSON(r, &in); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	p := in.Pool
	if p.ID != "" && p.ID != id {
		http.Error(w, "pool ID in body must match URL", http.StatusBadRequest)
		return
	}
	p.ID = id
	token := pacFenceStr(r, "etag", in.ETag)
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	before := pacProfiles.Get()
	candidate := pacProfiles.Get() // independent deep copy (audit diff keeps before intact)
	found := false
	for i := range candidate.Pools {
		if candidate.Pools[i].ID != id {
			continue
		}
		// 2F-A fence: a pool PUT must echo the etag of the pool it loaded.
		if !pacCheckEtag(w, "etag", token, pac.PoolETag(candidate.Pools[i])) {
			return
		}
		candidate.Pools[i] = p
		found = true
		break
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	if pacApplyProfilesMutation(w, r, "pac.pool_update", id, before, candidate) {
		jsonOK(w, p)
	}
}

func pacPoolDelete(w http.ResponseWriter, r *http.Request, id string) {
	token := pacFenceStr(r, "etag", "")
	pacProfilesAPIMu.Lock()
	defer pacProfilesAPIMu.Unlock()
	before := pacProfiles.Get()
	existing, ok := pacProfiles.PoolByID(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	// 2F-A fence: a DELETE must echo the etag of the pool it loaded. The
	// vanished (404) and stale/missing-token (409/428) decisions precede the
	// referenced-by-profile refusal so the caller learns the truthful reason.
	if !pacCheckEtag(w, "etag", token, pac.PoolETag(existing)) {
		return
	}
	for i := range before.Profiles {
		if before.Profiles[i].PoolID == id {
			http.Error(w, "pool is referenced by profile "+sanitizeLog(before.Profiles[i].ID), http.StatusConflict)
			return
		}
		for _, rule := range before.Profiles[i].Rules {
			if rule.PoolID == id {
				http.Error(w, "pool is referenced by a rule in profile "+sanitizeLog(before.Profiles[i].ID), http.StatusConflict)
				return
			}
		}
	}
	candidate := pacProfiles.Get() // independent deep copy (audit diff keeps before intact)
	found := false
	for i := range candidate.Pools {
		if candidate.Pools[i].ID == id {
			candidate.Pools = append(candidate.Pools[:i:i], candidate.Pools[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	if pacApplyProfilesMutation(w, r, "pac.pool_delete", id, before, candidate) {
		w.WriteHeader(http.StatusNoContent)
	}
}

// pacPoolView is a pool as read through the API: the stored pool plus its
// 2F-A optimistic-concurrency token. The token is computed on read and is
// never part of the persisted or cluster-synced Pool.
type pacPoolView struct {
	pac.Pool
	ETag string `json:"etag"`
}

func pacPoolViews(pools []pac.Pool) []pacPoolView {
	out := make([]pacPoolView, 0, len(pools))
	for i := range pools {
		out = append(out, pacPoolView{Pool: pools[i], ETag: pac.PoolETag(pools[i])})
	}
	return out
}

func pacPoolEtags(cfg pac.ProfilesConfig) map[string]string {
	m := make(map[string]string, len(cfg.Pools))
	for i := range cfg.Pools {
		m[cfg.Pools[i].ID] = pac.PoolETag(cfg.Pools[i])
	}
	return m
}
