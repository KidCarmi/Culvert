// Release Management API — P1.6d-0 (foundation; NO GUI in this slice).
//
// Read-only catalog/current endpoints plus the async dispatch + resume control
// endpoints, all backed by the P1.6c DispatchService. The handlers own only HTTP
// concerns (auth, decode, the async 202 split, and a bounded per-agent status
// store); planning/execution/verify-by-digest/audit/alert all live in the
// service. Agent endpoints are resolved by an injected resolver (NOT a config
// route — config is a later slice), so this slice adds no /api/releases/config,
// no GUI panel, no auto-update, no scheduling.
//
// Dispatch is asynchronous: the handler starts DispatchService.Dispatch in the
// background and returns 202 the instant the op_id + resume context are durably
// recorded (the service's onApplied observer). A planner/preflight refusal that
// happens BEFORE apply returns a synchronous 4xx/503 instead. The watch then
// runs to terminal in the background and updates the status store, which the
// GET status endpoint surfaces.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// agentResolver maps an agent key to its current endpoint (transport). It returns
// false for unknown keys; the API rejects those before reaching the service, so
// the service's registry stays bounded by the configured agent set.
type agentResolver func(key string) (AgentEndpoint, bool)

// releaseManager is the API backend: the dispatch service, the agent resolver,
// and the bounded status store. Constructed at startup and published via
// setReleaseManager; nil ⇒ the routes report "not configured" (503).
type releaseManager struct {
	svc     *DispatchService
	resolve agentResolver
	store   *dispatchStore
	newID   func() string
}

func newReleaseManager(svc *DispatchService, resolve agentResolver) *releaseManager {
	return &releaseManager{svc: svc, resolve: resolve, store: newDispatchStore(), newID: newDispatchOpID}
}

var (
	releaseMgrMu     sync.RWMutex
	globalReleaseMgr *releaseManager
)

func setReleaseManager(rm *releaseManager) {
	releaseMgrMu.Lock()
	globalReleaseMgr = rm
	releaseMgrMu.Unlock()
}

func currentReleaseManager() *releaseManager {
	releaseMgrMu.RLock()
	defer releaseMgrMu.RUnlock()
	return globalReleaseMgr
}

// ─── bounded per-agent status store ──────────────────────────────────────────

type dispatchPhase string

const (
	phasePlanning   dispatchPhase = "planning"
	phaseDispatched dispatchPhase = "dispatched"
	phaseResuming   dispatchPhase = "resuming"
	phaseTerminal   dispatchPhase = "terminal"
	phaseRefused    dispatchPhase = "refused"
)

// dispatchRecord is the LATEST dispatch state for one agent. The store keeps at
// most one record per agent key, so it is bounded by the configured agent set.
type dispatchRecord struct {
	DispatchID    string                `json:"dispatch_id"`
	Agent         string                `json:"agent"`
	Phase         dispatchPhase         `json:"phase"`
	OpID          string                `json:"op_id,omitempty"`
	ReleaseID     string                `json:"release_id,omitempty"`
	Terminal      DispatchTerminal      `json:"terminal,omitempty"`
	Verified      bool                  `json:"verified"`
	Detail        string                `json:"detail,omitempty"`
	ResumeContext DispatchResumeContext `json:"resume_context,omitempty"`
	StartedAt     time.Time             `json:"started_at"`
	UpdatedAt     time.Time             `json:"updated_at"`
}

type dispatchStore struct {
	mu      sync.Mutex
	now     func() time.Time
	byAgent map[string]*dispatchRecord
}

func newDispatchStore() *dispatchStore {
	return &dispatchStore{now: time.Now, byAgent: make(map[string]*dispatchRecord)}
}

// update mutates the record for (agent, dispatchID). A LATER dispatch (larger
// ULID dispatch_id) owns the per-agent slot, so a stale late update from an
// older dispatch is ignored — never clobbering a newer one.
func (st *dispatchStore) update(agent, dispatchID string, mut func(*dispatchRecord)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	cur, ok := st.byAgent[agent]
	if ok && cur.DispatchID != dispatchID {
		if cur.DispatchID > dispatchID {
			return // a newer dispatch owns the slot
		}
		ok = false // older slot — replace
	}
	if !ok {
		cur = &dispatchRecord{DispatchID: dispatchID, Agent: agent, StartedAt: st.now()}
		st.byAgent[agent] = cur
	}
	mut(cur)
	cur.UpdatedAt = st.now()
}

func (st *dispatchStore) begin(agent, dispatchID string, phase dispatchPhase) {
	st.update(agent, dispatchID, func(rec *dispatchRecord) { rec.Phase = phase })
}

func (st *dispatchStore) markDispatched(agent, dispatchID string, rc DispatchResumeContext) {
	st.update(agent, dispatchID, func(rec *dispatchRecord) {
		rec.Phase = phaseDispatched
		rec.OpID = rc.OpID
		rec.ReleaseID = rc.ReleaseID
		rec.ResumeContext = rc
	})
}

func (st *dispatchStore) markTerminal(agent, dispatchID string, rep *DispatchReport, refused bool) {
	st.update(agent, dispatchID, func(rec *dispatchRecord) {
		if refused {
			rec.Phase = phaseRefused
		} else {
			rec.Phase = phaseTerminal
		}
		if rep != nil {
			rec.Terminal = rep.Terminal
			rec.Verified = rep.Verified
			rec.Detail = rep.Detail
			if rep.OpID != "" {
				rec.OpID = rep.OpID
			}
			if rep.ReleaseID != "" {
				rec.ReleaseID = rep.ReleaseID
			}
		}
	})
}

func (st *dispatchStore) get(agent string) (dispatchRecord, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	rec, ok := st.byAgent[agent]
	if !ok {
		return dispatchRecord{}, false
	}
	return *rec, true
}

// ─── route registration ──────────────────────────────────────────────────────

func registerReleaseRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/releases", apiReleases)
	mux.HandleFunc("/api/releases/current", apiReleaseCurrent)
	mux.HandleFunc("/api/releases/dispatch", apiReleaseDispatch)
	mux.HandleFunc("/api/releases/dispatch/status", apiReleaseDispatchStatus)
	mux.HandleFunc("/api/releases/dispatch/resume", apiReleaseDispatchResume)
}

func writeReleaseUnavailable(w http.ResponseWriter) {
	http.Error(w, "release management not configured", http.StatusServiceUnavailable)
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ─── GET /api/releases ───────────────────────────────────────────────────────

func apiReleases(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	rm := currentReleaseManager()
	if rm == nil || rm.svc == nil {
		writeReleaseUnavailable(w)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cat := rm.svc.catalog()
	if cat == nil {
		jsonOK(w, map[string]any{"available": false, "reason": "no catalog published"})
		return
	}
	jsonOK(w, map[string]any{
		"available":    true,
		"generated_at": cat.GeneratedAt().UTC().Format(time.RFC3339),
		"releases":     cat.List(),
		"channels":     channelPointers(cat),
	})
}

func channelPointers(cat *Catalog) map[string]any {
	out := make(map[string]any, 3)
	for _, ch := range []Channel{ChannelRecommended, ChannelLTS, ChannelCritical} {
		if rel, err := cat.Resolve(ch); err == nil {
			out[string(ch)] = map[string]string{
				"release_id": rel.ReleaseID,
				"version_id": rel.VersionID,
				"severity":   string(rel.Severity),
			}
		}
	}
	return out
}

// ─── GET /api/releases/current?agent=<key> ──────────────────────────────────

func apiReleaseCurrent(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	rm := currentReleaseManager()
	if rm == nil || rm.svc == nil {
		writeReleaseUnavailable(w)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agent := r.URL.Query().Get("agent")
	if agent == "" {
		http.Error(w, "agent query parameter is required", http.StatusBadRequest)
		return
	}
	ep, ok := rm.resolve(agent)
	if !ok {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}
	view, err := rm.svc.Current(r.Context(), ep)
	if err != nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"agent": agent, "error": err.Error()})
		return
	}
	jsonOK(w, map[string]any{
		"agent":      agent,
		"known":      view.Known,
		"release_id": view.ReleaseID,
		"version_id": view.VersionID,
	})
}

// ─── GET /api/releases/dispatch/status?agent=<key> ──────────────────────────

func apiReleaseDispatchStatus(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	rm := currentReleaseManager()
	if rm == nil {
		writeReleaseUnavailable(w)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	agent := r.URL.Query().Get("agent")
	if agent == "" {
		http.Error(w, "agent query parameter is required", http.StatusBadRequest)
		return
	}
	rec, ok := rm.store.get(agent)
	if !ok {
		jsonOK(w, map[string]any{"agent": agent, "phase": "none"})
		return
	}
	jsonOK(w, rec)
}

// ─── POST /api/releases/dispatch ─────────────────────────────────────────────

type dispatchRequest struct {
	ReleaseID      string `json:"release_id,omitempty"`
	Channel        string `json:"channel,omitempty"`
	Agent          string `json:"agent"`
	PreBackup      bool   `json:"pre_backup,omitempty"`
	NoRollback     bool   `json:"no_rollback,omitempty"`
	PassphraseRef  string `json:"passphrase_ref,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

func (b dispatchRequest) target() (DispatchTarget, error) {
	hasRel, hasCh := b.ReleaseID != "", b.Channel != ""
	switch {
	case hasRel && hasCh:
		return DispatchTarget{}, errors.New("specify release_id OR channel, not both")
	case hasRel:
		return DispatchTarget{ReleaseID: b.ReleaseID}, nil
	case hasCh:
		return DispatchTarget{Channel: Channel(b.Channel)}, nil
	default:
		return DispatchTarget{}, errors.New("release_id or channel is required")
	}
}

func apiReleaseDispatch(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	rm := currentReleaseManager()
	if rm == nil || rm.svc == nil {
		writeReleaseUnavailable(w)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body dispatchRequest
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	target, terr := body.target()
	if terr != nil {
		http.Error(w, terr.Error(), http.StatusBadRequest)
		return
	}
	if body.Agent == "" {
		http.Error(w, "agent is required", http.StatusBadRequest)
		return
	}
	ep, ok := rm.resolve(body.Agent)
	if !ok {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}

	actor := auditActor(r)
	opts := DispatchOptions{
		PreBackup:      body.PreBackup,
		NoRollback:     body.NoRollback,
		PassphraseRef:  body.PassphraseRef,
		IdempotencyKey: body.IdempotencyKey, // honored when set; else the service mints a stable key
	}
	dispatchID := rm.newID()
	rm.store.begin(ep.Key, dispatchID, phasePlanning)

	applied := make(chan struct{}, 1)
	done := make(chan struct{})
	var appliedFlag atomic.Bool
	var rep *DispatchReport
	var derr error
	go func() {
		defer close(done)
		// Detached context: the dispatch (and its watch) must outlive this HTTP
		// request. The executor caps a deadline-less ctx at its maxWatch.
		rep, derr = rm.svc.Dispatch(context.Background(), actor, ep, target, opts,
			func(opID string, rc DispatchResumeContext) {
				rm.store.markDispatched(ep.Key, dispatchID, rc)
				appliedFlag.Store(true)
				select {
				case applied <- struct{}{}:
				default:
				}
			})
		rm.store.markTerminal(ep.Key, dispatchID, rep, rep != nil && rep.Outcome == OutcomeRefused)
	}()

	// Return 202 as soon as the op is durably recorded (applied), even if the
	// whole watch has already finished by the time we get here (done + applied
	// both ready ⇒ the appliedFlag check keeps it a 202, never a pre-apply reply).
	select {
	case <-applied:
		rm.write202(w, ep.Key, dispatchID)
	case <-done:
		if appliedFlag.Load() {
			rm.write202(w, ep.Key, dispatchID)
		} else {
			rm.respondPreApply(w, rep, derr)
		}
	}
}

func (rm *releaseManager) write202(w http.ResponseWriter, agentKey, dispatchID string) {
	loc := "/api/releases/dispatch/status?agent=" + url.QueryEscape(agentKey)
	rec, _ := rm.store.get(agentKey)
	w.Header().Set("Location", loc)
	writeJSONStatus(w, http.StatusAccepted, map[string]any{
		"dispatch_id":     dispatchID,
		"agent":           agentKey,
		"op_id":           rec.OpID,
		"status":          "dispatched",
		"status_location": loc,
	})
}

// respondPreApply maps a pre-apply outcome (no op started) to an HTTP status.
func (rm *releaseManager) respondPreApply(w http.ResponseWriter, rep *DispatchReport, err error) {
	switch {
	case errors.Is(err, errDispatchInFlight):
		writeJSONStatus(w, http.StatusConflict, map[string]any{"status": "in_flight", "detail": "a dispatch is already in flight on this agent"})
	case errors.Is(err, errStaleAlreadyCurrent):
		// Re-plan signal, NOT a critical incident.
		writeJSONStatus(w, http.StatusConflict, map[string]any{"status": "stale_replan_required", "detail": detailOf(rep)})
	case rep != nil && rep.Outcome == OutcomeRefused:
		writeJSONStatus(w, refusalHTTPStatus(rep.RefusedKind), map[string]any{
			"status": "refused", "kind": string(rep.RefusedKind), "detail": detailOf(rep),
		})
	case err != nil:
		// Preflight read failure (agent unreachable) — retryable.
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "detail": err.Error()})
	case rep != nil && rep.Terminal == TerminalAlreadyCurrent:
		writeJSONStatus(w, http.StatusOK, map[string]any{"status": "already_current", "release_id": rep.ReleaseID})
	default:
		writeJSONStatus(w, http.StatusOK, map[string]any{"status": "ok"})
	}
}

func detailOf(rep *DispatchReport) string {
	if rep == nil {
		return ""
	}
	return rep.Detail
}

func refusalHTTPStatus(k RefusedKind) int {
	switch k {
	case RefusedNoCatalog:
		return http.StatusServiceUnavailable
	case RefusedUnknownTarget:
		return http.StatusNotFound
	default: // no_target, ambiguous, repo_mismatch, malformed_ref, invalid config/rewrite
		return http.StatusBadRequest
	}
}

// ─── POST /api/releases/dispatch/resume ──────────────────────────────────────

type resumeRequest struct {
	Agent         string                 `json:"agent"`
	DispatchID    string                 `json:"dispatch_id,omitempty"`
	ResumeContext *DispatchResumeContext `json:"resume_context,omitempty"`
}

func apiReleaseDispatchResume(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	rm := currentReleaseManager()
	if rm == nil || rm.svc == nil {
		writeReleaseUnavailable(w)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body resumeRequest
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Agent == "" {
		http.Error(w, "agent is required", http.StatusBadRequest)
		return
	}
	ep, ok := rm.resolve(body.Agent)
	if !ok {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}
	rc, rerr := rm.resolveResumeContext(body)
	if rerr != nil {
		http.Error(w, rerr.Error(), http.StatusBadRequest)
		return
	}
	if rc.OpID == "" {
		http.Error(w, "resume needs an op_id", http.StatusBadRequest)
		return
	}

	actor := auditActor(r)
	dispatchID := rm.newID()
	rm.store.begin(ep.Key, dispatchID, phaseResuming)
	rm.store.markDispatched(ep.Key, dispatchID, rc) // record the op being resumed

	go func() {
		// Re-poll the EXISTING op to terminal; never calls Apply.
		rep, _ := rm.svc.Resume(context.Background(), actor, ep, rc)
		rm.store.markTerminal(ep.Key, dispatchID, rep, false)
	}()

	w.Header().Set("Location", "/api/releases/dispatch/status?agent="+url.QueryEscape(ep.Key))
	writeJSONStatus(w, http.StatusAccepted, map[string]any{
		"dispatch_id":     dispatchID,
		"agent":           ep.Key,
		"op_id":           rc.OpID,
		"status":          "resuming",
		"status_location": "/api/releases/dispatch/status?agent=" + url.QueryEscape(ep.Key),
	})
}

func (rm *releaseManager) resolveResumeContext(body resumeRequest) (DispatchResumeContext, error) {
	if body.ResumeContext != nil {
		return *body.ResumeContext, nil
	}
	if body.DispatchID == "" {
		return DispatchResumeContext{}, errors.New("resume_context or dispatch_id is required")
	}
	rec, ok := rm.store.get(body.Agent)
	if !ok || rec.DispatchID != body.DispatchID || rec.ResumeContext.OpID == "" {
		return DispatchResumeContext{}, errors.New("no resumable op for dispatch_id")
	}
	return rec.ResumeContext, nil
}
