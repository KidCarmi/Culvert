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
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// agentResolver maps an agent key to its current endpoint (transport). It returns
// false for unknown keys; the API rejects those before reaching the service, so
// the service's registry stays bounded by the configured agent set.
type agentResolver func(key string) (AgentEndpoint, bool)

const releaseMethodNotAllowed = "method not allowed"

// releaseManager is the API backend: the dispatch service, the agent resolver,
// and the bounded status store. Constructed at startup and published via
// setReleaseManager; nil ⇒ the routes report "not configured" (503).
type releaseManager struct {
	svc     *DispatchService
	resolve agentResolver
	store   *dispatchStore
	// newID mints a dispatch_id. It MUST be lexicographically time-ordered (a
	// ULID) — the per-agent status store relies on lexical dispatch_id ordering
	// to decide which dispatch owns an agent's slot (see dispatchStore.update).
	newID func() string
	// verifyMode is the catalog signature mode this manager was wired with,
	// surfaced read-only on GET /api/releases so operators can see whether the
	// channel is enforced or in a break-glass state. Zero value = enforce.
	verifyMode VerifyMode
	// trustSchemes is the compact log-safe description of the active trust
	// schemes ("ed25519", "sigstore", "ed25519+sigstore", or "none"), surfaced
	// read-only on GET /api/releases (P2b). Empty ⇒ omitted.
	trustSchemes string
	// refresh re-fetches the catalog from the configured origin (P1.7 auto-seed,
	// when CULVERT_RELEASE_CATALOG_URL is set + enforce) and reloads the on-disk
	// catalog, so a release published AFTER startup appears without restarting the
	// proxy. Set at startup by loadReleaseManagement; nil ⇒ refresh unavailable.
	// On a fetch/verify failure it returns an error and leaves the current catalog
	// untouched (fail-closed, mirroring startup auto-seed).
	refresh func(context.Context) error
	// refreshInterval is the periodic refresh cadence this manager was wired with
	// (M1-2), surfaced read-only on GET /api/releases. 0 ⇒ loop disabled.
	refreshInterval time.Duration
	// catalogOrigin is the HOST of the effective catalog origin and
	// catalogURLSource says whether it is the baked default or an operator
	// override (M1-2 product revision) — both read-only on GET /api/releases.
	// Host-only for overrides: a presigned/credentialed override URL must never
	// reach viewers; the full URL is shown only for the public baked default.
	catalogOrigin    string
	catalogURLSource string // "default" | "override"
	// refreshStatus is the SHARED outcome record for BOTH refresh callers — the
	// periodic loop and the manual admin endpoint (M1-2 / RT-H1: loop-local state
	// diverges the moment an admin fixes the origin and refreshes by hand). Guarded
	// by its own mutex, NOT refreshMu, so a status read never blocks ~30s behind an
	// in-flight fetch. lastErr holds the already-REDACTED error string (rm.refresh
	// redacts before returning; viewers read this via /api/releases).
	statusMu      sync.Mutex
	refreshStatus refreshStatus
	// M1-3 once-per-crossing alert latches (RT-H2), guarded by statusMu. Reset
	// on restart (accepted + documented in release_alerts.go): a restart
	// re-fires a still-active alert once.
	refreshFailingLatched bool // release_catalog_refresh_failing fired, no success since
	staleLatched          bool // release_catalog_stale fired, catalog still within threshold
	// observeCatalog returns the RAW published catalog for observability (the
	// stale watchdog + expiry gauge + expired-state API surfacing), bypassing
	// GetCatalog's use-time expiry hide — an expired catalog must stay VISIBLE
	// to detection precisely when it becomes invisible to serving/dispatch
	// (M1-3 impl review MED-1). Set at wiring to holder.PublishedRaw; nil ⇒ no
	// observability source (permissive unit fixtures).
	observeCatalog func() *Catalog
	// refreshRunMu serializes the WHOLE runRefresh (refresh call + status fold) so
	// two overlapping callers cannot record outcomes out of order (a stale success
	// must not overwrite a newer failure — M1-2 impl review MED). statusMu alone
	// still guards reads, so /api/releases never blocks behind an in-flight fetch.
	refreshRunMu sync.Mutex
}

// refreshStatus records the most recent catalog-refresh outcome (M1-2).
type refreshStatus struct {
	LastAt              time.Time `json:"last_at"`
	LastOK              bool      `json:"last_ok"`
	LastErr             string    `json:"last_error,omitempty"`
	LastTrigger         string    `json:"last_trigger,omitempty"` // "startup" | "loop" | "manual"
	ConsecutiveFailures int       `json:"consecutive_failures"`
}

// runRefresh is the ONE entry point both refresh callers use: it runs rm.refresh,
// folds the outcome into the shared status (with the M1-3 failing/recovered
// alert transitions), and runs one catalog-freshness (stale) evaluation — so
// every loop tick, including 304 no-ops, re-checks the installed catalog's
// expiry (the freshness watchdog must fire even when the origin never changes).
func (rm *releaseManager) runRefresh(ctx context.Context, trigger string) error {
	rm.refreshRunMu.Lock()
	defer rm.refreshRunMu.Unlock()
	err := rm.refresh(ctx)
	rm.recordRefreshOutcome(trigger, err)
	rm.evaluateCatalogFreshness()
	return err
}

// recordRefreshOutcome folds one refresh outcome into the shared status under
// statusMu, advances the refresh_total metrics, and fires any failing/recovered
// alert transition (computed under the lock, emitted after unlock). Extracted
// from runRefresh so the startup auto-seed can record its outcome directly (it
// runs before the manager's refresh seam is invoked, and re-running rm.refresh
// at boot would double-fetch). err MUST already be redacted — LastErr is
// viewer-readable via /api/releases and alert Detail reaches webhooks.
func (rm *releaseManager) recordRefreshOutcome(trigger string, err error) {
	if err != nil {
		atomic.AddInt64(&statReleaseRefreshFailure, 1)
	} else {
		atomic.AddInt64(&statReleaseRefreshSuccess, 1)
	}
	rm.statusMu.Lock()
	rm.refreshStatus.LastAt = time.Now()
	rm.refreshStatus.LastTrigger = trigger
	if err != nil {
		rm.refreshStatus.LastOK = false
		rm.refreshStatus.LastErr = err.Error()
		rm.refreshStatus.ConsecutiveFailures++
	} else {
		rm.refreshStatus.LastOK = true
		rm.refreshStatus.LastErr = ""
		rm.refreshStatus.ConsecutiveFailures = 0
	}
	events := rm.evaluateRefreshTransitions(err)
	rm.statusMu.Unlock()
	for _, p := range events {
		releaseAlertFire(p.Event, p)
	}
}

// refreshStatusSnapshot returns a copy of the shared status for read paths.
func (rm *releaseManager) refreshStatusSnapshot() refreshStatus {
	rm.statusMu.Lock()
	defer rm.statusMu.Unlock()
	return rm.refreshStatus
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
	phaseDispatched dispatchPhase = "dispatched" // op accepted, watch in progress
	phaseTerminal   dispatchPhase = "terminal"   // op reached a terminal state
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

// update mutates the record for (agent, dispatchID). The per-agent slot is owned
// by the LATEST dispatch, decided by lexicographic comparison of dispatch_id —
// which is correct ONLY because dispatch_id is a ULID (lexical order == creation
// order). A stale late update from an older dispatch (smaller ULID) is ignored,
// so it can never clobber a newer one. If newID ever stops producing ULIDs this
// ordering invariant breaks.
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

func (st *dispatchStore) markDispatched(agent, dispatchID string, rc DispatchResumeContext) {
	st.update(agent, dispatchID, func(rec *dispatchRecord) {
		rec.Phase = phaseDispatched
		rec.OpID = rc.OpID
		rec.ReleaseID = rc.ReleaseID
		rec.ResumeContext = rc
	})
}

func (st *dispatchStore) markTerminal(agent, dispatchID string, rep *DispatchReport) {
	st.update(agent, dispatchID, func(rec *dispatchRecord) {
		rec.Phase = phaseTerminal
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
	mux.HandleFunc("/api/releases/catalog-refresh", apiReleaseCatalogRefresh)
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
		http.Error(w, releaseMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	cat := rm.svc.catalog()
	if cat == nil {
		unavail := map[string]any{
			"available":   false,
			"reason":      "no catalog published",
			"verify_mode": rm.verifyMode.String(),
		}
		// M1-3: distinguish "just expired" (a catalog IS published but hidden by
		// the use-time freshness gate) from "nothing installed" — the raw
		// observability accessor still sees it, so the admin learns WHY reads
		// degraded and the panel can render the EXPIRED state (impl review MED-1).
		if rm.observeCatalog != nil {
			if raw := rm.observeCatalog(); raw != nil {
				if exp := raw.ExpiresAt(); !exp.IsZero() && time.Now().After(exp) {
					unavail["reason"] = "installed catalog expired"
					unavail["expires_at"] = exp.UTC().Format(time.RFC3339)
					unavail["expires_in_days"] = int(math.Floor(time.Until(exp).Hours() / 24))
				}
			}
		}
		if rm.trustSchemes != "" {
			unavail["trust_schemes"] = rm.trustSchemes
		}
		rm.addRefreshFields(unavail)
		jsonOK(w, unavail)
		return
	}
	out := map[string]any{
		"available":    true,
		"verify_mode":  rm.verifyMode.String(),
		"generated_at": cat.GeneratedAt().UTC().Format(time.RFC3339),
		"releases":     cat.List(),
		"channels":     channelPointers(cat),
	}
	if rm.trustSchemes != "" {
		out["trust_schemes"] = rm.trustSchemes
	}
	if v := cat.Version(); v > 0 {
		out["catalog_version"] = v
	}
	if exp := cat.ExpiresAt(); !exp.IsZero() {
		out["expires_at"] = exp.UTC().Format(time.RFC3339)
		// GUI parity for the M1-3 freshness watchdog: whole days remaining,
		// rendered in the Release panel. True floor — 12h past expiry must read
		// -1 ("EXPIRED"), not truncate to 0 ("0 days left").
		out["expires_in_days"] = int(math.Floor(time.Until(exp).Hours() / 24))
	}
	rm.addRefreshFields(out)
	jsonOK(w, out)
}

// addRefreshFields folds the M1-2 refresh surface into an /api/releases response:
// the wired cadence (read-only; env-configured) and the shared last-refresh
// outcome, present once any refresh has run.
func (rm *releaseManager) addRefreshFields(out map[string]any) {
	if rm.refreshInterval > 0 {
		out["refresh_interval"] = rm.refreshInterval.String()
	}
	if rm.catalogURLSource != "" {
		out["catalog_url_source"] = rm.catalogURLSource
		if rm.catalogOrigin != "" {
			// Host only for overrides; omitted entirely when fetch is disabled.
			out["catalog_origin"] = rm.catalogOrigin
		}
		if rm.catalogURLSource == catalogURLSourceDefault {
			// Safe to show the full URL: it is the public baked constant, not an
			// operator-supplied value that might carry credentials.
			out["catalog_url"] = defaultReleaseCatalogURL
		}
	}
	if st := rm.refreshStatusSnapshot(); !st.LastAt.IsZero() {
		out["last_refresh"] = st
	}
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

// ─── POST /api/releases/catalog-refresh ──────────────────────────────────────
//
// Re-fetches the signed catalog from the configured origin
// (CULVERT_RELEASE_CATALOG_URL, when set + enforce mode) and reloads it, so a
// release published after startup appears WITHOUT restarting the proxy. Admin-
// only and audited. Verification is NOT relaxed — the same baked-root + pinned-
// identity + freshness/rollback gate runs as at startup, and on any fetch/verify
// failure the existing catalog is left untouched (fail-closed).
func apiReleaseCatalogRefresh(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	rm := currentReleaseManager()
	if rm == nil || rm.svc == nil || rm.refresh == nil {
		writeReleaseUnavailable(w)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, releaseMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}
	if err := rm.runRefresh(r.Context(), "manual"); err != nil {
		auditEvent(r, "release.catalog.refresh", "catalog", "result=error: "+sanitizeLog(err.Error()))
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"refreshed": false, "error": err.Error()})
		return
	}
	cat := rm.svc.catalog()
	avail := cat != nil
	detail := "result=ok available=false"
	if avail {
		detail = "result=ok available=true"
	}
	auditEvent(r, "release.catalog.refresh", "catalog", detail)
	out := map[string]any{"refreshed": true, "available": avail, "verify_mode": rm.verifyMode.String()}
	if avail {
		if v := cat.Version(); v > 0 {
			out["catalog_version"] = v
		}
		out["channels"] = channelPointers(cat)
	}
	jsonOK(w, out)
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
		http.Error(w, releaseMethodNotAllowed, http.StatusMethodNotAllowed)
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
	if errors.Is(err, errDispatchNoCatalog) {
		// No catalog published yet: Current() bails BEFORE contacting the agent,
		// so this is NOT an agent-reachability failure. Surface it as a normal
		// no-catalog read (200 / available:false) — the same signal GET /api/releases
		// uses — instead of a 503 the UI mislabels as "Agent unreachable".
		jsonOK(w, map[string]any{"agent": agent, "available": false, "known": false})
		return
	}
	if err != nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"agent": agent, "error": err.Error()})
		return
	}
	jsonOK(w, map[string]any{
		"agent":      agent,
		"available":  true,
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
		http.Error(w, releaseMethodNotAllowed, http.StatusMethodNotAllowed)
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
		http.Error(w, releaseMethodNotAllowed, http.StatusMethodNotAllowed)
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

	applied := make(chan struct{}, 1)
	done := make(chan struct{})
	var appliedFlag atomic.Bool
	var rep *DispatchReport
	var derr error
	go func() {
		defer close(done)
		// DETACHED context (context.Background, NOT r.Context()): once the agent
		// has accepted the apply we MUST drive the op to terminal even if the
		// client disconnects or cancels the request after the 202. Inheriting the
		// request context would cancel an already-accepted upgrade mid-flight. The
		// executor caps a deadline-less ctx at its maxWatch so it cannot run forever.
		rep, derr = rm.svc.Dispatch(context.Background(), actor, ep, target, opts,
			func(opID string, rc DispatchResumeContext) {
				rm.store.markDispatched(ep.Key, dispatchID, rc)
				appliedFlag.Store(true)
				select {
				case applied <- struct{}{}:
				default:
				}
			})
		// Only claim the per-agent status slot if THIS dispatch actually owned the
		// agent (acquired single-flight): an in-flight rejection or a planner
		// refusal never ran an op, so it must NOT overwrite the record of the op
		// that is actually running (P2: status-clobber).
		if ownedAgent(rep, derr) {
			rm.store.markTerminal(ep.Key, dispatchID, rep)
		}
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
	case rep != nil && rep.RefusedKind != RefusedNone:
		// Planner refusal (unknown target, repo mismatch, …).
		writeJSONStatus(w, refusalHTTPStatus(rep.RefusedKind), map[string]any{
			"status": "refused", "kind": string(rep.RefusedKind), "detail": detailOf(rep),
		})
	case err != nil:
		// Preflight read failure (agent /v1/status unreachable / no op started) — retryable.
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "detail": err.Error()})
	case rep != nil && rep.Terminal == TerminalAlreadyCurrent:
		writeJSONStatus(w, http.StatusOK, map[string]any{"status": "already_current", "release_id": rep.ReleaseID})
	case rep != nil && rep.Terminal == TerminalFailedNeedsAttn && strings.HasPrefix(rep.Detail, detailAnchorReadFailed):
		// Anchor read of /v1/status failed before apply — same "agent status
		// unavailable / retryable" condition as a preflight read failure, so it
		// maps to the SAME 503 (LOW-2: consistent mapping), not 502.
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "detail": detailOf(rep)})
	case rep != nil && rep.Terminal == TerminalFailedNeedsAttn:
		// Apply was rejected / failed BEFORE an op_id was returned (no op created).
		// Surface it as an upstream-agent failure — never a 200 "ok".
		writeJSONStatus(w, http.StatusBadGateway, map[string]any{
			"status": "failed", "terminal": string(rep.Terminal), "detail": detailOf(rep),
		})
	default:
		writeJSONStatus(w, http.StatusOK, map[string]any{"status": "ok"})
	}
}

// ownedAgent reports whether a dispatch outcome actually claimed the agent
// (acquired single-flight). An in-flight rejection and a planner/preflight
// refusal never ran an op, so they must NOT write the per-agent status slot.
func ownedAgent(rep *DispatchReport, err error) bool {
	if errors.Is(err, errDispatchInFlight) {
		return false
	}
	if rep != nil && rep.Outcome == OutcomeRefused {
		return false
	}
	return true
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
		http.Error(w, releaseMethodNotAllowed, http.StatusMethodNotAllowed)
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

	go func() {
		// Re-poll the EXISTING op to terminal; never calls Apply. Only claim the
		// per-agent status slot if the resume actually acquired single-flight — an
		// in-flight rejection must not clobber the running op's record (P2).
		rep, rerr := rm.svc.Resume(context.Background(), actor, ep, rc)
		if !errors.Is(rerr, errDispatchInFlight) {
			rm.store.markDispatched(ep.Key, dispatchID, rc) // record the op being resumed
			rm.store.markTerminal(ep.Key, dispatchID, rep)
		}
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
