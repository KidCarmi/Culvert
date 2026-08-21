package main

// ui_policy_learning.go — M5A admin API for Policy Learning Mode (ADR-0025):
// governed enablement, session operations, and the READ-ONLY recommendation
// surface. No Accept/Reject, no policy translation, no Draft mutation — M5B
// owns the trust boundary.
//
// API privacy boundary (M5A §7): NOTHING internal is serialized directly.
// Every response goes through the explicit DTOs below, which carry factual
// summaries only. Deliberately ABSENT from every DTO: subject tokens, the
// subject-key identity, raw subjects, internal aggregation maps/cells,
// credentials, headers, and URLs/query strings. Staleness is evaluated
// SERVER-SIDE from explicit current StaleInputs (§10); clients render the
// returned reasons and reproduce no staleness logic.
//
// Scope honesty (M5A §13): learning is NODE-LOCAL. Every status payload says
// so; nothing here implies fleet/global coverage.

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

func registerPolicyLearningRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/policy-learning", apiPolicyLearningStatus)
	mux.HandleFunc("/api/policy-learning/config", apiPolicyLearningConfig)
	mux.HandleFunc("/api/policy-learning/session", apiPolicyLearningSession)
	mux.HandleFunc("/api/policy-learning/sessions", apiPolicyLearningSessions)
	mux.HandleFunc("/api/policy-learning/recommendations", apiPolicyLearningRecommendations)
	mux.HandleFunc("/api/policy-learning/recommendations/generate", apiPolicyLearningGenerate)
}

// plScopeNote is the node-local honesty statement carried on the status
// surface and rendered by the GUI (M5A §13).
const plScopeNote = "Learning observes traffic on this node only; sessions, evidence, and recommendations are node-local and are not aggregated across the fleet."

// plAdvisoryNote is the ADR-0025 advisory statement.
const plAdvisoryNote = "Policy Learning is advisory only: it observes and recommends, and cannot alter enforcement policy."

// ── DTOs (every field reviewed — see header) ─────────────────────────────────

type plBaselineDTO struct {
	PolicyGeneration  int64  `json:"policy_generation"`
	DefaultAction     string `json:"default_action,omitempty"`
	CapturedAt        string `json:"captured_at,omitempty"`
	CategoryEpoch     string `json:"category_epoch,omitempty"`
	GuardrailsHash    string `json:"guardrails_hash,omitempty"`
	PolicyContentHash string `json:"policy_content_hash,omitempty"`
}

type plGapDTO struct {
	At     string `json:"at"`
	Reason string `json:"reason"`
}

type plTransportDTO struct {
	Accepted       int64 `json:"accepted"`
	Dropped        int64 `json:"dropped"`
	Rejected       int64 `json:"rejected"`
	ConsumerPanics int64 `json:"consumer_panics"`
	// GroupsTruncated (M5B.1): accepted observations whose identity carried
	// more than the 16-group bound — group context is incomplete for those
	// events (a coverage fact, not a Degraded trigger: omitted groups simply
	// received no evidence).
	GroupsTruncated int64 `json:"groups_truncated"`
	Degraded        bool  `json:"degraded"`
}

type plSessionDTO struct {
	ID        string        `json:"id"`
	State     string        `json:"state"`
	CreatedAt string        `json:"created_at"`
	StartedAt string        `json:"started_at"`
	StoppedAt string        `json:"stopped_at,omitempty"`
	CreatedBy string        `json:"created_by"`
	StoppedBy string        `json:"stopped_by,omitempty"`
	Baseline  plBaselineDTO `json:"baseline"`
	Gaps      []plGapDTO    `json:"gaps,omitempty"`
	// Transport is the session-window observation loss accounting (facts, not
	// percentages). ChurnEvents counts recorded mid-session category-generation
	// changes.
	Transport   plTransportDTO `json:"transport"`
	ChurnEvents int            `json:"churn_events"`
	// Aggregate overview: bounded counts + degradation flags only — never cell
	// contents or subject tokens.
	Cells             int   `json:"cells"`
	CellsDropped      int64 `json:"cells_dropped"`
	ChurnOverflow     int64 `json:"churn_overflow"`
	SubjectKeyChanged bool  `json:"subject_key_changed"`
}

type plRecommendationDTO struct {
	ID                string                           `json:"id"`
	SessionID         string                           `json:"session_id"`
	State             string                           `json:"state"`
	Group             string                           `json:"group"`
	Category          string                           `json:"category"`
	ProposedRule      policylearn.ProposedRule         `json:"proposed_rule"`
	Confidence        string                           `json:"confidence"`
	ConfidenceReasons []string                         `json:"confidence_reasons,omitempty"`
	ConfidenceLimits  []string                         `json:"confidence_limits,omitempty"`
	Coverage          policylearn.CoverageEvidence     `json:"coverage"`
	Evidence          policylearn.Evidence             `json:"evidence"`
	Baseline          plBaselineDTO                    `json:"baseline"`
	Policy            policylearn.RecommendationPolicy `json:"policy"` // read-only decision-policy transparency
	PolicyHash        string                           `json:"policy_hash"`
	GeneratedAt       string                           `json:"generated_at"`
	// StaleReasons is computed server-side at read time against the CURRENT
	// identities (policy content + generation, category epoch, guardrails,
	// subject key, recommendation policy). Empty = fresh. Historical evidence
	// is never mutated by staleness.
	StaleReasons []string `json:"stale_reasons"`
	// M5B decision facts (administrative metadata — actor identities are the
	// audit-actor strings, never subject evidence).
	TargetRuleID string `json:"target_rule_id,omitempty"`
	AcceptedAt   string `json:"accepted_at,omitempty"`
	AcceptedBy   string `json:"accepted_by,omitempty"`
	RejectedAt   string `json:"rejected_at,omitempty"`
	RejectedBy   string `json:"rejected_by,omitempty"`
	RejectReason string `json:"reject_reason,omitempty"`
}

func plBaselineToDTO(b policylearn.Baseline) plBaselineDTO {
	return plBaselineDTO{
		PolicyGeneration:  b.PolicyGeneration,
		DefaultAction:     b.DefaultAction,
		CapturedAt:        b.CapturedAt,
		CategoryEpoch:     b.CategoryEpoch,
		GuardrailsHash:    b.GuardrailsHash,
		PolicyContentHash: b.PolicyContentHash,
	}
}

func plSessionToDTO(eng *policylearn.Engine, s policylearn.Session) plSessionDTO {
	d := plSessionDTO{
		ID:        s.ID,
		State:     s.State,
		CreatedAt: s.CreatedAt,
		StartedAt: s.StartedAt,
		StoppedAt: s.StoppedAt,
		CreatedBy: s.CreatedBy,
		StoppedBy: s.StoppedBy,
		Baseline:  plBaselineToDTO(s.Baseline),
		Transport: plTransportDTO{
			Accepted:        s.Transport.Accepted,
			Dropped:         s.Transport.Dropped,
			Rejected:        s.Transport.Rejected,
			ConsumerPanics:  s.Transport.ConsumerPanics,
			GroupsTruncated: s.Transport.GroupsTruncated,
			Degraded:        s.Transport.Degraded(),
		},
		ChurnEvents: len(s.CategoryChurn),
	}
	for _, g := range s.Gaps {
		d.Gaps = append(d.Gaps, plGapDTO{At: g.At, Reason: g.Reason})
	}
	if o, ok := eng.SessionOverview(s.ID); ok {
		d.Cells = o.Cells
		d.CellsDropped = o.CellsDropped
		d.ChurnOverflow = o.ChurnOverflow
		d.SubjectKeyChanged = o.SubjectKeyChanged
	}
	return d
}

func plRecommendationToDTO(r policylearn.Recommendation, cur policylearn.StaleInputs) plRecommendationDTO {
	stale := policylearn.StaleReasons(&r, cur)
	if stale == nil {
		stale = []string{} // explicit empty = "fresh", never null
	}
	return plRecommendationDTO{
		ID:                r.ID,
		SessionID:         r.SessionID,
		State:             r.State,
		Group:             r.Group,
		Category:          r.Category,
		ProposedRule:      r.ProposedRule,
		Confidence:        r.Confidence,
		ConfidenceReasons: r.ConfidenceReasons,
		ConfidenceLimits:  r.ConfidenceLimits,
		Coverage:          r.Coverage,
		Evidence:          r.Evidence,
		Baseline:          plBaselineToDTO(r.Baseline),
		Policy:            r.Policy,
		PolicyHash:        r.PolicyHash,
		GeneratedAt:       r.GeneratedAt,
		StaleReasons:      stale,
		TargetRuleID:      r.TargetRuleID,
		AcceptedAt:        r.AcceptedAt,
		AcceptedBy:        r.AcceptedBy,
		RejectedAt:        r.RejectedAt,
		RejectedBy:        r.RejectedBy,
		RejectReason:      r.RejectReason,
	}
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// apiPolicyLearningStatus (GET, viewer): the factual operational status.
func apiPolicyLearningStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	st, _ := policyLearnSnapshotState()
	resp := map[string]any{
		"enabled":       st.Enabled,
		"scope":         "node-local",
		"scope_note":    plScopeNote,
		"advisory_note": plAdvisoryNote,
	}
	if msg := policyLearnGetRunErr(); msg != "" {
		resp["runtime_error"] = msg
	}
	eng := policyLearnEngine.Load()
	if eng == nil {
		resp["learning_active"] = false
		jsonOK(w, resp)
		return
	}
	resp["learning_active"] = eng.LearningActive()
	if act, ok := eng.ActiveSession(); ok {
		dto := plSessionToDTO(eng, act)
		resp["active_session"] = dto
	}
	stats := eng.Snapshot()
	resp["engine"] = map[string]any{
		"sessions":         stats.Sessions,
		"recommendations":  stats.Recommendations,
		"read_only":        stats.ReadOnly,
		"schema_version":   stats.SchemaVersion,
		"max_retained":     stats.MaxRetained,
		"max_duration_sec": int64(stats.MaxDuration.Seconds()),
	}
	obs := eng.ObservationStats()
	resp["observation"] = plTransportDTO{
		Accepted: obs.Accepted, Dropped: obs.Dropped, Rejected: obs.Rejected,
		ConsumerPanics: obs.ConsumerPanics, GroupsTruncated: obs.GroupsTruncated,
		Degraded: obs.Dropped > 0 || obs.Rejected > 0 || obs.ConsumerPanics > 0,
	}
	resp["recommendation_policy"] = eng.CurrentRecommendationPolicy() // read-only transparency (thresholds NOT editable in M5A)
	resp["recommendation_policy_hash"] = eng.RecommendationPolicyHash()
	resp["guardrails_hash"] = eng.GuardrailsHash()
	jsonOK(w, resp)
}

// apiPolicyLearningConfig — GET (viewer): governed configuration; PUT (admin):
// enable/disable + the recommendable-category guardrail. Deterministic 409s:
// disabling or changing the guardrail while a Learning session is active is
// refused — the operator must explicitly Complete or Cancel first (§3, §5).
func apiPolicyLearningConfig(w http.ResponseWriter, r *http.Request) { //nolint:cyclop,funlen,gocognit,nestif // method-switch handler: transition fencing is intentionally explicit
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		st, saved := policyLearnSnapshotState()
		resp := map[string]any{
			"enabled":                  st.Enabled,
			"governed":                 saved,
			"recommendable_categories": policyLearnEffectiveCategories(st),
			"categories_are_seed":      st.Categories == nil,
			"seed_source":              "embedded business-category set",
			"thresholds_editable":      false, // M5A: decision policy is read-only
			"advisory_note":            plAdvisoryNote,
			"scope":                    "node-local",
		}
		if eng := policyLearnEngine.Load(); eng != nil {
			resp["recommendation_policy"] = eng.CurrentRecommendationPolicy()
			resp["recommendation_policy_hash"] = eng.RecommendationPolicyHash()
			resp["guardrails_hash"] = eng.GuardrailsHash()
		}
		jsonOK(w, resp)

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			Enabled                 *bool     `json:"enabled"`
			RecommendableCategories *[]string `json:"recommendable_categories"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		policyLearnAdminMu.Lock()
		defer policyLearnAdminMu.Unlock()

		cur, _ := policyLearnSnapshotState()
		target := cur
		if body.Enabled != nil {
			target.Enabled = *body.Enabled
		}
		if body.RecommendableCategories != nil {
			// Deterministic canonicalization; an explicitly EMPTY list is a
			// legitimate fail-closed governance choice (nothing recommendable).
			target.Categories = policyLearnCanonicalCategories(*body.RecommendableCategories)
		}
		catsChanged := policylearn.GuardrailsHashForCategories(policyLearnEffectiveCategories(target)) !=
			policylearn.GuardrailsHashForCategories(policyLearnEffectiveCategories(cur))

		// State fencing (§3, §5): a Learning session pins its baseline to the
		// current guardrails and must be explicitly completed or cancelled
		// before the feature is disabled or the guardrail moves.
		if eng := policyLearnEngine.Load(); eng != nil { //nolint:nestif // active-session fencing decision tree is intentionally explicit (§3, §5)
			if _, active := eng.ActiveSession(); active {
				if !target.Enabled {
					http.Error(w, "cannot disable policy learning: "+errPolicyLearnActiveSession.Error(), http.StatusConflict)
					return
				}
				if catsChanged {
					http.Error(w, "cannot change recommendable categories: "+errPolicyLearnActiveSession.Error(), http.StatusConflict)
					return
				}
			}
		}

		// Persist-before-apply (autoexclude precedent): the durable write is the
		// only fallible step; on failure runtime and disk still agree on the old
		// state. The apply runs inside the save's lock so a concurrent omnibus
		// save cannot revert the just-persisted target.
		applied := false
		if err := saveAdminSettingsWithOverrides(adminSaveOverrides{
			policyLearning: &target,
			applyOnSuccess: func() {
				applied = true
				policyLearnSetState(target, true)
				policyLearnApplyDesiredLocked(target)
			},
		}); err != nil {
			logger.Printf("policy learning: config persist failed, runtime unchanged: %v", err)
			http.Error(w, "failed to persist policy learning config", http.StatusInternalServerError)
			return
		}
		if !applied {
			// No settings path configured (memory-only/test posture): the save
			// was a no-op success and never ran applyOnSuccess — apply directly
			// so a reported success is never a silent runtime no-op.
			policyLearnSetState(target, true)
			policyLearnApplyDesiredLocked(target)
		}

		if body.Enabled != nil && cur.Enabled != target.Enabled {
			if target.Enabled {
				auditEvent(r, "policy_learning.enable", "policy-learning", "enabled policy learning mode (advisory; observation stays idle until a session starts)")
			} else {
				auditEvent(r, "policy_learning.disable", "policy-learning", "disabled policy learning mode (node-local state retained on disk)")
			}
		}
		if catsChanged {
			auditEventDiff(r, "policy_learning.guardrail", "recommendable-categories",
				"updated the recommendable-category guardrail (existing recommendations become stale)",
				policyLearnEffectiveCategories(cur), policyLearnEffectiveCategories(target))
		}

		resp := map[string]any{
			"enabled":                  target.Enabled,
			"recommendable_categories": policyLearnEffectiveCategories(target),
		}
		if msg := policyLearnGetRunErr(); msg != "" {
			resp["runtime_error"] = msg
		}
		jsonOK(w, resp)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiPolicyLearningSession (POST, operator): the Start/Complete/Cancel state
// machine. Invalid transitions are deterministic 409s from the engine's
// one-active-session invariant.
func apiPolicyLearningSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	policyLearnAdminMu.Lock()
	defer policyLearnAdminMu.Unlock()
	eng := policyLearnEngine.Load()
	if eng == nil {
		if policyLearnGetRunErr() != "" {
			http.Error(w, errPolicyLearnUnavailable.Error(), http.StatusServiceUnavailable)
			return
		}
		http.Error(w, errPolicyLearnDisabled.Error(), http.StatusConflict)
		return
	}
	actor := auditActor(r)
	var (
		sess policylearn.Session
		err  error
	)
	switch body.Action {
	case "start":
		sess, err = eng.StartSession(actor)
	case "complete":
		sess, err = eng.StopSession(actor)
	case "cancel":
		sess, err = eng.CancelSession(actor)
	default:
		http.Error(w, "action must be one of start|complete|cancel", http.StatusBadRequest)
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, policylearn.ErrActiveSession),
			errors.Is(err, policylearn.ErrNoActiveSession),
			errors.Is(err, policylearn.ErrStoreReadOnly):
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	auditEvent(r, "policy_learning.session."+body.Action, sess.ID,
		"policy learning session "+body.Action+" (state: "+sess.State+")")
	jsonOK(w, plSessionToDTO(eng, sess))
}

// apiPolicyLearningSessions (GET, viewer): retained session listing (?id= for
// one).
func apiPolicyLearningSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	eng := policyLearnEngine.Load()
	if eng == nil {
		jsonOK(w, map[string]any{"sessions": []plSessionDTO{}, "enabled": false, "scope": "node-local"})
		return
	}
	// Index-based ranges: the session/recommendation DTO sources are large
	// structs (rangeValCopy convention).
	if id := r.URL.Query().Get("id"); id != "" {
		list := eng.Sessions()
		for i := range list {
			if list[i].ID == id {
				jsonOK(w, plSessionToDTO(eng, list[i]))
				return
			}
		}
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	list := eng.Sessions()
	out := make([]plSessionDTO, 0, len(list))
	for i := range list {
		out = append(out, plSessionToDTO(eng, list[i]))
	}
	jsonOK(w, map[string]any{"sessions": out, "enabled": true, "scope": "node-local"})
}

// apiPolicyLearningRecommendations — GET (viewer): recommendation listing
// (?id= for one), staleness evaluated server-side at read time (§10);
// POST (M5B): the accept|reject decision — accept is ADMIN-only inside the
// branch (reject is operator+); route metadata declares the operator floor
// with the stricter accept branch documented (the apiIdPRouter / C4
// role-divergence convention).
func apiPolicyLearningRecommendations(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		eng := policyLearnEngine.Load()
		if eng == nil {
			jsonOK(w, map[string]any{"recommendations": []plRecommendationDTO{}, "enabled": false, "scope": "node-local"})
			return
		}
		cur := policyLearnStaleInputs(eng)
		if id := r.URL.Query().Get("id"); id != "" {
			list := eng.Recommendations()
			for i := range list { // index-based: Recommendation is a large struct (rangeValCopy)
				if list[i].ID == id {
					jsonOK(w, plRecommendationToDTO(list[i], cur))
					return
				}
			}
			http.Error(w, "recommendation not found", http.StatusNotFound)
			return
		}
		list := eng.Recommendations()
		out := make([]plRecommendationDTO, 0, len(list))
		for i := range list {
			out = append(out, plRecommendationToDTO(list[i], cur))
		}
		ver, _ := effectivePolicyVersion()
		jsonOK(w, map[string]any{
			"recommendations": out, "enabled": true, "scope": "node-local",
			// M5B accept prerequisites, exposed as facts so the GUI can gate
			// its controls (the server remains the authority via 409).
			"draft_mode_armed": requireCommitEnabled(),
			"policy_version":   ver,
		})

	case http.MethodPost:
		apiPolicyLearningDecision(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiPolicyLearningDecision is the M5B accept|reject POST. No policy fields
// are accepted from the client — only the recommendation identity, the action,
// the version fence (accept), and a bounded reject reason.
func apiPolicyLearningDecision(w http.ResponseWriter, r *http.Request) { //nolint:cyclop,funlen // deterministic per-state refusal table is intentionally explicit
	if !requireRole(w, r, RoleOperator) { // floor; accept re-checks admin below
		return
	}
	var body struct {
		ID        string `json:"id"`
		Action    string `json:"action"`
		IfVersion *int64 `json:"if_version"` // accept: REQUIRED optimistic fence
		Reason    string `json:"reason"`     // reject only; bounded server-side
	}
	if err := decodeJSON(r, &body); err != nil || body.ID == "" {
		http.Error(w, "id and action required", http.StatusBadRequest)
		return
	}
	policyLearnAdminMu.Lock()
	defer policyLearnAdminMu.Unlock()
	eng := policyLearnEngine.Load()
	if eng == nil {
		http.Error(w, errPolicyLearnDisabled.Error(), http.StatusConflict)
		return
	}
	actor := auditActor(r)

	switch body.Action {
	case "accept":
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		if body.IfVersion == nil {
			http.Error(w, "if_version required for accept (read it from the recommendations listing)", http.StatusBadRequest)
			return
		}
		out, err := plAcceptRecommendation(eng, body.ID, *body.IfVersion, actor)
		if err != nil {
			auditEvent(r, "policy_learning.accept.refused", body.ID, "accept refused: "+err.Error())
			plDecisionError(w, err)
			return
		}
		rec := out.Recommendation
		auditEvent(r, "policy_learning.accept", rec.ID,
			fmt.Sprintf("accepted to DRAFT: session=%s group=%s category=%s target_rule=%s idempotent=%t (disabled rule in Policy Draft; enforcement unchanged)",
				rec.SessionID, rec.Group, rec.Category, out.RuleID, out.AlreadyDone))
		jsonOK(w, map[string]any{
			"recommendation": plRecommendationToDTO(rec, policyLearnStaleInputs(eng)),
			"rule_id":        out.RuleID,
			"already_done":   out.AlreadyDone,
			"note":           "Created a DISABLED rule in the Policy Draft. Enforcement is unchanged until the draft is reviewed and committed.",
		})

	case "reject":
		rec, err := eng.Reject(body.ID, actor, body.Reason)
		if err != nil {
			plDecisionError(w, err)
			return
		}
		auditEvent(r, "policy_learning.reject", rec.ID,
			fmt.Sprintf("rejected: session=%s group=%s category=%s reason=%q",
				rec.SessionID, rec.Group, rec.Category, rec.RejectReason))
		jsonOK(w, map[string]any{"recommendation": plRecommendationToDTO(rec, policyLearnStaleInputs(eng))})

	default:
		http.Error(w, "action must be accept or reject", http.StatusBadRequest)
	}
}

// plDecisionError maps decision errors to deterministic statuses.
func plDecisionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, policylearn.ErrRecommendationNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, policylearn.ErrRecommendationSuperseded),
		errors.Is(err, policylearn.ErrRecommendationAccepted),
		errors.Is(err, policylearn.ErrRecommendationRejected),
		errors.Is(err, policylearn.ErrRecommendationAccepting),
		errors.Is(err, policylearn.ErrStoreReadOnly),
		errors.Is(err, policylearn.ErrAcceptInvalidatedByLateLoss),
		errors.Is(err, errAcceptRequiresDraftMode),
		errors.Is(err, errAcceptVersionConflict),
		errors.Is(err, errAcceptIntegrityConflict),
		errors.Is(err, errStaleRecommendation):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// apiPolicyLearningGenerate (POST, operator): deterministic recommendation
// generation from a COMPLETED session (M4 engine contract; every refusal is a
// deterministic status).
func apiPolicyLearningGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	var body struct {
		SessionID string `json:"session_id"`
	}
	if err := decodeJSON(r, &body); err != nil || body.SessionID == "" {
		http.Error(w, "session_id required", http.StatusBadRequest)
		return
	}
	policyLearnAdminMu.Lock()
	defer policyLearnAdminMu.Unlock()
	eng := policyLearnEngine.Load()
	if eng == nil {
		http.Error(w, errPolicyLearnDisabled.Error(), http.StatusConflict)
		return
	}
	res, err := eng.GenerateRecommendations(body.SessionID)
	if err != nil {
		switch {
		case errors.Is(err, policylearn.ErrSessionNotFound):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, policylearn.ErrSessionNotCompleted),
			errors.Is(err, policylearn.ErrGuardrailsChanged),
			errors.Is(err, policylearn.ErrNoGuardrailBaseline),
			errors.Is(err, policylearn.ErrSubjectKeyChanged),
			errors.Is(err, policylearn.ErrStoreReadOnly):
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	auditEvent(r, "policy_learning.recommendations.generate", body.SessionID,
		"generated policy-learning recommendations (advisory; no enforcement change)")
	cur := policyLearnStaleInputs(eng)
	out := make([]plRecommendationDTO, 0, len(res.Recommendations))
	for i := range res.Recommendations { // index-based: large struct (rangeValCopy)
		out = append(out, plRecommendationToDTO(res.Recommendations[i], cur))
	}
	jsonOK(w, map[string]any{
		"session_id":                  res.SessionID,
		"recommendations":             out,
		"eligible_cells":              res.EligibleCells,
		"truncated_cells":             res.TruncatedCells,
		"skipped_synthetic_scope":     res.SkippedSyntheticScope,
		"skipped_category":            res.SkippedCategory,
		"skipped_no_allowed_evidence": res.SkippedNoAllowedEvidence,
		"superseded":                  res.SupersededCount,
		"unchanged":                   res.UnchangedCount,
	})
}
