// Release Dispatch — P1.6 Slice c (CP-side orchestration wiring).
//
// DispatchService is the CP-side wrapper that ties the PURE planner (P1.6a) to
// the execution wrapper (P1.6b/c-0) and the rest of the Control Plane: the audit
// ring (release.dispatch + release.dispatch.outcome), the alert webhook hook,
// and the real HTTP transport to the EXISTING agent /v1 surface.
//
// It owns an AGENT-KEYED single-flight registry: exactly one DispatchExecutor
// per agent identity, so the executor's per-instance single-flight becomes a
// per-AGENT guarantee regardless of how many Dispatch calls arrive. A second
// dispatch to an agent already mid-op is rejected (errDispatchInFlight) and
// audited, never queued or duplicated.
//
// The agent stays release-agnostic: only image_ref + existing apply flags cross
// the wire (no upgrades.check, no tags, no fallback). Verify-by-digest remains
// the only success gate, and the CP idempotency key is generated ONCE per
// dispatch op and threaded through the plan so the executor honors it (P1.6c-0).
//
// Scope (roadmap/D1.6d-P1.6-release-dispatch-plan.md — Slice c): service wrapper,
// agent registry, Resume/re-poll, audit + alert wiring, real transport. NO GUI,
// NO agent change, NO new agent endpoint, NO legacy-updater work, NO auto-update,
// NO rollback-candidate logic.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// AgentEndpoint identifies one maintenance agent and how to reach it. Key is the
// stable agent identity used as the single-flight registry key; BaseURL + Client
// address its existing /v1 surface (TLS/mTLS/auth wiring lives on the Client).
type AgentEndpoint struct {
	Key     string
	BaseURL string
	Client  *http.Client
}

// DispatchResumeContext is the explicit, persistable record needed to re-poll an
// in-flight dispatch op after a CP restart — independent of any in-memory plan.
// OpID is the resume AUTHORITY; TargetPinnedRef is the verify-by-digest target;
// IdempotencyKey is ONLY apply-time dedupe / audit-correlation metadata and is
// never used to decide what to resume. The caller persists it from a
// DispatchReport via DispatchReport.ResumeContext(agentID).
type DispatchResumeContext struct {
	AgentID         string
	OpID            string
	ReleaseID       string
	VersionID       string
	Severity        Severity
	TargetPinnedRef string
	ImageRef        string
	IdempotencyKey  string
}

// auditPlan builds the identity-only plan used to feed the executor's audit hook
// during a resume. It is NEVER the resume authority (rc.OpID) or the verify
// target (rc.TargetPinnedRef) — only a carrier for the audit event's fields.
func (rc DispatchResumeContext) auditPlan() *DispatchPlan {
	return &DispatchPlan{
		Outcome:   OutcomePlan,
		ReleaseID: rc.ReleaseID,
		VersionID: rc.VersionID,
		Severity:  rc.Severity,
		PinnedRef: rc.TargetPinnedRef,
		ImageRef:  rc.ImageRef,
		Apply:     UpgradeApplyRequest{ImageRef: rc.ImageRef, IdempotencyKey: rc.IdempotencyKey},
	}
}

// DispatchReport is the service-level result of one Dispatch/Resume. It carries
// the planning outcome, the execution terminal (when one was reached), and the
// release identity — enough for the caller to render a result and to build a
// ResumeHandle for later recovery.
type DispatchReport struct {
	Outcome           DispatchOutcome  // from planning: refused | plan | already_current
	RefusedKind       RefusedKind      // set iff Outcome == OutcomeRefused
	Terminal          DispatchTerminal // set iff an execution terminal was reached
	OpID              string
	IdempotencyKey    string
	Verified          bool
	Detail            string
	ReleaseID         string
	VersionID         string
	Severity          Severity
	ImageRef          string
	PinnedRef         string
	PreBackup         bool
	RollbackOnFailure bool
}

// ResumeContext extracts the persistable record needed to re-poll this op later
// against the given agent identity.
func (r *DispatchReport) ResumeContext(agentID string) DispatchResumeContext {
	return DispatchResumeContext{
		AgentID:         agentID,
		OpID:            r.OpID,
		ReleaseID:       r.ReleaseID,
		VersionID:       r.VersionID,
		Severity:        r.Severity,
		TargetPinnedRef: r.PinnedRef,
		ImageRef:        r.ImageRef,
		IdempotencyKey:  r.IdempotencyKey,
	}
}

// agentReg is one registry entry: a long-lived executor (the single-flight owner
// for this agent) plus the client used for the pre-plan running read, and the
// endpoint it was built from (so a rebind can be detected).
type agentReg struct {
	ep     AgentEndpoint
	client AgentClient
	exec   *DispatchExecutor
}

// DispatchService orchestrates dispatch against a pinned catalog snapshot and a
// set of agents. Construct with NewDispatchService; the hooks (audit/alert/
// transport/op-id/clock) default to the production wiring and are injectable for
// tests.
type DispatchService struct {
	planner   *Dispatcher
	cfg       DispatchConfig
	newClient func(ep AgentEndpoint) (AgentClient, error)
	newOpID   func() string
	auditSink func(AuditEntry)
	alert     func(event string, p AlertPayload)
	now       func() time.Time

	mu sync.Mutex
	// execs is bounded by the set of CONFIGURED agent keys: the API layer only
	// ever passes endpoints for known agents (unknown keys are rejected before
	// reaching the service), so this map cannot grow without bound. Entries are
	// rebuilt in place on an endpoint rebind, never accumulated per address.
	execs map[string]*agentReg
}

// NewDispatchService validates the deployment binding (proxy_repo / rewrite) and
// returns a service wired to the production audit ring, alert webhooks, and real
// agent HTTP transport.
func NewDispatchService(provider catalogSnapshotProvider, cfg DispatchConfig) (*DispatchService, error) {
	planner, err := NewDispatcher(provider, cfg)
	if err != nil {
		return nil, err
	}
	return &DispatchService{
		planner:   planner,
		cfg:       cfg,
		newClient: defaultAgentClientFactory,
		newOpID:   newDispatchOpID,
		auditSink: auditAdd,
		alert:     fireAlert,
		now:       time.Now,
		execs:     make(map[string]*agentReg),
	}, nil
}

func defaultAgentClientFactory(ep AgentEndpoint) (AgentClient, error) {
	return NewHTTPAgentClient(ep.BaseURL, ep.Client)
}

// catalog returns the currently-published immutable catalog snapshot (nil ⇒ no
// catalog), for the read-only API surface.
func (s *DispatchService) catalog() *Catalog { return s.planner.provider.GetCatalog() }

// Current reads the agent's running_image.repo_digests and maps it through the
// pinned catalog (reverse repo-rewrite + exact Lookup, the SAME normalization as
// the planner) to the running release. An unmatched/empty array yields
// {Known:false} — a normal state, NOT an error. Current detection is derived
// EXCLUSIVELY from running_image.repo_digests (never upgrades.check).
func (s *DispatchService) Current(ctx context.Context, ep AgentEndpoint) (CurrentView, error) {
	cat := s.catalog()
	if cat == nil {
		return CurrentView{}, errDispatchNoCatalog
	}
	reg, err := s.registryFor(ep)
	if err != nil {
		return CurrentView{}, err
	}
	running, err := reg.client.RunningDigests(ctx)
	if err != nil {
		return CurrentView{}, err
	}
	for _, ref := range running {
		if v := cat.Current(s.cfg.reverse(ref)); v.Known {
			return v, nil
		}
	}
	return CurrentView{}, nil // Unknown — normal
}

// registryFor returns the single executor bound to ep.Key, creating it (and its
// agent client) on first use. ONE executor per agent ⇒ single-flight per agent.
// If the endpoint's transport changed (rebind — agent re-addressed or re-TLS'd)
// the client+executor are rebuilt, UNLESS an op is currently in flight: a live
// op must finish on its original client, so the rebind is deferred until it
// drains (the next call rebinds).
func (s *DispatchService) registryFor(ep AgentEndpoint) (*agentReg, error) {
	if ep.Key == "" {
		return nil, errors.New("dispatch: agent endpoint needs a key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if reg, ok := s.execs[ep.Key]; ok {
		if (reg.ep.BaseURL == ep.BaseURL && reg.ep.Client == ep.Client) || reg.exec.inFlight() {
			return reg, nil // unchanged, or changed-but-busy (rebind after it drains)
		}
		// fall through to rebuild for the new endpoint
	}
	client, err := s.newClient(ep)
	if err != nil {
		return nil, err
	}
	reg := &agentReg{ep: ep, client: client, exec: NewDispatchExecutor(client, s.cfg, nil)}
	s.execs[ep.Key] = reg
	return reg, nil
}

// Dispatch plans target against the pinned catalog snapshot, then executes it
// against ep's agent under per-agent single-flight. Refusals, already-current,
// and terminal outcomes are all audited; a FAILED_NEEDS_ATTN terminal fires the
// alert hook. The returned error mirrors the executor (errDispatchInFlight on a
// concurrent dispatch, errStaleAlreadyCurrent on a drifted no-op).
// onApplied observers fire once, at the durable-record point (op_id known, before
// the watch), with the op_id and the resume context — the API layer uses this to
// record the op and release the 202 response.
func (s *DispatchService) Dispatch(ctx context.Context, actor string, ep AgentEndpoint, target DispatchTarget, opts DispatchOptions, onApplied ...func(opID string, rc DispatchResumeContext)) (*DispatchReport, error) {
	reg, err := s.registryFor(ep)
	if err != nil {
		return nil, fmt.Errorf("dispatch: agent %q: %w", ep.Key, err)
	}

	// Preflight running read feeds the planner's already-current detection. A
	// failure refuses before any apply (design E4, retryable) and is audited.
	running, rerr := reg.client.RunningDigests(ctx)
	if rerr != nil {
		rep := &DispatchReport{Outcome: OutcomeRefused, Detail: "preflight_read_failed: " + rerr.Error()}
		s.auditDispatch(actor, ep, target, rep)
		return rep, fmt.Errorf("dispatch: preflight running read: %w", rerr)
	}

	plan := s.planner.Plan(target, running, opts)

	// Stable idempotency key per dispatch op: generated ONCE here, threaded into
	// the plan so the executor honors it (P1.6c-0) and reuses it across retries.
	if plan.Outcome == OutcomePlan && plan.Apply.IdempotencyKey == "" {
		plan.Apply.IdempotencyKey = "rel-" + plan.ReleaseID + "-" + s.newOpID()
	}

	if plan.Refused() {
		rep := reportFromRefusal(plan)
		s.auditDispatch(actor, ep, target, rep)
		return rep, plan.Reason
	}

	// The release.dispatch audit is written from the onApplied hook — as soon as
	// the agent returns an op_id and BEFORE the blocking watch — so a CP crash
	// mid-watch still leaves a durable op_id/key record for the resume path.
	applied := false
	res, eerr := reg.exec.Execute(ctx, plan, func(opID string) error {
		applied = true
		early := reportFromPlan(plan)
		early.OpID = opID
		// auditAdd is in-memory + best-effort file persistence, so this does not
		// fail today; the error return honors the executor's durable-record
		// contract for a future persistent recorder.
		s.auditDispatch(actor, ep, target, early)
		rc := resumeContextFor(ep.Key, plan, opID)
		for _, ob := range onApplied {
			ob(opID, rc)
		}
		return nil
	})
	rep := reportFromResult(plan, res)
	if errors.Is(eerr, errDispatchInFlight) {
		// Concurrent dispatch on the same agent — rejected before any apply.
		s.auditDispatch(actor, ep, target, rep)
		return rep, eerr
	}
	if !applied {
		// already_current / stale: no apply happened, so the onApplied hook did
		// not fire — record the dispatch decision here.
		s.auditDispatch(actor, ep, target, rep)
	}
	s.auditOutcome(actor, ep, target, rep)
	// Stale already-current is a re-plan signal, not an incident — audit it but
	// do NOT page. Genuine FAILED_NEEDS_ATTN terminals still alert.
	if !errors.Is(eerr, errStaleAlreadyCurrent) {
		s.maybeAlert(actor, ep, rep)
	}
	return rep, eerr
}

// resumeContextFor builds the persistable resume record at apply time.
func resumeContextFor(agentID string, plan *DispatchPlan, opID string) DispatchResumeContext {
	return DispatchResumeContext{
		AgentID:         agentID,
		OpID:            opID,
		ReleaseID:       plan.ReleaseID,
		VersionID:       plan.VersionID,
		Severity:        plan.Severity,
		TargetPinnedRef: plan.PinnedRef,
		ImageRef:        plan.ImageRef,
		IdempotencyKey:  plan.Apply.IdempotencyKey,
	}
}

// Resume re-polls an existing op (from a prior Dispatch whose watch was
// interrupted) to a terminal state WITHOUT a fresh apply, under the same
// per-agent single-flight. Verify-by-digest stays the success gate; the outcome
// is audited and a FAILED_NEEDS_ATTN terminal alerts.
func (s *DispatchService) Resume(ctx context.Context, actor string, ep AgentEndpoint, rc DispatchResumeContext) (*DispatchReport, error) {
	if rc.OpID == "" {
		return nil, errors.New("dispatch: resume needs an op_id")
	}
	reg, err := s.registryFor(ep)
	if err != nil {
		return nil, fmt.Errorf("dispatch: agent %q: %w", ep.Key, err)
	}

	res, eerr := reg.exec.Resume(ctx, rc)
	rep := reportFromResume(rc, res)
	target := DispatchTarget{ReleaseID: rc.ReleaseID}
	if errors.Is(eerr, errDispatchInFlight) {
		s.auditDispatch(actor, ep, target, rep)
		return rep, eerr
	}
	s.auditOutcome(actor, ep, target, rep)
	s.maybeAlert(actor, ep, rep)
	return rep, eerr
}

// ─── report builders ─────────────────────────────────────────────────────────

// reportFromResume builds a report from the resume context + executor result.
// Identity comes from rc (op_id-driven), terminal/verified from res.
func reportFromResume(rc DispatchResumeContext, res *DispatchResult) *DispatchReport {
	rep := &DispatchReport{
		Outcome:        OutcomePlan,
		OpID:           rc.OpID,
		ReleaseID:      rc.ReleaseID,
		VersionID:      rc.VersionID,
		Severity:       rc.Severity,
		ImageRef:       rc.ImageRef,
		PinnedRef:      rc.TargetPinnedRef,
		IdempotencyKey: rc.IdempotencyKey,
	}
	if res == nil {
		rep.Detail = "dispatch_in_flight"
		return rep
	}
	rep.Terminal = res.Terminal
	rep.Verified = res.Verified
	rep.Detail = res.Detail
	return rep
}

func reportFromRefusal(plan *DispatchPlan) *DispatchReport {
	detail := string(plan.Kind)
	if plan.Reason != nil {
		detail = plan.Reason.Error()
	}
	return &DispatchReport{
		Outcome:     OutcomeRefused,
		RefusedKind: plan.Kind,
		ReleaseID:   plan.ReleaseID,
		Detail:      detail,
	}
}

// reportFromPlan builds the plan-derived report (identity + apply flags) with no
// terminal/op_id yet — the shape used for the early release.dispatch audit.
func reportFromPlan(plan *DispatchPlan) *DispatchReport {
	return &DispatchReport{
		Outcome:           plan.Outcome,
		ReleaseID:         plan.ReleaseID,
		VersionID:         plan.VersionID,
		Severity:          plan.Severity,
		ImageRef:          plan.ImageRef,
		PinnedRef:         plan.PinnedRef,
		IdempotencyKey:    plan.Apply.IdempotencyKey,
		PreBackup:         plan.Apply.PreBackup,
		RollbackOnFailure: plan.Apply.RollbackOnFailure,
	}
}

func reportFromResult(plan *DispatchPlan, res *DispatchResult) *DispatchReport {
	rep := reportFromPlan(plan)
	if res == nil {
		rep.Detail = "dispatch_in_flight"
		return rep
	}
	rep.Terminal = res.Terminal
	rep.OpID = res.OpID
	rep.Verified = res.Verified
	rep.Detail = res.Detail
	if res.IdempotencyKey != "" {
		rep.IdempotencyKey = res.IdempotencyKey
	}
	return rep
}

// ─── audit + alert wiring ────────────────────────────────────────────────────

func (s *DispatchService) entry(actor, action, object, detail string) AuditEntry {
	now := s.now()
	return AuditEntry{
		TS:     now.UnixMilli(),
		Time:   now.Format("2006-01-02 15:04:05"),
		Actor:  actor,
		Action: action,
		Object: object,
		Detail: detail,
	}
}

// auditDispatch records the release.dispatch decision (target + what was sent or
// why it was refused). op_id is included once the executor has returned it.
func (s *DispatchService) auditDispatch(actor string, ep AgentEndpoint, target DispatchTarget, rep *DispatchReport) {
	detail := fmt.Sprintf("agent=%s target=%s outcome=%s severity=%s image_ref=%s op_id=%s key=%s pre_backup=%v rollback=%v",
		sanitizeLog(ep.Key), sanitizeLog(targetString(target)), rep.Outcome, rep.Severity,
		sanitizeLog(rep.ImageRef), sanitizeLog(rep.OpID), sanitizeLog(rep.IdempotencyKey),
		rep.PreBackup, rep.RollbackOnFailure)
	if rep.RefusedKind != RefusedNone {
		detail += " refused=" + string(rep.RefusedKind)
	}
	if rep.Detail != "" {
		detail += " detail=" + sanitizeLog(rep.Detail)
	}
	s.auditSink(s.entry(actor, "release.dispatch", auditObject(rep, target), detail))
}

// auditOutcome records the release.dispatch.outcome terminal state.
func (s *DispatchService) auditOutcome(actor string, ep AgentEndpoint, target DispatchTarget, rep *DispatchReport) {
	detail := fmt.Sprintf("agent=%s terminal=%s op_id=%s key=%s verified=%v detail=%s",
		sanitizeLog(ep.Key), rep.Terminal, sanitizeLog(rep.OpID), sanitizeLog(rep.IdempotencyKey),
		rep.Verified, sanitizeLog(rep.Detail))
	s.auditSink(s.entry(actor, "release.dispatch.outcome", auditObject(rep, target), detail))
}

// maybeAlert fires the (minimal) alert hook ONLY for a FAILED_NEEDS_ATTN terminal
// — the one state that requires operator intervention.
func (s *DispatchService) maybeAlert(actor string, ep AgentEndpoint, rep *DispatchReport) {
	if rep.Terminal != TerminalFailedNeedsAttn {
		return
	}
	s.alert("release_dispatch_attention", AlertPayload{
		Actor:  actor,
		Detail: fmt.Sprintf("agent=%s release=%s op=%s terminal=%s %s", ep.Key, rep.ReleaseID, rep.OpID, rep.Terminal, rep.Detail),
		Source: "release",
	})
}

func targetString(t DispatchTarget) string {
	switch {
	case t.ReleaseID != "":
		return "release:" + t.ReleaseID
	case t.Channel != "":
		return "channel:" + string(t.Channel)
	default:
		return "none"
	}
}

func auditObject(rep *DispatchReport, t DispatchTarget) string {
	if rep.ReleaseID != "" {
		return rep.ReleaseID
	}
	return targetString(t)
}
