// Release Dispatch — P1.6 Slice b (CP-side execution wrapper).
//
// DispatchExecutor takes a FROZEN DispatchPlan (P1.6a), generates the CP
// idempotency key, POSTs the EXISTING upgrades.apply, polls the EXISTING agent
// op to a terminal state, re-reads running_image.repo_digests, and classifies a
// terminal DispatchTerminal by VERIFYING THE RUNNING DIGEST itself (never the
// agent's self-report). It is single-flight per agent and emits audit events
// via a hook.
//
// The agent is untouched and stays release-agnostic: only image_ref + existing
// apply flags cross the wire (no upgrades.check, no tags, no fallback). The
// transport is behind the AgentClient seam so the orchestration is fully
// testable with a fake; httpAgentClient is the concrete adapter over the
// existing /v1 endpoints.
//
// Scope (roadmap/D1.6d-P1.6-release-dispatch-plan.md — Slice b): execution +
// verify-by-digest + terminal classification + audit structs/hooks. NO GUI, NO
// auto-update, NO rollback-candidate computation, NO legacy-updater change, NO
// new agent endpoint.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// Agent op states (mirrored as constants — no agent import).
const (
	agentStateSucceeded = "succeeded"
	agentStateFailed    = "failed"
	agentStateCancelled = "cancelled"
)

// DispatchTerminal is the terminal state of an execution (design §7).
type DispatchTerminal string

const (
	TerminalSucceeded        DispatchTerminal = "succeeded"
	TerminalAlreadyCurrent   DispatchTerminal = "already_current"
	TerminalFailedRolledBack DispatchTerminal = "failed_rolled_back"
	TerminalFailedNeedsAttn  DispatchTerminal = "failed_needs_attn"
)

var errDispatchInFlight = errors.New("dispatch: an execution is already in flight")

// detailAnchorReadFailed prefixes the DispatchResult.Detail when the pre-apply
// anchor read of /v1/status fails. The API layer matches this prefix to map the
// outcome to 503 (agent status unavailable / retryable), consistent with a
// preflight read failure — see respondPreApply.
const detailAnchorReadFailed = "anchor_read_failed"

// detailAgentUnreachableAfterUpdate prefixes the Detail when an apply the agent
// reported as SUCCEEDED is immediately followed by a TRANSPORT failure on the
// post-verify /v1/status read — while the pre-apply anchor read had succeeded.
// That differential is a HINT (not proof) that the recreate dropped the CP↔agent
// socket. It is a HEURISTIC: a benign blip in the post-recreate settling window
// can also produce it, and a slow-hanging drop surfacing as context.DeadlineExceeded
// (non-transient per isTransientAgentErr) falls back to the generic detail.
//
// REACHABILITY (important): for a CP-LOCAL agent — the common single-node case,
// where CULVERT_MAINT_AGENT_URL is a unix socket mounted into the SAME proxy
// container that runs this dispatcher — a real recreate SIGKILLs this process
// mid-Execute, so classifyTerminal never runs; recovery goes through Resume()
// (which reports the generic post_verify_read_failed). This distinct label
// therefore mostly fires for a REMOTE agent (network transport, dispatcher not
// co-recreated) or when the restart did not recreate this container. The durable
// prevention is the structural override-carry (the socket survives by
// construction); the more reachable proactive signal is the agent's
// compose_override_configured flag (op params / /v1/status), which a future GUI
// consumer should surface pre-dispatch rather than relying on this post-facto
// label. Either way the terminal stays FAILED_NEEDS_ATTN, so the operator is
// alerted regardless.
const detailAgentUnreachableAfterUpdate = "agent_unreachable_after_update"

// errStaleAlreadyCurrent is returned when a plan's already-current determination
// (computed from plan-time running digests by P1.6a) no longer holds against a
// FRESH status read at execute time — the node drifted off the target between
// planning and execution. The caller MUST re-plan; the executor refuses to
// silently report success. errors.Is detects it; the DispatchResult carries the
// audited detail.
var errStaleAlreadyCurrent = errors.New("dispatch: plan is stale (node no longer on target) — re-plan required")

// dispatchDefaultMaxWatch bounds WaitOp when the caller supplies a ctx without
// its own deadline, so a never-terminal agent op cannot poll forever (§7 watch
// timeout contract). A caller-supplied deadline always takes precedence.
const dispatchDefaultMaxWatch = 30 * time.Minute

// agentHTTPError is a structured non-2xx response from the agent. It lets the
// orchestration distinguish a deterministic 4xx rejection (e.g. image_allowlist
// denial — design E5, never retry) from a transient 5xx (retry).
type agentHTTPError struct {
	Status int
	Method string
	Path   string
}

func (e *agentHTTPError) Error() string {
	return fmt.Sprintf("dispatch: agent %s %s: HTTP %d", e.Method, e.Path, e.Status)
}

// isTransientAgentErr reports whether an agent call error is worth retrying: a
// transport error (dial/reset/timeout) or an HTTP 5xx. A deterministic HTTP 4xx
// (agent rejection) and a context error are NOT transient.
func isTransientAgentErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var he *agentHTTPError
	if errors.As(err, &he) {
		return he.Status >= 500
	}
	return true // non-HTTP transport error
}

// AgentClient is the seam over the EXISTING agent /v1 surface. Apply POSTs
// upgrades.apply and returns the async op id; WaitOp polls the op to a terminal
// state; RunningDigests reads running_image.repo_digests.
type AgentClient interface {
	RunningDigests(ctx context.Context) ([]string, error)
	Apply(ctx context.Context, req UpgradeApplyRequest) (opID string, err error)
	WaitOp(ctx context.Context, opID string) (state string, err error)
}

// DispatchAuditEvent is the structured release-level audit record (design §8).
// The hook persists it (audit ring); this slice does not wire the UI.
type DispatchAuditEvent struct {
	Phase             string // "dispatch" (at apply) | "outcome" (at terminal)
	ReleaseID         string
	VersionID         string
	Severity          Severity
	ImageRef          string
	PreBackup         bool
	RollbackOnFailure bool
	IdempotencyKey    string
	OpID              string
	Terminal          DispatchTerminal // set on the "outcome" event
	Detail            string
}

// DispatchResult is the execution outcome.
type DispatchResult struct {
	Terminal       DispatchTerminal
	OpID           string
	IdempotencyKey string
	Verified       bool   // running digest verified against the target (success) — design §7
	Detail         string // reason on failure
}

// DispatchExecutor runs frozen plans against one agent (single-flight per agent).
type DispatchExecutor struct {
	client       AgentClient
	cfg          DispatchConfig // for verify-by-digest reverse normalization
	audit        func(DispatchAuditEvent)
	newOpID      func() string
	applyRetries int           // extra Apply attempts on TRANSIENT error (same key reused)
	maxWatch     time.Duration // WaitOp ceiling when ctx has no deadline (§7)

	mu       sync.Mutex
	inflight bool
}

// NewDispatchExecutor builds an executor. audit may be nil.
func NewDispatchExecutor(client AgentClient, cfg DispatchConfig, audit func(DispatchAuditEvent)) *DispatchExecutor {
	return &DispatchExecutor{
		client:       client,
		cfg:          cfg,
		audit:        audit,
		newOpID:      newDispatchOpID,
		applyRetries: 2,
		maxWatch:     dispatchDefaultMaxWatch,
	}
}

func newDispatchOpID() string { return ulid.MustNew(ulid.Now(), rand.Reader).String() }

// Execute runs a frozen plan. A refused/non-plan returns an error; a second
// concurrent Execute on the same agent returns errDispatchInFlight (the
// already-current path is single-flighted too). The optional onApplied hooks
// fire EXACTLY ONCE, right after the agent accepts the apply and returns an
// op_id — BEFORE the (potentially long) WaitOp — so a caller can durably record
// the op_id/key for crash recovery before blocking on the terminal state. If an
// onApplied hook returns an error the durable record did NOT land, so Execute
// fails closed with FAILED_NEEDS_ATTN/durable_record_failed rather than block in
// WaitOp with an unrecorded op_id; the reused idempotency key keeps a later
// retry from starting a second upgrade.
func (e *DispatchExecutor) Execute(ctx context.Context, plan *DispatchPlan, onApplied ...func(opID string) error) (*DispatchResult, error) {
	if plan == nil {
		return nil, errors.New("dispatch: nil plan")
	}
	switch plan.Outcome {
	case OutcomeAlreadyCurrent:
		return e.executeAlreadyCurrent(ctx, plan)
	case OutcomePlan:
		// proceed
	default:
		return nil, fmt.Errorf("dispatch: cannot execute a %s plan", plan.Outcome)
	}

	if !e.acquire() {
		return nil, errDispatchInFlight
	}
	defer e.release()

	// Anchor: the pre-dispatch running digests, REQUIRED for rolled-back
	// verification. If the anchor read fails (e.g. /v1/status is briefly down
	// while /v1/upgrades/apply is reachable) we REFUSE before apply (design §E4)
	// rather than proceed best-effort: starting a destructive upgrade with no
	// rollback anchor would leave any later failure unclassifiable.
	anchor, err := e.client.RunningDigests(ctx)
	if err != nil {
		res := &DispatchResult{Terminal: TerminalFailedNeedsAttn, Detail: detailAnchorReadFailed + ": " + err.Error()}
		e.emitOutcome(plan, res)
		return res, nil
	}

	// CP idempotency key. The planner (P1.6a) owns op identity: if it supplied a
	// key (DispatchOptions.IdempotencyKey, threaded through plan.Apply), HONOR it
	// verbatim so a re-execution of the SAME op reuses it and the agent dedupes.
	// Only when none was supplied do we mint rel-<release_id>-<ulid>. The key is
	// constant for the rest of THIS execution (reused across Apply retries).
	req := plan.Apply
	key := req.IdempotencyKey
	if key == "" {
		key = "rel-" + plan.ReleaseID + "-" + e.newOpID()
		req.IdempotencyKey = key
	}
	res := &DispatchResult{IdempotencyKey: key}

	opID, err := e.applyWithRetry(ctx, req)
	if err != nil {
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "apply_failed: "+err.Error()
		e.emitOutcome(plan, res)
		return res, nil
	}
	res.OpID = opID
	e.emitDispatch(plan, key, opID)
	for _, h := range onApplied {
		// Durable correlation point — BEFORE the blocking watch. A failure here
		// means the op_id was not recorded, so we cannot safely watch/resume it.
		if rerr := h(opID); rerr != nil {
			res.Terminal, res.Detail = TerminalFailedNeedsAttn, "durable_record_failed: "+rerr.Error()
			e.emitOutcome(plan, res)
			return res, nil
		}
	}

	// Bound the watch: a caller deadline always wins; otherwise cap at maxWatch so
	// a never-terminal op cannot poll forever (§7). The ctx remains the hard stop.
	watchCtx, cancel := e.watchContext(ctx)
	defer cancel()

	state, werr := e.client.WaitOp(watchCtx, opID)
	if werr != nil {
		// State unobserved (timeout / poll error) — the agent op runs on; the
		// operator must inspect it. The reused key makes a re-poll safe.
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "watch_timeout: "+werr.Error()
		e.emitOutcome(plan, res)
		return res, nil
	}

	e.classifyTerminal(ctx, plan, res, anchor, state)
	e.emitOutcome(plan, res)
	return res, nil
}

// executeAlreadyCurrent re-validates an already-current plan against a FRESH
// status read before honoring the no-op. The planner's already-current was
// computed from plan-time digests (possibly stale, design §5.1); the node may
// have drifted off the target between planning and execution. Re-reading closes
// that window: still-on-target ⇒ already_current; drifted ⇒ refuse with
// errStaleAlreadyCurrent so the caller re-plans (NO apply in this slice).
//
// It takes the SAME single-flight as a real dispatch: while an op is in flight on
// the agent the running image is in flux, so a confident already_current no-op is
// unsafe — a concurrent already-current request is rejected with
// errDispatchInFlight, not answered from a racing status read.
func (e *DispatchExecutor) executeAlreadyCurrent(ctx context.Context, plan *DispatchPlan) (*DispatchResult, error) {
	if !e.acquire() {
		return nil, errDispatchInFlight
	}
	defer e.release()

	running, err := e.client.RunningDigests(ctx)
	if err != nil {
		res := &DispatchResult{Terminal: TerminalFailedNeedsAttn, Detail: "already_current_recheck_read_failed: " + err.Error()}
		e.emitOutcome(plan, res)
		return res, nil
	}
	if !e.verifyRunning(running, plan.PinnedRef) {
		res := &DispatchResult{Terminal: TerminalFailedNeedsAttn, Detail: "stale_already_current: node no longer on target — re-plan required"}
		e.emitOutcome(plan, res)
		return res, errStaleAlreadyCurrent
	}
	res := &DispatchResult{Terminal: TerminalAlreadyCurrent, Verified: true}
	e.emitOutcome(plan, res)
	return res, nil
}

// watchContext derives the context used for WaitOp. A caller-supplied deadline
// always takes precedence; only a deadline-less ctx is capped at maxWatch. The
// returned cancel must always be called.
func (e *DispatchExecutor) watchContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok || e.maxWatch <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, e.maxWatch)
}

// Resume re-polls an EXISTING agent op to a terminal state and classifies it by
// verify-by-digest — WITHOUT a fresh apply. It recovers a dispatch whose CP-side
// watch was interrupted (CP restart / watch timeout): the agent op kept running,
// so re-polling the same op_id is safe and never starts a second upgrade. It is
// single-flight per agent (shares the executor mutex), so a resume cannot race a
// live dispatch on the same agent.
//
// Resume is op_id-driven: rc.OpID is the re-poll AUTHORITY and rc.TargetPinnedRef
// is the verify-by-digest target. rc.IdempotencyKey is ONLY correlation metadata
// (it is never used to decide what to resume). Because a fresh CP process has no
// pre-dispatch anchor, Resume never asserts FAILED_ROLLED_BACK: anything other
// than a verified success is FAILED_NEEDS_ATTN (the safe classification).
func (e *DispatchExecutor) Resume(ctx context.Context, rc DispatchResumeContext) (*DispatchResult, error) {
	if rc.OpID == "" {
		return nil, errors.New("dispatch: resume needs an op_id")
	}
	if rc.TargetPinnedRef == "" {
		return nil, errors.New("dispatch: resume needs a target pinned ref to verify")
	}
	if !e.acquire() {
		return nil, errDispatchInFlight
	}
	defer e.release()

	res := &DispatchResult{OpID: rc.OpID, IdempotencyKey: rc.IdempotencyKey}
	// auditPlan carries identity ONLY for the audit hook; it is never the resume
	// authority (that is rc.OpID) nor the verify target (that is rc.TargetPinnedRef).
	plan := rc.auditPlan()

	watchCtx, cancel := e.watchContext(ctx)
	defer cancel()
	state, werr := e.client.WaitOp(watchCtx, rc.OpID)
	if werr != nil {
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "watch_timeout: "+werr.Error()
		e.emitOutcome(plan, res)
		return res, nil
	}

	post, perr := e.client.RunningDigests(ctx)
	if perr != nil {
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "post_verify_read_failed: "+perr.Error()
		e.emitOutcome(plan, res)
		return res, nil
	}
	res.Verified = e.verifyRunning(post, rc.TargetPinnedRef)
	if state == agentStateSucceeded && res.Verified {
		res.Terminal = TerminalSucceeded
	} else {
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "resume_unverified (state="+state+")"
	}
	e.emitOutcome(plan, res)
	return res, nil
}

// classifyTerminal re-reads the running digests (the verify-by-digest gate) and
// sets res.Terminal/Detail/Verified. A failed re-read is FAILED_NEEDS_ATTN —
// NOT inferred from nil/empty digests (which would falsely read as a mismatch or
// an un-rolled-back failure).
func (e *DispatchExecutor) classifyTerminal(ctx context.Context, plan *DispatchPlan, res *DispatchResult, anchor []string, state string) {
	post, perr := e.client.RunningDigests(ctx)
	if perr != nil {
		// The pre-apply anchor read succeeded (Execute bails before dispatch
		// otherwise), so a post-op read that fails with a TRANSPORT/transient
		// error right after a SUCCEEDED apply is the fingerprint of the recreate
		// dropping the CP↔agent socket — surface it distinctly. A deterministic
		// (non-transient) read error keeps the generic post_verify_read_failed.
		if state == agentStateSucceeded && isTransientAgentErr(perr) {
			res.Terminal, res.Detail = TerminalFailedNeedsAttn, detailAgentUnreachableAfterUpdate+": "+perr.Error()
			return
		}
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "post_verify_read_failed: "+perr.Error()
		return
	}
	res.Verified = e.verifyRunning(post, plan.PinnedRef)

	switch {
	case state == agentStateSucceeded && res.Verified:
		res.Terminal = TerminalSucceeded
	case state == agentStateSucceeded:
		// Agent reported success but the running digest is NOT the target.
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "verify_mismatch"
	case digestOverlap(anchor, post):
		// Op failed/cancelled and the prior image is running again. This is the
		// SAFE failure (inline auto-rollback restored it, or nothing changed),
		// but the re-read cannot prove a rollback actually ran vs. the upgrade
		// never taking effect — the detail says so explicitly.
		res.Terminal, res.Detail = TerminalFailedRolledBack, "prior_running_after_failed_op (state="+state+")"
	default:
		// Op failed and the prior image is NOT confirmed back — manual attention.
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "op_failed_not_rolled_back (state="+state+")"
	}
}

// applyWithRetry re-POSTs the SAME request (same idempotency key) on a TRANSIENT
// error only (transport / HTTP 5xx). A deterministic 4xx agent rejection (e.g.
// image_allowlist denial — design E5) is returned immediately: retrying it just
// repeats the same rejection. Reuse is safe ONLY because the key is constant
// across attempts and the agent's idempotency contract dedupes a repeated key to
// the same op — so a retry after a request that actually reached the agent
// returns that op rather than starting a second upgrade.
func (e *DispatchExecutor) applyWithRetry(ctx context.Context, req UpgradeApplyRequest) (string, error) {
	var lastErr error
	for attempt := 0; attempt <= e.applyRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		opID, err := e.client.Apply(ctx, req) // req.IdempotencyKey constant across attempts
		if err == nil {
			return opID, nil
		}
		lastErr = err
		if !isTransientAgentErr(err) {
			return "", err // deterministic rejection — do not retry
		}
	}
	return "", lastErr
}

// verifyRunning reports whether any running digest (reverse-rewritten to the
// catalog repo) equals the target's catalog PinnedRef — the same normalization
// the planner uses, so the air-gap repo edge is handled.
func (e *DispatchExecutor) verifyRunning(running []string, pinnedRef string) bool {
	for _, ref := range running {
		if e.cfg.reverse(ref) == pinnedRef {
			return true
		}
	}
	return false
}

func digestOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, x := range a {
		set[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := set[y]; ok {
			return true
		}
	}
	return false
}

// ─── single-flight ───────────────────────────────────────────────────────────

func (e *DispatchExecutor) acquire() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.inflight {
		return false
	}
	e.inflight = true
	return true
}

func (e *DispatchExecutor) release() {
	e.mu.Lock()
	e.inflight = false
	e.mu.Unlock()
}

// inFlight reports whether an op currently holds the single-flight. Used by the
// service registry to decide whether an endpoint can be safely rebound (an
// in-flight op must finish on its original client before rebinding).
func (e *DispatchExecutor) inFlight() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.inflight
}

// ─── audit emission ──────────────────────────────────────────────────────────

func (e *DispatchExecutor) emitDispatch(plan *DispatchPlan, key, opID string) {
	if e.audit == nil {
		return
	}
	e.audit(DispatchAuditEvent{
		Phase: "dispatch", ReleaseID: plan.ReleaseID, VersionID: plan.VersionID,
		Severity: plan.Severity, ImageRef: plan.ImageRef, PreBackup: plan.Apply.PreBackup,
		RollbackOnFailure: plan.Apply.RollbackOnFailure, IdempotencyKey: key, OpID: opID,
	})
}

func (e *DispatchExecutor) emitOutcome(plan *DispatchPlan, res *DispatchResult) {
	if e.audit == nil {
		return
	}
	e.audit(DispatchAuditEvent{
		Phase: "outcome", ReleaseID: plan.ReleaseID, VersionID: plan.VersionID,
		Severity: plan.Severity, ImageRef: plan.ImageRef, PreBackup: plan.Apply.PreBackup,
		RollbackOnFailure: plan.Apply.RollbackOnFailure, IdempotencyKey: res.IdempotencyKey,
		OpID: res.OpID, Terminal: res.Terminal, Detail: res.Detail,
	})
}

// ─── concrete HTTP agent client (existing /v1 endpoints) ─────────────────────

const (
	dispatchAgentPollInterval = 2 * time.Second
	dispatchAgentReadBound    = 1 << 20 // 1 MiB
	dispatchPollErrorBudget   = 3       // consecutive TRANSIENT poll errors tolerated
)

// httpAgentClient talks to the agent over its existing /v1 surface. The caller
// supplies the *http.Client (TLS/mTLS/auth wiring lives there) and the base URL.
type httpAgentClient struct {
	base         *url.URL
	client       *http.Client
	pollInterval time.Duration
	pollBudget   int // consecutive transient poll errors tolerated before giving up
}

// NewHTTPAgentClient builds a client for the agent at baseURL.
func NewHTTPAgentClient(baseURL string, client *http.Client) (*httpAgentClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("dispatch: parse agent base URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("dispatch: agent base URL needs scheme and host")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &httpAgentClient{base: u, client: client, pollInterval: dispatchAgentPollInterval, pollBudget: dispatchPollErrorBudget}, nil
}

func (c *httpAgentClient) RunningDigests(ctx context.Context) ([]string, error) {
	var st struct {
		RunningImage *struct {
			RepoDigests []string `json:"repo_digests"`
		} `json:"running_image"`
	}
	if err := c.getJSON(ctx, "/v1/status", &st); err != nil {
		return nil, err
	}
	if st.RunningImage == nil {
		return nil, nil
	}
	return st.RunningImage.RepoDigests, nil
}

func (c *httpAgentClient) Apply(ctx context.Context, req UpgradeApplyRequest) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	var op struct {
		OpID string `json:"op_id"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/upgrades/apply", body, &op); err != nil {
		return "", err
	}
	if op.OpID == "" {
		return "", errors.New("dispatch: agent apply returned no op_id")
	}
	return op.OpID, nil
}

// WaitOp polls the op to a terminal state. A TRANSIENT poll error (transport /
// HTTP 5xx) does not abort the watch: up to pollBudget CONSECUTIVE transient
// errors are tolerated (the counter resets on any successful poll), so a brief
// blip while the agent op runs on does not produce a spurious failure. A
// deterministic 4xx (e.g. op-not-found after an agent restart) aborts at once,
// and the context deadline is always the hard stop.
func (c *httpAgentClient) WaitOp(ctx context.Context, opID string) (string, error) {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()
	transient := 0
	for {
		var op struct {
			State string `json:"state"`
		}
		err := c.getJSON(ctx, path.Join("/v1/operations", opID), &op)
		switch {
		case err == nil:
			transient = 0
			switch op.State {
			case agentStateSucceeded, agentStateFailed, agentStateCancelled:
				return op.State, nil
			}
		case !isTransientAgentErr(err):
			return "", err // deterministic (4xx) or context error — give up now
		default:
			transient++
			if transient > c.pollBudget {
				return "", fmt.Errorf("dispatch: agent op poll failed %d times: %w", transient, err)
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *httpAgentClient) getJSON(ctx context.Context, p string, out any) error {
	return c.doJSON(ctx, http.MethodGet, p, nil, out)
}

func (c *httpAgentClient) doJSON(ctx context.Context, method, p string, body []byte, out any) error {
	u := *c.base
	u.Path = path.Join("/", u.Path, p)
	var rdr io.Reader = http.NoBody
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, dispatchAgentReadBound))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return &agentHTTPError{Status: resp.StatusCode, Method: method, Path: p}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}
