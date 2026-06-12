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
	applyRetries int // extra Apply attempts on transport error (same key reused)

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
	}
}

func newDispatchOpID() string { return ulid.MustNew(ulid.Now(), rand.Reader).String() }

// Execute runs a frozen plan. An already-current plan returns immediately
// WITHOUT contacting the agent. A refused/non-plan returns an error. A second
// concurrent Execute returns errDispatchInFlight.
func (e *DispatchExecutor) Execute(ctx context.Context, plan *DispatchPlan) (*DispatchResult, error) {
	switch plan.Outcome {
	case OutcomeAlreadyCurrent:
		res := &DispatchResult{Terminal: TerminalAlreadyCurrent, Verified: true}
		e.emitOutcome(plan, res)
		return res, nil
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
		res := &DispatchResult{Terminal: TerminalFailedNeedsAttn, Detail: "anchor_read_failed: " + err.Error()}
		e.emitOutcome(plan, res)
		return res, nil
	}

	// CP idempotency key: rel-<release_id>-<ulid>. Generated ONCE; reused across
	// Apply retries of THIS execution so the agent deduplicates.
	key := "rel-" + plan.ReleaseID + "-" + e.newOpID()
	req := plan.Apply
	req.IdempotencyKey = key
	res := &DispatchResult{IdempotencyKey: key}

	opID, err := e.applyWithRetry(ctx, req)
	if err != nil {
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "apply_failed: "+err.Error()
		e.emitOutcome(plan, res)
		return res, nil
	}
	res.OpID = opID
	e.emitDispatch(plan, key, opID)

	state, werr := e.client.WaitOp(ctx, opID)
	if werr != nil {
		// State unobserved (timeout / poll error) — the agent op runs on; the
		// operator must inspect it. The reused key makes a re-poll safe.
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "watch_timeout: "+werr.Error()
		e.emitOutcome(plan, res)
		return res, nil
	}

	post, _ := e.client.RunningDigests(ctx)
	res.Verified = e.verifyRunning(post, plan.PinnedRef)

	switch {
	case state == agentStateSucceeded && res.Verified:
		res.Terminal = TerminalSucceeded
	case state == agentStateSucceeded:
		// Agent reported success but the running digest is NOT the target.
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "verify_mismatch"
	case digestOverlap(anchor, post):
		// Op failed/cancelled but the prior image is running again (inline
		// auto-rollback restored it, or nothing changed) — the safe failure.
		res.Terminal, res.Detail = TerminalFailedRolledBack, "op_state="+state
	default:
		// Op failed and the prior image is NOT confirmed back — manual attention.
		res.Terminal, res.Detail = TerminalFailedNeedsAttn, "op_failed_not_rolled_back (state="+state+")"
	}
	e.emitOutcome(plan, res)
	return res, nil
}

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
)

// httpAgentClient talks to the agent over its existing /v1 surface. The caller
// supplies the *http.Client (TLS/mTLS/auth wiring lives there) and the base URL.
type httpAgentClient struct {
	base         *url.URL
	client       *http.Client
	pollInterval time.Duration
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
	return &httpAgentClient{base: u, client: client, pollInterval: dispatchAgentPollInterval}, nil
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

func (c *httpAgentClient) WaitOp(ctx context.Context, opID string) (string, error) {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()
	for {
		var op struct {
			State string `json:"state"`
		}
		if err := c.getJSON(ctx, path.Join("/v1/operations", opID), &op); err != nil {
			return "", err
		}
		switch op.State {
		case agentStateSucceeded, agentStateFailed, agentStateCancelled:
			return op.State, nil
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
		return fmt.Errorf("dispatch: agent %s %s: HTTP %d", method, p, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}
