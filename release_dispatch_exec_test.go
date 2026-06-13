package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ─── fake agent ──────────────────────────────────────────────────────────────

type fakeAgent struct {
	mu sync.Mutex

	applyReqs   []UpgradeApplyRequest // every Apply request seen (incl. retries)
	applyErrs   []error               // error to return per Apply attempt (nil ⇒ ok)
	applyOpID   string
	waitState   string
	waitErr     error
	runningSeq  [][]string // RunningDigests returns these in order (anchor, post, ...)
	runningErrs []error    // error to return per RunningDigests call (nil ⇒ ok)
	runningCall int

	waitGate chan struct{} // if non-nil, WaitOp blocks on it before returning
}

func (f *fakeAgent) Apply(_ context.Context, req UpgradeApplyRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := len(f.applyReqs)
	f.applyReqs = append(f.applyReqs, req)
	if i < len(f.applyErrs) && f.applyErrs[i] != nil {
		return "", f.applyErrs[i]
	}
	return f.applyOpID, nil
}

func (f *fakeAgent) WaitOp(ctx context.Context, _ string) (string, error) {
	if f.waitGate != nil {
		select {
		case <-f.waitGate:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return f.waitState, f.waitErr
}

func (f *fakeAgent) RunningDigests(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.runningCall < len(f.runningErrs) && f.runningErrs[f.runningCall] != nil {
		err := f.runningErrs[f.runningCall]
		f.runningCall++
		return nil, err
	}
	if f.runningCall < len(f.runningSeq) {
		r := f.runningSeq[f.runningCall]
		f.runningCall++
		return r, nil
	}
	if len(f.runningSeq) > 0 {
		return f.runningSeq[len(f.runningSeq)-1], nil
	}
	return nil, nil
}

func planTo(t *testing.T, cat *Catalog, cfg DispatchConfig, running []string) *DispatchPlan {
	t.Helper()
	d, _ := newDispatcher(t, cat, cfg)
	return d.Plan(DispatchTarget{ReleaseID: "rel_a"}, running, DefaultDispatchOptions())
}

func newExec(agent AgentClient, audit func(DispatchAuditEvent)) *DispatchExecutor {
	e := NewDispatchExecutor(agent, DispatchConfig{ProxyRepo: dispatchRepo}, audit)
	e.newOpID = func() string { return "OP01" } // deterministic key
	return e
}

// ─── tests ───────────────────────────────────────────────────────────────────

// An already-current plan re-reads status (freshness re-check) but NEVER applies
// — and when the fresh read still shows the target, the outcome is already_current.
func TestExec_AlreadyCurrentDoesNotApply(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, []string{dispatchRepo + "@" + digA})
	if plan.Outcome != OutcomeAlreadyCurrent {
		t.Fatalf("precondition: want already_current; got %s", plan.Outcome)
	}
	// Fresh status read confirms the node is still on the target.
	agent := &fakeAgent{applyOpID: "op-x", runningSeq: [][]string{{dispatchRepo + "@" + digA}}}
	res, err := newExec(agent, nil).Execute(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if res.Terminal != TerminalAlreadyCurrent || !res.Verified {
		t.Fatalf("terminal=%s verified=%v; want already_current/true", res.Terminal, res.Verified)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("agent must not be applied for an already-current plan; saw %d applies", len(agent.applyReqs))
	}
	if agent.runningCall == 0 {
		t.Fatal("already-current must re-read RunningDigests (freshness re-check)")
	}
}

func TestExec_SendsExactApplyRequest(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil) // fresh dispatch
	agent := &fakeAgent{applyOpID: "op-1", waitState: agentStateSucceeded,
		runningSeq: [][]string{nil, {dispatchRepo + "@" + digA}}} // anchor, post (verifies)
	res, err := newExec(agent, nil).Execute(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(agent.applyReqs) != 1 {
		t.Fatalf("want 1 apply; got %d", len(agent.applyReqs))
	}
	got := agent.applyReqs[0]
	if got.ImageRef != plan.Apply.ImageRef || got.PreBackup != plan.Apply.PreBackup ||
		got.PassphraseRef != plan.Apply.PassphraseRef || got.RollbackOnFailure != plan.Apply.RollbackOnFailure {
		t.Fatalf("apply request mismatch:\n got  %+v\n want %+v", got, plan.Apply)
	}
	if got.IdempotencyKey != "rel-rel_a-OP01" {
		t.Fatalf("idempotency_key = %q; want rel-rel_a-OP01", got.IdempotencyKey)
	}
	if res.Terminal != TerminalSucceeded {
		t.Fatalf("terminal = %s; want succeeded", res.Terminal)
	}
}

func TestExec_IdempotencyKeyReusedOnRetry(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	agent := &fakeAgent{
		applyErrs:  []error{errors.New("transient"), nil}, // fail first, succeed second
		applyOpID:  "op-2",
		waitState:  agentStateSucceeded,
		runningSeq: [][]string{nil, {dispatchRepo + "@" + digA}},
	}
	if _, err := newExec(agent, nil).Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if len(agent.applyReqs) != 2 {
		t.Fatalf("want 2 apply attempts (1 retry); got %d", len(agent.applyReqs))
	}
	if agent.applyReqs[0].IdempotencyKey != agent.applyReqs[1].IdempotencyKey {
		t.Fatalf("idempotency key changed across retry: %q vs %q",
			agent.applyReqs[0].IdempotencyKey, agent.applyReqs[1].IdempotencyKey)
	}
}

func TestExec_SuccessVerified(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	agent := &fakeAgent{applyOpID: "op-3", waitState: agentStateSucceeded,
		runningSeq: [][]string{{dispatchRepo + "@" + digB}, {dispatchRepo + "@" + digA}}} // prior rel_b, now target
	res, _ := newExec(agent, nil).Execute(context.Background(), plan)
	if res.Terminal != TerminalSucceeded || !res.Verified {
		t.Fatalf("terminal=%s verified=%v; want succeeded/true", res.Terminal, res.Verified)
	}
}

func TestExec_SuccessButVerifyMismatch(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	// Op says succeeded, but post-running is NOT the target digest.
	agent := &fakeAgent{applyOpID: "op-4", waitState: agentStateSucceeded,
		runningSeq: [][]string{nil, {dispatchRepo + "@sha256:" + strings.Repeat("c", 64)}}}
	res, _ := newExec(agent, nil).Execute(context.Background(), plan)
	if res.Terminal != TerminalFailedNeedsAttn || res.Detail != "verify_mismatch" {
		t.Fatalf("terminal=%s detail=%q; want failed_needs_attn/verify_mismatch", res.Terminal, res.Detail)
	}
}

func TestExec_FailedRolledBack(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	prior := dispatchRepo + "@" + digB
	// Op failed; the prior image is running again (inline auto-rollback restored it).
	agent := &fakeAgent{applyOpID: "op-5", waitState: agentStateFailed,
		runningSeq: [][]string{{prior}, {prior}}}
	res, _ := newExec(agent, nil).Execute(context.Background(), plan)
	if res.Terminal != TerminalFailedRolledBack {
		t.Fatalf("terminal=%s; want failed_rolled_back", res.Terminal)
	}
}

func TestExec_FailedNotRolledBackNeedsAttn(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	// Op failed and the node is NOT back on the prior image (rollback failed/disabled).
	agent := &fakeAgent{applyOpID: "op-6", waitState: agentStateFailed,
		runningSeq: [][]string{{dispatchRepo + "@" + digB}, {dispatchRepo + "@sha256:" + strings.Repeat("d", 64)}}}
	res, _ := newExec(agent, nil).Execute(context.Background(), plan)
	if res.Terminal != TerminalFailedNeedsAttn {
		t.Fatalf("terminal=%s; want failed_needs_attn", res.Terminal)
	}
}

func TestExec_WatchTimeoutNeedsAttn(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	agent := &fakeAgent{applyOpID: "op-7", waitErr: context.DeadlineExceeded,
		runningSeq: [][]string{nil}}
	res, _ := newExec(agent, nil).Execute(context.Background(), plan)
	if res.Terminal != TerminalFailedNeedsAttn || !strings.HasPrefix(res.Detail, "watch_timeout") {
		t.Fatalf("terminal=%s detail=%q; want failed_needs_attn/watch_timeout", res.Terminal, res.Detail)
	}
}

func TestExec_ConcurrentRejected(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	e := newExec(&fakeAgent{applyOpID: "op-8", waitState: agentStateSucceeded,
		runningSeq: [][]string{nil, {dispatchRepo + "@" + digA}}}, nil)

	// Hold the single-flight, then a concurrent Execute is rejected.
	if !e.acquire() {
		t.Fatal("acquire should succeed")
	}
	if _, err := e.Execute(context.Background(), plan); !errors.Is(err, errDispatchInFlight) {
		t.Fatalf("concurrent Execute: err = %v; want errDispatchInFlight", err)
	}
	e.release()
	if _, err := e.Execute(context.Background(), plan); err != nil {
		t.Fatalf("Execute after release: %v", err)
	}
}

// An already-current plan is single-flighted too: while an op is in flight on
// the agent, a concurrent already-current request is rejected rather than
// answered from a racing status read.
func TestExec_AlreadyCurrentRejectedWhenInFlight(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, []string{dispatchRepo + "@" + digA})
	if plan.Outcome != OutcomeAlreadyCurrent {
		t.Fatalf("precondition: want already_current; got %s", plan.Outcome)
	}
	agent := &fakeAgent{runningSeq: [][]string{{dispatchRepo + "@" + digA}}}
	e := newExec(agent, nil)
	if !e.acquire() {
		t.Fatal("acquire should succeed")
	}
	defer e.release()
	if _, err := e.Execute(context.Background(), plan); !errors.Is(err, errDispatchInFlight) {
		t.Fatalf("already-current during in-flight op: err = %v; want errDispatchInFlight", err)
	}
	if agent.runningCall != 0 {
		t.Fatal("a rejected already-current must not read status")
	}
}

// The onApplied hook fires exactly once with the op_id, before the watch.
func TestExec_OnAppliedFiresWithOpID(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	agent := &fakeAgent{applyOpID: "op-cb", waitState: agentStateSucceeded,
		runningSeq: [][]string{nil, {dispatchRepo + "@" + digA}}}
	var ops []string
	res, err := newExec(agent, nil).Execute(context.Background(), plan, func(opID string) { ops = append(ops, opID) })
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 1 || ops[0] != "op-cb" {
		t.Fatalf("onApplied fired %v; want exactly [op-cb]", ops)
	}
	if res.Terminal != TerminalSucceeded {
		t.Fatalf("terminal=%s; want succeeded", res.Terminal)
	}
}

// onApplied must NOT fire when no apply happens (already-current).
func TestExec_OnAppliedSilentOnAlreadyCurrent(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, []string{dispatchRepo + "@" + digA})
	agent := &fakeAgent{runningSeq: [][]string{{dispatchRepo + "@" + digA}}}
	fired := false
	_, _ = newExec(agent, nil).Execute(context.Background(), plan, func(string) { fired = true })
	if fired {
		t.Fatal("onApplied must not fire for an already-current plan (no apply)")
	}
}

// A failed anchor read must refuse BEFORE apply (design §E4): the agent is
// never contacted and the outcome is failed_needs_attn/anchor_read_failed.
func TestExec_AnchorReadFailureRefusesBeforeApply(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	agent := &fakeAgent{applyOpID: "op-a", waitState: agentStateSucceeded,
		runningErrs: []error{errors.New("status unavailable")}} // anchor read fails
	var events []DispatchAuditEvent
	res, err := newExec(agent, func(ev DispatchAuditEvent) { events = append(events, ev) }).
		Execute(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if res.Terminal != TerminalFailedNeedsAttn || !strings.HasPrefix(res.Detail, "anchor_read_failed") {
		t.Fatalf("terminal=%s detail=%q; want failed_needs_attn/anchor_read_failed", res.Terminal, res.Detail)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("apply must not be called when the anchor read fails; saw %d", len(agent.applyReqs))
	}
	if len(events) != 1 || events[0].Phase != "outcome" || events[0].Terminal != TerminalFailedNeedsAttn {
		t.Fatalf("want a single outcome event; got %+v", events)
	}
}

// A failed post-apply re-read is the verify gate failing: classify
// FAILED_NEEDS_ATTN/post_verify_read_failed regardless of the op state, never
// inferring mismatch/rolled-back from a missing read.
func TestExec_PostVerifyReadFailureAfterSucceeded(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	agent := &fakeAgent{applyOpID: "op-pv1", waitState: agentStateSucceeded,
		runningSeq:  [][]string{nil},                         // anchor (call 0) ok
		runningErrs: []error{nil, errors.New("status gone")}} // post (call 1) errors
	res, _ := newExec(agent, nil).Execute(context.Background(), plan)
	if res.Terminal != TerminalFailedNeedsAttn || !strings.HasPrefix(res.Detail, "post_verify_read_failed") {
		t.Fatalf("terminal=%s detail=%q; want failed_needs_attn/post_verify_read_failed", res.Terminal, res.Detail)
	}
}

func TestExec_PostVerifyReadFailureAfterFailed(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	agent := &fakeAgent{applyOpID: "op-pv2", waitState: agentStateCancelled,
		runningSeq:  [][]string{{dispatchRepo + "@" + digB}}, // anchor (call 0) ok
		runningErrs: []error{nil, errors.New("status gone")}} // post (call 1) errors
	res, _ := newExec(agent, nil).Execute(context.Background(), plan)
	if res.Terminal != TerminalFailedNeedsAttn || !strings.HasPrefix(res.Detail, "post_verify_read_failed") {
		t.Fatalf("terminal=%s detail=%q; want failed_needs_attn/post_verify_read_failed", res.Terminal, res.Detail)
	}
}

func TestExec_NilPlanReturnsErrorNotPanic(t *testing.T) {
	agent := &fakeAgent{}
	res, err := newExec(agent, nil).Execute(context.Background(), nil)
	if err == nil {
		t.Fatal("want a clean error for a nil plan")
	}
	if res != nil {
		t.Fatalf("want nil result on error; got %+v", res)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("agent must not be contacted for a nil plan; saw %d applies", len(agent.applyReqs))
	}
}

// Audit hook fires a dispatch event (with op_id) and an outcome event.
func TestExec_AuditHook(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	var events []DispatchAuditEvent
	agent := &fakeAgent{applyOpID: "op-9", waitState: agentStateSucceeded,
		runningSeq: [][]string{nil, {dispatchRepo + "@" + digA}}}
	_, _ = newExec(agent, func(ev DispatchAuditEvent) { events = append(events, ev) }).Execute(context.Background(), plan)

	if len(events) != 2 || events[0].Phase != "dispatch" || events[1].Phase != "outcome" {
		t.Fatalf("want dispatch+outcome events; got %+v", events)
	}
	if events[0].OpID != "op-9" || events[0].IdempotencyKey != "rel-rel_a-OP01" {
		t.Fatalf("dispatch event missing op_id/key: %+v", events[0])
	}
	if events[1].Terminal != TerminalSucceeded {
		t.Fatalf("outcome terminal = %s; want succeeded", events[1].Terminal)
	}
}

// ─── P1.6c-0 hardening: idempotency ownership ───────────────────────────────

// A planner-supplied idempotency key (DispatchOptions → plan.Apply) is honored
// verbatim — never overwritten with a freshly-minted one.
func TestExec_HonorsPlannerSuppliedIdempotencyKey(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	plan.Apply.IdempotencyKey = "rel-rel_a-CALLER123" // orchestration-owned op identity
	agent := &fakeAgent{applyOpID: "op-k", waitState: agentStateSucceeded,
		runningSeq: [][]string{nil, {dispatchRepo + "@" + digA}}}
	res, err := newExec(agent, nil).Execute(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if got := agent.applyReqs[0].IdempotencyKey; got != "rel-rel_a-CALLER123" {
		t.Fatalf("apply key = %q; want the planner-supplied rel-rel_a-CALLER123 (must not be minted over)", got)
	}
	if res.IdempotencyKey != "rel-rel_a-CALLER123" {
		t.Fatalf("result key = %q; want rel-rel_a-CALLER123", res.IdempotencyKey)
	}
}

// When the planner supplied NO key, the executor mints rel-<release_id>-<ulid>.
func TestExec_GeneratesIdempotencyKeyWhenEmpty(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	if plan.Apply.IdempotencyKey != "" {
		t.Fatalf("precondition: want empty key from default options; got %q", plan.Apply.IdempotencyKey)
	}
	agent := &fakeAgent{applyOpID: "op-g", waitState: agentStateSucceeded,
		runningSeq: [][]string{nil, {dispatchRepo + "@" + digA}}}
	res, err := newExec(agent, nil).Execute(context.Background(), plan) // newExec pins newOpID → OP01
	if err != nil {
		t.Fatal(err)
	}
	if got := agent.applyReqs[0].IdempotencyKey; got != "rel-rel_a-OP01" {
		t.Fatalf("apply key = %q; want minted rel-rel_a-OP01", got)
	}
	if res.IdempotencyKey != "rel-rel_a-OP01" {
		t.Fatalf("result key = %q; want rel-rel_a-OP01", res.IdempotencyKey)
	}
}

// ─── P1.6c-0 hardening: already-current freshness ───────────────────────────

// A plan that was already-current at plan time but whose node has DRIFTED off
// the target by execute time must NOT silently succeed: re-read shows a
// different digest ⇒ errStaleAlreadyCurrent + failed_needs_attn, and no apply.
func TestExec_AlreadyCurrentStaleRequiresReplan(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, []string{dispatchRepo + "@" + digA})
	if plan.Outcome != OutcomeAlreadyCurrent {
		t.Fatalf("precondition: want already_current; got %s", plan.Outcome)
	}
	// Fresh status read: the node drifted to a foreign digest.
	drifted := dispatchRepo + "@sha256:" + strings.Repeat("e", 64)
	agent := &fakeAgent{applyOpID: "op-s", runningSeq: [][]string{{drifted}}}
	res, err := newExec(agent, nil).Execute(context.Background(), plan)
	if !errors.Is(err, errStaleAlreadyCurrent) {
		t.Fatalf("err = %v; want errStaleAlreadyCurrent", err)
	}
	if res.Terminal != TerminalFailedNeedsAttn || !strings.HasPrefix(res.Detail, "stale_already_current") {
		t.Fatalf("terminal=%s detail=%q; want failed_needs_attn/stale_already_current", res.Terminal, res.Detail)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("a stale already-current plan must NOT apply; saw %d", len(agent.applyReqs))
	}
}

// A failed freshness re-read (status unavailable) is failed_needs_attn, not a
// silent already-current success — and still no apply.
func TestExec_AlreadyCurrentRecheckReadFailure(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, []string{dispatchRepo + "@" + digA})
	agent := &fakeAgent{applyOpID: "op-r", runningErrs: []error{errors.New("status down")}}
	res, _ := newExec(agent, nil).Execute(context.Background(), plan)
	if res.Terminal != TerminalFailedNeedsAttn || !strings.HasPrefix(res.Detail, "already_current_recheck_read_failed") {
		t.Fatalf("terminal=%s detail=%q; want failed_needs_attn/already_current_recheck_read_failed", res.Terminal, res.Detail)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("must not apply; saw %d", len(agent.applyReqs))
	}
}

// ─── P1.6c-0 hardening: apply retry classification ──────────────────────────

// A deterministic 4xx agent rejection (image_allowlist denial, design E5) is
// NOT retried — applyWithRetry returns after a single attempt.
func TestExec_ApplyDoesNotRetry4xx(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	agent := &fakeAgent{applyOpID: "op-4", applyErrs: []error{&agentHTTPError{Status: 400, Method: "POST", Path: "/v1/upgrades/apply"}}}
	res, _ := newExec(agent, nil).Execute(context.Background(), plan)
	if len(agent.applyReqs) != 1 {
		t.Fatalf("4xx must not be retried; saw %d apply attempts", len(agent.applyReqs))
	}
	if res.Terminal != TerminalFailedNeedsAttn || !strings.HasPrefix(res.Detail, "apply_failed") {
		t.Fatalf("terminal=%s detail=%q; want failed_needs_attn/apply_failed", res.Terminal, res.Detail)
	}
}

// A transient 5xx IS retried (same key), then succeeds.
func TestExec_ApplyRetriesTransient5xx(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	agent := &fakeAgent{
		applyErrs:  []error{&agentHTTPError{Status: 503, Method: "POST", Path: "/v1/upgrades/apply"}, nil},
		applyOpID:  "op-5",
		waitState:  agentStateSucceeded,
		runningSeq: [][]string{nil, {dispatchRepo + "@" + digA}},
	}
	res, _ := newExec(agent, nil).Execute(context.Background(), plan)
	if len(agent.applyReqs) != 2 {
		t.Fatalf("5xx should be retried once; saw %d attempts", len(agent.applyReqs))
	}
	if agent.applyReqs[0].IdempotencyKey != agent.applyReqs[1].IdempotencyKey {
		t.Fatal("idempotency key must be constant across transient retry")
	}
	if res.Terminal != TerminalSucceeded {
		t.Fatalf("terminal=%s; want succeeded", res.Terminal)
	}
}

func TestIsTransientAgentErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"transport", errors.New("dial tcp: connection refused"), true},
		{"http_500", &agentHTTPError{Status: 500}, true},
		{"http_503", &agentHTTPError{Status: 503}, true},
		{"http_400", &agentHTTPError{Status: 400}, false},
		{"http_404", &agentHTTPError{Status: 404}, false},
		{"ctx_canceled", context.Canceled, false},
		{"ctx_deadline", context.DeadlineExceeded, false},
	}
	for _, tc := range cases {
		if got := isTransientAgentErr(tc.err); got != tc.want {
			t.Errorf("%s: isTransientAgentErr = %v; want %v", tc.name, got, tc.want)
		}
	}
}

// ─── P1.6c-0 hardening: explicit watch deadline ─────────────────────────────

// With a deadline-less ctx, a never-terminal op is bounded by the executor's
// maxWatch and resolves to failed_needs_attn/watch_timeout (never hangs).
func TestExec_WatchDeadlineBoundsNeverTerminalOp(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/status":
			_, _ = w.Write([]byte(`{"running_image":{"repo_digests":["` + dispatchRepo + `@` + digB + `"]}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/upgrades/apply":
			_, _ = w.Write([]byte(`{"op_id":"op-never"}`))
		case r.URL.Path == "/v1/operations/op-never":
			_, _ = w.Write([]byte(`{"state":"running"}`)) // never terminal
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client, err := NewHTTPAgentClient(ts.URL, ts.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.pollInterval = 5 * time.Millisecond

	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	exec := NewDispatchExecutor(client, DispatchConfig{ProxyRepo: dispatchRepo}, nil)
	exec.maxWatch = 40 * time.Millisecond // bound a deadline-less ctx

	res, err := exec.Execute(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if res.Terminal != TerminalFailedNeedsAttn || !strings.HasPrefix(res.Detail, "watch_timeout") {
		t.Fatalf("terminal=%s detail=%q; want failed_needs_attn/watch_timeout", res.Terminal, res.Detail)
	}
}

// ─── concrete HTTP client (existing /v1 endpoints) ──────────────────────────

func TestHTTPAgentClient_ApplyWaitRunning(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/upgrades/apply":
			_, _ = w.Write([]byte(`{"op_id":"op-abc","state":"running"}`))
		case r.URL.Path == "/v1/operations/op-abc":
			_, _ = w.Write([]byte(`{"op_id":"op-abc","state":"succeeded"}`))
		case r.URL.Path == "/v1/status":
			_, _ = w.Write([]byte(`{"running_image":{"repo_digests":["` + dispatchRepo + `@` + digA + `"]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	c, err := NewHTTPAgentClient(ts.URL, ts.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.pollInterval = 1 // fast poll

	opID, err := c.Apply(context.Background(), UpgradeApplyRequest{ImageRef: dispatchRepo + "@" + digA})
	if err != nil || opID != "op-abc" {
		t.Fatalf("Apply: opID=%q err=%v", opID, err)
	}
	state, err := c.WaitOp(context.Background(), opID)
	if err != nil || state != agentStateSucceeded {
		t.Fatalf("WaitOp: state=%q err=%v", state, err)
	}
	dg, err := c.RunningDigests(context.Background())
	if err != nil || len(dg) != 1 || dg[0] != dispatchRepo+"@"+digA {
		t.Fatalf("RunningDigests: %v err=%v", dg, err)
	}
}

// WaitOp tolerates a bounded number of CONSECUTIVE transient (5xx) poll errors,
// then succeeds once the op turns terminal — the blip does not fail the watch.
func TestHTTPAgentClient_WaitOpToleratesTransientPollErrors(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// First 2 polls 503 (transient), then succeeded.
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"state":"succeeded"}`))
	}))
	defer ts.Close()

	c, err := NewHTTPAgentClient(ts.URL, ts.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.pollInterval = time.Millisecond

	state, err := c.WaitOp(context.Background(), "op-x")
	if err != nil || state != agentStateSucceeded {
		t.Fatalf("WaitOp: state=%q err=%v; want succeeded after tolerated blips", state, err)
	}
}

// A 4xx poll response (e.g. op-not-found after an agent restart) is deterministic
// — WaitOp gives up at once rather than retrying.
func TestHTTPAgentClient_WaitOpFailsFastOn4xx(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	c, err := NewHTTPAgentClient(ts.URL, ts.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.pollInterval = time.Millisecond

	if _, err := c.WaitOp(context.Background(), "op-gone"); err == nil {
		t.Fatal("WaitOp: want an error on 4xx")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("WaitOp polled %d times on 4xx; want exactly 1 (no retry)", got)
	}
}

// Persistent transient errors exhaust the budget and surface an error rather
// than polling forever.
func TestHTTPAgentClient_WaitOpExhaustsTransientBudget(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway) // always 502
	}))
	defer ts.Close()

	c, err := NewHTTPAgentClient(ts.URL, ts.Client())
	if err != nil {
		t.Fatal(err)
	}
	c.pollInterval = time.Millisecond

	if _, err := c.WaitOp(context.Background(), "op-bad"); err == nil {
		t.Fatal("WaitOp: want an error after the transient budget is exhausted")
	}
}
