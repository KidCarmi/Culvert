package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
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

func (f *fakeAgent) WaitOp(_ context.Context, _ string) (string, error) {
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

func TestExec_AlreadyCurrentDoesNotCallAgent(t *testing.T) {
	cat := mustLoad(t, validSource())
	plan := planTo(t, cat, DispatchConfig{ProxyRepo: dispatchRepo}, []string{dispatchRepo + "@" + digA})
	if plan.Outcome != OutcomeAlreadyCurrent {
		t.Fatalf("precondition: want already_current; got %s", plan.Outcome)
	}
	agent := &fakeAgent{applyOpID: "op-x"}
	res, err := newExec(agent, nil).Execute(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if res.Terminal != TerminalAlreadyCurrent {
		t.Fatalf("terminal = %s; want already_current", res.Terminal)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("agent must not be called for an already-current plan; saw %d applies", len(agent.applyReqs))
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
