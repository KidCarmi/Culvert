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

// ─── capture sinks ───────────────────────────────────────────────────────────

type capturedAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (c *capturedAudit) add(e AuditEntry) {
	c.mu.Lock()
	c.entries = append(c.entries, e)
	c.mu.Unlock()
}

func (c *capturedAudit) byAction(action string) []AuditEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []AuditEntry
	for _, e := range c.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

type capturedAlerts struct {
	mu       sync.Mutex
	events   []string
	payloads []AlertPayload
}

func (c *capturedAlerts) fire(event string, p AlertPayload) {
	c.mu.Lock()
	c.events = append(c.events, event)
	c.payloads = append(c.payloads, p)
	c.mu.Unlock()
}

func (c *capturedAlerts) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// newService builds a DispatchService whose transport, audit, alert, and op-id
// are injected (one shared fake agent for every endpoint key).
func newService(t *testing.T, cat *Catalog, agent AgentClient) (*DispatchService, *capturedAudit, *capturedAlerts) {
	t.Helper()
	return newServiceWith(t, cat, func(AgentEndpoint) (AgentClient, error) { return agent, nil })
}

// newServiceWith builds a service with a caller-supplied client factory (for
// multi-agent / endpoint-rebinding tests); audit/alert/op-id are injected.
func newServiceWith(t *testing.T, cat *Catalog, newClient func(AgentEndpoint) (AgentClient, error)) (*DispatchService, *capturedAudit, *capturedAlerts) {
	t.Helper()
	svc, err := NewDispatchService(&fakeCatProvider{cat: cat}, DispatchConfig{ProxyRepo: dispatchRepo})
	if err != nil {
		t.Fatalf("NewDispatchService: %v", err)
	}
	au, al := &capturedAudit{}, &capturedAlerts{}
	svc.newClient = newClient
	svc.newOpID = func() string { return "OP01" }
	svc.auditSink = au.add
	svc.alert = al.fire
	return svc, au, al
}

// freshDispatchSeq is the RunningDigests sequence for a clean OutcomePlan
// dispatch driven through the SERVICE: pre-plan read (prior), executor anchor
// (prior), post-verify read (target).
func freshDispatchSeq() [][]string {
	return [][]string{
		{dispatchRepo + "@" + digB},
		{dispatchRepo + "@" + digB},
		{dispatchRepo + "@" + digA},
	}
}

var testEP = AgentEndpoint{Key: "agent-1", BaseURL: "http://agent.invalid"}

// ─── single-flight registry: duplicate dispatch rejection ───────────────────

func TestService_DuplicateDispatchRejected(t *testing.T) {
	cat := mustLoad(t, validSource())
	// Pre-plan read returns a DIFFERENT known release ⇒ a real OutcomePlan.
	agent := &fakeAgent{applyOpID: "op-1", waitState: agentStateSucceeded,
		runningSeq: [][]string{{dispatchRepo + "@" + digB}, {dispatchRepo + "@" + digA}}}
	svc, au, _ := newService(t, cat, agent)

	// Hold the agent's single-flight (as if a dispatch were mid-op).
	reg, err := svc.registryFor(testEP)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.exec.acquire() {
		t.Fatal("precondition: acquire should succeed")
	}
	defer reg.exec.release()

	rep, err := svc.Dispatch(context.Background(), "admin@10.0.0.1", testEP,
		DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions())
	if !errors.Is(err, errDispatchInFlight) {
		t.Fatalf("err = %v; want errDispatchInFlight", err)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("a rejected dispatch must not apply; saw %d", len(agent.applyReqs))
	}
	// The rejection is audited as a release.dispatch decision, with no outcome.
	disp := au.byAction("release.dispatch")
	if len(disp) != 1 || !strings.Contains(disp[0].Detail, "dispatch_in_flight") {
		t.Fatalf("want one release.dispatch with dispatch_in_flight; got %+v", disp)
	}
	if got := au.byAction("release.dispatch.outcome"); len(got) != 0 {
		t.Fatalf("rejected dispatch must emit no outcome; got %+v", got)
	}
	_ = rep
}

// ─── resume / re-poll by existing op_id (no fresh apply) ────────────────────

func TestService_ResumeSucceedsWithoutApply(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{waitState: agentStateSucceeded,
		runningSeq: [][]string{{dispatchRepo + "@" + digA}}} // post-read verifies the target
	svc, au, _ := newService(t, cat, agent)

	rc := DispatchResumeContext{AgentID: testEP.Key, OpID: "op-prior", ReleaseID: "rel_a",
		TargetPinnedRef: dispatchRepo + "@" + digA, ImageRef: dispatchRepo + "@" + digA, IdempotencyKey: "rel-rel_a-OP01"}
	rep, err := svc.Resume(context.Background(), "admin@10.0.0.2", testEP, rc)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Terminal != TerminalSucceeded || !rep.Verified {
		t.Fatalf("terminal=%s verified=%v; want succeeded/true", rep.Terminal, rep.Verified)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("resume must NOT apply; saw %d", len(agent.applyReqs))
	}
	out := au.byAction("release.dispatch.outcome")
	if len(out) != 1 || !strings.Contains(out[0].Detail, "op_id=op-prior") {
		t.Fatalf("want one outcome audit carrying op_id=op-prior; got %+v", out)
	}
}

// Resume works from a freshly-built context (simulating a CP restart with only
// the persisted record): op_id + target pinned ref are enough — NO in-memory
// plan and NO idempotency key required.
func TestService_ResumeFromContextWithoutPlanOrKey(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{waitState: agentStateSucceeded,
		runningSeq: [][]string{{dispatchRepo + "@" + digA}}}
	svc, _, _ := newService(t, cat, agent)

	rc := DispatchResumeContext{
		AgentID:         testEP.Key,
		OpID:            "op-restart",
		ReleaseID:       "rel_a",
		TargetPinnedRef: dispatchRepo + "@" + digA,
		// ImageRef + IdempotencyKey intentionally empty — not needed to resume.
	}
	rep, err := svc.Resume(context.Background(), "admin@10.0.0.20", testEP, rc)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Terminal != TerminalSucceeded || !rep.Verified {
		t.Fatalf("terminal=%s verified=%v; want succeeded/true from op_id+target alone", rep.Terminal, rep.Verified)
	}
	if rep.OpID != "op-restart" {
		t.Fatalf("op_id = %q; want op-restart", rep.OpID)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("resume must NOT apply; saw %d", len(agent.applyReqs))
	}
}

func TestService_ResumeVerifyMismatchAlerts(t *testing.T) {
	cat := mustLoad(t, validSource())
	// Op succeeded but the running digest is NOT the target ⇒ needs attention.
	agent := &fakeAgent{waitState: agentStateSucceeded,
		runningSeq: [][]string{{dispatchRepo + "@" + digB}}}
	svc, _, al := newService(t, cat, agent)

	rc := DispatchResumeContext{OpID: "op-x", ReleaseID: "rel_a", TargetPinnedRef: dispatchRepo + "@" + digA}
	rep, _ := svc.Resume(context.Background(), "admin@10.0.0.3", testEP, rc)
	if rep.Terminal != TerminalFailedNeedsAttn {
		t.Fatalf("terminal=%s; want failed_needs_attn", rep.Terminal)
	}
	if al.count() != 1 || al.events[0] != "release_dispatch_attention" {
		t.Fatalf("want one release_dispatch_attention alert; got %v", al.events)
	}
}

func TestService_ResumeRejectedWhenInFlight(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{waitState: agentStateSucceeded, runningSeq: [][]string{{dispatchRepo + "@" + digA}}}
	svc, _, _ := newService(t, cat, agent)
	reg, _ := svc.registryFor(testEP)
	if !reg.exec.acquire() {
		t.Fatal("acquire should succeed")
	}
	defer reg.exec.release()

	_, err := svc.Resume(context.Background(), "admin@10.0.0.4", testEP,
		DispatchResumeContext{OpID: "op-y", ReleaseID: "rel_a", TargetPinnedRef: dispatchRepo + "@" + digA})
	if !errors.Is(err, errDispatchInFlight) {
		t.Fatalf("err = %v; want errDispatchInFlight", err)
	}
}

func TestService_ResumeNeedsOpID(t *testing.T) {
	cat := mustLoad(t, validSource())
	svc, _, _ := newService(t, cat, &fakeAgent{})
	if _, err := svc.Resume(context.Background(), "a", testEP, DispatchResumeContext{ReleaseID: "rel_a"}); err == nil {
		t.Fatal("want an error when op_id is empty")
	}
}

// ─── refusals audited ───────────────────────────────────────────────────────

func TestService_RefusalAudited(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{runningSeq: [][]string{nil}} // pre-read OK; target is the problem
	svc, au, _ := newService(t, cat, agent)

	rep, err := svc.Dispatch(context.Background(), "admin@10.0.0.5", testEP,
		DispatchTarget{ReleaseID: "does-not-exist"}, DefaultDispatchOptions())
	if err == nil {
		t.Fatal("want a refusal error")
	}
	if rep.Outcome != OutcomeRefused || rep.RefusedKind != RefusedUnknownTarget {
		t.Fatalf("outcome=%s kind=%s; want refused/unknown_target", rep.Outcome, rep.RefusedKind)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("a refused dispatch must not apply; saw %d", len(agent.applyReqs))
	}
	disp := au.byAction("release.dispatch")
	if len(disp) != 1 || !strings.Contains(disp[0].Detail, "refused=unknown_target") {
		t.Fatalf("want one release.dispatch carrying refused=unknown_target; got %+v", disp)
	}
	if got := au.byAction("release.dispatch.outcome"); len(got) != 0 {
		t.Fatalf("a pure refusal emits no outcome; got %+v", got)
	}
}

func TestService_PreflightReadFailureRefuses(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{runningErrs: []error{errors.New("status down")}}
	svc, au, al := newService(t, cat, agent)

	_, err := svc.Dispatch(context.Background(), "admin@10.0.0.6", testEP,
		DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions())
	if err == nil {
		t.Fatal("want an error when the preflight read fails")
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("must not apply; saw %d", len(agent.applyReqs))
	}
	if d := au.byAction("release.dispatch"); len(d) != 1 || !strings.Contains(d[0].Detail, "preflight_read_failed") {
		t.Fatalf("want one release.dispatch with preflight_read_failed; got %+v", d)
	}
	if al.count() != 0 {
		t.Fatal("a retryable preflight read failure must not alert")
	}
}

// ─── already-current audited ────────────────────────────────────────────────

func TestService_AlreadyCurrentAudited(t *testing.T) {
	cat := mustLoad(t, validSource())
	// Pre-read (plan) and the executor's fresh re-check both show the target.
	agent := &fakeAgent{runningSeq: [][]string{{dispatchRepo + "@" + digA}, {dispatchRepo + "@" + digA}}}
	svc, au, al := newService(t, cat, agent)

	rep, err := svc.Dispatch(context.Background(), "admin@10.0.0.7", testEP,
		DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Terminal != TerminalAlreadyCurrent {
		t.Fatalf("terminal=%s; want already_current", rep.Terminal)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("already-current must not apply; saw %d", len(agent.applyReqs))
	}
	if len(au.byAction("release.dispatch")) != 1 || len(au.byAction("release.dispatch.outcome")) != 1 {
		t.Fatalf("want a dispatch + outcome pair; got %+v", au.entries)
	}
	if al.count() != 0 {
		t.Fatal("already-current must not alert")
	}
}

// ─── terminal alert + idempotency ───────────────────────────────────────────

func TestService_NeedsAttnAlertsAndAudits(t *testing.T) {
	cat := mustLoad(t, validSource())
	// Op fails and the node is NOT back on the prior image ⇒ failed_needs_attn.
	// Reads in order: pre-plan, executor anchor (prior digB), post (foreign).
	agent := &fakeAgent{applyOpID: "op-7", waitState: agentStateFailed,
		runningSeq: [][]string{
			{dispatchRepo + "@" + digB},
			{dispatchRepo + "@" + digB},
			{dispatchRepo + "@sha256:" + repeat64('d')},
		}}
	svc, au, al := newService(t, cat, agent)

	rep, err := svc.Dispatch(context.Background(), "admin@10.0.0.8", testEP,
		DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Terminal != TerminalFailedNeedsAttn {
		t.Fatalf("terminal=%s; want failed_needs_attn", rep.Terminal)
	}
	if al.count() != 1 || al.events[0] != "release_dispatch_attention" {
		t.Fatalf("want one release_dispatch_attention alert; got %v", al.events)
	}
	if len(au.byAction("release.dispatch.outcome")) != 1 {
		t.Fatalf("want one outcome audit; got %+v", au.entries)
	}
}

func TestService_IdempotencyKeyStableAndHonored(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{applyOpID: "op-k", waitState: agentStateSucceeded,
		runningSeq: [][]string{{dispatchRepo + "@" + digB}, {dispatchRepo + "@" + digA}}}
	svc, _, _ := newService(t, cat, agent) // newOpID pinned → OP01

	rep, err := svc.Dispatch(context.Background(), "admin@10.0.0.9", testEP,
		DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions())
	if err != nil {
		t.Fatal(err)
	}
	if agent.applyReqs[0].IdempotencyKey != "rel-rel_a-OP01" {
		t.Fatalf("apply key = %q; want service-generated rel-rel_a-OP01", agent.applyReqs[0].IdempotencyKey)
	}
	if rep.IdempotencyKey != "rel-rel_a-OP01" {
		t.Fatalf("report key = %q; want rel-rel_a-OP01", rep.IdempotencyKey)
	}
	if rc := rep.ResumeContext(testEP.Key); rc.OpID != "op-k" || rc.TargetPinnedRef != dispatchRepo+"@"+digA || rc.AgentID != testEP.Key {
		t.Fatalf("ResumeContext = %+v; want op-k + target pinned ref + agent id", rc)
	}
}

// The release.dispatch audit (carrying op_id) is persisted BEFORE the blocking
// watch resolves — so a CP crash mid-watch still leaves a durable correlation
// handle for the resume path.
func TestService_DispatchAuditedBeforeTerminal(t *testing.T) {
	cat := mustLoad(t, validSource())
	gate := make(chan struct{})
	agent := &fakeAgent{applyOpID: "op-dur", waitState: agentStateSucceeded,
		runningSeq: [][]string{
			{dispatchRepo + "@" + digB}, // pre-plan ⇒ OutcomePlan
			{dispatchRepo + "@" + digB}, // anchor
			{dispatchRepo + "@" + digA}, // post (verifies)
		},
		waitGate: gate}
	svc, au, _ := newService(t, cat, agent)

	done := make(chan struct{})
	go func() {
		_, _ = svc.Dispatch(context.Background(), "admin@10.0.0.10", testEP,
			DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions())
		close(done)
	}()

	// The dispatch audit (with op_id) lands while WaitOp is still gated.
	waitFor(t, func() bool {
		d := au.byAction("release.dispatch")
		return len(d) == 1 && strings.Contains(d[0].Detail, "op_id=op-dur")
	}, "release.dispatch with op_id=op-dur before terminal")

	if got := au.byAction("release.dispatch.outcome"); len(got) != 0 {
		t.Fatalf("outcome must not be recorded while the watch is still blocked; got %+v", got)
	}

	close(gate) // let WaitOp return
	<-done
	if got := au.byAction("release.dispatch.outcome"); len(got) != 1 {
		t.Fatalf("want one outcome audit after terminal; got %+v", got)
	}
}

// ─── P1.6d-0 findings: isolation, rebinding, key, alert suppression ─────────

// A dispatch to agent B runs while agent A holds its single-flight — the
// registry is per-agent, not a global lock.
func TestService_PerAgentIsolation(t *testing.T) {
	cat := mustLoad(t, validSource())
	agentA := &fakeAgent{}
	agentB := &fakeAgent{applyOpID: "op-b", waitState: agentStateSucceeded, runningSeq: freshDispatchSeq()}
	agents := map[string]*fakeAgent{"A": agentA, "B": agentB}
	svc, _, _ := newServiceWith(t, cat, func(ep AgentEndpoint) (AgentClient, error) { return agents[ep.Key], nil })

	// Hold agent A's single-flight (as if a dispatch were mid-op).
	regA, err := svc.registryFor(AgentEndpoint{Key: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if !regA.exec.acquire() {
		t.Fatal("acquire A should succeed")
	}
	defer regA.exec.release()

	rep, err := svc.Dispatch(context.Background(), "admin@1", AgentEndpoint{Key: "B"},
		DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions())
	if err != nil {
		t.Fatalf("dispatch to B while A is busy: %v", err)
	}
	if rep.Terminal != TerminalSucceeded {
		t.Fatalf("agent B terminal=%s; want succeeded (A's lock must not block B)", rep.Terminal)
	}
	if len(agentB.applyReqs) != 1 {
		t.Fatalf("agent B should have applied once; got %d", len(agentB.applyReqs))
	}
}

// A caller-supplied idempotency key is preserved verbatim (never re-minted).
func TestService_CallerSuppliedIdempotencyKeyPreserved(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{applyOpID: "op-c", waitState: agentStateSucceeded, runningSeq: freshDispatchSeq()}
	svc, _, _ := newService(t, cat, agent) // newOpID pinned → OP01 (must NOT be used)

	opts := DefaultDispatchOptions()
	opts.IdempotencyKey = "caller-key-123"
	rep, err := svc.Dispatch(context.Background(), "admin@2", testEP, DispatchTarget{ReleaseID: "rel_a"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if agent.applyReqs[0].IdempotencyKey != "caller-key-123" {
		t.Fatalf("apply key = %q; want the caller-supplied caller-key-123", agent.applyReqs[0].IdempotencyKey)
	}
	if rep.IdempotencyKey != "caller-key-123" {
		t.Fatalf("report key = %q; want caller-key-123", rep.IdempotencyKey)
	}
}

func TestService_SuccessDoesNotAlert(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{applyOpID: "op-s", waitState: agentStateSucceeded, runningSeq: freshDispatchSeq()}
	svc, _, al := newService(t, cat, agent)
	rep, err := svc.Dispatch(context.Background(), "admin@3", testEP, DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Terminal != TerminalSucceeded {
		t.Fatalf("terminal=%s; want succeeded", rep.Terminal)
	}
	if al.count() != 0 {
		t.Fatalf("a successful dispatch must not alert; fired %d", al.count())
	}
}

// Stale already-current is audited but does NOT page (it is a re-plan signal).
func TestService_StaleAlreadyCurrentDoesNotAlert(t *testing.T) {
	cat := mustLoad(t, validSource())
	drift := dispatchRepo + "@sha256:" + repeat64('e')
	// pre-plan read shows target (already_current); executor re-read shows drift.
	agent := &fakeAgent{runningSeq: [][]string{{dispatchRepo + "@" + digA}, {drift}}}
	svc, au, al := newService(t, cat, agent)

	rep, err := svc.Dispatch(context.Background(), "admin@4", testEP, DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions())
	if !errors.Is(err, errStaleAlreadyCurrent) {
		t.Fatalf("err = %v; want errStaleAlreadyCurrent", err)
	}
	if rep.Terminal != TerminalFailedNeedsAttn {
		t.Fatalf("terminal=%s; want failed_needs_attn", rep.Terminal)
	}
	if al.count() != 0 {
		t.Fatalf("stale already-current must NOT page; fired %d", al.count())
	}
	if len(au.byAction("release.dispatch.outcome")) != 1 {
		t.Fatalf("stale must still be audited; got %+v", au.entries)
	}
}

// Changing an endpoint's transport for the same key rebuilds the client.
func TestService_EndpointRebindingUsesNewClient(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent1 := &fakeAgent{applyOpID: "op1", waitState: agentStateSucceeded, runningSeq: freshDispatchSeq()}
	agent2 := &fakeAgent{applyOpID: "op2", waitState: agentStateSucceeded, runningSeq: freshDispatchSeq()}
	var built []string
	svc, _, _ := newServiceWith(t, cat, func(ep AgentEndpoint) (AgentClient, error) {
		built = append(built, ep.BaseURL)
		if ep.BaseURL == "url1" {
			return agent1, nil
		}
		return agent2, nil
	})

	if _, err := svc.Dispatch(context.Background(), "admin@5", AgentEndpoint{Key: "X", BaseURL: "url1"},
		DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions()); err != nil {
		t.Fatal(err)
	}
	// Same key, new transport ⇒ rebind to the new client.
	if _, err := svc.Dispatch(context.Background(), "admin@5", AgentEndpoint{Key: "X", BaseURL: "url2"},
		DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions()); err != nil {
		t.Fatal(err)
	}
	if len(built) != 2 || built[0] != "url1" || built[1] != "url2" {
		t.Fatalf("client factory built from %v; want [url1 url2]", built)
	}
	if len(agent2.applyReqs) != 1 {
		t.Fatalf("rebind must route the second dispatch to the new client; agent2 applies=%d", len(agent2.applyReqs))
	}
}

// ─── real transport wiring (default httpAgentClient, end-to-end) ─────────────

func TestService_RealTransportEndToEnd(t *testing.T) {
	var applied atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/upgrades/apply":
			applied.Store(true)
			_, _ = w.Write([]byte(`{"op_id":"op-real"}`))
		case r.URL.Path == "/v1/operations/op-real":
			_, _ = w.Write([]byte(`{"state":"succeeded"}`))
		case r.URL.Path == "/v1/status":
			dg := dispatchRepo + "@" + digB // prior, until the upgrade applies
			if applied.Load() {
				dg = dispatchRepo + "@" + digA // now on target ⇒ verify passes
			}
			_, _ = w.Write([]byte(`{"running_image":{"repo_digests":["` + dg + `"]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	cat := mustLoad(t, validSource())
	svc, err := NewDispatchService(&fakeCatProvider{cat: cat}, DispatchConfig{ProxyRepo: dispatchRepo})
	if err != nil {
		t.Fatal(err)
	}
	svc.newOpID = func() string { return "OP01" }
	svc.auditSink = func(AuditEntry) {}       // isolate from the global ring
	svc.alert = func(string, AlertPayload) {} // isolate from global webhooks
	// newClient is NOT overridden ⇒ exercises the real httpAgentClient transport.

	ep := AgentEndpoint{Key: "agent-real", BaseURL: ts.URL, Client: ts.Client()}
	rep, err := svc.Dispatch(context.Background(), "admin@127.0.0.1", ep,
		DispatchTarget{ReleaseID: "rel_a"}, DefaultDispatchOptions())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Terminal != TerminalSucceeded || !rep.Verified {
		t.Fatalf("terminal=%s verified=%v; want succeeded/true (real transport)", rep.Terminal, rep.Verified)
	}
	if rep.OpID != "op-real" {
		t.Fatalf("op_id = %q; want op-real", rep.OpID)
	}
}

// ─── helpers ────────────────────────────────────────────────────────────────

func repeat64(b byte) string { return strings.Repeat(string(b), 64) }

// waitFor polls cond up to ~2s, failing the test if it never holds.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
