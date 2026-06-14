package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─── fixture ─────────────────────────────────────────────────────────────────

// newReleaseFixture wires a releaseManager (DispatchService over fake agents +
// a key→endpoint resolver), publishes it as the global, and returns the manager,
// the captured audit, and the captured alerts. newOpID is pinned for the service
// (idempotency key) but dispatch_id stays a real ULID (unique per dispatch).
func newReleaseFixture(t *testing.T, cat *Catalog, agents map[string]*fakeAgent) (*releaseManager, *capturedAudit, *capturedAlerts) {
	t.Helper()
	au, al := &capturedAudit{}, &capturedAlerts{}
	svc, err := NewDispatchService(&fakeCatProvider{cat: cat}, DispatchConfig{ProxyRepo: dispatchRepo})
	if err != nil {
		t.Fatalf("NewDispatchService: %v", err)
	}
	svc.newClient = func(ep AgentEndpoint) (AgentClient, error) {
		a, ok := agents[ep.Key]
		if !ok {
			t.Fatalf("no fake agent for key %q", ep.Key)
		}
		return a, nil
	}
	svc.newOpID = func() string { return "OP01" }
	svc.auditSink = au.add
	svc.alert = al.fire

	resolve := func(key string) (AgentEndpoint, bool) {
		if _, ok := agents[key]; ok {
			return AgentEndpoint{Key: key, BaseURL: "http://" + key}, true
		}
		return AgentEndpoint{}, false
	}
	rm := newReleaseManager(svc, resolve)
	setReleaseManager(rm)
	t.Cleanup(func() { setReleaseManager(nil) })
	return rm, au, al
}

func releaseReq(method, path string, body any, role UIRole) *http.Request {
	var rdr io.Reader = http.NoBody
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, rdr)
	r.RemoteAddr = "192.0.2.10:1234"
	return r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return m
}

// waitTerminal blocks until the agent's status record reaches a terminal phase.
//
//nolint:unparam // agent is parameterized for clarity; all current callers use "A"
func waitTerminal(t *testing.T, rm *releaseManager, agent string) dispatchRecord {
	t.Helper()
	var rec dispatchRecord
	waitFor(t, func() bool {
		r, ok := rm.store.get(agent)
		rec = r
		return ok && r.Phase == phaseTerminal
	}, "terminal status for "+agent)
	return rec
}

// ─── auth roles ──────────────────────────────────────────────────────────────

func TestReleaseAPI_AuthRoles(t *testing.T) {
	cat := mustLoad(t, validSource())
	newReleaseFixture(t, cat, map[string]*fakeAgent{"A": {runningSeq: freshDispatchSeq(), applyOpID: "op", waitState: agentStateSucceeded}})

	// viewer may read.
	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer GET /api/releases = %d; want 200", rec.Code)
	}

	// viewer may NOT mutate.
	rec = httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleViewer))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST dispatch = %d; want 403", rec.Code)
	}

	// admin may mutate (gets past auth — 202 for a fresh dispatch).
	rec = httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("admin POST dispatch = %d; want 202", rec.Code)
	}
}

func TestReleaseAPI_DispatchValidatesBody(t *testing.T) {
	cat := mustLoad(t, validSource())
	newReleaseFixture(t, cat, map[string]*fakeAgent{"A": {}})

	cases := []struct {
		name string
		body dispatchRequest
		code int
	}{
		{"both target", dispatchRequest{ReleaseID: "rel_a", Channel: "recommended", Agent: "A"}, http.StatusBadRequest},
		{"no target", dispatchRequest{Agent: "A"}, http.StatusBadRequest},
		{"no agent", dispatchRequest{ReleaseID: "rel_a"}, http.StatusBadRequest},
		{"unknown agent", dispatchRequest{ReleaseID: "rel_a", Agent: "ghost"}, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch", tc.body, RoleAdmin))
			if rec.Code != tc.code {
				t.Fatalf("code = %d; want %d (%s)", rec.Code, tc.code, rec.Body.String())
			}
		})
	}
}

// ─── refusal audited ─────────────────────────────────────────────────────────

func TestReleaseAPI_DispatchRefusalAudited(t *testing.T) {
	cat := mustLoad(t, validSource())
	// pre-plan read OK; the unknown release is the refusal.
	_, au, _ := newReleaseFixture(t, cat, map[string]*fakeAgent{"A": {runningSeq: [][]string{nil}}})

	rec := httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "does-not-exist", Agent: "A"}, RoleAdmin))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown release dispatch = %d; want 404", rec.Code)
	}
	if d := au.byAction("release.dispatch"); len(d) != 1 {
		t.Fatalf("want one release.dispatch refusal audit; got %+v", d)
	}
	if got := au.byAction("release.dispatch.outcome"); len(got) != 0 {
		t.Fatalf("a refusal emits no outcome; got %+v", got)
	}
}

// ─── already-current audited, no alert, 200 ─────────────────────────────────

func TestReleaseAPI_DispatchAlreadyCurrent(t *testing.T) {
	cat := mustLoad(t, validSource())
	// pre-plan + executor re-read both show the target ⇒ already_current.
	agent := &fakeAgent{runningSeq: [][]string{{dispatchRepo + "@" + digA}, {dispatchRepo + "@" + digA}}}
	rm, au, al := newReleaseFixture(t, cat, map[string]*fakeAgent{"A": agent})

	rec := httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("already-current dispatch = %d; want 200 (%s)", rec.Code, rec.Body.String())
	}
	if got := decodeBody(t, rec)["status"]; got != "already_current" {
		t.Fatalf("status = %v; want already_current", got)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("already-current must not apply; saw %d", len(agent.applyReqs))
	}
	if al.count() != 0 {
		t.Fatalf("already-current must not alert; fired %d", al.count())
	}
	if len(au.byAction("release.dispatch.outcome")) != 1 {
		t.Fatal("already-current must be audited")
	}
	_ = rm
}

// ─── success: 202 then terminal, no alert ───────────────────────────────────

func TestReleaseAPI_DispatchSuccess(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{applyOpID: "op-ok", waitState: agentStateSucceeded, runningSeq: freshDispatchSeq()}
	rm, _, al := newReleaseFixture(t, cat, map[string]*fakeAgent{"A": agent})

	rec := httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("success dispatch = %d; want 202 (%s)", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["op_id"] != "op-ok" {
		t.Fatalf("202 op_id = %v; want op-ok", body["op_id"])
	}
	rrec := waitTerminal(t, rm, "A")
	if rrec.Terminal != TerminalSucceeded || !rrec.Verified {
		t.Fatalf("terminal record = %+v; want succeeded/verified", rrec)
	}
	if al.count() != 0 {
		t.Fatalf("success must not alert; fired %d", al.count())
	}
}

// ─── failed_needs_attn: 202 then terminal + exactly one alert ───────────────

func TestReleaseAPI_DispatchNeedsAttnAlertsOnce(t *testing.T) {
	cat := mustLoad(t, validSource())
	// Op fails and the node is NOT back on the prior image ⇒ failed_needs_attn.
	agent := &fakeAgent{applyOpID: "op-fail", waitState: agentStateFailed,
		runningSeq: [][]string{
			{dispatchRepo + "@" + digB},
			{dispatchRepo + "@" + digB},
			{dispatchRepo + "@sha256:" + repeat64('d')},
		}}
	rm, _, al := newReleaseFixture(t, cat, map[string]*fakeAgent{"A": agent})

	rec := httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("dispatch = %d; want 202", rec.Code)
	}
	rrec := waitTerminal(t, rm, "A")
	if rrec.Terminal != TerminalFailedNeedsAttn {
		t.Fatalf("terminal = %s; want failed_needs_attn", rrec.Terminal)
	}
	if al.count() != 1 {
		t.Fatalf("failed_needs_attn must alert exactly once; fired %d", al.count())
	}
}

// ─── duplicate same-agent dispatch rejected (409) ───────────────────────────

func TestReleaseAPI_DuplicateDispatchRejected(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{applyOpID: "op-d", waitState: agentStateSucceeded, runningSeq: freshDispatchSeq()}
	rm, _, _ := newReleaseFixture(t, cat, map[string]*fakeAgent{"A": agent})

	// Hold A's single-flight, simulating an in-flight op.
	reg, err := rm.svc.registryFor(AgentEndpoint{Key: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if !reg.exec.acquire() {
		t.Fatal("acquire should succeed")
	}
	defer reg.exec.release()

	rec := httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate dispatch = %d; want 409 (%s)", rec.Code, rec.Body.String())
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("a rejected dispatch must not apply; saw %d", len(agent.applyReqs))
	}
}

// ─── resume: 202, re-polls, never applies ───────────────────────────────────

func TestReleaseAPI_ResumeDoesNotApply(t *testing.T) {
	cat := mustLoad(t, validSource())
	// WaitOp succeeded + post-read verifies ⇒ resume terminal succeeded, no Apply.
	agent := &fakeAgent{waitState: agentStateSucceeded, runningSeq: [][]string{{dispatchRepo + "@" + digA}}}
	rm, _, _ := newReleaseFixture(t, cat, map[string]*fakeAgent{"A": agent})

	body := resumeRequest{Agent: "A", ResumeContext: &DispatchResumeContext{
		AgentID: "A", OpID: "op-prior", ReleaseID: "rel_a", TargetPinnedRef: dispatchRepo + "@" + digA,
	}}
	rec := httptest.NewRecorder()
	apiReleaseDispatchResume(rec, releaseReq(http.MethodPost, "/api/releases/dispatch/resume", body, RoleAdmin))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("resume = %d; want 202 (%s)", rec.Code, rec.Body.String())
	}
	rrec := waitTerminal(t, rm, "A")
	if rrec.Terminal != TerminalSucceeded {
		t.Fatalf("resume terminal = %s; want succeeded", rrec.Terminal)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("resume must NOT apply; saw %d", len(agent.applyReqs))
	}
}

func TestReleaseAPI_ResumeRejectsViewer(t *testing.T) {
	cat := mustLoad(t, validSource())
	newReleaseFixture(t, cat, map[string]*fakeAgent{"A": {}})
	rec := httptest.NewRecorder()
	apiReleaseDispatchResume(rec, releaseReq(http.MethodPost, "/api/releases/dispatch/resume",
		resumeRequest{Agent: "A", ResumeContext: &DispatchResumeContext{OpID: "x", TargetPinnedRef: "r"}}, RoleViewer))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer resume = %d; want 403", rec.Code)
	}
}

// ─── status endpoint ─────────────────────────────────────────────────────────

func TestReleaseAPI_Status(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{applyOpID: "op-st", waitState: agentStateSucceeded, runningSeq: freshDispatchSeq()}
	rm, _, _ := newReleaseFixture(t, cat, map[string]*fakeAgent{"A": agent})

	// No dispatch yet ⇒ phase none.
	rec := httptest.NewRecorder()
	apiReleaseDispatchStatus(rec, releaseReq(http.MethodGet, "/api/releases/dispatch/status?agent=A", nil, RoleViewer))
	if rec.Code != http.StatusOK || decodeBody(t, rec)["phase"] != "none" {
		t.Fatalf("status before dispatch = %d %s; want 200/none", rec.Code, rec.Body.String())
	}

	// After a dispatch, status reflects the terminal record.
	drec := httptest.NewRecorder()
	apiReleaseDispatch(drec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))
	waitTerminal(t, rm, "A")

	rec = httptest.NewRecorder()
	apiReleaseDispatchStatus(rec, releaseReq(http.MethodGet, "/api/releases/dispatch/status?agent=A", nil, RoleViewer))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := decodeBody(t, rec)["terminal"]; got != string(TerminalSucceeded) {
		t.Fatalf("status terminal = %v; want succeeded", got)
	}
}

// A rejected duplicate (in-flight) must NOT clobber the running op's status
// record (P2: status-clobber).
func TestReleaseAPI_DuplicateDoesNotClobberStatus(t *testing.T) {
	cat := mustLoad(t, validSource())
	agent := &fakeAgent{applyOpID: "op-A", waitState: agentStateSucceeded, runningSeq: freshDispatchSeq()}
	rm, _, _ := newReleaseFixture(t, cat, map[string]*fakeAgent{"A": agent})

	// Seed agent A's slot as a running op, then hold its single-flight so a
	// second dispatch is rejected in-flight.
	idA := rm.newID()
	rm.store.markDispatched("A", idA, DispatchResumeContext{
		AgentID: "A", OpID: "op-A", ReleaseID: "rel_a", TargetPinnedRef: dispatchRepo + "@" + digA,
	})
	reg, err := rm.svc.registryFor(AgentEndpoint{Key: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if !reg.exec.acquire() {
		t.Fatal("acquire should succeed")
	}
	defer reg.exec.release()

	rec := httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate dispatch = %d; want 409", rec.Code)
	}
	// The in-flight op's record must be intact.
	st, ok := rm.store.get("A")
	if !ok || st.OpID != "op-A" || st.Phase != phaseDispatched {
		t.Fatalf("in-flight op status was clobbered: %+v", st)
	}
	if len(agent.applyReqs) != 0 {
		t.Fatalf("rejected dispatch must not apply; saw %d", len(agent.applyReqs))
	}
}

// An apply failure BEFORE an op_id (agent rejection / retries exhausted) must
// surface as an error, not 200 "ok" (P2: false success).
func TestReleaseAPI_ApplyFailureBeforeOpIsError(t *testing.T) {
	cat := mustLoad(t, validSource())
	// pre-plan + anchor reads OK; Apply returns a deterministic 4xx (not retried).
	agent := &fakeAgent{
		applyErrs:  []error{&agentHTTPError{Status: 400, Method: "POST", Path: "/v1/upgrades/apply"}},
		runningSeq: [][]string{{dispatchRepo + "@" + digB}, {dispatchRepo + "@" + digB}},
	}
	newReleaseFixture(t, cat, map[string]*fakeAgent{"A": agent})

	rec := httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("apply-failure dispatch = %d; want 502 (%s)", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["status"] != "failed" {
		t.Fatalf("status = %v; want failed", body["status"])
	}
	if len(agent.applyReqs) != 1 {
		t.Fatalf("a deterministic 4xx must not be retried; saw %d applies", len(agent.applyReqs))
	}
}

// An accepted dispatch must survive client disconnect / request cancellation
// after the 202: the background work runs on a detached context, not r.Context().
func TestReleaseAPI_DispatchSurvivesRequestCancel(t *testing.T) {
	cat := mustLoad(t, validSource())
	gate := make(chan struct{})
	agent := &fakeAgent{applyOpID: "op-detach", waitState: agentStateSucceeded,
		runningSeq: freshDispatchSeq(), waitGate: gate}
	rm, _, _ := newReleaseFixture(t, cat, map[string]*fakeAgent{"A": agent})

	// Build a request with a cancellable context (simulating the client).
	ctx, cancel := context.WithCancel(context.Background())
	b, _ := json.Marshal(dispatchRequest{ReleaseID: "rel_a", Agent: "A"})
	r := httptest.NewRequest(http.MethodPost, "/api/releases/dispatch", bytes.NewReader(b))
	r.RemoteAddr = "192.0.2.11:5555"
	r = r.WithContext(context.WithValue(ctx, uiRoleKey{}, RoleAdmin))

	rec := httptest.NewRecorder()
	apiReleaseDispatch(rec, r) // returns 202 once the op is recorded; watch is gated
	if rec.Code != http.StatusAccepted {
		t.Fatalf("dispatch = %d; want 202 (%s)", rec.Code, rec.Body.String())
	}

	// Client disconnects / cancels AFTER the 202 — the accepted op must not abort.
	cancel()
	close(gate) // let the (still-running) watch finish

	rrec := waitTerminal(t, rm, "A")
	if rrec.Terminal != TerminalSucceeded || !rrec.Verified {
		t.Fatalf("terminal after cancel = %+v; want succeeded/verified (request cancel must not kill the dispatch)", rrec)
	}
	if len(agent.applyReqs) != 1 {
		t.Fatalf("apply must have happened exactly once; saw %d", len(agent.applyReqs))
	}
}

// The status store resolves slot ownership by ULID-lexical dispatch_id ordering:
// a newer (larger) id wins, and a stale update from an older id is ignored.
func TestDispatchStore_ULIDOrderingOwnsSlot(t *testing.T) {
	st := newDispatchStore()
	older, newer := "01AAAAAAAA", "01ZZZZZZZZ" // ULIDs sort lexically by creation time
	if older >= newer {
		t.Fatal("precondition: older must sort before newer")
	}
	st.markDispatched("A", newer, DispatchResumeContext{OpID: "op-new"})
	// A late update from the OLDER dispatch must be ignored, not clobber the slot.
	st.markTerminal("A", older, &DispatchReport{Terminal: TerminalSucceeded})
	rec, ok := st.get("A")
	if !ok || rec.DispatchID != newer || rec.OpID != "op-new" {
		t.Fatalf("older update clobbered the newer slot: %+v", rec)
	}
	// The newer dispatch's own terminal update applies.
	st.markTerminal("A", newer, &DispatchReport{Terminal: TerminalSucceeded, OpID: "op-new"})
	if rec, _ := st.get("A"); rec.Phase != phaseTerminal {
		t.Fatalf("newer terminal update did not apply: %+v", rec)
	}
}

func TestReleaseAPI_Unconfigured503(t *testing.T) {
	setReleaseManager(nil)
	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured GET /api/releases = %d; want 503", rec.Code)
	}
}
