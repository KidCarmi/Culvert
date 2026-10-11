package main

// release_dispatch_panic_chaos_test.go — CHAOS-75 gates for the release-dispatch
// plane's two detached executor goroutines.
//
// Why these gates exist. Both dispatch entry points hand the upgrade to a
// goroutine that outlives its request, and neither had a panic tap. Against the
// pre-fix tree the first two tests below do not fail — they CRASH the test
// binary, which is the finding: one authenticated admin POST killed the proxy
// data plane, the admin plane and /healthz together.
//
// The sharper half is TestCHAOS75_DispatchWorkerPanicBeforeApply_Answers500 and
// its unit-level sibling. The pre-fix goroutine's only defer was close(done),
// which fires DURING unwinding — before `rep, derr = …` lands — so the handler
// woke on a zero pair and respondPreApply's `default` branch answered
// `200 {"status":"ok"}` for an upgrade that never started. Reproduced against
// main before the fix:
//
//	ZZPROBE STATUS=200 BODY={"status":"ok"}
//	panic: zz injected agent-client fault
//
// Today the runtime kills the process a moment later so that 200 is a race the
// client usually loses. Containment ALONE resolves the race the wrong way every
// time: the process survives to deliver a permanent, deterministic false
// success. So the gates assert the outcome, not just the survival.
//
// Assertions use the per-component crash COUNTER, never lastCrash or the audit
// ring: recordCrash throttles the expensive sinks to one per component per
// second (crashThrottleEvery) and the audit ring is bounded, while the counter
// always increments (crashguard.go:102-105).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// ─── fault injection ─────────────────────────────────────────────────────────

// panicAgent is an AgentClient that behaves like a healthy agent right up to a
// chosen call and panics there. The two injection points matter because they
// land on opposite sides of the 202: "running" faults the pre-apply read (no op
// exists, the HTTP reply is still open) and "wait" faults the watch (the op is
// LIVE on the agent and the 202 has shipped).
type panicAgent struct {
	panicAt string // "running" | "wait"

	mu          sync.Mutex
	runningSeq  [][]string
	runningCall int
	opID        string
	panics      atomic.Int32
}

func (p *panicAgent) RunningDigests(context.Context) ([]string, error) {
	if p.panicAt == "running" {
		p.panics.Add(1)
		panic("CHAOS-75 injected fault: agent running-digest read")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	i := p.runningCall
	p.runningCall++
	if i < len(p.runningSeq) {
		return p.runningSeq[i], nil
	}
	return nil, nil
}

func (p *panicAgent) Apply(context.Context, UpgradeApplyRequest) (string, error) {
	return p.opID, nil
}

func (p *panicAgent) WaitOp(context.Context, string) (string, error) {
	if p.panicAt == "wait" {
		p.panics.Add(1)
		panic("CHAOS-75 injected fault: agent op watch")
	}
	return agentStateSucceeded, nil
}

// newPanicReleaseFixture wires a releaseManager over a single injected
// AgentClient under the agent key "A". It mirrors newReleaseFixture but takes an
// arbitrary client so a panicking one can be installed.
func newPanicReleaseFixture(t *testing.T, client AgentClient) *releaseManager {
	t.Helper()
	cat := mustLoad(t, validSource())
	svc, err := NewDispatchService(&fakeCatProvider{cat: cat}, DispatchConfig{ProxyRepo: dispatchRepo})
	if err != nil {
		t.Fatalf("NewDispatchService: %v", err)
	}
	svc.newClient = func(AgentEndpoint) (AgentClient, error) { return client, nil }
	svc.auditSink = (&capturedAudit{}).add
	svc.alert = (&capturedAlerts{}).fire

	rm := newReleaseManager(svc, func(key string) (AgentEndpoint, bool) {
		if key != "A" {
			return AgentEndpoint{}, false
		}
		return AgentEndpoint{Key: key, BaseURL: "http://" + key}, true
	})
	setReleaseManager(rm)
	t.Cleanup(func() { setReleaseManager(nil) })
	return rm
}

var crashMetricRe = regexp.MustCompile(`culvert_crash_records_total\{component="([^"]+)"\} (\d+)`)

// crashCount reads the current culvert_crash_records_total value for one
// component out of the Prometheus rendering — the same accessor crashguard_test
// uses. An absent label reads as 0.
func crashCount(component string) int64 {
	var b strings.Builder
	crashByComponent.writePrometheus(&b)
	for _, m := range crashMetricRe.FindAllStringSubmatch(b.String(), -1) {
		if m[1] == component {
			n, _ := strconv.ParseInt(m[2], 10, 64)
			return n
		}
	}
	return 0
}

// ─── the silent false success, at unit level ────────────────────────────────

// A no-outcome pair is unreachable by the DispatchService contract (Dispatch
// returns a report OR an error on every path), which is exactly why it must not
// be answered "ok": the only way to reach it is a detached writer that died
// before assigning either. Pre-fix this returned 200 {"status":"ok"}.
func TestCHAOS75_RespondPreApply_NoOutcomeIsNever200(t *testing.T) {
	rm := &releaseManager{}
	rec := httptest.NewRecorder()
	rm.respondPreApply(rec, nil, nil)

	if rec.Code == http.StatusOK {
		t.Fatalf("no-outcome dispatch answered 200 %q — a false success for an upgrade that never started", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("no-outcome dispatch = %d; want 500 (%s)", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["status"] == "ok" {
		t.Fatalf(`no-outcome dispatch reported status "ok": %q`, rec.Body.String())
	}
	if body["status"] != "internal_error" {
		t.Fatalf("no-outcome status = %v; want internal_error", body["status"])
	}
}

// The worker-failed sentinel must map to the same definite 500 rather than to a
// 409 (client-correctable) or a 2xx. It is a server fault with no op started.
func TestCHAOS75_RespondPreApply_WorkerFailedIs500(t *testing.T) {
	rm := &releaseManager{}
	rec := httptest.NewRecorder()
	rm.respondPreApply(rec, nil, errDispatchWorkerFailed)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("worker-failed dispatch = %d; want 500 (%s)", rec.Code, rec.Body.String())
	}
	if body := decodeBody(t, rec); body["status"] != "internal_error" {
		t.Fatalf("worker-failed status = %v; want internal_error", body["status"])
	}
}

// ─── end-to-end: pre-apply panic ────────────────────────────────────────────

// Pre-fix this test CRASHES the binary (panic in a detached goroutine). Post-fix
// the process survives, the admin API answers a definite 500, and — because a
// pre-apply panic proves nothing about whether this dispatch ever owned the
// agent's single-flight — the per-agent status slot is left untouched so it
// cannot clobber a concurrently running op's record (P2).
func TestCHAOS75_DispatchWorkerPanicBeforeApply_Answers500(t *testing.T) {
	agent := &panicAgent{panicAt: "running", opID: "op-unreached"}
	rm := newPanicReleaseFixture(t, agent)
	before := crashCount(crashComponentReleaseDispatch)

	rec := httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))

	if rec.Code == http.StatusOK {
		t.Fatalf("panicking dispatch answered 200 %q — a false success for an upgrade that never started", rec.Body.String())
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panicking dispatch = %d; want 500 (%s)", rec.Code, rec.Body.String())
	}
	if body := decodeBody(t, rec); body["status"] != "internal_error" {
		t.Fatalf("panicking dispatch status = %v; want internal_error (%s)", body["status"], rec.Body.String())
	}
	if agent.panics.Load() != 1 {
		t.Fatalf("injected fault fired %d times; want 1", agent.panics.Load())
	}
	// The panic is observable, not swallowed: operators alert on
	// culvert_crash_records_total{component="release_dispatch"}.
	if got := crashCount(crashComponentReleaseDispatch); got <= before {
		t.Fatalf("crash counter for %q = %d; want > %d", crashComponentReleaseDispatch, got, before)
	}
	// No op started and ownership is unproven ⇒ the status slot stays as it was.
	if rec, ok := rm.store.get("A"); ok {
		t.Fatalf("pre-apply panic wrote the per-agent status slot (%+v); it may belong to another op", rec)
	}
}

// A pre-apply panic must not overwrite a status record that another dispatch
// owns, even though the panicking request holds a NEWER dispatch_id (ULID order
// decides the slot owner in dispatchStore.update, so a careless write wins).
func TestCHAOS75_DispatchWorkerPanicBeforeApply_DoesNotClobberAnotherOp(t *testing.T) {
	agent := &panicAgent{panicAt: "running", opID: "op-unreached"}
	rm := newPanicReleaseFixture(t, agent)

	// Seed the slot as if an earlier dispatch were mid-flight on agent A.
	incumbent := rm.newID()
	rm.store.markDispatched("A", incumbent, DispatchResumeContext{AgentID: "A", OpID: "op-incumbent", ReleaseID: "rel_a"})

	rec := httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panicking dispatch = %d; want 500 (%s)", rec.Code, rec.Body.String())
	}

	got, ok := rm.store.get("A")
	if !ok {
		t.Fatal("the incumbent status record was removed")
	}
	if got.DispatchID != incumbent || got.OpID != "op-incumbent" || got.Phase != phaseDispatched {
		t.Fatalf("incumbent record clobbered: %+v", got)
	}
}

// ─── end-to-end: post-apply panic ───────────────────────────────────────────

// Once the agent has accepted the apply, the 202 has shipped and the status
// record is the only channel left. A panic in the watch must leave a DEFINITE
// terminal there, not a phantom phase=dispatched record that is
// indistinguishable from a slow but healthy op.
func TestCHAOS75_DispatchWorkerPanicAfterApply_MarksTerminal(t *testing.T) {
	agent := &panicAgent{panicAt: "wait", opID: "op-live", runningSeq: freshDispatchSeq()}
	rm := newPanicReleaseFixture(t, agent)
	before := crashCount(crashComponentReleaseDispatch)

	rec := httptest.NewRecorder()
	apiReleaseDispatch(rec, releaseReq(http.MethodPost, "/api/releases/dispatch",
		dispatchRequest{ReleaseID: "rel_a", Agent: "A"}, RoleAdmin))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("post-apply panic dispatch = %d; want 202 (the agent did accept the apply) (%s)", rec.Code, rec.Body.String())
	}

	got := waitTerminal(t, rm, "A")
	if got.Terminal != TerminalFailedNeedsAttn {
		t.Fatalf("terminal = %q; want %q", got.Terminal, TerminalFailedNeedsAttn)
	}
	if got.Verified {
		t.Fatal("an abandoned watch must never report verified")
	}
	if got.Detail != detailDispatchWorkerPanicAfterApply {
		t.Fatalf("detail = %q; want %q", got.Detail, detailDispatchWorkerPanicAfterApply)
	}
	// The op_id survives the panic: it is the resume authority, and the detail
	// tells the operator to re-poll rather than re-dispatch.
	if got.OpID != "op-live" {
		t.Fatalf("op_id = %q; want op-live (the resume authority must survive)", got.OpID)
	}
	if got := crashCount(crashComponentReleaseDispatch); got <= before {
		t.Fatalf("crash counter for %q = %d; want > %d", crashComponentReleaseDispatch, got, before)
	}
}

// ─── end-to-end: resume panic ───────────────────────────────────────────────

// The resume goroutine is fire-and-forget (the 202 ships before it starts), so
// containment is the whole contract: the process survives and the panic is
// counted. It deliberately writes NOTHING to the status store — a resume starts
// no op, and its dispatch_id is newer than the running op's, so any write would
// win the slot and overwrite the real owner's record.
func TestCHAOS75_ResumeWorkerPanic_ContainedAndDoesNotClobber(t *testing.T) {
	agent := &panicAgent{panicAt: "wait", opID: "op-live"}
	rm := newPanicReleaseFixture(t, agent)
	before := crashCount(crashComponentReleaseResume)

	incumbent := rm.newID()
	rm.store.markDispatched("A", incumbent, DispatchResumeContext{AgentID: "A", OpID: "op-incumbent", ReleaseID: "rel_a"})

	rc := DispatchResumeContext{
		AgentID:         "A",
		OpID:            "op-live",
		ReleaseID:       "rel_a",
		TargetPinnedRef: dispatchRepo + "@" + digA,
	}
	rec := httptest.NewRecorder()
	apiReleaseDispatchResume(rec, releaseReq(http.MethodPost, "/api/releases/dispatch/resume",
		resumeRequest{Agent: "A", ResumeContext: &rc}, RoleAdmin))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("resume = %d; want 202 (%s)", rec.Code, rec.Body.String())
	}

	// The panic is counted (and the process is alive to read the counter).
	waitFor(t, func() bool { return crashCount(crashComponentReleaseResume) > before },
		"the resume panic to be recorded on culvert_crash_records_total")

	got, ok := rm.store.get("A")
	if !ok {
		t.Fatal("the incumbent status record was removed")
	}
	if got.DispatchID != incumbent || got.OpID != "op-incumbent" || got.Phase != phaseDispatched {
		t.Fatalf("a panicking resume clobbered the incumbent record: %+v", got)
	}
}
