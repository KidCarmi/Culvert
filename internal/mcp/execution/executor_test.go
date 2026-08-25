package execution

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
	"github.com/KidCarmi/Culvert/internal/secret"
)

// fakeUpstream records calls and returns a canned result.
type fakeUpstream struct {
	calls    int
	lastAuth string
	lastMeth string
	result   string
	err      error
}

func (f *fakeUpstream) Call(_ context.Context, _ upstreamclient.Target, method string, _ json.RawMessage, opts upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	f.calls++
	f.lastAuth = opts.AuthHeader
	f.lastMeth = method
	if f.err != nil {
		return nil, f.err
	}
	res := f.result
	if res == "" {
		res = `{"ok":true}`
	}
	return &upstreamclient.Response{ID: jsonrpc.ID{Kind: jsonrpc.IDString, Str: "u"}, Result: json.RawMessage(res), RawBytes: []byte(res)}, nil
}

func testKEK() *secret.Provider {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 7)
	}
	return secret.MemoryProvider(k)
}

func realEvents(t *testing.T, be spool.Backend) *events.Manager {
	t.Helper()
	if be == nil {
		be = spool.NewOSBackend()
	}
	m, err := events.NewManager(events.ManagerConfig{
		NodeID: "n1", DataDir: t.TempDir(), KEK: testKEK(),
		GatewayLimits: limits.DefaultGatewayEvent(), ManagementLimits: limits.DefaultManagementEvent(),
		Backend: be, Clock: func() time.Time { return time.Unix(0, 1) },
	})
	if err != nil {
		t.Fatalf("events.NewManager: %v", err)
	}
	return m
}

func stateForMode(t *testing.T, mode rollout.Mode) *rollout.State {
	t.Helper()
	st := rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits())
	if mode == rollout.ModeDisabled {
		return st
	}
	cfg := rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: mode, ScopeRevision: 1,
		Scope:         rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Servers: []string{"s1"}},
		ConnectorMode: rollout.ConnectorLocalClient,
	}
	if err := st.SetConfig(cfg, "a", 1); err != nil {
		t.Fatalf("SetConfig: %v", err)
	}
	return st
}

func execInput(action policy.Action, hardFail bool) runtime.ExecInput {
	in := runtime.ExecInput{
		Capability: 0, // Gateway
		Method:     "tools/call",
		MessageID:  jsonrpc.ID{Kind: jsonrpc.IDString, Str: "c1"},
		RawParams:  []byte(`{"name":"read_file","arguments":{}}`),
		Decision:   policy.Decision{Action: action, Reason: policy.ReasonCode("MCP.POLICY.OK")},
		Input: policy.DecisionInput{
			Principal: policy.Principal{SubjectID: "p1", Tenant: "t1"},
			Client:    policy.Client{ClientID: "cl1"},
			Server:    &policy.Server{ServerID: "s1", Environment: "prod"},
			Tool:      &policy.Tool{Name: "read_file", ServerID: "s1", FingerprintHash: "fp1"},
			Operation: policy.Operation{Class: policy.OpRead},
			Session:   policy.Session{Fingerprint: "sess1"},
		},
		Server: &registry.ServerRecord{
			ID: "s1", Endpoint: "https://s1.internal:443", PinnedIdentity: "pin1",
			Enabled: true, Verification: registry.VerifyVerified,
		},
		SnapshotHash: "snap1",
		Now:          time.Unix(0, 1),
	}
	if hardFail {
		in.Inspection = &inspection.Result{HardFail: true, HardReason: mcperr.ReasonSSRFBlocked}
	}
	return in
}

func newExec(t *testing.T, st *rollout.State, up UpstreamCaller, ev *events.Manager) *Executor {
	t.Helper()
	e, err := New(Config{
		State: st, Upstream: up, Events: ev,
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           func() time.Time { return time.Unix(0, 1) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestExecDisabledNoUpstream(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeDisabled), up, realEvents(t, nil))
	out := e.Execute(context.Background(), execInput(policy.ActionAllow, false))
	if up.calls != 0 {
		t.Fatal("disabled must not call upstream")
	}
	if out.ExecutionState != "not_implemented" {
		t.Fatalf("disabled should be not_implemented, got %q", out.ExecutionState)
	}
}

func TestExecObserveNoUpstream(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeObserve), up, realEvents(t, nil))
	out := e.Execute(context.Background(), execInput(policy.ActionAllow, false))
	if up.calls != 0 {
		t.Fatal("observe must not call upstream")
	}
	if out.Executed {
		t.Fatal("observe must not execute")
	}
}

// Shadow EVALUATES a would-be DENY and records the override, but NEVER executes:
// no upstream call is made (SH-INV-1). This test was evolved from the pre-Shadow-
// architecture "TestExecShadowExecutesDenyWithOverride", which asserted the old,
// wrong "Shadow executes for real" semantics (up.calls==1).
func TestExecShadowEvaluatesDenyWithOverride(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeShadow), up, realEvents(t, nil))
	out := e.Execute(context.Background(), execInput(policy.ActionDeny, false))
	if up.calls != 0 {
		t.Fatalf("shadow must NOT cross the side-effect boundary — a Shadow evaluation makes no upstream call, calls=%d", up.calls)
	}
	if out.Executed {
		t.Fatal("a Shadow evaluation must not be reported as executed")
	}
	if out.ExecutionState != "shadow_evaluated" {
		t.Fatalf("shadow execution_state must be shadow_evaluated, got %q", out.ExecutionState)
	}
	if out.EffectiveAction != "shadow_evaluate" {
		t.Fatalf("shadow effective_action must be shadow_evaluate, got %q", out.EffectiveAction)
	}
	if !out.ShadowOverride {
		t.Fatal("shadow override must be set for a would-be DENY")
	}
	if out.EvaluatedAction != "DENY" {
		t.Fatalf("evaluated action must be preserved as DENY, got %q", out.EvaluatedAction)
	}
}

// TestExecShadowHardFailureEvaluatesWouldFailInspection pins the truthful,
// non-enforcing Shadow handling of a hard failure: an inspection hard-fail (SSRF) is
// NOT executed and NOT softened to would_execute — it is recorded as a non-executing
// shadow evaluation whose shadow_outcome is WOULD_FAIL_INSPECTION. No upstream call is
// made. This preserves the anti-weakening guarantee (a hard control is never bypassed)
// while keeping Shadow a pure predictor that never enforces.
func TestExecShadowHardFailureEvaluatesWouldFailInspection(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeShadow), up, realEvents(t, nil))
	out := e.Execute(context.Background(), execInput(policy.ActionAllow, true))
	if up.calls != 0 {
		t.Fatal("a hard failure must never reach upstream in shadow")
	}
	if out.Executed || out.ExecutionState != "shadow_evaluated" {
		t.Fatalf("hard failure must be a non-executing shadow evaluation: executed=%v state=%q", out.Executed, out.ExecutionState)
	}
	got := shadowOutcomeFromBody(t, out.ResponseBody)
	if got != string(ShadowWouldFailInspection) {
		t.Fatalf("shadow_outcome = %q, want %q — a hard inspection control must be predicted as WOULD_FAIL_INSPECTION, never softened", got, ShadowWouldFailInspection)
	}
	if got == string(ShadowWouldExecute) {
		t.Fatal("a hard failure must never be reported as WOULD_EXECUTE")
	}
}

// shadowOutcomeFromBody extracts the shadow_outcome field from a shadow-evaluation
// response body — the real wire contract an operator/evidence consumer reads.
func shadowOutcomeFromBody(t *testing.T, body []byte) string {
	t.Helper()
	var env struct {
		Result struct {
			ShadowOutcome string `json:"shadow_outcome"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("unmarshal shadow body: %v", err)
	}
	return env.Result.ShadowOutcome
}

func TestExecCanaryBlocksDeny(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	out := e.Execute(context.Background(), execInput(policy.ActionDeny, false))
	if up.calls != 0 {
		t.Fatal("canary must block a DENY — no upstream")
	}
	if out.EffectiveAction != "block" {
		t.Fatalf("effective action should be block, got %q", out.EffectiveAction)
	}
}

func TestExecCanaryExecutesAllow(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	out := e.Execute(context.Background(), execInput(policy.ActionAllow, false))
	if up.calls != 1 {
		t.Fatalf("canary must execute an ALLOW, calls=%d", up.calls)
	}
	if !out.Executed {
		t.Fatal("canary ALLOW must be marked executed")
	}
}

func TestExecKillSwitchBlocks(t *testing.T) {
	st := stateForMode(t, rollout.ModeCanary)
	st.EngageKillSwitch("oncall", 1)
	up := &fakeUpstream{}
	e := newExec(t, st, up, realEvents(t, nil))
	out := e.Execute(context.Background(), execInput(policy.ActionAllow, false))
	if up.calls != 0 {
		t.Fatal("kill switch must stop admission — no upstream")
	}
	if out.Reason != mcperr.ReasonRolloutEmergencyActive {
		t.Fatalf("kill switch reason expected, got %v", out.Reason)
	}
}

// ── PR-8 commit-before-side-effect: a post-admission commit failure must produce
// NO upstream call (the irreversible side effect never happens). ──

// failBackend fails AppendSync (a post-admission durable-commit failure).
type failBackend struct{ inner spool.Backend }

func (f failBackend) MkdirAll(d string, p os.FileMode) error { return f.inner.MkdirAll(d, p) }
func (f failBackend) AppendSync(_ string, _ []byte, _ os.FileMode) error {
	return &os.PathError{Op: "append", Path: "x", Err: os.ErrInvalid}
}
func (f failBackend) AtomicReplace(pth string, d []byte, p os.FileMode) error {
	return f.inner.AtomicReplace(pth, d, p)
}
func (f failBackend) ReadFile(p string) ([]byte, error)               { return f.inner.ReadFile(p) }
func (f failBackend) ReadAt(p string, o int64, b []byte) (int, error) { return f.inner.ReadAt(p, o, b) }
func (f failBackend) Truncate(p string, s int64) error                { return f.inner.Truncate(p, s) }
func (f failBackend) Remove(p string) error                           { return f.inner.Remove(p) }
func (f failBackend) Size(p string) (int64, error)                    { return f.inner.Size(p) }
func (f failBackend) List(d string) ([]string, error)                 { return f.inner.List(d) }

func TestExecCommitFailureNoUpstream(t *testing.T) {
	ev := realEvents(t, failBackend{inner: spool.NewOSBackend()})
	up := &fakeUpstream{}
	// Canary + ALLOW ⇒ would execute, but the durable commit MUST fail closed first.
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, ev)
	out := e.Execute(context.Background(), execInput(policy.ActionAllow, false))
	if up.calls != 0 {
		t.Fatalf("a durable-commit failure must prevent the upstream call, calls=%d", up.calls)
	}
	if out.Executed {
		t.Fatal("no execution may be reported when the commit failed")
	}
}

func TestExecNilEventsFailsClosed(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, nil)
	out := e.Execute(context.Background(), execInput(policy.ActionAllow, false))
	if up.calls != 0 {
		t.Fatal("nil events (no durability) must fail closed — no upstream")
	}
	if out.Executed {
		t.Fatal("must not execute without a durability seam")
	}
}
