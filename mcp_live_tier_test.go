package main

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
	"github.com/KidCarmi/Culvert/internal/secret"
)

// ── Test harness for the LIVE-tier composition/arming/quiesce phase ──
//
// The live executor is driven DIRECTLY (Resolve then Execute) exactly as the runtime does, so a
// controlled test exercises the real gate + boundary without standing up the whole listener. Every
// synthetic collaborator (recording upstream, real events manager) crosses the SAME production
// composition path (composeGatewayLiveTierInto), so what these tests exercise is the real wiring.

// recordingUpstream is a synthetic execution.UpstreamCaller that COUNTS every irreversible call and
// records the last method/auth, so a test can assert "upstream invocations == 0" (§16/§19) or count
// the exact executions the rehearsal expects. It performs no network I/O.
type recordingUpstream struct {
	mu       sync.Mutex
	calls    int
	lastAuth string
	lastMeth string
	// block, when non-nil, is received-from before each call returns, so a test can hold an
	// execution "in flight" deterministically (channels/barriers, not sleeps — §20).
	block chan struct{}
	err   error
}

func (u *recordingUpstream) Call(ctx context.Context, target upstreamclient.Target, method string, params json.RawMessage, opts upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	if u.block != nil {
		<-u.block
	}
	u.mu.Lock()
	u.calls++
	u.lastAuth = opts.AuthHeader
	u.lastMeth = method
	u.mu.Unlock()
	if u.err != nil {
		return nil, u.err
	}
	res := `{"ok":true}`
	return &upstreamclient.Response{ID: jsonrpc.ID{Kind: jsonrpc.IDString, Str: "u"}, Result: json.RawMessage(res), RawBytes: []byte(res)}, nil
}

func (u *recordingUpstream) callCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

// liveTestKEK is a deterministic memory KEK for the events manager.
func liveTestKEK() *secret.Provider {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 11)
	}
	return secret.MemoryProvider(k)
}

// liveTestEvents builds a real durable-event manager on a temp dir (commit-before-side-effect is
// mandatory for the live path).
func liveTestEvents(t *testing.T) *events.Manager {
	t.Helper()
	m, err := events.NewManager(events.ManagerConfig{
		NodeID: "n1", DataDir: t.TempDir(), KEK: liveTestKEK(),
		GatewayLimits: limits.DefaultGatewayEvent(), ManagementLimits: limits.DefaultManagementEvent(),
		Backend: spool.NewOSBackend(), Clock: func() time.Time { return time.Unix(0, 1) },
	})
	if err != nil {
		t.Fatalf("events.NewManager: %v", err)
	}
	return m
}

// resetLiveTierGlobals isolates the process-global live-tier / canary-runtime / execdeps state per
// test (the PR3d fence-pollution class — a shared global would leak an armed bit across tests).
func resetLiveTierGlobals(t *testing.T) {
	t.Helper()
	prevTier, prevMgmt := globalMCPLiveTier, globalMCPLiveTierMgmt
	prevExecDeps := globalExecDeps
	prevRuntime := globalCanaryRuntime
	globalMCPLiveTier = newMCPLiveTier(rollout.CapabilityGateway)
	globalMCPLiveTierMgmt = newMCPLiveTier(rollout.CapabilityManagement)
	globalExecDeps = &execDepsRegistry{}
	globalCanaryRuntime = &canaryRuntime{}
	t.Cleanup(func() {
		globalMCPLiveTier, globalMCPLiveTierMgmt = prevTier, prevMgmt
		globalExecDeps = prevExecDeps
		globalCanaryRuntime = prevRuntime
	})
}

// liveExecInput builds an ExecInput for a Gateway tools/call on (server s1, tool read_file) with the
// given operation class, tenant, and principal.
func liveExecInput(opClass policy.OperationClass, tenant, principal string) mcpruntime.ExecInput {
	return mcpruntime.ExecInput{
		Capability: 0, // Gateway
		Method:     "tools/call",
		MessageID:  jsonrpc.ID{Kind: jsonrpc.IDString, Str: "c1"},
		RawParams:  []byte(`{"name":"read_file","arguments":{}}`),
		Decision:   policy.Decision{Action: policy.ActionAllow, Reason: policy.ReasonCode("MCP.POLICY.OK")},
		Input: policy.DecisionInput{
			Principal: policy.Principal{SubjectID: principal, Tenant: tenant},
			Client:    policy.Client{ClientID: "cl1"},
			Server:    &policy.Server{ServerID: "s1", Environment: "prod"},
			Tool:      &policy.Tool{Name: "read_file", ServerID: "s1", FingerprintHash: "fp1"},
			Operation: policy.Operation{Class: opClass},
			Session:   policy.Session{Fingerprint: "sess1"},
		},
		Server: &registry.ServerRecord{
			ID: "s1", Endpoint: "https://s1.internal:443", PinnedIdentity: "pin1",
			Enabled: true, Verification: registry.VerifyVerified,
		},
		SnapshotHash: "snap1",
		Now:          time.Unix(0, 1),
	}
}

// alwaysAdmitGate is an execution.LiveExecutionGate that admits every request — used to prove that
// even with the gate satisfied, an out-of-scope/record-only disposition makes no upstream call.
type alwaysAdmitGate struct{ admitted int }

func (g *alwaysAdmitGate) AdmitSideEffect(execution.LiveGateInput) execution.LiveGateDecision {
	g.admitted++
	return execution.LiveGateDecision{Admit: true, Release: func() {}}
}

// ── §2 lifecycle: absent → composed → armed → quiescing → composed ──

func TestLiveTier_LifecycleStatesAreDistinct(t *testing.T) {
	resetLiveTierGlobals(t)
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	if lt.State() != liveTierAbsent {
		t.Fatalf("fresh tier must be absent, got %s", lt.State())
	}
	if lt.composed() || lt.armed() {
		t.Fatal("absent tier is neither composed nor armed")
	}
	lt.markComposed("composed")
	if lt.State() != liveTierComposed || !lt.composed() || lt.armed() {
		t.Fatalf("composed tier must be composed and NOT armed, state=%s", lt.State())
	}
	// composed does NOT arm the execdeps bit.
	if liveExecDepsConfigured(false) {
		t.Fatal("composition must NOT set the armed bit (composed != armed)")
	}
	if err := lt.arm(true, "armed"); err != nil {
		t.Fatalf("arm from composed+ready must succeed: %v", err)
	}
	if lt.State() != liveTierArmed || !lt.armed() || !liveExecDepsConfigured(false) {
		t.Fatalf("armed tier must be armed and set the execdeps bit, state=%s", lt.State())
	}
	// quiesce (no in-flight) returns to composed and clears the armed bit.
	if rem := lt.quiesce(func(func() int) int { return 0 }); rem != 0 {
		t.Fatalf("clean quiesce residual must be 0, got %d", rem)
	}
	if lt.State() != liveTierComposed || lt.armed() || liveExecDepsConfigured(false) {
		t.Fatalf("quiesced tier must be composed+unarmed with cleared bit, state=%s", lt.State())
	}
}

func TestLiveTier_ArmRefusesWhenNotComposed(t *testing.T) {
	resetLiveTierGlobals(t)
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	if err := lt.arm(true, "x"); err != errLiveTierNotComposed {
		t.Fatalf("arming an absent tier must fail errLiveTierNotComposed, got %v", err)
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("a refused arm must not set the armed bit")
	}
}

func TestLiveTier_ArmRefusesWhenNotReady(t *testing.T) {
	resetLiveTierGlobals(t)
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	lt.markComposed("composed")
	if err := lt.arm(false, "not_ready"); err != errLiveTierNotReady {
		t.Fatalf("arming without readiness must fail errLiveTierNotReady, got %v", err)
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("a not-ready arm must not set the armed bit")
	}
}

// ── §16 the non-negotiable regression: compose + arm does NOT activate Canary ──

func TestLiveTier_ComposeAndArmDoesNotActivateCanary(t *testing.T) {
	resetLiveTierGlobals(t)
	// Compose the live tier with a synthetic recording upstream via the REAL production path.
	up := &recordingUpstream{}
	cfg := &mcpruntime.Config{}
	if err := composeGatewayLiveTierInto(cfg, liveTierComposition{
		Upstream: up, Events: liveTestEvents(t),
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           func() time.Time { return time.Unix(0, 1) },
	}); err != nil {
		t.Fatalf("compose live tier: %v", err)
	}
	// Arm it directly (bypassing the readiness gate — we are asserting the arm↔activation split).
	if err := mcpLiveTierFor(rollout.CapabilityGateway).arm(true, "armed"); err != nil {
		t.Fatalf("arm: %v", err)
	}
	// Now the tier is COMPOSED and ARMED. The regression: the rollout mode must remain
	// Observe/Disabled and NO upstream invocation may occur until an independently-accepted Canary
	// transition. We drive a request through the executor: with the rollout state Disabled/Observe,
	// Resolve yields record-only and Execute makes no upstream call.
	ex := cfg.Deps.Executor
	if ex == nil {
		t.Fatal("compose must install Deps.Executor")
	}
	in := liveExecInput(policy.OpRead, "t1", "p1")
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 0 {
		t.Fatalf("arming must NOT make an upstream call — the rollout mode is not Canary; calls=%d", up.callCount())
	}
	if out.Executed {
		t.Fatalf("no execution may occur on a composed+armed but not-activated tier; out=%+v", out)
	}
	// The lifecycle is armed but Canary is not active (no generation begun).
	if globalCanaryRuntime.armed(rollout.CapabilityGateway) {
		t.Fatal("arming the tier must NOT begin a Canary activation generation")
	}
}

// ── §6/§8/§9/§10 gate admission logic (injected seams for deterministic coverage) ──

// injectedGate builds a gate whose seams the test controls, so each admission rule is exercised in
// isolation. lifecycleAdmit/readFirst/trust/reserve default to "admit"; a test overrides one.
type gateSeams struct {
	admitOK  bool
	readOK   bool
	trustOK  bool
	outcome  canary.BudgetOutcome
	released *int // incremented by the budget release
	admitRel *int // incremented by the lifecycle release
}

func newInjectedGate(s *gateSeams) *mcpLiveSideEffectGate {
	return &mcpLiveSideEffectGate{
		capb: rollout.CapabilityGateway,
		admit: func() (func(), bool) {
			if !s.admitOK {
				return nil, false
			}
			return func() {
				if s.admitRel != nil {
					*s.admitRel++
				}
			}, true
		},
		readFirst: func(policy.OperationClass) bool { return s.readOK },
		trustOK:   func(string, string, string, time.Time) bool { return s.trustOK },
		reserve: func(time.Time, canary.ExecutionIdentity) (canary.BudgetOutcome, uint64) {
			return s.outcome, 7
		},
		releaseBudget: func(uint64) {
			if s.released != nil {
				*s.released++
			}
		},
	}
}

func gateInput() execution.LiveGateInput {
	return execution.LiveGateInput{
		Capability: 0, Operation: policy.OpRead, Tenant: "t1", Principal: "p1",
		ServerID: "s1", ToolName: "read_file", Fingerprint: "fp1", Now: time.Unix(0, 1),
	}
}

func TestLiveGate_QuiescingRejectsNewAdmission(t *testing.T) {
	admitRel := 0
	g := newInjectedGate(&gateSeams{admitOK: false, readOK: true, trustOK: true, outcome: canary.BudgetGranted, admitRel: &admitRel})
	d := g.AdmitSideEffect(gateInput())
	if d.Admit {
		t.Fatal("a quiescing/unarmed tier must reject a new admission (§6)")
	}
	if d.Reason != mcperr.ReasonRolloutModeInvalid {
		t.Fatalf("quiesce refusal reason=%s want rollout_mode_invalid", d.Reason.Code())
	}
	if admitRel != 0 {
		t.Fatal("a rejected admission must not have taken (or released) a lifecycle slot")
	}
}

func TestLiveGate_ReadFirstRejectsControl(t *testing.T) {
	admitRel, released := 0, 0
	g := newInjectedGate(&gateSeams{admitOK: true, readOK: false, trustOK: true, outcome: canary.BudgetGranted, admitRel: &admitRel, released: &released})
	d := g.AdmitSideEffect(gateInput())
	if d.Admit {
		t.Fatal("a non-read-first operation must be rejected before upstream (§9)")
	}
	if d.Reason != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("read-first refusal reason=%s want rollout_out_of_scope", d.Reason.Code())
	}
	if admitRel != 1 {
		t.Fatalf("a read-first rejection must release the lifecycle slot it took, releases=%d", admitRel)
	}
	if released != 0 {
		t.Fatal("no budget was reserved yet, so none must be released")
	}
}

func TestLiveGate_TrustRevalidationRejects(t *testing.T) {
	admitRel := 0
	g := newInjectedGate(&gateSeams{admitOK: true, readOK: true, trustOK: false, outcome: canary.BudgetGranted, admitRel: &admitRel})
	d := g.AdmitSideEffect(gateInput())
	if d.Admit {
		t.Fatal("no valid live approval ⇒ reject (§10)")
	}
	if d.Reason != mcperr.ReasonLiveTrustRevalidationFailed {
		t.Fatalf("trust refusal reason=%s want live_trust_revalidation_failed", d.Reason.Code())
	}
	if admitRel != 1 {
		t.Fatalf("a trust rejection must release the lifecycle slot, releases=%d", admitRel)
	}
}

func TestLiveGate_BudgetDenialRejects(t *testing.T) {
	admitRel, released := 0, 0
	g := newInjectedGate(&gateSeams{admitOK: true, readOK: true, trustOK: true, outcome: canary.BudgetDeniedTotal, admitRel: &admitRel, released: &released})
	d := g.AdmitSideEffect(gateInput())
	if d.Admit {
		t.Fatal("a denied budget must reject (§8) so Upstream.Call == 0")
	}
	if d.Reason != mcperr.ReasonRolloutBudgetExhausted {
		t.Fatalf("budget refusal reason=%s want rollout_budget_exhausted", d.Reason.Code())
	}
	if admitRel != 1 {
		t.Fatalf("a budget rejection must release the lifecycle slot, releases=%d", admitRel)
	}
	if released != 0 {
		t.Fatal("a DENIED reserve took no slot, so releaseBudget must not run")
	}
}

func TestLiveGate_AdmitReleasesBothSlots(t *testing.T) {
	admitRel, released := 0, 0
	g := newInjectedGate(&gateSeams{admitOK: true, readOK: true, trustOK: true, outcome: canary.BudgetGranted, admitRel: &admitRel, released: &released})
	d := g.AdmitSideEffect(gateInput())
	if !d.Admit || d.Release == nil {
		t.Fatal("all gates satisfied ⇒ admit with a non-nil release")
	}
	d.Release()
	if admitRel != 1 || released != 1 {
		t.Fatalf("release must return BOTH the lifecycle and budget slots: admit=%d budget=%d", admitRel, released)
	}
}

// ── §6 quiesce: reject new admissions, drain in-flight ──

func TestLiveTier_QuiesceRejectsNewAndDrainsInFlight(t *testing.T) {
	resetLiveTierGlobals(t)
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	lt.markComposed("composed")
	if err := lt.arm(true, "armed"); err != nil {
		t.Fatalf("arm: %v", err)
	}
	// Admit ONE execution and hold it in flight.
	rel, ok := lt.admitExecution()
	if !ok {
		t.Fatal("armed tier must admit a first execution")
	}
	if lt.inFlightCount() != 1 {
		t.Fatalf("in-flight must be 1, got %d", lt.inFlightCount())
	}
	// Start quiesce on a goroutine; it un-arms immediately and then blocks draining the one
	// in-flight execution. Use a channel barrier (not a sleep) to sequence.
	done := make(chan int, 1)
	go func() { done <- lt.quiesce(drainWaitFn(lt, time.Now().Add(5*time.Second))) }()
	// Spin until the quiesce has un-armed (state==quiescing) — deterministic via the observable bit.
	for i := 0; i < 100000 && lt.armed(); i++ {
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("quiesce must clear the armed bit BEFORE draining (reject new Canary transitions)")
	}
	// A NEW admission during quiesce is rejected (§6 "reject new live executions").
	if _, ok := lt.admitExecution(); ok {
		t.Fatal("a quiescing tier must reject a NEW admission")
	}
	// Release the in-flight execution → the drain completes and quiesce returns 0.
	rel()
	rem := <-done
	if rem != 0 {
		t.Fatalf("after the in-flight execution released, the drain must be clean (0), got %d", rem)
	}
	if lt.State() != liveTierComposed || lt.armed() {
		t.Fatalf("post-quiesce state must be composed+unarmed, got %s", lt.State())
	}
}

func TestLiveTier_QuiesceBoundedDrainReportsResidual(t *testing.T) {
	resetLiveTierGlobals(t)
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	lt.markComposed("composed")
	if err := lt.arm(true, "armed"); err != nil {
		t.Fatalf("arm: %v", err)
	}
	// Admit an execution and NEVER release it; quiesce with a past deadline returns the residual.
	if _, ok := lt.admitExecution(); !ok {
		t.Fatal("armed tier must admit")
	}
	rem := lt.quiesce(drainWaitFn(lt, time.Now().Add(-time.Second)))
	if rem != 1 {
		t.Fatalf("a bounded drain that elapses with 1 in flight must report residual 1, got %d", rem)
	}
	// Even with a residual, the tier is unarmed and admits no new work.
	if lt.armed() {
		t.Fatal("a quiesced tier is unarmed even with an in-flight residual")
	}
	if _, ok := lt.admitExecution(); ok {
		t.Fatal("an unarmed tier admits no new execution")
	}
}

// ── §17 restart posture: a re-composed tier is never automatically re-armed ──

func TestLiveTier_RestartDoesNotReArm(t *testing.T) {
	resetLiveTierGlobals(t)
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	lt.markComposed("composed")
	if err := lt.arm(true, "armed"); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if !lt.armed() || !liveExecDepsConfigured(false) {
		t.Fatal("precondition: armed")
	}
	// Simulate a restart's fail-closed posture: the tier re-composes but must NOT re-arm.
	lt.disarmForRestart()
	if lt.State() != liveTierComposed {
		t.Fatalf("restart posture must land composed, got %s", lt.State())
	}
	if lt.armed() || liveExecDepsConfigured(false) {
		t.Fatal("a re-composed tier must NEVER be automatically re-armed (§17)")
	}
	if _, ok := lt.admitExecution(); ok {
		t.Fatal("an unarmed (restart) tier admits no execution")
	}
}
