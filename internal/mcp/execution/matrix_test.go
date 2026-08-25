package execution

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// ── Canary nine-action matrix ───────────────────────────────────────────────

func TestCanaryNineActionMatrix(t *testing.T) {
	// ALLOW_WITH_REDACTION does NOT execute on the guarded path: it requires a
	// re-validated request-argument transform before egress, which this path does not
	// perform, so it fails closed (no untransformed arguments reach the upstream).
	execClass := map[policy.Action]bool{
		policy.ActionAllow:               true,
		policy.ActionMonitor:             true,
		policy.ActionAllowOnce:           true,
		policy.ActionAllowForSession:     true,
		policy.ActionAllowWithRedaction:  false,
		policy.ActionDeny:                false,
		policy.ActionQuarantine:          false,
		policy.ActionRequireConfirmation: false,
		policy.ActionRequireApproval:     false,
	}
	for action, shouldExecute := range execClass {
		up := &fakeUpstream{}
		e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
		out := e.Execute(context.Background(), execInput(action, false))
		if shouldExecute && up.calls != 1 {
			t.Fatalf("canary action %v should execute (calls=%d)", action, up.calls)
		}
		if !shouldExecute && up.calls != 0 {
			t.Fatalf("canary action %v must NOT execute (calls=%d)", action, up.calls)
		}
		if !shouldExecute && out.EffectiveAction != "block" {
			t.Fatalf("canary action %v should block, got %q", action, out.EffectiveAction)
		}
	}
}

// TestCanaryRedactionFailsClosed proves ALLOW_WITH_REDACTION never egresses
// untransformed arguments on the guarded-execute path: it blocks with
// redaction_failed and makes no upstream call, in an executing mode.
func TestCanaryRedactionFailsClosed(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	out := e.Execute(context.Background(), execInput(policy.ActionAllowWithRedaction, false))
	if up.calls != 0 {
		t.Fatalf("redaction must not reach the upstream (calls=%d)", up.calls)
	}
	if out.Executed || out.EffectiveAction != "block" {
		t.Fatalf("redaction must fail closed (executed=%v effective=%q)", out.Executed, out.EffectiveAction)
	}
	if out.Reason != mcperr.ReasonRedactionFailed {
		t.Fatalf("expected redaction_failed, got %q", out.Reason.Code())
	}
}

// ── PR-8 admission saturation (distinct from post-admission commit failure) ──

// TestExecAdmissionSaturationNoUpstream proves that a CRITICAL durable domain that
// rejects admission (write-not-allowed — the degraded/saturated critical state)
// produces NO upstream call. This is the admission-side failure mode, kept SEPARATE
// from the post-admission spool-commit failure case (TestExecCommitFailureNoUpstream
// in executor_test.go). The domain is degraded first by one failing critical commit,
// so the executor's subsequent commit is rejected AT ADMISSION (before any event is
// built) with ReasonEventDurabilityDegraded.
func TestExecAdmissionSaturationNoUpstream(t *testing.T) {
	ev := realEvents(t, failBackend{inner: spoolNewOSBackend()})
	// Degrade the critical domain via one failing critical commit (append fault).
	_ = ev.CommitThenAct(eventsCritFacts(), func(_ spoolReceipt) error { return nil })
	if ev.WriteAllowedCritical(evCapGateway) {
		t.Fatal("critical domain should be degraded after a failing commit")
	}
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, ev)
	out := e.Execute(context.Background(), execInput(policy.ActionAllow, false))
	if up.calls != 0 {
		t.Fatalf("a degraded/saturated critical domain must reject admission with no upstream call (calls=%d)", up.calls)
	}
	if out.Executed {
		t.Fatal("no execution when admission is rejected")
	}
}

// ── Discovery ───────────────────────────────────────────────────────────────

func TestDiscoveryHappyAndFailureRetainsCatalog(t *testing.T) {
	reg := registry.New(limits.DefaultCatalog())
	id := registry.Identity("pin-1")
	if _, err := reg.Register(registry.Registration{
		ID: "s1", Endpoint: "https://s1.internal:443", PinnedIdentity: id, Capability: 0,
		CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(1, 0),
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, _, err := reg.VerifyIdentity("s1", id); err != nil {
		t.Fatalf("verify: %v", err)
	}
	cat := catalog.New(limits.DefaultCatalog())

	// Happy path: an empty (well-formed) tools/list ingests cleanly.
	up := &fakeUpstream{result: `{"tools":[]}`}
	d, err := NewDiscovery(reg, cat, up)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Discover(context.Background(), "s1"); err != nil {
		t.Fatalf("discovery happy path: %v", err)
	}
	revAfterOK := cat.Current().Revision()

	// Failure path: the upstream errors — the previous catalog is retained unchanged.
	up.err = mcperr.New(mcperr.ReasonUpstreamTimeout, "test", "boom")
	if _, err := d.Discover(context.Background(), "s1"); mcperr.ReasonOf(err) != mcperr.ReasonUpstreamDiscoveryFailed {
		t.Fatalf("discovery failure should classify as discovery-failed, got %v", err)
	}
	if cat.Current().Revision() != revAfterOK {
		t.Fatal("a discovery failure must retain the previous catalog snapshot unchanged")
	}
}

func TestDiscoveryRejectsUnregisteredServer(t *testing.T) {
	reg := registry.New(limits.DefaultCatalog())
	cat := catalog.New(limits.DefaultCatalog())
	up := &fakeUpstream{}
	d, _ := NewDiscovery(reg, cat, up)
	if _, err := d.Discover(context.Background(), "nope"); mcperr.ReasonOf(err) != mcperr.ReasonUnregisteredServer {
		t.Fatalf("unregistered server must be rejected, got %v", err)
	}
	if up.calls != 0 {
		t.Fatal("no upstream call for an unregistered server")
	}
}

// ── Anti-weakening (test-local invariants; no production bypass flags) ───────

func TestAntiWeakening_OutOfScopeDoesNotExecute(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	in := execInput(policy.ActionAllow, false)
	in.Input.Server.ServerID = "OTHER" // not in the canary scope (servers: s1)
	in.Server.ID = "OTHER"
	out := e.Execute(context.Background(), in)
	if up.calls != 0 {
		t.Fatal("an out-of-scope call must not execute")
	}
	if out.Executed {
		t.Fatal("out-of-scope must not be marked executed")
	}
}

// TestAntiWeakening_ShadowCannotSoftenHardAuthFailure proves a policy HARD OVERRIDE (a
// tenant/auth hard failure) is never softened by Shadow. Under the truthful non-enforcing
// model Shadow does not enforce (no EffectBlock) and does not execute — it PREDICTS the
// hard control as WOULD_FAIL_HARD_CONTROL. The anti-weakening guarantee is intact: no
// upstream call, not executed, and the outcome is never WOULD_EXECUTE.
func TestAntiWeakening_ShadowCannotSoftenHardAuthFailure(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeShadow), up, realEvents(t, nil))
	in := execInput(policy.ActionAllow, false)
	in.Decision.HardOverride = true
	in.Decision.Reason = policy.ReasonTenantMismatch // a hard auth/tenant failure
	out := e.Execute(context.Background(), in)
	if up.calls != 0 {
		t.Fatal("shadow must never soften a hard tenant/auth failure to an upstream call")
	}
	if out.Executed || out.ExecutionState != "shadow_evaluated" {
		t.Fatalf("hard auth failure must be a non-executing shadow evaluation: executed=%v state=%q", out.Executed, out.ExecutionState)
	}
	got := shadowOutcomeFromBody(t, out.ResponseBody)
	if got != string(ShadowWouldFailHardControl) {
		t.Fatalf("shadow_outcome = %q, want %q — a hard auth/tenant control must be predicted, never softened", got, ShadowWouldFailHardControl)
	}
	if got == string(ShadowWouldExecute) {
		t.Fatal("a hard auth failure must never be reported as WOULD_EXECUTE")
	}
}

func TestAntiWeakening_DefaultEmptyScopeExecutesNothing(t *testing.T) {
	// Shadow with the DEFAULT empty scope must execute nothing.
	st := rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits())
	_ = st.SetConfig(rollout.SignedConfig{SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeShadow,
		Scope: rollout.ScopeSpec{Capability: rollout.CapabilityGateway}, ConnectorMode: rollout.ConnectorLocalClient}, "a", 1)
	up := &fakeUpstream{}
	e := newExec(t, st, up, realEvents(t, nil))
	if out := e.Execute(context.Background(), execInput(policy.ActionAllow, false)); out.Executed || up.calls != 0 {
		t.Fatal("a default empty shadow scope must execute nothing")
	}
}

func TestAntiWeakening_AllowOnceConsumedOnce(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	in := execInput(policy.ActionAllowOnce, false)
	if out := e.Execute(context.Background(), in); !out.Executed {
		t.Fatal("first ALLOW_ONCE should execute")
	}
	if out := e.Execute(context.Background(), in); out.Executed {
		t.Fatal("a second ALLOW_ONCE must not execute (single use)")
	}
	if up.calls != 1 {
		t.Fatalf("ALLOW_ONCE must permit exactly one upstream call, got %d", up.calls)
	}
}

// ── Response DLP before egress ──────────────────────────────────────────────

func TestExecResponseDLPBlocksSecret(t *testing.T) {
	// The upstream returns a private key in its result; response DLP must BLOCK it
	// before it is delivered to the client (no sensitive content returned).
	up := &fakeUpstream{result: `{"data":"-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q\n-----END RSA PRIVATE KEY-----"}`} // #nosec G101 -- test fixture; asserts response DLP blocks a private key
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	out := e.Execute(context.Background(), execInput(policy.ActionAllow, false))
	if up.calls != 1 {
		t.Fatal("the upstream is called, then the response is inspected")
	}
	if out.Executed {
		t.Fatal("a response carrying a secret must be blocked, not delivered")
	}
	if out.EffectiveAction != "block" {
		t.Fatalf("response DLP block expected, got %q", out.EffectiveAction)
	}
}

// ── Concurrency: transition vs execution, allowance races ───────────────────

func TestConcurrencyTransitionVsExecution(t *testing.T) {
	st := stateForMode(t, rollout.ModeCanary)
	up := &fakeUpstream{}
	e := newExec(t, st, up, realEvents(t, nil))
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			// Flip between Canary and Observe concurrently with executions.
			m := rollout.ModeObserve
			if i%2 == 0 {
				m = rollout.ModeCanary
			}
			_ = st.SetConfig(rollout.SignedConfig{SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: m, ScopeRevision: uint64(i),
				Scope: rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Servers: []string{"s1"}}, ConnectorMode: rollout.ConnectorLocalClient}, "a", int64(i))
		}
		close(done)
	}()
	for i := 0; i < 200; i++ {
		// Must never panic or observe a half-applied mode; the result is always one
		// of the valid dispositions.
		out := e.Execute(context.Background(), execInput(policy.ActionAllow, false))
		if out.ExecutionState == "" {
			t.Fatal("execution produced no state under concurrency")
		}
	}
	<-done
}

// ── No-token-passthrough + credential containment (no broker ⇒ no auth) ──────

func TestNoTokenPassthrough(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	// The ExecInput carries a resolved identity, never a raw token; with no broker
	// configured the upstream call carries NO Authorization header.
	_ = e.Execute(context.Background(), execInput(policy.ActionAllow, false))
	if up.lastAuth != "" {
		t.Fatalf("no client token / auth header may be forwarded upstream, got %q", up.lastAuth)
	}
}

// ── helpers reused from executor_test.go: fakeUpstream, stateForMode, execInput,
//    newExec, realEvents, failBackend. ──

// eventsCritFacts builds a CRITICAL write decision fact to degrade the critical
// durable domain (used only by the admission-saturation test).
func eventsCritFacts() events.DecisionFacts {
	return events.DecisionFacts{
		Capability:  model.CapGateway,
		Criticality: model.CritCritical,
		ActionClass: model.ActionClassWrite,
		Identity:    model.IdentityEvidence{Tenant: "t1", PrincipalID: "p1", PrincipalType: "workload"},
		Decision:    model.DecisionEvidence{Action: "ALLOW", ReasonCode: "MCP.POLICY.OK"},
	}
}

const evCapGateway = model.CapGateway

func spoolNewOSBackend() spool.Backend { return spool.NewOSBackend() }

type spoolReceipt = spool.CommitReceipt

var _ = json.Marshal
