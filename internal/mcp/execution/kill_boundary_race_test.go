package execution

// PREREQ-MCP-KILL-1 — emergency-kill side-effect-boundary revalidation.
//
// These tests prove the core invariant: if an emergency kill is engaged (or its
// authoritative generation otherwise changes) before the irreversible upstream side
// effect, the request MUST NOT cross Upstream.Call. Detection is centralized at the ONE
// boundary (run.go callUpstream) via a monotonic kill-generation captured at admission
// (Model B / epoch semantics), so a kill engaged in ANY post-admission window — durable
// commit, credential Plan, materialization, or the final tool-freshness check — is caught
// at the boundary, and an engage→clear (ABA) that straddles the request is caught too.
//
// Ordering is made deterministic with channels/barriers, never sleeps. The boundary hook
// (ToolStillCurrent) is the executor's last pre-call callback; the credential path reaches
// it inside the broker's zeroizing materialize callback, and the killable provider below
// gives a genuine "kill during materialization" (during provider Fetch) injection point.
//
// Execution posture stays CLOSED: these compose an Executor in controlled tests only; no
// production LiveExecutor, no Canary/Production activation, no real external side effect.
//
// Mutation campaign (PREREQ-MCP-KILL-1 §10). Each defect below was mechanically
// re-introduced into the production source and the named guard confirmed to FAIL (a passing
// guard would be vacuous); the driver is scratch tooling, the mapping is the durable record:
//   M1  remove the final boundary kill re-read          → TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary
//   M2  move the kill re-read before ToolStillCurrent    → TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary
//   M3  drop kill reclassification on credential path    → TestKillBoundary_RaceMatrix (credential subtests)
//   M4  drop kill reclassification on no-credential path → TestKillBoundary_NoCredentialReasonMapping
//   M5  map the boundary kill to ReasonNone              → TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary
//   M6  detect the kill but still call upstream          → TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary
//   M7  weaken the admission (Execute-entry) kill check  → TestKillBoundary_KillBetweenResolveAndExecute
//   M8  break the monotonic kill generation (ABA)        → TestKillBoundary_RaceMatrix (9_engage_clear_aba)
//   M9  re-resolve rollout at Execute (F7 violation)     → TestExecute_CarriesModeScopeResolutionWithoutReResolving
//   M10 report Executed=true after a boundary kill       → TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// killReq fails the test unless ok (a compact local assertion for this file).
func killReq(t *testing.T, ok bool, format string, a ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, a...)
	}
}

// req0Upstream asserts the upstream side effect never happened.
func req0Upstream(t *testing.T, up *fakeUpstream) {
	t.Helper()
	killReq(t, up.calls == 0, "SECURITY: upstream must NOT be called after an emergency kill at the boundary, got %d call(s)", up.calls)
}

// mustEmergencyBlock asserts the standard boundary emergency-kill refusal shape: not
// executed, terminal block, reason rollout_emergency_active (never ReasonNone / transport /
// durability).
func mustEmergencyBlock(t *testing.T, out runtime.ExecOutput) {
	t.Helper()
	killReq(t, !out.Executed, "SECURITY: a boundary emergency-kill refusal must not report Executed=true (state=%q)", out.ExecutionState)
	killReq(t, out.ExecutionState == "blocked", "boundary kill must be a terminal block, got state=%q", out.ExecutionState)
	killReq(t, out.Reason == mcperr.ReasonRolloutEmergencyActive, "boundary kill reason=%v want rollout_emergency_active", out.Reason)
}

// ── credential-path harness with a genuine materialization (Fetch) hook ──────

// killableProvider embeds the in-memory provider and runs onFetch on the FIRST Fetch,
// giving a deterministic injection point INSIDE credential materialization — before the
// broker's zeroizing callback (and thus before the boundary kill re-check) runs.
type killableProvider struct {
	*provider.InMemoryProvider
	onFetch func()
	once    sync.Once
}

func (p *killableProvider) Fetch(ctx context.Context, req provider.Request) (*provider.Result, error) {
	if p.onFetch != nil {
		p.once.Do(p.onFetch)
	}
	return p.InMemoryProvider.Fetch(ctx, req)
}

// newCredKillBroker builds a real credential broker (mirroring credDriftSetup) whose
// provider runs onFetch during materialization, plus the resolved identity the plan
// validates against. onFetch nil ⇒ an ordinary materializing broker.
func newCredKillBroker(t *testing.T, onFetch func()) (*broker.Broker, *identity.ResolvedContext) {
	t.Helper()
	clk := credDriftClock()
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: credDriftSrv, Endpoint: "mcp://srv-1", PinnedIdentity: credDriftIdent,
		Capability: protocol.Gateway, CredentialProfile: "cred-a", OwnerScope: registry.OwnerScope(credDriftTenant),
	}); err != nil {
		t.Fatal(err)
	}
	cat := catalog.New(limits.DefaultCatalog())
	store := profile.NewStore(limits.DefaultCredential())
	rs, err := profile.NewResourceScope([]string{"repo:foo"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Add(profile.Input{
		ID: credDriftProf, Provider: credDriftProv, Tenant: credDriftTenant, Environment: "prod", Server: credDriftSrv,
		Resources: rs, Operations: []profile.OperationClass{profile.OpRead, profile.OpWrite},
		Kind: profile.KindBearerToken, Power: profile.PowerWrite, MaxTTL: 30 * time.Minute,
		Cache:    profile.CachePolicy{Enabled: true, Freshness: time.Minute},
		Rotation: profile.RotationPolicy{Enabled: true, Grace: 30 * time.Second, MaxAttempts: 3},
		Failure:  profile.FailurePolicy{HighRiskFailClosed: true, AllowLowRiskCachedFallback: true},
		Enabled:  true,
	}, reg.Current()); err != nil {
		t.Fatal(err)
	}
	inner := provider.NewInMemory(credDriftProv, provider.Capabilities{})
	inner.SetMaterial(profile.KindBearerToken,
		map[provider.FieldName][]byte{provider.FieldToken: []byte("UPSTREAM-v1")},
		provider.Lease{
			Version: "v1", IssuedAt: clk(), Expiry: clk().Add(20 * time.Minute),
			Scope: profile.EffectiveScope{
				Tenant: credDriftTenant, Environment: "prod", Server: credDriftSrv,
				Resources: rs, Power: profile.PowerReadOnly, HasScopeProof: true,
			},
		})
	prov := &killableProvider{InMemoryProvider: inner, onFetch: onFetch}
	b := broker.New(broker.Deps{Profiles: store, Registry: reg, Catalog: cat, KEK: testKEK(), Clock: clk}, limits.DefaultCredential())
	if err := b.RegisterProvider(prov); err != nil {
		t.Fatal(err)
	}
	sid := credDriftSrv
	id, err := identity.Resolve(identity.ResolveInput{
		Capability: protocol.Gateway, Tenant: identity.Tenant{ID: credDriftTenant},
		Subject: identity.Subject{Kind: identity.SubjectHuman, Human: &identity.Human{
			Subject: "u1", Tenant: credDriftTenant, Issuer: "iss", Assurance: identity.AssuranceHigh,
		}},
		Client:            identity.Client{ClientID: "c1", Tenant: credDriftTenant, Capability: protocol.Gateway},
		Server:            &sid,
		CanonicalResource: "/mcp/gateway/srv-1", Issuer: "iss", TokenDigest: "digest-abc123",
	}, reg, cat)
	if err != nil {
		t.Fatalf("resolve identity: %v", err)
	}
	return b, id
}

// credKillExecutor builds a live Executor over a credential broker whose provider runs
// onFetch during materialization.
func credKillExecutor(t *testing.T, st *rollout.State, up *fakeUpstream, onFetch func()) (*Executor, *identity.ResolvedContext) {
	t.Helper()
	b, id := newCredKillBroker(t, onFetch)
	return credDriftExecutorForState(t, b, up, st), id
}

// ── the race matrix ──────────────────────────────────────────────────────────

// TestKillBoundary_RaceMatrix drives an emergency kill at every relevant window and asserts
// the request never crosses Upstream.Call, never reports Executed, and terminates with
// rollout_emergency_active (unless an earlier documented fail-closed reason already fired).
func TestKillBoundary_RaceMatrix(t *testing.T) {
	// 1. kill BEFORE Execute (admission) — no-credential path.
	t.Run("1_kill_before_execute", func(t *testing.T) {
		st := stateForMode(t, rollout.ModeCanary)
		up := &fakeUpstream{}
		e := newExec(t, st, up, realEvents(t, nil))
		st.EngageKillSwitch("oncall", 1)
		out := runExec(e, context.Background(), execInput(policy.ActionAllow, false))
		req0Upstream(t, up)
		mustEmergencyBlock(t, out)
	})

	// 2. kill AFTER admission, at the boundary (no-credential path).
	t.Run("2_kill_after_admission_boundary", func(t *testing.T) {
		st := stateForMode(t, rollout.ModeCanary)
		up := &fakeUpstream{}
		e := newExec(t, st, up, realEvents(t, nil))
		in := execInput(policy.ActionAllow, false)
		reached := false
		in.ToolStillCurrent = func() bool { reached = true; st.EngageKillSwitch("oncall", 2); return true }
		out := runExec(e, context.Background(), in)
		killReq(t, reached, "boundary hook not reached")
		req0Upstream(t, up)
		mustEmergencyBlock(t, out)
	})

	// 3. kill during the durable-commit window (concurrent operator), no-credential path.
	// The events manager is a concrete collaborator with no independent commit hook, so the
	// kill is engaged by a concurrent goroutine and the boundary hook rendezvouses with it:
	// the request cannot cross the boundary until the concurrent kill has landed. Detection
	// is at the boundary regardless of the exact pre-boundary window (epoch model).
	t.Run("3_kill_during_commit_concurrent", func(t *testing.T) {
		st := stateForMode(t, rollout.ModeCanary)
		up := &fakeUpstream{}
		e := newExec(t, st, up, realEvents(t, nil))
		killed := make(chan struct{})
		in := execInput(policy.ActionAllow, false)
		in.ToolStillCurrent = func() bool { <-killed; return true } // block until the concurrent kill lands
		go func() { st.EngageKillSwitch("oncall", 3); close(killed) }()
		out := runExec(e, context.Background(), in)
		req0Upstream(t, up)
		mustEmergencyBlock(t, out)
	})

	// 4. kill while Broker.Plan / pre-materialization is in flight (credential path). The
	// broker is concrete; the kill is engaged concurrently and the boundary (inside the
	// materialize callback) rendezvouses with it.
	t.Run("4_kill_during_plan_concurrent_credential", func(t *testing.T) {
		st := credDriftStateMode(t, rollout.ModeCanary)
		up := &fakeUpstream{}
		e, id := credKillExecutor(t, st, up, nil)
		killed := make(chan struct{})
		in := credDriftInput(id, func() bool { <-killed; return true })
		go func() { st.EngageKillSwitch("oncall", 4); close(killed) }()
		out := runExec(e, context.Background(), in)
		req0Upstream(t, up)
		mustEmergencyBlock(t, out)
	})

	// 5. kill DURING credential materialization (genuine provider Fetch hook), credential path.
	t.Run("5_kill_during_materialization_credential", func(t *testing.T) {
		st := credDriftStateMode(t, rollout.ModeCanary)
		up := &fakeUpstream{}
		fetched := false
		e, id := credKillExecutor(t, st, up, func() {
			// Runs inside provider.Fetch, i.e. DURING materialization, before the broker's
			// zeroizing callback reaches the boundary kill re-check.
			fetched = true
			st.EngageKillSwitch("oncall", 5)
		})
		out := runExec(e, context.Background(), credDriftInput(id, func() bool { return true }))
		killReq(t, fetched, "provider Fetch (materialization) was never reached")
		req0Upstream(t, up)
		mustEmergencyBlock(t, out)
	})

	// 6. kill from INSIDE ToolStillCurrent (final tool-freshness check) — credential path.
	t.Run("6_kill_from_tool_freshness_credential", func(t *testing.T) {
		st := credDriftStateMode(t, rollout.ModeCanary)
		up := &fakeUpstream{}
		e, id := credKillExecutor(t, st, up, nil)
		reached := false
		in := credDriftInput(id, func() bool { reached = true; st.EngageKillSwitch("oncall", 6); return true })
		out := runExec(e, context.Background(), in)
		killReq(t, reached, "boundary hook not reached")
		req0Upstream(t, up)
		mustEmergencyBlock(t, out)
	})

	// 7. tool drift WITHOUT kill — the existing stale refusal is unchanged (upstream 0,
	// decision_snapshot_stale), proving the new check did not disturb drift handling.
	t.Run("7_tool_drift_without_kill", func(t *testing.T) {
		st := stateForMode(t, rollout.ModeCanary)
		up := &fakeUpstream{}
		e := newExec(t, st, up, realEvents(t, nil))
		in := execInput(policy.ActionAllow, false)
		in.ToolStillCurrent = func() bool { return false } // drifted
		out := runExec(e, context.Background(), in)
		req0Upstream(t, up)
		killReq(t, !out.Executed, "drift refusal must not execute")
		killReq(t, out.Reason == mcperr.ReasonDecisionSnapshotStale, "drift-only reason=%v want decision_snapshot_stale", out.Reason)
	})

	// 8. tool drift + kill concurrently — the boundary refuses (upstream 0). Drift is checked
	// first, so its reason wins; either way it is a fail-closed refusal that never executes.
	t.Run("8_drift_and_kill", func(t *testing.T) {
		st := stateForMode(t, rollout.ModeCanary)
		up := &fakeUpstream{}
		e := newExec(t, st, up, realEvents(t, nil))
		in := execInput(policy.ActionAllow, false)
		in.ToolStillCurrent = func() bool { st.EngageKillSwitch("oncall", 8); return false } // drifted AND killed
		out := runExec(e, context.Background(), in)
		req0Upstream(t, up)
		killReq(t, !out.Executed, "drift+kill refusal must not execute")
		killReq(t, out.Reason == mcperr.ReasonDecisionSnapshotStale || out.Reason == mcperr.ReasonRolloutEmergencyActive,
			"drift+kill reason=%v want a fail-closed refusal (stale or emergency)", out.Reason)
	})

	// 9. engage→clear ABA: the kill is engaged AND cleared before the boundary, so at the
	// boundary Killed()==false — but the monotonic generation advanced, so Model B still
	// refuses. This is the case a boolean-only implementation would miss.
	t.Run("9_engage_clear_aba", func(t *testing.T) {
		st := stateForMode(t, rollout.ModeCanary)
		up := &fakeUpstream{}
		e := newExec(t, st, up, realEvents(t, nil))
		in := execInput(policy.ActionAllow, false)
		in.ToolStillCurrent = func() bool {
			st.EngageKillSwitch("oncall", 9)
			st.ClearKillSwitch()
			killReq(t, !st.Killed(), "precondition: kill must be cleared at the boundary for the ABA case")
			return true
		}
		out := runExec(e, context.Background(), in)
		req0Upstream(t, up)
		mustEmergencyBlock(t, out)
	})

	// 10. many concurrent executions + one emergency kill mid-flight. Every request whose
	// boundary is reached AFTER the kill lands must refuse; none corrupts the others. All
	// boundaries rendezvous on the kill, so upstream is 0 across the fleet.
	t.Run("10_many_concurrent_with_kill", func(t *testing.T) {
		st := stateForMode(t, rollout.ModeCanary)
		up := &fakeUpstream{}
		e := newExec(t, st, up, realEvents(t, nil))
		const n = 24
		killed := make(chan struct{})
		var once sync.Once
		var wg sync.WaitGroup
		var refused int64
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				in := execInput(policy.ActionAllow, false)
				in.ToolStillCurrent = func() bool {
					once.Do(func() { st.EngageKillSwitch("oncall", 10); close(killed) })
					<-killed // every boundary waits until the kill has landed
					return true
				}
				out := runExec(e, context.Background(), in)
				if !out.Executed && out.Reason == mcperr.ReasonRolloutEmergencyActive {
					atomic.AddInt64(&refused, 1)
				}
			}()
		}
		wg.Wait()
		req0Upstream(t, up)
		killReq(t, refused == n, "all %d concurrent requests must refuse with emergency after the kill, got %d", n, refused)
	})
}

// TestKillBoundary_NoCredentialReasonMapping proves the no-credential path maps a boundary
// kill to rollout_emergency_active (never ReasonNone / transport / durability).
func TestKillBoundary_NoCredentialReasonMapping(t *testing.T) {
	st := stateForMode(t, rollout.ModeCanary)
	up := &fakeUpstream{}
	e := newExec(t, st, up, realEvents(t, nil))
	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = func() bool { st.EngageKillSwitch("oncall", 2); return true }
	out := runExec(e, context.Background(), in)
	req0Upstream(t, up)
	mustEmergencyBlock(t, out)
}

// TestKillBoundary_KillBetweenResolveAndExecute pins the LIVE Executor's admission kill
// re-check (executor.go, Execute entry). A kill engaged AFTER Resolve but BEFORE Execute is
// caught by neither the resolution (it was clear when Resolve ran) nor — because admKillGen is
// captured at Execute entry, already past the engage — the boundary generation check. The
// Execute-entry Killed() re-read is the ONLY thing that stops it, so dropping it lets the
// request execute. runExec resolves and executes back-to-back, so this drives the window by
// hand: Resolve, engage, Execute.
func TestKillBoundary_KillBetweenResolveAndExecute(t *testing.T) {
	st := stateForMode(t, rollout.ModeCanary)
	up := &fakeUpstream{}
	e := newExec(t, st, up, realEvents(t, nil))
	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = func() bool { return true }

	res := e.Resolve(in) // resolved while NOT killed
	killReq(t, res.Disposition == rollout.EffectExecute, "precondition: in-scope Canary must resolve to execute, got %v", res.Disposition)
	st.EngageKillSwitch("oncall", 1) // emergency stop lands in the Resolve→Execute window
	out := e.Execute(context.Background(), in, res)

	req0Upstream(t, up)
	mustEmergencyBlock(t, out)
}

// TestKillBoundary_CleanRequestStillExecutes is the control (and the "don't widen / don't
// spuriously block" guard): with NO kill, an in-scope request still crosses the boundary and
// executes. A mutation that re-resolved-and-widened, or that blocked a clean request, fails here.
func TestKillBoundary_CleanRequestStillExecutes(t *testing.T) {
	st := stateForMode(t, rollout.ModeCanary)
	up := &fakeUpstream{}
	e := newExec(t, st, up, realEvents(t, nil))
	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = func() bool { return true }
	out := runExec(e, context.Background(), in)
	killReq(t, up.calls == 1, "a clean (un-killed) request must still execute: upstream calls=%d want 1", up.calls)
	killReq(t, out.Executed, "a clean request must be marked executed")
}
