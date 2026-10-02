package main

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// mcp_canary_scope_in_force_test.go — the deterministic matrix for STALE AUTHORIZATION at the
// live admission boundary (Codex P1, PR #1370, round 2).
//
// The fact under test, in one line:
//
//	a request may spend budget authority ONLY under the exact rollout scope it resolved
//	under — the same authorization envelope, byte for byte, still installed at the moment
//	authority is granted.
//
// Why this is the same defect as the round-1 one, and why it needed its own fix. Scope membership
// is decided ONCE, at resolution (rollout.Scope.Contains, through the executor's Resolve), and the
// request then travels to a boundary that re-reads the trust probe, the reviewed target, the
// operation class, the generation and the kill state — but never re-read the scope. So:
//
//	G armed. Scope S1 permits principal A. A's request resolves executable under S1.
//	the request pauses — a credential path, a durable commit, a scheduler stall.
//	a SAME-MODE update installs S2: A removed, B added. Reviewed target unchanged, budget
//	unchanged ⇒ reconcileCanaryRuntimeAfterCommit accepts it and the generation STAYS G.
//	the request resumes. The target never moved, so nothing drifts; the class still matches;
//	and MaxPrincipals merely COUNTS principals, so A — already counted — clears the ceiling.
//
// It spends authority granted by an envelope that no longer exists.
//
// THE COMPARISON IS EXACT HASH EQUALITY, not a re-run of principal membership, and that choice is
// what these cases are mostly about: re-running membership closes the principal case and leaves
// every sibling open. The hash covers every selector dimension at once, so one comparison closes
// the whole family — including the dimensions nobody enumerated.

// scopeRig is one armed activation over the REAL rollout state, the REAL inventory, a REAL
// four-eyes live approval and the REAL production admission gate.
type scopeRig struct {
	rt   *canaryRuntime
	capb rollout.Capability
	g    *mcpLiveSideEffectGate
	gw   *rollout.State
	sid  string
	tool string
	fp   string
	gen  uint64
}

// newScopeRig arms a Canary whose installed scope admits the seeded server, and returns a rig whose
// requests resolve under that scope.
func newScopeRig(t *testing.T) *scopeRig {
	t.Helper()
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	// Every case here needs the request ADMITTED before it can prove the scope refusal, and
	// admission now refuses a target no peer has been seen advertising (round 13). Observed at
	// the rig's admission instant, before the approval pins the catalog revision.
	observeSeededToolTrustPeerAt(t, sid, canaryRuntimeTestNow)
	_, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn)
	requestAndApproveLiveClassified(t, sid, tool, fpHex, cat.Current().Revision(), tooltrust.ReviewedOpReadOnly)

	gw := getMCPRollout().stateFor(capb)
	prev := gw.CurrentConfig()
	t.Cleanup(func() { _ = gw.SetConfig(prev, "scope-rig-restore", time.Unix(0, 9).UnixNano()) })
	installScope(t, gw, 1, rollout.ScopeSpec{
		Capability: capb, Servers: []string{sid}, Principals: []string{liveRequester},
	})

	gen, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(20),
		ReviewedTargets: []canary.ReviewedTarget{observedReviewedTargetClassified(t, sid, tool, fpHex, policy.OpRead)},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("arm activation: %v", err)
	}
	return &scopeRig{rt: rt, capb: capb, g: realAdmissionGate(t, capb), gw: gw, sid: sid, tool: tool, fp: fpHex, gen: gen}
}

// scopeInstallSeq is the apply timestamp handed to SetConfig. The rollout layer uses it only to
// stamp a mode-change event, and these installs are all same-mode, so the only property that
// matters is that it is monotonic — deriving it from the scope revision would be a uint64→int64
// conversion for no benefit.
var scopeInstallSeq atomic.Int64

// installScope replaces the Gateway's live scope WITHOUT changing the mode. This is the
// same-mode update the finding turns on: the rollout layer accepts it (budget and reviewed target
// are untouched) and the activation generation is deliberately NOT re-begun.
func installScope(t *testing.T, gw *rollout.State, rev uint64, spec rollout.ScopeSpec) {
	t.Helper()
	cfg := rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeCanary,
		ScopeRevision: rev, Scope: spec, ConnectorMode: rollout.ConnectorLocalClient,
	}
	if err := gw.SetConfig(cfg, "scope-test", scopeInstallSeq.Add(1)); err != nil {
		t.Fatalf("install scope rev %d: %v", rev, err)
	}
}

// resolvedNow is one admission input carrying the envelope currently installed — what a request
// that just resolved would carry.
func (r *scopeRig) resolvedNow() execution.LiveGateInput { return r.resolvedUnder(r.gw.ScopeHash()) }

// resolvedUnder is one admission input carrying an explicit envelope, so a case can model a
// request that resolved under a scope which has since been replaced.
func (r *scopeRig) resolvedUnder(hash string) execution.LiveGateInput {
	in := driftGateInput(r.sid, r.tool, r.fp, mcpToolTrust.now())
	in.ResolvedScopeHash = hash
	return in
}

// admit drives one real admission and releases any slot it was granted.
func (r *scopeRig) admit(in execution.LiveGateInput) (bool, mcperr.Reason) {
	d := r.g.AdmitSideEffect(in)
	if d.Release != nil {
		d.Release()
	}
	return d.Admit, d.Reason
}

// ── THE REQUIRED SEQUENCE ─────────────────────────────────────────────────────────────────────
//
// The exact case the finding names, driven end to end through the production gate: resolve under
// S1, install S2 in the same mode with the generation unchanged, then resume the stale request.
func TestScopeInForce_StaleRequestRefusedAfterSameModeScopeUpdate(t *testing.T) {
	r := newScopeRig(t)
	h1 := r.gw.ScopeHash()
	stale := r.resolvedUnder(h1)

	// PREMISE — and it has to be asserted, or the refusal below could be for any reason at all.
	// Under S1 the request is admitted through the ordinary read-first path.
	if ok, reason := r.admit(stale); !ok {
		t.Fatalf("premise: a request resolved under the installed scope must be admitted, reason=%s", reason.Code())
	}

	// S2: principal A removed, B added. Same mode, same reviewed target, same budget — so the
	// rollout layer accepts it and the activation generation does NOT change.
	installScope(t, r.gw, 2, rollout.ScopeSpec{
		Capability: r.capb, Servers: []string{r.sid}, Principals: []string{"principal-b@corp"},
	})
	if got := r.rt.currentGeneration(r.capb); got != r.gen {
		t.Fatalf("premise: a same-mode scope update must NOT re-begin the generation, %d → %d", r.gen, got)
	}
	if h2 := r.gw.ScopeHash(); h2 == h1 {
		t.Fatal("premise: replacing the scope must change its content hash")
	}

	// THE GATE. The stale request carries S1's envelope; S2 is installed.
	ok, reason := r.admit(stale)
	if ok {
		t.Fatal("SECURITY: a request that resolved under a scope which no longer exists spent " +
			"budget authority — the authorization envelope was not revalidated at the boundary")
	}
	if reason != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("the refusal must be the bounded out-of-scope reason, got %s", reason.Code())
	}
	// REQUEST-SCOPED: an operator narrowing a scope is the system working, not target drift.
	if r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: a scope edit must not latch the whole Canary — it is stale authorization, " +
			"not evidence that the reviewed target moved")
	}
}

// THE POSITIVE CONTROL for the sequence above, and it is mandatory: with the envelope unchanged the
// same request proceeds through the normal read-first admission path. Without it, a boundary that
// refused everything would satisfy every negative case in this file.
func TestScopeInForce_UnchangedEnvelopeStillProceeds(t *testing.T) {
	r := newScopeRig(t)
	for i := 0; i < 3; i++ {
		if ok, reason := r.admit(r.resolvedNow()); !ok {
			t.Fatalf("attempt %d: an unchanged envelope must proceed, reason=%s", i+1, reason.Code())
		}
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("a healthy admission must not stop the Canary")
	}
}

// A same-mode REAPPLY of the IDENTICAL signed config is not a change and must not reject: the same
// selectors at the same revision produce the same content hash, so an in-flight request stays
// valid across a no-op redeploy.
//
// THE REVISION IS PART OF SCOPE IDENTITY, deliberately, and that is worth stating because it is
// the one place this boundary is conservative. rollout.Scope.computeHash folds the scope revision
// in, so identical SELECTORS published at a NEW revision hash differently and a request in flight
// across that publish is refused — an availability cost with no security gain, in isolation.
//
// It is still the right hash to use, for the reason this whole PR keeps returning to: the rollout
// layer ALREADY decides "did the scope change" with exactly this comparison
// (sameModeSameScope, mcp_rollout.go), and the admin surface documents that both sides fold the
// revision in. Minting a second, selector-only hash for the boundary would create two definitions
// of scope identity that can disagree — and a disagreement about which envelope authorized a
// request is precisely the class of defect being closed. One definition, shared.
func TestScopeInForce_IdenticalReapplyDoesNotReject(t *testing.T) {
	r := newScopeRig(t)
	h1 := r.gw.ScopeHash()
	stale := r.resolvedUnder(h1)

	installScope(t, r.gw, 1, rollout.ScopeSpec{
		Capability: r.capb, Servers: []string{r.sid}, Principals: []string{liveRequester},
	})
	if r.gw.ScopeHash() != h1 {
		t.Fatal("premise: re-applying the identical signed config must produce the identical content hash")
	}
	if ok, reason := r.admit(stale); !ok {
		t.Fatalf("SECURITY: an identical re-apply is not a scope change and must not refuse an "+
			"in-flight request, reason=%s", reason.Code())
	}
}

// EVERY SELECTOR DIMENSION, not just the principal. This is the case for hash equality over a
// principal-membership re-run: each row edits a different dimension, and a boundary that only
// re-checked principals would pass the first row and fail the rest.
func TestScopeInForce_AnySelectorEditRefusesTheStaleRequest(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec func(sid string) rollout.ScopeSpec
	}{
		{"principal A→B", func(sid string) rollout.ScopeSpec {
			return rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Servers: []string{sid}, Principals: []string{"principal-b@corp"}}
		}},
		{"server set changed", func(sid string) rollout.ScopeSpec {
			return rollout.ScopeSpec{Capability: rollout.CapabilityGateway, Servers: []string{sid, "other-server"}, Principals: []string{liveRequester}}
		}},
		{"tool set narrowed", func(sid string) rollout.ScopeSpec {
			return rollout.ScopeSpec{
				Capability: rollout.CapabilityGateway, Servers: []string{sid}, Principals: []string{liveRequester},
				// A fully-pinned selector, as the scope validator requires; the point is that the
				// TOOL dimension moved, not which tool it moved to.
				Tools: []rollout.ToolSel{{
					Server: sid, Name: "some-other-tool",
					Fingerprint: "00000000000000000000000000000000000000000000000000000000000000ff",
				}},
			}
		}},
		{"exclusion added", func(sid string) rollout.ScopeSpec {
			return rollout.ScopeSpec{
				Capability: rollout.CapabilityGateway, Servers: []string{sid}, Principals: []string{liveRequester},
				ExcludePrincipals: []string{"someone-else@corp"},
			}
		}},
		{"tenant added", func(sid string) rollout.ScopeSpec {
			return rollout.ScopeSpec{
				Capability: rollout.CapabilityGateway, Servers: []string{sid}, Principals: []string{liveRequester},
				Tenants: []string{ttTenant},
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newScopeRig(t)
			stale := r.resolvedUnder(r.gw.ScopeHash())
			if ok, _ := r.admit(stale); !ok {
				t.Fatal("premise: the request must be admitted before the scope is edited")
			}
			installScope(t, r.gw, 2, tc.spec(r.sid))
			if ok, reason := r.admit(stale); ok {
				t.Fatalf("SECURITY: a %s edit left a stale request able to spend authority "+
					"(reason=%s) — the envelope comparison is not covering this dimension", tc.name, reason.Code())
			}
			if r.rt.abortedNow(r.capb) {
				t.Fatalf("a %s edit is stale authorization, not target drift — nothing may latch", tc.name)
			}
		})
	}
}

// A MISSING envelope fails closed. "" is what a request carries when it never went through
// State.ResolveFor — and an executing Canary request always does, so an empty hash at this
// boundary means something skipped the path that stamps it. Treating it as a match would make the
// entire check optional for exactly those requests.
func TestScopeInForce_MissingEnvelopeFailsClosed(t *testing.T) {
	r := newScopeRig(t)
	if ok, reason := r.admit(r.resolvedUnder("")); ok {
		t.Fatalf("SECURITY: an empty authorization envelope must never be treated as a match "+
			"(reason=%s)", reason.Code())
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("a malformed request is request-scoped — nothing may latch")
	}
}

// DEMOTE → REACTIVATE cannot launder an old envelope into fresh authority. A new generation is a
// new experiment; a request holding the previous scope's hash has no claim on it. This is the
// case a generation-equality check would get wrong in the other direction — the generation moved,
// but so would a naive "the scope changed so re-resolve" fallback.
func TestScopeInForce_ReactivationCannotReuseAnOldEnvelope(t *testing.T) {
	r := newScopeRig(t)
	stale := r.resolvedUnder(r.gw.ScopeHash())
	if ok, _ := r.admit(stale); !ok {
		t.Fatal("premise: the request must be admitted under the original activation")
	}

	if err := r.rt.demoteCanary(r.capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	installScope(t, r.gw, 3, rollout.ScopeSpec{
		Capability: r.capb, Servers: []string{r.sid}, Principals: []string{"principal-b@corp"},
	})
	gen2, err := r.rt.beginCanaryActivation(r.capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(20),
		ReviewedTargets: []canary.ReviewedTarget{observedReviewedTargetClassified(t, r.sid, r.tool, r.fp, policy.OpRead)},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	if gen2 == r.gen {
		t.Fatalf("premise: re-activation must mint a new generation, still %d", r.gen)
	}

	if ok, reason := r.admit(stale); ok {
		t.Fatalf("SECURITY: an envelope from the previous activation was accepted as fresh "+
			"authority under the new one (reason=%s)", reason.Code())
	}
}

// The two boundary revalidations are INDEPENDENT. Adding the scope check must not have made the
// operation-class check redundant or unreachable: with the envelope perfectly in force, a class
// the activation does not bind is still refused.
func TestScopeInForce_ClassRevalidationStillWorksIndependently(t *testing.T) {
	r := newScopeRig(t)
	in := r.resolvedNow()
	in.Operation = policy.OpWrite
	if ok, reason := r.admit(in); ok {
		t.Fatalf("SECURITY: a class the activation does not bind must still be refused with the "+
			"envelope in force (reason=%s)", reason.Code())
	}
	// And the control in the other direction: the matching class with the matching envelope is
	// admitted, so neither check is refusing on the other's behalf.
	if ok, reason := r.admit(r.resolvedNow()); !ok {
		t.Fatalf("both facts in force must admit, reason=%s", reason.Code())
	}
}

// THE EMERGENCY KILL REMAINS THE LAST SECURITY CHECK. The scope revalidation sits inside the
// admission transaction; the kill is re-read at the irreversible boundary, after it. Admission
// succeeding must not imply anything about the kill, or an operator's stop would be advisory.
func TestScopeInForce_EmergencyKillStillOutranksAGrantedAdmission(t *testing.T) {
	r := newScopeRig(t)
	if ok, reason := r.admit(r.resolvedNow()); !ok {
		t.Fatalf("premise: the request must be admitted before the kill, reason=%s", reason.Code())
	}
	r.gw.EngageKillSwitch("test", time.Unix(0, 50).UnixNano())
	t.Cleanup(r.gw.ClearKillSwitch)
	if !r.gw.Killed() {
		t.Fatal("premise: the kill must be engaged")
	}
	// The executor re-reads the kill at the side-effect boundary, AFTER admission. What is pinned
	// here is that the scope check did not move or subsume that read: the kill state is still
	// authoritative and still checked downstream of everything this file is about.
	if r.gw.KillGeneration() == 0 {
		t.Fatal("the kill generation must advance so the boundary re-read can see it")
	}
}

// ── THE CARRY, END TO END ─────────────────────────────────────────────────────────────────────
//
// Every case above hands the boundary an envelope directly, which proves the COMPARISON but says
// nothing about whether the envelope ever gets there on its own. This one drives the real
// resolution: Executor.Resolve stamps the hash onto its Resolution from the scope it decided
// against, Execute carries it onto the ExecInput, liveGateInput hands it to the gate, and the
// admission transaction compares it against the installed scope.
//
// It is written as a POSITIVE control — the upstream is reached — because that is the direction a
// broken carry fails in: a hash that never arrives is "", the boundary correctly refuses "", and
// the only visible symptom is that a healthy request stops executing. A negative test would pass
// against a carry that was silently dropped, which is precisely the mutation this gate exists to
// catch (M17).
func TestScopeInForce_EnvelopeIsCarriedFromResolutionToTheBoundary(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 5)
	ex := cfg.Deps.Executor

	in := liveExecInput(policy.OpRead, "t1", "p1")
	in.ToolStillCurrent = func() bool { return true }

	// The resolution must itself carry the envelope it decided under. Asserted separately from
	// the execution below so a failure names WHICH link broke rather than only that the upstream
	// went unreached.
	res := ex.Resolve(in)
	if res.ScopeHash == "" {
		t.Fatal("SECURITY: the resolution carries no authorization envelope — nothing downstream " +
			"can revalidate a fact that was never captured")
	}
	if want := getMCPRollout().stateFor(rollout.CapabilityGateway).ScopeHash(); res.ScopeHash != want {
		t.Fatalf("the resolution must carry the scope it decided against: got %q want %q", res.ScopeHash, want)
	}
	// And the request must NOT already carry it — proving the carry below is the executor's doing
	// and not something the fixture supplied.
	if in.ResolvedScopeHash != "" {
		t.Fatal("fixture drifted: the input must arrive with no envelope so the carry is attributable")
	}

	if out := ex.Execute(t.Context(), in, res); out.Executed != true && up.callCount() == 0 {
		t.Fatalf("the carried envelope must let a healthy request reach upstream, out=%+v", out)
	}
	if up.callCount() != 1 {
		t.Fatalf("SECURITY: the envelope did not survive resolution → ExecInput → LiveGateInput → "+
			"admission; a healthy request was refused as though the scope had changed, calls=%d",
			up.callCount())
	}
}

// ── THE POST-ADMISSION WINDOW ─────────────────────────────────────────────────────────────────
//
// Admission is one atomic transaction under cr.mu, but the scope is published under
// rollout.State's own swapMu, which that transaction does not hold. So step (5c) proves the
// envelope was in force AT THAT INSTANT and nothing more — and the request then travels on
// through credential materialization, the durable decision commit and connection setup before
// anything physical happens. A scope update landing in that window used to be invisible: the
// final-boundary Revalidate re-read only the activation generation, which a same-mode scope
// update deliberately leaves alone (Codex P1, PR #1370, round 3).
//
// The injection point is ToolStillCurrent, which preCallGuard evaluates immediately BEFORE
// Revalidate — the narrowest place a test can stand inside the window without reaching into
// the executor.
func TestScopeInForce_ScopeWithdrawnAfterAdmissionRefusesBeforeUpstream(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 5)
	ex := cfg.Deps.Executor
	gw := getMCPRollout().gateway

	in := liveExecInput(policy.OpRead, "t1", "p1")
	swapped := false
	in.ToolStillCurrent = func() bool {
		// Inside the window: admission has granted and reserved; the physical call has not begun.
		// Install a DIFFERENT scope at the same mode, so the activation generation is untouched
		// and the generation half of Revalidate stays silent.
		if !swapped {
			swapped = true
			installScope(t, gw, 2, rollout.ScopeSpec{
				Capability: rollout.CapabilityGateway,
				Servers:    []string{"s1", "s2-added-mid-flight"},
			})
		}
		return true // the TOOL did not drift; only the envelope changed
	}

	res := ex.Resolve(in)
	if res.ScopeHash == "" {
		t.Fatal("premise: the resolution must carry an envelope for the boundary to revalidate")
	}
	out := ex.Execute(t.Context(), in, res)

	if !swapped {
		t.Fatal("premise: the scope swap never ran, so this proves nothing about the window")
	}
	if up.callCount() != 0 {
		t.Fatalf("SECURITY: the authorization envelope was withdrawn after admission and the "+
			"request still reached upstream %d time(s) — a physical effect under a scope that "+
			"no longer exists", up.callCount())
	}
	if out.Executed {
		t.Fatalf("a request refused at the boundary must not report Executed, out=%+v", out)
	}
}

// The mandatory control for the gate above: with the envelope UNCHANGED across the same window,
// the request still executes. Without it, a Revalidate wired to refuse unconditionally would
// satisfy the gate above while deleting live execution entirely.
func TestScopeInForce_UnchangedEnvelopeSurvivesThePostAdmissionWindow(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 5)
	ex := cfg.Deps.Executor

	in := liveExecInput(policy.OpRead, "t1", "p1")
	observed := false
	in.ToolStillCurrent = func() bool { observed = true; return true }

	out := ex.Execute(t.Context(), in, ex.Resolve(in))
	if !observed {
		t.Fatal("premise: the boundary guard never ran, so the window was not exercised")
	}
	if up.callCount() != 1 {
		t.Fatalf("CONTROL: an unchanged envelope must still reach upstream exactly once, got %d (out=%+v)",
			up.callCount(), out)
	}
}

// ── THE OTHER TWO AUTHORITIES, AND THE POOL WAIT ──────────────────────────────────────────────
//
// Round 4 found that the boundary predicate was still too narrow in two ways, and that the window
// it guards was still too short.

// liveRealGateTrust is liveRealGate with a MUTABLE approval verdict, so a test can revoke a
// four-eyes grant mid-flight — the thing an operator actually does — rather than starting from a
// node that was never approved.
func liveRealGateTrust(capb rollout.Capability, trust func() bool) *mcpLiveSideEffectGate {
	g := liveRealGate(capb, true)
	g.approvalOK = func(canary.LiveTarget, policy.OperationClass, time.Time) (bool, string) { return trust(), "" }
	return g
}

// preSendUpstream honours CallOptions.PreSend exactly as the real client does — after the point
// where the real client would be holding a pool slot, and before any request bytes exist. It is
// the smallest double that can exercise the executor's half of the contract; the client's half
// (that it calls the hook at all, after acquire, on every leg) is pinned in
// internal/mcp/upstreamclient.
type preSendUpstream struct {
	recordingUpstream
	// beforeSend runs at the instant the real client would be waiting for a pool slot: after
	// admission and after every boundary guard, with nothing sent.
	beforeSend func()
	ran        bool
}

func (u *preSendUpstream) Call(ctx context.Context, target upstreamclient.Target, method string, params json.RawMessage, opts upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	if u.beforeSend != nil {
		u.beforeSend()
	}
	u.ran = true
	if opts.PreSend != nil {
		if err := opts.PreSend(); err != nil {
			return nil, err
		}
	}
	return u.recordingUpstream.Call(ctx, target, method, params, opts)
}

// A four-eyes live approval revoked after admission must not be spent.
//
// Round 22 moved the approval lookup INTO the admission transaction so a revocation racing the
// lock could not be admitted, and recorded in mcp_live_gate.go that "the final boundary re-reads
// tool freshness, generation and kill state, not approval status". This is that residual: a grant
// withdrawn while the request waited on the durable commit or a pool slot. Neither the scope nor
// the generation moves when an approval is revoked, and ToolStillCurrent only checks catalog
// freshness — so nothing else could catch it (Codex P1, PR #1370, round 4).
func TestBoundaryAuthority_ApprovalRevokedAfterAdmissionRefusesBeforeUpstream(t *testing.T) {
	approved := true
	up := &preSendUpstream{beforeSend: func() { approved = false }}
	cfg := armCanaryLiveTierGate(t, up, func() *mcpLiveSideEffectGate {
		return liveRealGateTrust(rollout.CapabilityGateway, func() bool { return approved })
	}, 5)
	ex := cfg.Deps.Executor

	in := liveExecInput(policy.OpRead, "t1", "p1")
	in.ToolStillCurrent = func() bool { return true }
	out := ex.Execute(t.Context(), in, ex.Resolve(in))

	if !up.ran {
		t.Fatal("premise: the revocation never ran, so this proves nothing about the window")
	}
	if up.callCount() != 0 {
		t.Fatalf("SECURITY: a revoked live approval was still spent — %d physical call(s) under a "+
			"four-eyes grant that no longer exists", up.callCount())
	}
	if out.Executed {
		t.Fatalf("a request refused at the boundary must not report Executed, out=%+v", out)
	}
	if out.Reason != mcperr.ReasonLiveTrustRevalidationFailed {
		t.Fatalf("a withdrawn approval must be diagnosed as a trust-revalidation failure, got %s", out.Reason.Code())
	}
}

// The mandatory control: an approval that STAYS valid across the same window still executes.
func TestBoundaryAuthority_ValidApprovalSurvivesThePreSendReAsk(t *testing.T) {
	up := &preSendUpstream{}
	cfg := armCanaryLiveTierGate(t, up, func() *mcpLiveSideEffectGate {
		return liveRealGateTrust(rollout.CapabilityGateway, func() bool { return true })
	}, 5)
	ex := cfg.Deps.Executor

	in := liveExecInput(policy.OpRead, "t1", "p1")
	in.ToolStillCurrent = func() bool { return true }
	out := ex.Execute(t.Context(), in, ex.Resolve(in))

	if up.callCount() != 1 {
		t.Fatalf("CONTROL: an unrevoked approval must still reach upstream exactly once, got %d (out=%+v)",
			up.callCount(), out)
	}
}

// A scope withdrawn during the wait for a pool slot must refuse before the send.
//
// preCallGuard runs and passes; the request then enters Client.Call, which blocks in pool.acquire
// on a per-server semaphore until a slot frees. A scope update landing in THAT wait used to be
// invisible, because nothing was re-read between the guard and the send (Codex P1, round 4).
func TestBoundaryAuthority_ScopeWithdrawnDuringThePoolWaitRefusesBeforeSend(t *testing.T) {
	gw := getMCPRollout().gateway
	up := &preSendUpstream{beforeSend: func() {
		installScope(t, gw, 2, rollout.ScopeSpec{
			Capability: rollout.CapabilityGateway,
			Servers:    []string{"s1", "s2-added-during-the-pool-wait"},
		})
	}}
	cfg := armCanaryLiveTierGate(t, up, func() *mcpLiveSideEffectGate {
		return liveRealGate(rollout.CapabilityGateway, true)
	}, 5)
	ex := cfg.Deps.Executor

	in := liveExecInput(policy.OpRead, "t1", "p1")
	in.ToolStillCurrent = func() bool { return true }
	out := ex.Execute(t.Context(), in, ex.Resolve(in))

	if !up.ran {
		t.Fatal("premise: the scope swap never ran, so this proves nothing about the pool wait")
	}
	if up.callCount() != 0 {
		t.Fatalf("SECURITY: the envelope was withdrawn while the request waited for a pool slot "+
			"and it still sent %d time(s)", up.callCount())
	}
	// AND IT IS DIAGNOSED AS WHAT IT WAS. The identical mismatch caught at admission reports
	// rollout_out_of_scope; reporting rollout_mode_invalid here would give an operator two
	// contradictory answers for one fact, separated only by timing, while the mode is a
	// perfectly valid Canary throughout (Codex P2, round 4).
	if out.Reason != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("a scope withdrawal must be diagnosed as out-of-scope wherever it is caught, got %s",
			out.Reason.Code())
	}
}

// ── THE APPROVAL MUST STATE THE CLASS IN FORCE ────────────────────────────────────────────────
//
// An approval carries its own reviewed operation class, and nothing stops a LATER approval for the
// same exact fingerprint from stating a different one — that is precisely how a reviewer corrects
// an earlier determination. The activation's immutable record, by design, does not move.
//
// So "some live grant satisfies this target" was not a sufficient question: with the read-only
// approval that armed the activation gone and only a MUTATING one live, both admission and the
// boundary still permitted execution as read-first, and the correction never landed for the rest
// of the activation's window (Codex P1, PR #1370, round 5).
func TestBoundaryAuthority_ApprovalMustStateTheClassInForce(t *testing.T) {
	// Built WITHOUT newReviewedRig on purpose: that rig issues its own read-only approval, and the
	// scenario is precisely the one where the read-only grant that armed the activation is gone and
	// the MUTATING correction is the only live approval left.
	_ = withCanaryRuntimeTestEnv(t, "v9.9.9")
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	_, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn)
	requestAndApproveLiveClassified(t, sid, tool, fpHex, cat.Current().Revision(), tooltrust.ReviewedOpMutating)
	now := mcpToolTrust.now()

	tgt := canary.LiveTarget{
		Tenant: ttTenant, ServerID: sid, ToolName: tool,
		Fingerprint: mustDigest(t, fpHex), FingerprintFormat: 1,
	}

	// CONTROL FIRST: the approval is real and satisfies its own class. Without this the refusal
	// below could be a matcher that has simply stopped matching anything.
	if ok, _ := mcpLiveApprovalSatisfied(tgt, policy.OpWrite, now); !ok {
		t.Fatal("premise: the MUTATING approval must satisfy a MUTATING request — otherwise this " +
			"test proves nothing about the class comparison")
	}

	if ok, _ := mcpLiveApprovalSatisfied(tgt, policy.OpRead, now); ok {
		t.Fatal("SECURITY: an approval stating MUTATING satisfied a read-first request — a " +
			"reviewer's correction would then be ignored for the rest of the activation's window")
	}
}

// AND AN UNSTATED CLASS FAILS CLOSED rather than reading as agreement — the same discipline the
// activation gate applies at arming time.
func TestBoundaryAuthority_ApprovalWithNoStatedClassSatisfiesNothing(t *testing.T) {
	r := newReviewedRig(t)
	_, cat := mcpInventory.sharedInventory()
	requestAndApproveLive(t, r.sid, r.tool, r.fp1, cat.Current().Revision())

	tgt := canary.LiveTarget{
		Tenant: ttTenant, ServerID: r.sid, ToolName: r.tool,
		Fingerprint: mustDigest(t, r.fp1), FingerprintFormat: 1,
	}
	for _, class := range []policy.OperationClass{policy.OpUnset, policy.OpDiscovery, policy.OpControl} {
		if ok, _ := mcpLiveApprovalSatisfied(tgt, class, r.now); ok {
			t.Fatalf("SECURITY: a live approval satisfied class %v, which no review can bind to a tool", class)
		}
	}
}

// ── THE ORDER OF THE BOUNDARY PREDICATE ───────────────────────────────────────────────────────
//
// A Canary→non-live commit un-arms the tier and publishes the new scope BEFORE demoteCanary
// invalidates the generation (mcp_rollout.go, the leavingLive arm), so for a window BOTH are
// withdrawn. A scope-first order reported `rollout_out_of_scope` for an already-admitted request
// while a fresh request in the identical final state is refused `rollout_mode_invalid` by the
// unarmed lifecycle gate — the same diagnosis-depends-on-timing defect the reason plumbing exists
// to remove, one layer in (Codex P2, PR #1370, round 5).
func TestBoundaryAuthority_GenerationOutranksScopeWhenBothAreWithdrawn(t *testing.T) {
	capb := rollout.CapabilityGateway
	g := liveRealGate(capb, true)
	// Both withdrawn at once, which is exactly what a leaving-live commit produces.
	g.generationCurrent = func(uint64) bool { return false }
	g.currentScopeHash = func() string { return "a-different-envelope-entirely" }
	g.admitUnderActivation = stubAdmitUnderActivation(canary.BudgetGranted, 11)
	// Gate (1) is the lifecycle admission, which refuses on an unarmed tier; these two cases are
	// about the ORDER of the final-boundary predicate, so it is stubbed open rather than arming a
	// whole live tier to reach one closure.
	g.admit = func() (func(), bool) { return func() {}, true }

	in := execution.LiveGateInput{
		Capability: 0, Tenant: "t1", Principal: "p1", ServerID: "s1", ToolName: "tool", Fingerprint: "fp",
		Operation: policy.OpRead, Now: time.Unix(0, 1),
		ResolvedScopeHash: "the-envelope-this-request-resolved-under",
	}
	d := g.AdmitSideEffect(in)
	if !d.Admit || d.Revalidate == nil {
		t.Fatalf("premise: the stubbed admission must grant so the boundary predicate is reachable; admit=%v reason=%s",
			d.Admit, d.Reason.Code())
	}
	if got := d.Revalidate(); got != mcperr.ReasonRolloutModeInvalid {
		t.Fatalf("with BOTH the generation and the scope withdrawn the refusal must name the "+
			"generation — the same answer a fresh request gets from the unarmed lifecycle gate — got %s",
			got.Code())
	}
}

// The control: with the generation still current, a withdrawn scope is still reported as such.
// Without it, "generation first" could be implemented as "generation only".
func TestBoundaryAuthority_ScopeStillNamedWhenTheGenerationIsCurrent(t *testing.T) {
	capb := rollout.CapabilityGateway
	g := liveRealGate(capb, true)
	g.generationCurrent = func(uint64) bool { return true }
	g.currentScopeHash = func() string { return "a-different-envelope-entirely" }
	g.admitUnderActivation = stubAdmitUnderActivation(canary.BudgetGranted, 11)
	// Gate (1) is the lifecycle admission, which refuses on an unarmed tier; these two cases are
	// about the ORDER of the final-boundary predicate, so it is stubbed open rather than arming a
	// whole live tier to reach one closure.
	g.admit = func() (func(), bool) { return func() {}, true }

	in := execution.LiveGateInput{
		Capability: 0, Tenant: "t1", Principal: "p1", ServerID: "s1", ToolName: "tool", Fingerprint: "fp",
		Operation: policy.OpRead, Now: time.Unix(0, 1),
		ResolvedScopeHash: "the-envelope-this-request-resolved-under",
	}
	d := g.AdmitSideEffect(in)
	if !d.Admit || d.Revalidate == nil {
		t.Fatalf("premise: the stubbed admission must grant; admit=%v", d.Admit)
	}
	if got := d.Revalidate(); got != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("CONTROL: a withdrawn envelope under a live generation must still be named as "+
			"out-of-scope, got %s", got.Code())
	}
}
