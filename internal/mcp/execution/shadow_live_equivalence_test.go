package execution

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// TestShadow_LivePreSideEffectEquivalence is the §10 differential gate. For every
// decision class it drives BOTH the capability-reduced ShadowEvaluator (Shadow mode) and
// the live Executor up to — but never across — the side-effect boundary (Canary mode,
// fake upstream, no real network) with the SAME input, then asserts the Shadow Model-1
// outcome equals what live enforcement would actually do at that boundary.
//
// The point: Shadow evidence is only usable for a Canary-readiness decision if it is a
// faithful predictor of live enforcement. A policy DENY/APPROVAL/CONFIRMATION must never
// read as WOULD_EXECUTE; a hard control, stale decision, or credential-readiness failure
// must land on its own would-fail outcome — not a spurious would-execute and not a
// generic block that hides which control fired.
func TestShadow_LivePreSideEffectEquivalence(t *testing.T) {
	clk := func() time.Time { return time.Unix(0, 1) }

	cases := []struct {
		name string
		want canon
		// setup returns the shared input plus a live Canary executor and a Shadow
		// evaluator wired from matching dependencies (fake upstream captured for the
		// live-executed assertion).
		setup func(t *testing.T) (in runtime.ExecInput, live *Executor, shadow *ShadowEvaluator, up *fakeUpstream)
	}{
		{
			name: "allow_executes",
			want: cExecute,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				live, up := liveCanary(t)
				return execInput(policy.ActionAllow, false), live, shadowEval(t, nil), up
			},
		},
		{
			name: "deny_blocks",
			want: cBlock,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				live, up := liveCanary(t)
				return execInput(policy.ActionDeny, false), live, shadowEval(t, nil), up
			},
		},
		{
			name: "require_approval",
			want: cRequireApproval,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				live, up := liveCanary(t)
				return execInput(policy.ActionRequireApproval, false), live, shadowEval(t, nil), up
			},
		},
		{
			name: "require_confirmation",
			want: cRequireConfirmation,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				live, up := liveCanary(t)
				return execInput(policy.ActionRequireConfirmation, false), live, shadowEval(t, nil), up
			},
		},
		{
			name: "allow_once_available_executes",
			want: cExecute,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				live, up := liveCanary(t)
				return execInput(policy.ActionAllowOnce, false), live, shadowEval(t, nil), up
			},
		},
		{
			name: "allow_once_consumed_blocks",
			want: cBlock,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				in := execInput(policy.ActionAllowOnce, false)
				live, up := liveCanary(t)
				shadow := shadowEval(t, nil)
				// Seed BOTH allowance views to the already-consumed state, so the
				// differential compares the same allowance history.
				seedConsumedOnce(t, live.allowances, in)
				seedConsumedOnce(t, shadow.allowances, in)
				return in, live, shadow, up
			},
		},
		{
			name: "allow_for_session_valid_executes",
			want: cExecute,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				live, up := liveCanary(t)
				return execInput(policy.ActionAllowForSession, false), live, shadowEval(t, nil), up
			},
		},
		{
			name: "allow_for_session_exhausted_blocks",
			want: cBlock,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				in := execInput(policy.ActionAllowForSession, false)
				live, up := liveCanary(t)
				shadow := shadowEval(t, nil)
				seedSessionAtCap(live.allowances, in, clk())
				seedSessionAtCap(shadow.allowances, in, clk())
				return in, live, shadow, up
			},
		},
		{
			name: "credential_missing_fails_readiness",
			want: cFailCredential,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				b, id := credDriftSetup(t)
				up := &fakeUpstream{}
				live := credDriftExecutorForState(t, b, up, credDriftStateMode(t, rollout.ModeCanary))
				shadow := shadowEvalPlanner(t, credDriftStateMode(t, rollout.ModeShadow), b)
				in := credDriftInput(id, func() bool { return true })
				in.Decision.Obligations.CredentialProfile = "no-such-profile" // Plan fails closed
				return in, live, shadow, up
			},
		},
		{
			// Codex P2 round-6: a profile is named but NO broker/planner is composed. The live
			// executor now FAILS CLOSED (a credential is required but cannot be planned/materialized,
			// so reaching the upstream with no Authorization would bypass the required credential
			// path) — and Shadow must predict WOULD_FAIL_CREDENTIAL_READINESS to stay equivalent.
			// Live: newExec builds the Executor with a nil Broker; Shadow: planner nil.
			name: "credential_no_broker_fails_closed",
			want: cFailCredential,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				in := execInput(policy.ActionAllow, false)
				in.Decision.Obligations.CredentialProfile = "prof-x"
				live, up := liveCanary(t)
				return in, live, shadowEval(t, nil), up
			},
		},
		{
			// Codex P2 precedence: a request that is BOTH credential-invalid AND
			// drifted-after-entry must return the CREDENTIAL failure in both paths — live
			// plans the credential (materializeAndCall → Broker.Plan) before callUpstream's
			// drift re-check, so Plan fails first. decide() checks credential before the
			// boundary stale re-check to match.
			name: "credential_invalid_and_drift_prefers_credential",
			want: cFailCredential,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				b, id := credDriftSetup(t)
				up := &fakeUpstream{}
				live := credDriftExecutorForState(t, b, up, credDriftStateMode(t, rollout.ModeCanary))
				shadow := shadowEvalPlanner(t, credDriftStateMode(t, rollout.ModeShadow), b)
				in := credDriftInput(id, func() bool { return false }) // drifted at the boundary
				in.Decision.Obligations.CredentialProfile = "no-such-profile"
				return in, live, shadow, up
			},
		},
		{
			name: "tool_fingerprint_drift_fails_stale",
			want: cFailStale,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				in := execInput(policy.ActionAllow, false)
				in.ToolStillCurrent = func() bool { return false } // drifted since the decision
				live, up := liveCanary(t)
				return in, live, shadowEval(t, nil), up
			},
		},
		{
			name: "tool_eligibility_changed_fails_hard_control",
			want: cFailHardControl,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				in := execInput(policy.ActionAllow, false)
				in.Decision.HardOverride = true
				in.Decision.Reason = policy.ReasonToolUnknown // no longer an eligible tool
				live, up := liveCanary(t)
				return in, live, shadowEval(t, nil), up
			},
		},
		{
			name: "server_disabled_fails_hard_control",
			want: cFailHardControl,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				in := execInput(policy.ActionAllow, false)
				in.Decision.HardOverride = true
				in.Decision.Reason = policy.ReasonServerDisabled
				live, up := liveCanary(t)
				return in, live, shadowEval(t, nil), up
			},
		},
		{
			// Provider-level contract: both paths map an inspection hard-fail to the same
			// verdict WHEN reached. NOTE (SHADOW-EVIDENCE-ROUTING-1): the live runtime
			// terminally rejects an inspection HardFail in dispatchPolicy BEFORE the
			// executor, so in production neither path reaches the provider for this case —
			// this asserts the provider contract via direct invocation, not live routing.
			name: "request_inspection_fail",
			want: cFailInspection,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				live, up := liveCanary(t)
				return execInput(policy.ActionAllow, true), live, shadowEval(t, nil), up
			},
		},
		{
			name: "kill_switch_active",
			want: cKilled,
			setup: func(t *testing.T) (runtime.ExecInput, *Executor, *ShadowEvaluator, *fakeUpstream) {
				liveSt := stateForMode(t, rollout.ModeCanary)
				liveSt.EngageKillSwitch("oncall", 1)
				up := &fakeUpstream{}
				live := mustExec(t, liveSt, up, realEvents(t, nil))
				shSt := stateForMode(t, rollout.ModeShadow)
				shSt.EngageKillSwitch("oncall", 1)
				shadow := shadowEvalState(t, shSt, nil)
				return execInput(policy.ActionAllow, false), live, shadow, up
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, live, shadow, up := tc.setup(t)

			liveOut := runExec(live, context.Background(), in)
			shadowOut := runExec(shadow, context.Background(), in)

			// The Shadow evaluator must NEVER execute or touch upstream, ever.
			if shadowOut.Executed {
				t.Fatalf("shadow marked executed for %q", tc.name)
			}

			gotLive := liveCanon(t, in, liveOut, up.calls)
			gotShadow := shadowCanon(t, shadowOut)

			if gotLive != tc.want {
				t.Fatalf("live pre-side-effect outcome = %v, want %v", gotLive, tc.want)
			}
			if gotShadow != tc.want {
				t.Fatalf("shadow outcome = %v, want %v", gotShadow, tc.want)
			}
			if gotLive != gotShadow {
				t.Fatalf("DIFFERENTIAL DIVERGENCE: live=%v shadow=%v — shadow evidence must faithfully predict live enforcement", gotLive, gotShadow)
			}
		})
	}
}

// TestShadow_PreservesPolicyVerdictSeparately proves the §8 invariant: a Shadow
// evaluation records the RAW policy verdict (evaluated_policy_action) SEPARATELY from the
// enforcement prediction (shadow_outcome). A policy DENY / REQUIRE_APPROVAL /
// REQUIRE_CONFIRMATION is never laundered into a plain WOULD_EXECUTE, and the two fields
// carry distinct information (the evaluated action is not overwritten by the outcome).
//
// This is the gate for mutation #5 (removing policy-outcome preservation): collapsing
// evaluated_policy_action onto shadow_outcome, or dropping it, fails here.
func TestShadow_PreservesPolicyVerdictSeparately(t *testing.T) {
	cases := []struct {
		action       policy.Action
		wantOutcome  ShadowOutcome
		wantAction   string
		wantOverride bool
	}{
		{policy.ActionAllow, ShadowWouldExecute, "ALLOW", false},
		{policy.ActionDeny, ShadowWouldBlock, "DENY", true},
		{policy.ActionRequireApproval, ShadowWouldRequireApproval, "REQUIRE_APPROVAL", true},
		{policy.ActionRequireConfirmation, ShadowWouldRequireConfirmation, "REQUIRE_CONFIRMATION", true},
	}
	for _, tc := range cases {
		t.Run(tc.wantAction, func(t *testing.T) {
			shadow := shadowEval(t, nil)
			out := runExec(shadow, context.Background(), execInput(tc.action, false))
			if out.Executed {
				t.Fatal("shadow must never execute")
			}
			gotAction, gotOutcome, gotOverride := shadowBodyFields(t, out.ResponseBody)
			if gotAction != tc.wantAction {
				t.Fatalf("evaluated_policy_action = %q, want %q — the raw policy verdict must be preserved verbatim", gotAction, tc.wantAction)
			}
			if gotOutcome != string(tc.wantOutcome) {
				t.Fatalf("shadow_outcome = %q, want %q", gotOutcome, tc.wantOutcome)
			}
			if gotOverride != tc.wantOverride {
				t.Fatalf("shadow_override = %v, want %v", gotOverride, tc.wantOverride)
			}
			// The two fields must be DISTINCT carriers: a restrictive policy verdict must
			// not be represented ONLY by the outcome (which would erase which policy action
			// the operator actually configured).
			if tc.wantOverride && gotAction == gotOutcome {
				t.Fatalf("evaluated_policy_action (%q) and shadow_outcome (%q) collapsed to one value — the policy verdict must be preserved separately from the enforcement prediction", gotAction, gotOutcome)
			}
		})
	}
}

// shadowBodyFields extracts the evaluated_policy_action, shadow_outcome and
// shadow_override fields from a shadow-evaluation response body.
func shadowBodyFields(t *testing.T, body []byte) (action, outcome string, override bool) {
	t.Helper()
	var env struct {
		Result struct {
			EvaluatedPolicyAction string `json:"evaluated_policy_action"`
			ShadowOutcome         string `json:"shadow_outcome"`
			ShadowOverride        bool   `json:"shadow_override"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("unmarshal shadow body: %v", err)
	}
	return env.Result.EvaluatedPolicyAction, env.Result.ShadowOutcome, env.Result.ShadowOverride
}

// ── canon: the boundary-equivalent verdict shared by both paths ──

type canon int

const (
	cExecute canon = iota
	cBlock
	cRequireApproval
	cRequireConfirmation
	cFailCredential
	cFailInspection
	cFailStale
	cFailHardControl
	cKilled
)

func (c canon) String() string {
	switch c {
	case cExecute:
		return "execute"
	case cBlock:
		return "block"
	case cRequireApproval:
		return "require_approval"
	case cRequireConfirmation:
		return "require_confirmation"
	case cFailCredential:
		return "fail_credential"
	case cFailInspection:
		return "fail_inspection"
	case cFailStale:
		return "fail_stale"
	case cFailHardControl:
		return "fail_hard_control"
	case cKilled:
		return "killed"
	default:
		return "unknown"
	}
}

// liveCanon projects the live Executor's pre-side-effect result to a canonical verdict.
// It mirrors the executor's own reason taxonomy; an unmapped reason fails the test rather
// than silently collapsing to a bucket.
func liveCanon(t *testing.T, in runtime.ExecInput, out runtime.ExecOutput, upCalls int) canon {
	t.Helper()
	if out.Executed && upCalls > 0 {
		return cExecute
	}
	switch out.Reason {
	case mcperr.ReasonRolloutEmergencyActive:
		return cKilled
	case mcperr.ReasonApprovalRequired:
		return cRequireApproval
	case mcperr.ReasonConfirmationRequired:
		return cRequireConfirmation
	case mcperr.ReasonExecutionNotPermitted, mcperr.ReasonAllowanceConsumed, mcperr.ReasonRedactionFailed:
		return cBlock
	case mcperr.ReasonDecisionSnapshotStale:
		return cFailStale
	}
	// An inspection hard-fail is identified structurally (same signal decide() reads).
	if in.Inspection != nil && in.Inspection.HardFail && out.Reason == in.Inspection.HardReason {
		return cFailInspection
	}
	if isCredentialReason(out.Reason) {
		return cFailCredential
	}
	if rollout.IsHardFailure(out.Reason) {
		return cFailHardControl
	}
	t.Fatalf("live reason %q not mapped to a canonical verdict", out.Reason.Code())
	return cBlock
}

// shadowCanon projects a Shadow evaluation to the same canonical space. A shadow-evaluated
// result carries its Model-1 outcome in the body; a pre-decide block (kill switch) is read
// from the reason, exactly like the live path.
func shadowCanon(t *testing.T, out runtime.ExecOutput) canon {
	t.Helper()
	if out.ExecutionState != "shadow_evaluated" {
		switch out.Reason {
		case mcperr.ReasonRolloutEmergencyActive:
			return cKilled
		default:
			t.Fatalf("shadow non-evaluation with reason %q", out.Reason.Code())
		}
	}
	switch ShadowOutcome(shadowOutcomeFromBody(t, out.ResponseBody)) {
	case ShadowWouldExecute:
		return cExecute
	case ShadowWouldBlock:
		return cBlock
	case ShadowWouldRequireApproval:
		return cRequireApproval
	case ShadowWouldRequireConfirmation:
		return cRequireConfirmation
	case ShadowWouldFailCredentialReadiness:
		return cFailCredential
	case ShadowWouldFailInspection:
		return cFailInspection
	case ShadowWouldFailStaleDecision:
		return cFailStale
	case ShadowWouldFailHardControl:
		return cFailHardControl
	default:
		t.Fatalf("unmapped shadow outcome")
		return cBlock
	}
}

func isCredentialReason(r mcperr.Reason) bool {
	switch r {
	case mcperr.ReasonCredentialProfileMissing, mcperr.ReasonCredentialProfileDisabled,
		mcperr.ReasonCredentialVersionStale, mcperr.ReasonCredentialScopeMismatch:
		return true
	default:
		return false
	}
}

// ── harness helpers ──

// liveCanary builds a live Canary executor paired with the fake upstream wired into it,
// so the test can read the exact call count that executor produced.
func liveCanary(t *testing.T) (*Executor, *fakeUpstream) {
	t.Helper()
	up := &fakeUpstream{}
	return mustExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil)), up
}

func mustExec(t *testing.T, st *rollout.State, up UpstreamCaller, ev *events.Manager) *Executor {
	t.Helper()
	return newExec(t, st, up, ev)
}

func shadowEval(t *testing.T, planner CredentialPlanner) *ShadowEvaluator {
	t.Helper()
	return shadowEvalState(t, stateForMode(t, rollout.ModeShadow), planner)
}

func shadowEvalPlanner(t *testing.T, st *rollout.State, planner CredentialPlanner) *ShadowEvaluator {
	t.Helper()
	return shadowEvalState(t, st, planner)
}

func shadowEvalState(t *testing.T, st *rollout.State, planner CredentialPlanner) *ShadowEvaluator {
	t.Helper()
	s, err := NewShadowEvaluator(ShadowConfig{
		State: st, Events: realEvents(t, nil), Planner: planner,
		Clock: func() time.Time { return time.Unix(0, 1) },
	})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	return s
}

func seedConsumedOnce(t *testing.T, s *allowanceStore, in runtime.ExecInput) {
	t.Helper()
	if !s.consume(in, rollout.ActionKindAllowOnce, time.Unix(0, 1)) {
		t.Fatal("seed: first ALLOW_ONCE consume should succeed")
	}
}

func seedSessionAtCap(s *allowanceStore, in runtime.ExecInput, now time.Time) {
	key := allowanceKey(in)
	s.mu.Lock()
	s.sess[key] = &sessGrant{calls: sessionCallCap, expiry: now.Add(sessionTTL)}
	s.mu.Unlock()
}
