package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// mcp_canary_reviewed_binding_test.go — the §12 deterministic matrix for the ACTIVATION-BOUND
// REVIEWED TARGET SNAPSHOT (blocker #7, Round-24 P1).
//
// The fact under test, in one line:
//
//	an activation carries immutable durable evidence of the exact targets it was reviewed and
//	authorized to execute, and drift is decided against THAT — never against whether the original
//	approval happens to still be unexpired.
//
// Why the distinction is the whole point. A first Canary window may run for
// canary.FirstCanaryMaxWindowCeiling (7 days); a live-execution approval may live for at most
// canary.MaxInitialCanaryApprovalTTL (24 hours). For six of those seven days the approval store
// can no longer say what this activation was reviewed against. The superseded design inferred
// drift from an approval still pinned to the reviewed fingerprint, so drift detection expired
// with the approval — an attacker who waits out 24 hours and then republishes the tool faced an
// ordinary "not approved" denial instead of a whole-experiment abort. Case 4 is that sequence.
//
// Every case here uses explicit clock seams (the tool-trust fake clock, and the instant passed
// into the gate input). There are no sleeps.
//
// The cases, in the order the specification enumerates them:
//
//	 1  F1 healthy, approval alive                     → admitted
//	 2  F1 healthy, approval expired                   → request-scoped denial, NO drift
//	 3  F1→F2 while the approval is alive              → drift + whole-Canary latch
//	 4  approval expires, THEN F1→F2                   → drift + latch (the headline case)
//	 5  F1→F2, then F2 separately approved             → old G STILL drifts and latches
//	 6  a NEW activation explicitly against F2         → healthy control
//	 7  restart between approval expiry and F1→F2      → drift still detectable
//	 8  empty reviewed-target set                      → activation refused
//	 9  persisted active state missing the reviewed set → restore is NOT executable
//	10  same-generation reviewed-set mutation attempt  → refused
//	11  server identity change                         → server_identity_drift + latch
//	12  demote G, activate G+1 against F2              → the old snapshot cannot affect G+1
//	13  a RESOLVABLE tool never reviewed by this G     → request-scoped denial, NO latch
//	14  the reviewed SERVER becomes unusable            → server_identity_drift + latch
//	15  that anchor loss is a verdict, not silence      → reported as drift, latched
//	16  identity + fingerprint from ONE snapshot        → structural, no second lookup
//	17  the reviewed pair reassigned to another tenant → reviewed_target_tenant_drift + latch
//	18  the repin window (registry I2, catalog I1)     → detected, charged as identity drift
//	19  that window on the OBSERVATION path            → latched there too, not only in the precheck
//	20  every drift verdict is a named evidence key     → wall, not habit
//	21  A→B reassignment seen at ADMISSION              → latched; an unresolvable tool stays silent

// reviewedRig is one armed activation over the REAL inventory, the REAL approval store and the
// REAL admission gate. Everything the matrix asserts flows through production code.
type reviewedRig struct {
	rt   *canaryRuntime
	capb rollout.Capability
	g    *mcpLiveSideEffectGate
	clk  *liveTrustClock
	sid  string
	tool string
	fp1  string    // the reviewed (F1) fingerprint, hex
	now  time.Time // the instant the approval is alive at
	gen  uint64
}

// newReviewedRig seeds the controlled inventory, grants a real four-eyes live approval for it, and
// arms an activation whose reviewed-target snapshot is the target that was actually approved.
func newReviewedRig(t *testing.T) *reviewedRig {
	t.Helper()
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	// Admission refuses a target no peer has been seen advertising (round 13), so a rig whose
	// premise is "the reviewed target is admitted" must observe it — at the rig's admission
	// instant, and before the approval pins the catalog revision.
	observeSeededToolTrustPeerAt(t, sid, canaryRuntimeTestNow)
	clk, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn)
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())

	gen := armReviewedActivation(t, rt, capb, sid, tool, fpHex)
	return &reviewedRig{
		rt: rt, capb: capb, g: realAdmissionGate(t, capb), clk: clk,
		sid: sid, tool: tool, fp1: fpHex, now: mcpToolTrust.now(), gen: gen,
	}
}

// armReviewedActivation arms an activation bound to the CURRENT authoritative target for
// (sid, tool), read through the same precheck the gate uses. This is the test-side stand-in for
// the production projection (reviewedTargetsFromBindings): an explicit reviewed set, never an
// implicit one, because an activation with none must fail closed.
func armReviewedActivation(t *testing.T, rt *canaryRuntime, capb rollout.Capability, sid, tool, fpHex string) uint64 {
	t.Helper()
	gen, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(20),
		ReviewedTargets: []canary.ReviewedTarget{observedReviewedTarget(t, sid, tool, fpHex)},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("begin activation: %v", err)
	}
	return gen
}

// observedReviewedTarget reads the current authoritative target for (sid, tool) as the admission
// probe would, and shapes it as a reviewed record.
func observedReviewedTarget(t *testing.T, sid, tool, fpHex string) canary.ReviewedTarget {
	t.Helper()
	// READ-ONLY, because that is the only reviewed class the First Canary can execute: a tool call
	// reaches the side-effect gate as OpRead or not at all (gate 2), and the admission transaction
	// requires the activation to still bind that class (step 5b). A fixture that armed a MUTATING
	// target and then asserted "the reviewed request must be admitted" would be asserting a state
	// the product cannot reach — which is what the first version of this fixture did, and what the
	// boundary revalidation immediately exposed.
	//
	// Drift is a property of the target's IDENTITY, not of its semantics, so every case in this
	// matrix is indifferent to WHICH class is bound; what it is not indifferent to is the class
	// being the one the request carries.
	return observedReviewedTargetClassified(t, sid, tool, fpHex, policy.OpRead)
}

// observedReviewedTargetClassified is observedReviewedTarget with the reviewed operation class
// stated explicitly. The read-first matrix (blocker #4) uses it to arm a genuinely read-only
// reviewed record; everything else takes the conservative default above.
func observedReviewedTargetClassified(t *testing.T, sid, tool, fpHex string, class policy.OperationClass) canary.ReviewedTarget {
	t.Helper()
	live := mcpLiveTrustPrecheck(ttTenant, sid, tool, fpHex)
	if !live.Eligible {
		t.Fatalf("fixture: %s/%s must resolve to an eligible target, got %+v", sid, tool, live)
	}
	return canary.ReviewedTarget{
		Tenant: live.Target.Tenant, ServerID: live.Target.ServerID, ToolName: live.Target.ToolName,
		Fingerprint: live.Target.Fingerprint, FingerprintFormat: live.Target.FingerprintFormat,
		ServerIdentity: live.ServerIdentity,
		OperationClass: class,
	}
}

// request drives one admission through the production gate at an explicit instant, naming an
// explicit decision fingerprint, and releases any slot it was granted.
func (r *reviewedRig) request(fp string, at time.Time) bool {
	d := r.g.AdmitSideEffect(driftGateInput(r.sid, r.tool, fp, at))
	if d.Release != nil {
		d.Release()
	}
	return d.Admit
}

// republishWithIdentity re-publishes the SAME server/tool under an explicit pinned identity and
// input schema, and returns the tool's new fingerprint. It is how the matrix moves a target: a
// changed schema moves the fingerprint, a changed identity moves the server binding.
func republishWithIdentity(t *testing.T, sid, tool, identity, schema string) string {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"` + identity + `","enabled":true,
	   "tools":[{"name":"` + tool + `","input_schema":` + schema + `}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: registry.ServerID(sid), Name: tool})
	if !ok {
		t.Fatalf("republished tool %s/%s is not in the catalog", sid, tool)
	}
	sum := rec.Fingerprint.Sum()
	return hex.EncodeToString(sum[:])
}

// moveToF2 republishes the reviewed tool with a different schema, so its fingerprint moves while
// its identity and server binding stay exactly as reviewed. It returns the NEW fingerprint, which
// later requests are decided against — so the precheck sees F2 == F2 and reports no drift of its
// own. Only the activation's reviewed snapshot can still tell that the target moved.
func (r *reviewedRig) moveToF2(t *testing.T) string {
	t.Helper()
	fp2 := republishWithIdentity(t, r.sid, r.tool, "id", `{"type":"object","properties":{"moved":{"type":"string"}}}`)
	if fp2 == r.fp1 {
		t.Fatal("premise: the republished tool must carry a DIFFERENT fingerprint")
	}
	// The peer is SEEN advertising F2, so a request decided against F2 is refused for what it is
	// about — the reviewed snapshot — and never merely because a republish left the record
	// unobserved (round 13: admission now refuses an unobserved target before anything else).
	// Observing F2 cannot mask drift: the drift verdict is taken from the same capture BEFORE the
	// freshness answer is consulted.
	observePeerAdvertisingAt(t, r.sid, r.now,
		`{"tools":[{"name":"`+r.tool+`","inputSchema":{"type":"object","properties":{"moved":{"type":"string"}}}}]}`, r.tool)
	// The precheck itself must be blind to this, or the matrix would be proving the OLD mechanism.
	if live := mcpLiveTrustPrecheck(ttTenant, r.sid, r.tool, fp2); live.DriftCode != "" {
		t.Fatalf("premise: a request decided against F2 must show no precheck drift, got %q", live.DriftCode)
	}
	return fp2
}

// assertLatched proves the whole Canary stopped with the named first cause.
func (r *reviewedRig) assertLatched(t *testing.T, wantCode string) {
	t.Helper()
	if !r.rt.abortedNow(r.capb) {
		t.Fatalf("SECURITY: %s is a breach of the experiment's premise — the whole Canary must stop", wantCode)
	}
	if code := r.rt.abortCodeNow(r.capb); code != wantCode {
		t.Fatalf("first cause = %q, want %q", code, wantCode)
	}
	// A latched Canary admits nothing further, whatever it is asked.
	if r.request(r.fp1, r.now) {
		t.Fatal("SECURITY: a latched Canary must admit nothing further")
	}
}

// ── 1 ────────────────────────────────────────────────────────────────────────────────────────
// The healthy baseline, and the control that keeps every refusal below honest: a gate that
// refused everything would satisfy cases 2–5 and 11 while being useless.
func TestReviewedBinding_C01_ReviewedTargetWithLiveApprovalIsAdmitted(t *testing.T) {
	r := newReviewedRig(t)
	if !r.request(r.fp1, r.now) {
		t.Fatal("the exact reviewed target, with a valid live approval, must be admitted")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("control: an admitted, authorized request must not stop the Canary")
	}
	if r.rt.currentGeneration(r.capb) != r.gen {
		t.Fatal("an admitted request must not change the activation generation")
	}
}

// ── 2 ────────────────────────────────────────────────────────────────────────────────────────
// The target has NOT moved; only the approval has expired. That is an ordinary unauthorized
// request, and classifying it as drift would let any caller stop the experiment simply by waiting
// out the TTL. Request-scoped, nothing latched.
func TestReviewedBinding_C02_ExpiredApprovalOnTheReviewedTargetIsRequestScoped(t *testing.T) {
	r := newReviewedRig(t)
	if !r.request(r.fp1, r.now) {
		t.Fatal("premise: the reviewed target must be admitted while the approval is alive")
	}
	expired := r.now.Add(48 * time.Hour) // past MaxInitialCanaryApprovalTTL
	// Seen again AT the expired instant, so the approval is the only authority missing there;
	// otherwise the refusal would be for staleness and this case would prove nothing about expiry.
	observeSeededToolTrustPeerAt(t, r.sid, expired)
	if r.request(r.fp1, expired) {
		t.Fatal("an expired approval must not authorize live execution")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatalf("SECURITY: an expired approval on an UNCHANGED target must not stop the Canary "+
			"(abort code %q) — nothing about it says the reviewed target moved", r.rt.abortCodeNow(r.capb))
	}
}

// ── 3 ────────────────────────────────────────────────────────────────────────────────────────
// The reviewed tool moved while the approval was still alive. Whole-Canary breach.
func TestReviewedBinding_C03_FingerprintDriftWithLiveApprovalLatches(t *testing.T) {
	r := newReviewedRig(t)
	if !r.request(r.fp1, r.now) {
		t.Fatal("premise: the reviewed target must be admitted first")
	}
	fp2 := r.moveToF2(t)
	if r.request(fp2, r.now) {
		t.Fatal("a target that is no longer the reviewed one must fail closed")
	}
	r.assertLatched(t, "tool_fingerprint_drift")
}

// ── 4 ────────────────────────────────────────────────────────────────────────────────────────
// THE HEADLINE CASE (§7). T0: activate against F1. T+24h: the approval expires. Then the tool is
// republished as F2 and a request arrives decided against F2.
//
// At that instant NOTHING in the approval store mentions F1 any more, and the precheck sees
// F2 == F2. The superseded design had no evidence left and answered "missing approval", so a
// patient rug-pull cost the attacker nothing but a day. The activation's own reviewed snapshot is
// unaffected by approval lifetime, so the drift is still authoritative — and still stops the
// whole experiment.
func TestReviewedBinding_C04_DriftAfterApprovalExpiryStillLatches(t *testing.T) {
	r := newReviewedRig(t)
	expired := r.now.Add(48 * time.Hour)

	// Establish that the approval really is gone: on the UNCHANGED target this is a plain denial.
	observeSeededToolTrustPeerAt(t, r.sid, expired) // the premise must be refused for EXPIRY, not staleness
	if r.request(r.fp1, expired) {
		t.Fatal("premise: the approval must have expired")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("premise: expiry alone must not have latched anything")
	}

	fp2 := r.moveToF2(t)
	if r.request(fp2, expired) {
		t.Fatal("a drifted target must fail closed")
	}
	if !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: drift detection must NOT expire with the approval. An activation that " +
			"can run for 7 days while its approval lives 24 hours would be blind to a rug-pull for " +
			"six of them — the exact window this snapshot exists to close")
	}
	if code := r.rt.abortCodeNow(r.capb); code != "tool_fingerprint_drift" {
		t.Fatalf("first cause = %q, want tool_fingerprint_drift — reported as an ordinary missing "+
			"approval, a rug-pull stops nothing", code)
	}
}

// ── 5 ────────────────────────────────────────────────────────────────────────────────────────
// §8, "the most important Round-24 gate": after the tool moves to F2, someone grants a perfectly
// valid four-eyes approval FOR F2. Generation G was reviewed against F1 and must not be
// resurrected by it — a new approval authorizes a new experiment, it does not rewrite what an
// existing one was reviewed to do.
func TestReviewedBinding_C05_ALaterApprovalForF2DoesNotResurrectG(t *testing.T) {
	r := newReviewedRig(t)
	fp2 := r.moveToF2(t)

	// A genuine, current, four-eyes live approval for the NEW fingerprint.
	reg2, cat2 := mcpInventory.sharedInventory()
	_ = reg2
	requestAndApproveLive(t, r.sid, r.tool, fp2, cat2.Current().Revision())
	if ok, _ := mcpLiveApprovalSatisfied(canary.LiveTarget{
		Tenant: ttTenant, ServerID: r.sid, ToolName: r.tool,
		Fingerprint: mustDigest(t, fp2), FingerprintFormat: 1,
	}, policy.OpRead, r.now); !ok {
		t.Fatal("premise: the F2 approval must itself be valid — otherwise this proves nothing")
	}

	if r.request(fp2, r.now) {
		t.Fatal("SECURITY: an approval granted AFTER the activation must not authorize a target " +
			"generation G was never reviewed for")
	}
	r.assertLatched(t, "tool_fingerprint_drift")
}

// ── 6 ────────────────────────────────────────────────────────────────────────────────────────
// The healthy control for case 5: a NEW activation, explicitly reviewed against F2, executes F2
// normally. The refusal above is about WHICH activation was reviewed for what, not about F2 being
// untouchable.
func TestReviewedBinding_C06_NewActivationExplicitlyAgainstF2IsHealthy(t *testing.T) {
	r := newReviewedRig(t)
	fp2 := r.moveToF2(t)
	_, cat2 := mcpInventory.sharedInventory()
	requestAndApproveLive(t, r.sid, r.tool, fp2, cat2.Current().Revision())

	// Demote G and activate a fresh generation bound to F2 — the demote → re-activate cycle §10
	// requires for any change to what an activation may execute.
	if err := r.rt.demoteCanary(r.capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	genNew := armReviewedActivation(t, r.rt, r.capb, r.sid, r.tool, fp2)
	if genNew <= r.gen {
		t.Fatalf("a re-activation must begin a strictly newer generation, got %d after %d", genNew, r.gen)
	}
	r.g = realAdmissionGate(t, r.capb)
	if !r.request(fp2, r.now) {
		t.Fatal("an activation explicitly reviewed against F2 must execute F2")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("control: the fresh activation must not inherit the old snapshot's verdict")
	}
}

// ── 7 ────────────────────────────────────────────────────────────────────────────────────────
// The node restarts in the window between the approval expiring and the tool moving. The reviewed
// set is durable, so the restored activation can still tell F2 from what it was reviewed for.
func TestReviewedBinding_C07_RestartBetweenExpiryAndDriftStillDetects(t *testing.T) {
	r := newReviewedRig(t)
	expired := r.now.Add(48 * time.Hour)
	observeSeededToolTrustPeerAt(t, r.sid, expired) // the premise must be refused for EXPIRY, not staleness
	if r.request(r.fp1, expired) {
		t.Fatal("premise: the approval must have expired")
	}

	// Restart: a fresh runtime object restores from the durable record alone.
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if !fresh.armed(r.capb) {
		t.Fatal("premise: an active durable record must come back armed")
	}
	set, ok := fresh.activeReviewedTargets(r.capb)
	if !ok || set.Len() != 1 {
		t.Fatalf("the restored activation must carry its reviewed set, got ok=%v n=%d", ok, set.Len())
	}
	r.rt = fresh
	r.g = realAdmissionGate(t, r.capb)

	fp2 := r.moveToF2(t)
	if r.request(fp2, expired) {
		t.Fatal("a drifted target must fail closed after a restart")
	}
	r.assertLatched(t, "tool_fingerprint_drift")
}

// ── 8 ────────────────────────────────────────────────────────────────────────────────────────
// §2: production activation MUST supply reviewed targets, and an empty set fails CLOSED. An
// activation that cannot say what it was reviewed for cannot detect drift for its whole window,
// so it must not exist at all.
func TestReviewedBinding_C08_EmptyReviewedTargetSetRefusesActivation(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	for _, tc := range []struct {
		name    string
		targets []canary.ReviewedTarget
	}{
		{"nil", nil},
		{"empty", []canary.ReviewedTarget{}},
		{"zero fingerprint", []canary.ReviewedTarget{func() canary.ReviewedTarget {
			x := testReviewedTarget()
			x.Fingerprint = tooltrustZeroDigest()
			return x
		}()}},
		{"no server identity", []canary.ReviewedTarget{func() canary.ReviewedTarget {
			x := testReviewedTarget()
			x.ServerIdentity = ""
			return x
		}()}},
		{"incomplete identity", []canary.ReviewedTarget{func() canary.ReviewedTarget {
			x := testReviewedTarget()
			x.ToolName = ""
			return x
		}()}},
		{"ambiguous duplicate", []canary.ReviewedTarget{reviewedAt(fpF1), reviewedAt(fpF2)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gen, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
				Budget: runtimeTestBudget(5), ReviewedTargets: tc.targets, StartedAt: canaryRuntimeTestNow,
			})
			if !errors.Is(err, errCanaryReviewedTargetsInvalid) {
				t.Fatalf("activation must fail closed, got gen=%d err=%v", gen, err)
			}
			if rt.armed(capb) || rt.executionEligible(capb, canaryRuntimeTestNow) {
				t.Fatal("SECURITY: a refused activation must leave nothing armed")
			}
		})
	}
}

// ── 9 ────────────────────────────────────────────────────────────────────────────────────────
// §5/§11: a durable ACTIVE record that cannot prove what it was reviewed for does not come back
// executable — including an old record written by a build that had no such field at all.
func TestReviewedBinding_C09_ActiveRecordWithoutReviewedSetIsNotExecutable(t *testing.T) {
	r := newReviewedRig(t)
	if !r.request(r.fp1, r.now) {
		t.Fatal("premise: the activation must be executable before the record is damaged")
	}
	stripReviewedTargetsFromDurableRecord(t, r.capb)

	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.armed(r.capb) || fresh.executionEligible(r.capb, r.now) {
		t.Fatal("SECURITY: an active record with no reviewed-target set must NOT restore executable " +
			"authority — it could not distinguish a drifted target from an unauthorized one for the " +
			"rest of its window")
	}
	if fresh.currentGeneration(r.capb) < r.gen {
		t.Fatal("the monotonic generation must be preserved so a fresh activation bumps past it")
	}
	r.rt = fresh
	r.g = realAdmissionGate(t, r.capb)
	if r.request(r.fp1, r.now) {
		t.Fatal("SECURITY: nothing may be admitted under a non-restorable activation")
	}
}

// ── 10 ───────────────────────────────────────────────────────────────────────────────────────
// §10: generation G's reviewed set is immutable for its whole life. A same-mode control-plane
// update that would bind a different set is refused — otherwise the control plane itself performs
// the drift the runtime exists to catch, and G evolves from F1 into F2 without anyone reviewing it.
func TestReviewedBinding_C10_SameGenerationReviewedSetMutationIsRefused(t *testing.T) {
	resetLiveTierGlobals(t)
	setDataDirForTest(t, t.TempDir())
	capb := rollout.CapabilityGateway
	budget := runtimeTestBudget(10)
	if _, err := globalCanaryRuntime.beginCanaryActivation(capb, canaryActivationSpec{
		Budget: budget, ReviewedTargets: []canary.ReviewedTarget{reviewedAt(fpF1)}, StartedAt: time.Unix(0, 1),
	}); err != nil {
		t.Fatalf("begin: %v", err)
	}
	r := newTestRollout()
	st := r.gateway
	prevCfg := *gwCanaryCfg(1)
	if err := st.SetConfig(prevCfg, "prev", time.Unix(0, 1).UnixNano()); err != nil {
		t.Fatalf("install prev canary: %v", err)
	}
	cfg := gwCanaryCfg(2) // SAME mode, new scope revision
	if err := st.SetConfig(*cfg, "new", time.Unix(0, 2).UnixNano()); err != nil {
		t.Fatalf("install new canary: %v", err)
	}
	tgt := commitTransitionTarget{
		st: st, persist: func(*rollout.State) error { return nil },
		setStatus: func(string) {}, countTransition: func() {}, reconcileRuntime: true,
	}

	// A DIFFERENT reviewed set on a same-mode update ⇒ refused, state rolled back.
	err := r.reconcileCanaryRuntimeAfterCommit(tgt, cfg, prevCfg.Mode, prevCfg, st.Evidence(),
		canaryActivationSpec{Budget: budget, ReviewedTargets: []canary.ReviewedTarget{reviewedAt(fpF2)}, StartedAt: time.Unix(0, 2)},
		"new", time.Unix(0, 2))
	if !errors.Is(err, errRolloutCanaryReviewedTargetsChanged) {
		t.Fatalf("a same-mode update that rebinds the reviewed set must be refused, got %v", err)
	}
	if st.CurrentMode() != prevCfg.Mode {
		t.Fatalf("state must roll back to the prior live mode, got %v", st.CurrentMode())
	}
	// The running generation kept the set it was armed with.
	set, ok := globalCanaryRuntime.activeReviewedTargets(capb)
	if !ok || !set.Equal(mustCanonical(t, reviewedAt(fpF1))) {
		t.Fatal("SECURITY: the refused update must not have mutated the active reviewed set")
	}
	// The IDENTICAL set is not a change and proceeds (a scope revision that renames nothing
	// re-supplies the same targets).
	if err := r.reconcileCanaryRuntimeAfterCommit(tgt, cfg, prevCfg.Mode, prevCfg, st.Evidence(),
		canaryActivationSpec{Budget: budget, ReviewedTargets: []canary.ReviewedTarget{reviewedAt(fpF1)}, StartedAt: time.Unix(0, 3)},
		"same", time.Unix(0, 3)); err != nil {
		t.Fatalf("a same-mode update re-supplying the SAME reviewed set must proceed, got %v", err)
	}
}

// ── 11 ───────────────────────────────────────────────────────────────────────────────────────
// §9: the same principle for the server the tool lives on.
//
// The catalog's composite fingerprint already folds the server's pinned identity in, so an
// identity rotation moves the fingerprint too — this test asserts that coupling rather than
// assuming it. What the reviewed snapshot's own ServerIdentity field buys is the CLASSIFICATION:
// the first cause reported is server_identity_drift, not tool_fingerprint_drift, because the tool
// definition is byte-identical and it is the workload serving it that changed. An operator
// reading "the tool schema moved" would look in the wrong place, and the field keeps the verdict
// correct even if the digest's composition later changes.
func TestReviewedBinding_C11_ServerIdentityChangeLatchesServerDrift(t *testing.T) {
	r := newReviewedRig(t)
	if !r.request(r.fp1, r.now) {
		t.Fatal("premise: the reviewed target must be admitted first")
	}
	// Byte-identical tool definition; different pinned identity.
	fpRotated := republishWithIdentity(t, r.sid, r.tool, "id-rotated-by-an-attacker", `{"type":"object"}`)
	if fpRotated == r.fp1 {
		t.Fatal("premise: the composite fingerprint is expected to fold the pinned identity in, " +
			"so this republication should have moved it")
	}
	// The request is decided against the CURRENT fingerprint, so the precheck sees no drift of its
	// own and the verdict comes entirely from the activation's reviewed snapshot.
	if live := mcpLiveTrustPrecheck(ttTenant, r.sid, r.tool, fpRotated); live.DriftCode != "" {
		t.Fatalf("premise: a request decided against the current fingerprint must show no precheck "+
			"drift, got %q", live.DriftCode)
	}
	if r.request(fpRotated, r.now) {
		t.Fatal("a tool served under an identity the activation never reviewed must fail closed")
	}
	r.assertLatched(t, "server_identity_drift")
}

// ── 12 ───────────────────────────────────────────────────────────────────────────────────────
// The demoted generation's snapshot is inert: it can neither authorize nor stop G+1. Generation
// binding is what keeps one experiment's evidence from governing another's.
func TestReviewedBinding_C12_DemotedGenerationSnapshotCannotAffectTheNext(t *testing.T) {
	r := newReviewedRig(t)
	if err := r.rt.demoteCanary(r.capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if r.rt.armed(r.capb) {
		t.Fatal("premise: a demoted runtime must be disarmed")
	}
	// After the demotion the tool moves. Nothing is armed, so nothing may latch.
	fp2 := r.moveToF2(t)
	_, cat2 := mcpInventory.sharedInventory()
	requestAndApproveLive(t, r.sid, r.tool, fp2, cat2.Current().Revision())
	if r.request(fp2, r.now) {
		t.Fatal("a demoted runtime must admit nothing")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("a request against a demoted runtime must not latch an abort — there is no " +
			"generation to attribute it to")
	}

	// G+1, explicitly reviewed against F2, is unaffected by G's snapshot.
	genNew := armReviewedActivation(t, r.rt, r.capb, r.sid, r.tool, fp2)
	if genNew <= r.gen {
		t.Fatalf("a re-activation must begin a strictly newer generation, got %d after %d", genNew, r.gen)
	}
	r.g = realAdmissionGate(t, r.capb)
	if !r.request(fp2, r.now) {
		t.Fatal("G+1 reviewed against F2 must execute F2")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: G's superseded reviewed set must not stop G+1")
	}
	// And G+1 refuses what IT was not reviewed for: the old F1 is now out of scope, request-scoped.
	if r.request(r.fp1, r.now) {
		t.Fatal("G+1 must refuse a target it was not reviewed for")
	}
}

// ── matrix helpers ───────────────────────────────────────────────────────────────────────────

// mustDigest parses a hex fingerprint into the 32-byte digest the trust firewall compares.
func mustDigest(t *testing.T, fpHex string) tooltrust.FingerprintDigest {
	t.Helper()
	raw, err := hex.DecodeString(fpHex)
	if err != nil {
		t.Fatalf("decode fingerprint %q: %v", fpHex, err)
	}
	var d tooltrust.FingerprintDigest
	if len(raw) != len(d) {
		t.Fatalf("fingerprint %q is %d bytes, want %d", fpHex, len(raw), len(d))
	}
	copy(d[:], raw)
	return d
}

// tooltrustZeroDigest is the all-zero digest — never a real fingerprint, and rejected as one.
func tooltrustZeroDigest() tooltrust.FingerprintDigest { return tooltrust.FingerprintDigest{} }

// mustCanonical canonicalizes targets the way an activation does, for comparing sets in a test.
func mustCanonical(t *testing.T, targets ...canary.ReviewedTarget) canary.ReviewedTargetSet {
	t.Helper()
	set, reason := canary.CanonicalizeReviewedTargets(targets)
	if reason != canary.ReviewedOK {
		t.Fatalf("fixture targets must canonicalize, got %s", reason)
	}
	return set
}

// stripReviewedTargetsFromDurableRecord rewrites the on-disk activation record with its
// reviewed-target set removed, leaving every other field byte-identical. That is exactly the
// shape a record written by a build predating this field has, which is why §11 requires it to be
// non-executable rather than merely unusual.
func stripReviewedTargetsFromDurableRecord(t *testing.T, capb rollout.Capability) {
	t.Helper()
	path := canaryRuntimeStatePath(capb)
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read durable record: %v", err)
	}
	var st canaryRuntimeState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("decode durable record: %v", err)
	}
	if len(st.ReviewedTargets) == 0 {
		t.Fatal("premise: the record under test must have carried a reviewed set")
	}
	st.ReviewedTargets = nil
	out, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("re-encode durable record: %v", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write durable record: %v", err)
	}
}

// ── two gates the mutation campaign demanded ─────────────────────────────────────────────────
//
// Both of these were added because a mutation SURVIVED the matrix above: the campaign found
// behaviour the twelve cases assert nothing about. A surviving mutation is a hole in the test
// set, not a harmless edit, and closing it here is the whole point of running the campaign.

// A fresh activation binds the set it was GIVEN, unconditionally — it never inherits the previous
// generation's.
//
// Every case above reaches a new generation through demote → re-activate, and `demoteCanary`
// clears the reviewed set, so an "assign only if empty" mutation was inert against all twelve.
// `beginCanaryActivation` is reachable without that demotion, and there the difference is the
// whole security property: generation G+1 would silently enforce what G was reviewed for, so a
// re-activation deliberately narrowed to a new target would keep executing the old one.
func TestReviewedBinding_ReactivationWithoutDemoteBindsTheNewSet(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway

	genOld, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(10),
		ReviewedTargets: []canary.ReviewedTarget{reviewedAt(fpF1)},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("first activation: %v", err)
	}
	// NO demotion: begin again directly on the armed runtime.
	genNew, err := rt.beginCanaryActivation(capb, canaryActivationSpec{
		Budget:          runtimeTestBudget(10),
		ReviewedTargets: []canary.ReviewedTarget{reviewedAt(fpF2)},
		StartedAt:       canaryRuntimeTestNow,
	})
	if err != nil {
		t.Fatalf("re-activation: %v", err)
	}
	if genNew <= genOld {
		t.Fatalf("generations must be strictly monotonic, got %d after %d", genNew, genOld)
	}
	set, ok := rt.activeReviewedTargets(capb)
	if !ok {
		t.Fatal("the re-activated runtime must expose a reviewed set")
	}
	if !set.Equal(mustCanonical(t, reviewedAt(fpF2))) {
		t.Fatalf("SECURITY: the new generation is bound to %+v, not the set it was activated with. "+
			"An activation that inherits its predecessor's reviewed targets enforces a review nobody "+
			"performed for it", set.Targets())
	}
	if v := set.Compare(reviewedAt(fpF1)); v != canary.ReviewedFingerprintDrift {
		t.Fatalf("the SUPERSEDED target must now read as drift, got %q", v)
	}
}

// The live gate admits ONLY an explicit grant.
//
// The denial switch in AdmitSideEffect once listed the known denials and let everything else fall
// through to the admitted path, so adding `canaryAdmitNotReviewed` to the transaction ADMITTED the
// requests it was written to refuse — an unauthorized request was handed a reservation. The switch
// is now exhaustive by construction, and this pins that: a denial class the gate does not
// recognise must fail CLOSED, because the direction this boundary must never fail in is a new
// refusal reason arriving as a grant.
func TestReviewedBinding_AnUnrecognisedDenialClassFailsClosed(t *testing.T) {
	capb := rollout.CapabilityGateway
	g := realAdmissionGate(t, capb)

	// A denial class from the future: past every constant this build knows.
	const unknownDenial = canaryAdmissionDenial(200)
	if unknownDenial == canaryAdmitGranted {
		t.Fatal("premise: the injected class must not be the grant")
	}
	g.admitUnderActivation = func(time.Time, policy.OperationClass, string, canaryScopeProbe, canary.ExecutionIdentity, canaryTrustProbe) canaryAdmission {
		return canaryAdmission{Denial: unknownDenial, Active: true, Generation: 7}
	}
	d := g.AdmitSideEffect(driftGateInput("s", "t", "fp", canaryRuntimeTestNow))
	if d.Release != nil {
		d.Release()
	}
	if d.Admit {
		t.Fatal("SECURITY: a denial class the gate cannot name must fail CLOSED. Falling through to " +
			"the admitted path means every denial added to the admission transaction in future " +
			"silently grants the requests it was written to refuse")
	}
	if d.ReservationID != "" || d.ActivationGeneration != 0 {
		t.Fatalf("a refused request must carry no reservation (id=%q gen=%d)", d.ReservationID, d.ActivationGeneration)
	}

	// Control: the SAME harness admits an explicit grant, so the assertion above cannot be
	// satisfied by a gate that refuses everything.
	g.admitUnderActivation = func(time.Time, policy.OperationClass, string, canaryScopeProbe, canary.ExecutionIdentity, canaryTrustProbe) canaryAdmission {
		return canaryAdmission{Denial: canaryAdmitGranted, Active: true, Generation: 7, Trusted: true, Outcome: canary.BudgetGranted}
	}
	ok := g.AdmitSideEffect(driftGateInput("s", "t", "fp", canaryRuntimeTestNow))
	if ok.Release != nil {
		ok.Release()
	}
	if !ok.Admit {
		t.Fatalf("control: an explicit grant must be admitted, reason=%s", ok.Reason.Code())
	}
}

// ── the scope-independent path (Codex P1, PR #1360) ──────────────────────────────────────────
//
// The twelve cases above drive the admission gate directly, which proves the COMPARISON. They do
// not prove it is REACHED, and in the sequence that matters most it was not: a Canary ScopeSpec
// pins the reviewed fingerprint in its tool selector, so a tool that moves F1→F2 puts every later
// request out of scope, `resolveEnforcing` routes them to the shadow/record-only fallback, and the
// activation transaction is never entered. The premise of the experiment is violated and the
// violation is exactly what hides the evidence.
//
// `canaryReviewedTargetObserved` is the path that cannot be hidden that way: it is keyed on the
// tool IDENTITY, reported for every dispatched request whatever disposition it resolved to (proven
// reachable in internal/mcp/runtime/canary_reviewed_target_test.go), and it compares against the
// activation's reviewed snapshot inside the activation lock.

// observeTarget drives the production sink for one tool identity at the activation's generation.
func (r *reviewedRig) observeTarget(gen uint64) {
	canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
		Generation: gen, ServerID: r.sid, ToolName: r.tool,
	})
}

// THE GATE. The reviewed tool moves; no request ever reaches the admission transaction; the
// experiment still stops.
func TestReviewedBinding_ScopeIndependentPathLatchesDriftWithoutAdmission(t *testing.T) {
	r := newReviewedRig(t)
	// Control first: while the target is the reviewed one, observing it stops nothing. Without
	// this, "the drift latched" below could mean the sink latches on everything.
	r.observeTarget(r.gen)
	if r.rt.abortedNow(r.capb) {
		t.Fatal("control: observing the UNCHANGED reviewed target must not stop the Canary")
	}

	r.moveToF2(t)
	r.observeTarget(r.gen)
	if !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: the reviewed tool moved and the whole Canary must stop — even though no " +
			"request reached the admission transaction, because a fingerprint move puts every " +
			"request out of the Canary scope and the scope-gated paths can no longer see it")
	}
	if code := r.rt.abortCodeNow(r.capb); code != "tool_fingerprint_drift" {
		t.Fatalf("first cause = %q, want tool_fingerprint_drift", code)
	}
}

// The same path, after the reviewing approval has expired — the full §7 sequence with nothing in
// the approval store left to consult and nothing in scope to route the request through.
func TestReviewedBinding_ScopeIndependentPathSurvivesApprovalExpiry(t *testing.T) {
	r := newReviewedRig(t)
	expired := r.now.Add(48 * time.Hour)
	observeSeededToolTrustPeerAt(t, r.sid, expired) // the premise must be refused for EXPIRY, not staleness
	if r.request(r.fp1, expired) {
		t.Fatal("premise: the approval must have expired")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatal("premise: expiry alone must not have latched anything")
	}

	r.moveToF2(t)
	r.observeTarget(r.gen)
	if !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: drift detection must survive BOTH the approval expiring and the target " +
			"falling out of scope — the two conditions that arrive together in the sequence this " +
			"whole change exists for")
	}
	if code := r.rt.abortCodeNow(r.capb); code != "tool_fingerprint_drift" {
		t.Fatalf("first cause = %q, want tool_fingerprint_drift", code)
	}
}

// A server identity rotation is caught on the same path, and classified as itself.
func TestReviewedBinding_ScopeIndependentPathLatchesServerIdentityDrift(t *testing.T) {
	r := newReviewedRig(t)
	republishWithIdentity(t, r.sid, r.tool, "id-rotated-by-an-attacker", `{"type":"object"}`)
	r.observeTarget(r.gen)
	if !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: a rotated server identity must stop the Canary on this path too")
	}
	if code := r.rt.abortCodeNow(r.capb); code != "server_identity_drift" {
		t.Fatalf("first cause = %q, want server_identity_drift", code)
	}
}

// THE COUNTERWEIGHT, and it is the reason this path may fire for every request at all.
//
// The sink is called for tools the experiment never reviewed. Latching for one of those would let
// any unrelated catalog change stop the Canary — the direction a safety control must never err in,
// and the exact hazard the previous design avoided only by the `canaryScoped` proxy that a
// fingerprint move defeats. The reviewed set decides it EXACTLY: an unreviewed key is out of scope,
// request-scoped, and latches nothing.
func TestReviewedBinding_ScopeIndependentPathIgnoresUnreviewedTools(t *testing.T) {
	r := newReviewedRig(t)

	// A tool that RESOLVES but was never reviewed is the case that matters, and it is the one an
	// earlier version of this test missed: every identity it named was absent from the catalog, so
	// the sink returned "nothing to compare" before the reviewed comparison was ever reached and
	// the gate proved nothing about it. The inventory therefore gains a second, real tool on the
	// same server, with the reviewed tool republished UNCHANGED beside it.
	const otherTool = "sibling"
	publishTwoToolInventory(t, r.sid, r.tool, otherTool)
	if !mcpCurrentAuthoritativeTarget(r.sid, otherTool).Found {
		t.Fatal("premise: the sibling tool must resolve to a real authoritative target")
	}
	if cur := mcpCurrentAuthoritativeTarget(r.sid, r.tool); !cur.Found || cur.Target.Fingerprint != mustDigest(t, r.fp1) {
		t.Fatal("premise: republishing must have left the REVIEWED tool exactly as reviewed")
	}

	for _, tc := range []struct {
		name, sid, tool string
		resolves        bool
	}{
		{"a resolvable sibling tool on the reviewed server", r.sid, otherTool, true},
		{"a tool that does not resolve at all", r.sid, "no-such-tool", false},
		{"another server", "some-other-server", r.tool, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mcpCurrentAuthoritativeTarget(tc.sid, tc.tool).Found; got != tc.resolves {
				t.Fatalf("premise: resolvability = %v, want %v", !tc.resolves, tc.resolves)
			}
			canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
				Generation: r.gen, ServerID: tc.sid, ToolName: tc.tool,
			})
			if r.rt.abortedNow(r.capb) {
				t.Fatalf("SECURITY: a catalog observation for a tool this activation never reviewed "+
					"must not stop it (abort code %q)", r.rt.abortCodeNow(r.capb))
			}
			// And it must produce NO DRIFT VERDICT at all, not merely fail to latch. The abort
			// taxonomy would refuse to latch an unrecognised code anyway, so asserting only on
			// abortedNow lets this path quietly report drift for a tool nobody reviewed — bounded
			// evidence an operator would then have to explain. The verdict itself is the contract.
			latch := r.rt.latchReviewedDriftUnderActivation(r.capb, r.gen, r.now,
				func() mcpAuthoritativeTarget {
					return mcpCurrentAuthoritativeTarget(tc.sid, tc.tool)
				})
			if latch.DriftCode != "" || latch.Latched {
				t.Fatalf("SECURITY: an unreviewed tool produced drift verdict %q (latched=%v) — an "+
					"activation must report drift only about the targets it was reviewed for",
					latch.DriftCode, latch.Latched)
			}
		})
	}
	// And the experiment is still genuinely alive afterwards.
	if !r.request(r.fp1, r.now) {
		t.Fatal("the Canary must still admit its own reviewed target")
	}
}

// publishTwoToolInventory republishes the server carrying the reviewed tool UNCHANGED plus one
// additional real tool, so a test can observe an identity that resolves but was never reviewed.
func publishTwoToolInventory(t *testing.T, sid, reviewedTool, otherTool string) {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"id","enabled":true,
	   "tools":[{"name":"` + reviewedTool + `","input_schema":{"type":"object"}},
	            {"name":"` + otherTool + `","input_schema":{"type":"object","properties":{"z":{"type":"string"}}}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
	// A republish leaves every record unobserved, and the callers go on to require that the
	// REVIEWED tool is still admitted (round 13). The peer is seen advertising both tools, so the
	// sibling is refused for being unreviewed and never for being unobserved.
	observePeerAdvertisingAt(t, sid, canaryRuntimeTestNow,
		`{"tools":[{"name":"`+reviewedTool+`","inputSchema":{"type":"object"}},`+
			`{"name":"`+otherTool+`","inputSchema":{"type":"object","properties":{"z":{"type":"string"}}}}]}`,
		reviewedTool, otherTool)
}

// The generation rules are the same as every other latch on this runtime, and they are what stop a
// stale observation from reaching an activation it was never made under.
// ── 13 ───────────────────────────────────────────────────────────────────────────────────────
// A RESOLVABLE tool the activation was never reviewed for is REQUEST-SCOPED, not a breach.
//
// This is the control that keeps every latch in this file honest, and it belongs on the ADMISSION
// path specifically. latchReviewedDriftUnderActivation has its own version
// (ScopeIndependentPathIgnoresUnreviewedTools), but the admission transaction reaches the same
// decision through a different branch — canaryAdmitNotReviewed — and nothing here exercised it
// against a target that actually resolves. Without this, folding ReviewedOutOfScope into the drift
// branch would pass the whole suite while letting any unrelated request stop a healthy experiment:
// an activation correctly refusing a target outside its review IS the Canary working.
//
// The sibling tool must RESOLVE, or the probe reports "not found" and returns before the reviewed
// comparison is reached — the hole a previous round of this campaign found the hard way.
func TestReviewedBinding_C13_UnreviewedTargetIsRequestScopedNotDrift(t *testing.T) {
	r := newReviewedRig(t)

	const otherTool = "sibling"
	publishTwoToolInventory(t, r.sid, r.tool, otherTool)
	cur := mcpCurrentAuthoritativeTarget(r.sid, otherTool)
	if !cur.Found {
		t.Fatal("premise: the sibling tool must resolve to a real authoritative target, or the " +
			"admission probe returns before the reviewed comparison and this proves nothing")
	}
	if !mcpCurrentAuthoritativeTarget(r.sid, r.tool).Found {
		t.Fatal("premise: republishing must have left the reviewed tool resolvable")
	}

	d := r.g.AdmitSideEffect(driftGateInput(r.sid, otherTool, hex.EncodeToString(cur.Target.Fingerprint[:]), r.now))
	if d.Release != nil {
		d.Release()
	}
	if d.Admit {
		t.Fatal("SECURITY: a target this activation was never reviewed for must not be admitted")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatalf("SECURITY: refusing an UNREVIEWED target is the Canary working, not a breach of "+
			"it — latching here (first cause %q) lets any unrelated request stop a healthy "+
			"experiment", r.rt.abortCodeNow(r.capb))
	}
	// And the experiment is still live for the target it WAS reviewed for.
	if !r.request(r.fp1, r.now) {
		t.Fatal("the reviewed target must still be admitted after an unreviewed one was refused")
	}
}

func TestReviewedBinding_ScopeIndependentPathHonoursGenerationRules(t *testing.T) {
	t.Run("generation zero latches nothing", func(t *testing.T) {
		r := newReviewedRig(t)
		r.moveToF2(t)
		r.observeTarget(0)
		if r.rt.abortedNow(r.capb) {
			t.Fatal("SECURITY: an observation naming no activation must never be read as 'whatever " +
				"is current' — that wildcard belongs only to the unbound entry point")
		}
	})
	t.Run("a superseded generation latches nothing", func(t *testing.T) {
		r := newReviewedRig(t)
		stale := r.gen
		if err := r.rt.demoteCanary(r.capb); err != nil {
			t.Fatalf("demote: %v", err)
		}
		fp2 := r.moveToF2(t)
		genNew := armReviewedActivation(t, r.rt, r.capb, r.sid, r.tool, fp2)
		if genNew == stale {
			t.Fatal("premise: the re-activation must have bumped the generation")
		}
		// The stale observation names the OLD activation; the one in force was explicitly
		// reviewed against F2 and is healthy.
		r.observeTarget(stale)
		if r.rt.abortedNow(r.capb) {
			t.Fatal("SECURITY: an observation made under a superseded activation must not stop the " +
				"one that replaced it — its reviewed set may legitimately differ")
		}
	})
	t.Run("a demoted runtime latches nothing", func(t *testing.T) {
		r := newReviewedRig(t)
		gen := r.gen
		if err := r.rt.demoteCanary(r.capb); err != nil {
			t.Fatalf("demote: %v", err)
		}
		r.moveToF2(t)
		r.observeTarget(gen)
		if r.rt.abortedNow(r.capb) {
			t.Fatal("SECURITY: with no live activation there is nothing to stop, and nothing an " +
				"observation may be charged to")
		}
	})
}

// ── 14 ───────────────────────────────────────────────────────────────────────────────────────
// A reviewed server that is no longer USABLE latches the whole Canary, even though the reviewed
// target itself is untouched.
//
// This is the case the scope-independent path had to learn (Codex P1, round 3). Disabling a server
// leaves the fingerprint and the pinned identity exactly as reviewed, so the reviewed comparison
// alone returns ReviewedMatches and latches nothing. mcpLiveTrustPrecheck already charges an
// unusable server as server_identity_drift — "the approved anchor is gone" — but it is not
// guaranteed to run: a disable that SETTLES before a request starts leaves no transition for
// refuseOnToolDrift to see, and a policy or inspection rejection returns above the precheck
// entirely. The observation path runs for every dispatched request, so it is the one that has to
// carry the verdict; otherwise the experiment could be disabled, re-enabled and resumed on the same
// activation with nothing ever latched.
func TestReviewedBinding_C14_UnusableReviewedServerLatchesAnchorLoss(t *testing.T) {
	r := newReviewedRig(t)

	// Disable the server. Nothing about the REVIEWED target changes: same tool, same schema, so the
	// same fingerprint, and the same pinned identity.
	before := mcpCurrentAuthoritativeTarget(r.sid, r.tool)
	if !before.Found || !before.Usable {
		t.Fatalf("premise: the reviewed server must start usable, got %+v", before)
	}
	disableSeededServer(t, r.sid, r.tool)

	after := mcpCurrentAuthoritativeTarget(r.sid, r.tool)
	if !after.Found {
		t.Fatal("premise: a disabled server must still RESOLVE — if it stops resolving this gate is " +
			"exercising the not-found branch, which is deliberately not drift")
	}
	if after.Usable {
		t.Fatal("premise: the server must now be unusable, or nothing is being tested")
	}
	if after.Target != before.Target {
		t.Fatalf("premise: disabling must leave the REVIEWED target identical (fingerprint and "+
			"identity), or this gate proves the ordinary drift path instead of the anchor-loss one.\n"+
			" before: %+v\n after:  %+v", before.Target, after.Target)
	}
	canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
		Generation: r.gen, ServerID: r.sid, ToolName: r.tool,
	})
	r.assertLatched(t, "server_identity_drift")
}

// The anchor-loss verdict is reported as drift, not merely as a failure to latch — and it is the
// FIRST cause, so an operator reads the reason the experiment stopped rather than a later symptom.
func TestReviewedBinding_C15_AnchorLossIsAVerdictNotSilence(t *testing.T) {
	r := newReviewedRig(t)
	disableSeededServer(t, r.sid, r.tool)

	latch := r.rt.latchReviewedDriftUnderActivation(r.capb, r.gen, r.now,
		func() mcpAuthoritativeTarget { return mcpCurrentAuthoritativeTarget(r.sid, r.tool) })
	if latch.DriftCode != "server_identity_drift" {
		t.Fatalf("drift code = %q, want server_identity_drift — the same code "+
			"mcpLiveTrustPrecheck already assigns to an unusable server, so one fact has one "+
			"dialect however it is discovered", latch.DriftCode)
	}
	if !latch.Latched {
		t.Fatal("SECURITY: the anchor-loss verdict must stop the whole Canary, not merely be reported")
	}
}

// disableSeededServer republishes the controlled inventory with the server DISABLED, leaving the
// tool and its schema untouched so the reviewed fingerprint and pinned identity do not move.
func disableSeededServer(t *testing.T, sid, tool string) {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"id","enabled":false,
	   "tools":[{"name":"` + tool + `","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
}

// ── 16 ───────────────────────────────────────────────────────────────────────────────────────
// The fingerprint and the pinned identity come from ONE snapshot read.
//
// The catalog's composite fingerprint folds the pinned identity in, but Registry.Repin and the
// catalog re-ingest that follows it are SEPARATE publications. A caller that reads the fingerprint
// from loadTarget and the identity from a fresh lookup can therefore compose (F1, I2) — a pair that
// was never simultaneously authoritative — and persist it as the reviewed target, after which an
// identity rotation compares as REVIEWED and executes under an approval issued for the old identity
// (Codex P1, round 3).
//
// The fix is structural: nothing on these paths performs a second inventory lookup for the
// identity. That is what this gate pins, by AST, because the window itself cannot be scheduled
// deterministically from a test — and a gate that can only sometimes observe a race is a gate that
// gets muted.
func TestReviewedBinding_C16_IdentityAndFingerprintComeFromOneSnapshot(t *testing.T) {
	fset := token.NewFileSet()
	var offenders []string
	for _, file := range []string{"mcp_canary_preflight.go", "mcp_live_gate.go", "mcp_canary_admission.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// A registry lookup anywhere on these paths is the shape that reintroduces the tear:
			// the identity must ride out of loadTarget's snapshot, never be fetched beside it.
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "PinnedIdentity" || sel.Sel.Name == "mcpServerPinnedIdentity" {
				offenders = append(offenders, fset.Position(call.Pos()).String())
			}
			if inner, ok := sel.X.(*ast.CallExpr); ok {
				if isel, ok := inner.Fun.(*ast.SelectorExpr); ok && isel.Sel.Name == "Current" && sel.Sel.Name == "Get" {
					offenders = append(offenders, fset.Position(call.Pos()).String())
				}
			}
			return true
		})
	}
	if len(offenders) != 0 {
		t.Fatalf("SECURITY: a second inventory lookup on the reviewed-target paths at %v. The "+
			"identity and the fingerprint must come from the ONE snapshot loadTarget read, or a "+
			"Registry.Repin landing between the two composes an (F1, I2) pair that was never "+
			"authoritative and persists it as reviewed", offenders)
	}
}

// CONTROL for C16: the single snapshot really does carry the identity, so the gate above is not
// passing merely because nothing reads an identity at all.
func TestReviewedBinding_C16Control_TheSnapshotCarriesTheIdentity(t *testing.T) {
	r := newReviewedRig(t)
	cur := mcpCurrentAuthoritativeTarget(r.sid, r.tool)
	if !cur.Found {
		t.Fatal("premise: the reviewed tool must resolve")
	}
	if cur.Target.ServerIdentity == "" {
		t.Fatal("the authoritative target must carry the server's pinned identity — an empty one " +
			"would make the AST gate above vacuous and server_identity_drift undetectable")
	}
	live := mcpLiveTrustPrecheck(ttTenant, r.sid, r.tool, r.fp1)
	if live.ServerIdentity != cur.Target.ServerIdentity {
		t.Fatalf("the two paths must report the SAME identity, got %q and %q",
			live.ServerIdentity, cur.Target.ServerIdentity)
	}
}

// ── 17 ───────────────────────────────────────────────────────────────────────────────────────
// A reviewed (server, tool) reassigned to ANOTHER TENANT latches, rather than reading as an
// unrelated target.
//
// The reviewed lookup key is (tenant, server, tool), so a reassignment A→B makes the current target
// miss the key and fall through to ReviewedOutOfScope — which the round-15 rule deliberately makes
// silent, so that a catalog change to a tool the experiment never reviewed cannot stop it. The
// reviewed target crossing a tenancy boundary would therefore be invisible, and reassigning it back
// to A later would let the original activation resume with nothing recorded (Codex P1, round 4).
//
// Tenancy is the isolation boundary the approval was granted within: a target that changed hands is
// not the target that was reviewed.
func TestReviewedBinding_C17_TenantReassignmentOfAReviewedTargetLatches(t *testing.T) {
	r := newReviewedRig(t)

	before := mcpCurrentAuthoritativeTarget(r.sid, r.tool)
	if !before.Found {
		t.Fatal("premise: the reviewed tool must resolve")
	}
	republishUnderTenant(t, r.sid, r.tool, "other-tenant")
	after := mcpCurrentAuthoritativeTarget(r.sid, r.tool)
	if !after.Found {
		t.Fatal("premise: the tool must still resolve after the reassignment — otherwise this gate " +
			"exercises the not-found branch, which is deliberately not drift")
	}
	if after.Target.Tenant == before.Target.Tenant {
		t.Fatalf("premise: the tenant must actually change, got %q both times", after.Target.Tenant)
	}

	canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
		Generation: r.gen, ServerID: r.sid, ToolName: r.tool,
	})
	r.assertLatched(t, "reviewed_target_tenant_drift")
}

// CONTROL for C17: a genuinely unrelated tool on the reviewed server still latches NOTHING.
// Without this, folding every key miss into tenant drift would pass C17 while letting any unrelated
// request stop a healthy experiment — the round-15 rule inverted.
func TestReviewedBinding_C17Control_AnUnrelatedToolIsStillSilent(t *testing.T) {
	r := newReviewedRig(t)
	const otherTool = "sibling"
	publishTwoToolInventory(t, r.sid, r.tool, otherTool)
	if !mcpCurrentAuthoritativeTarget(r.sid, otherTool).Found {
		t.Fatal("premise: the sibling tool must resolve")
	}
	canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
		Generation: r.gen, ServerID: r.sid, ToolName: otherTool,
	})
	if r.rt.abortedNow(r.capb) {
		t.Fatalf("SECURITY: an unrelated tool stopped the experiment (%q). Tenant drift must be "+
			"distinguished from out-of-scope, not merged with it", r.rt.abortCodeNow(r.capb))
	}
}

// republishUnderTenant re-publishes the same server and tool under a DIFFERENT tenant, leaving the
// tool's schema (and therefore its own contribution to the fingerprint) alone.
func republishUnderTenant(t *testing.T, sid, tool, tenant string) {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + tenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"id","enabled":true,
	   "tools":[{"name":"` + tool + `","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
}

// ── 18 ───────────────────────────────────────────────────────────────────────────────────────
// The REPIN WINDOW is detected, not read around.
//
// Registry.Repin and the catalog re-ingest that follows it are separate publications, so between
// them the registry genuinely pins I2 while the catalog's record genuinely describes I1. That
// inconsistency is in the PUBLISHED STATE, not in the reading of it — no consistent-snapshot read
// can avoid it, which is why the earlier "take both from one snapshot" framing was not enough
// (Codex P1, round 4).
//
// The catalog record is self-describing: its composite fingerprint folds in the identity it was
// ingested against. So the identity is taken from the record — atomic with the fingerprint by
// construction — and the registry's current pin is COMPARED against it. A disagreement means a
// request would be routed to a workload the reviewed record does not describe.
func TestReviewedBinding_C18_RepinWindowIsDetectedAsDrift(t *testing.T) {
	r := newReviewedRig(t)
	if cur := mcpCurrentAuthoritativeTarget(r.sid, r.tool); !cur.Found || cur.RegistryPinDiverged {
		t.Fatalf("premise: the reviewed target must start coherent, got %+v", cur)
	}

	// Repin the REGISTRY only — no catalog re-ingest. This is the window.
	reg, _ := mcpInventory.sharedInventory()
	if reg == nil {
		t.Fatal("premise: a shared registry must be published")
	}
	if _, err := reg.Repin(registry.ServerID(r.sid), registry.Identity("rotated"), canaryRuntimeTestNow); err != nil {
		t.Fatalf("repin: %v", err)
	}

	cur := mcpCurrentAuthoritativeTarget(r.sid, r.tool)
	if !cur.Found {
		t.Fatal("premise: the tool must still resolve inside the window")
	}
	if !cur.RegistryPinDiverged {
		t.Fatal("SECURITY: the repin window was not detected. The registry now pins an identity the " +
			"catalog record was not built against, so a request would reach a workload the reviewed " +
			"record does not describe")
	}
	// The target still describes the CATALOG's coherent view — identity and fingerprint together.
	if cur.Target.ServerIdentity == "rotated" {
		t.Fatal("the target must carry the identity the CATALOG record was built against, not the " +
			"registry's new pin — mixing the two is the hybrid pair this whole fix exists to prevent")
	}

	// And the live precheck reports it, so the request path refuses rather than executing.
	//
	// It reports the FACT (AnchorLost) rather than a pre-classified drift code: round 31 moved the
	// classification into canaryDriftCause, because whether a lost anchor may stop the activation
	// depends on the reviewed set, and pre-classifying it here let an UNREVIEWED target's disabled
	// server abort a healthy Canary. The window is still charged as server_identity_drift for the
	// reviewed target — C19 and C26Control pin that end to end.
	live := mcpLiveTrustPrecheck(ttTenant, r.sid, r.tool, r.fp1)
	if !live.AnchorLost {
		t.Fatalf("the live precheck must report the repin window as anchor loss, got %+v", live)
	}
	if live.Eligible {
		t.Fatal("SECURITY: a target inside the repin window must never be eligible to execute")
	}
}

// ── 19 ───────────────────────────────────────────────────────────────────────────────────────
// The OBSERVATION PATH latches the repin window too — not only the live precheck.
//
// C18 proved the window is detected and that mcpLiveTrustPrecheck charges it. It did not prove the
// scope-independent path does, and it didn't: obs.Target is internally coherent inside the window
// (the fingerprint and the identity it was ingested with really are unchanged), so Compare returned
// ReviewedMatches and nothing latched. An authenticated request rejected by inspection, policy or
// rollout scope never reaches the precheck, so restoring the old pin before the next request would
// let the activation continue with the observed anchor breach unrecorded (Codex P1, round 5).
//
// This is the same defect shape as the round-3 anchor loss — a new fact taught to one of the two
// consumers of the observation and not the other — which is why the gate is written against the
// path rather than against the field.
func TestReviewedBinding_C19_ObservationPathLatchesTheRepinWindow(t *testing.T) {
	r := newReviewedRig(t)
	reg, _ := mcpInventory.sharedInventory()
	if reg == nil {
		t.Fatal("premise: a shared registry must be published")
	}
	if _, err := reg.Repin(registry.ServerID(r.sid), registry.Identity("rotated"), canaryRuntimeTestNow); err != nil {
		t.Fatalf("repin: %v", err)
	}
	cur := mcpCurrentAuthoritativeTarget(r.sid, r.tool)
	if !cur.Found || !cur.Usable || !cur.RegistryPinDiverged {
		t.Fatalf("premise: the window must present as found+usable+diverged, got %+v", cur)
	}
	// The comparison ALONE sees nothing — the fact that makes this branch necessary.
	set, ok := r.rt.activeReviewedTargets(r.capb)
	if !ok {
		t.Fatal("premise: the activation must carry a reviewed set")
	}
	if v := set.Compare(cur.Target); v != canary.ReviewedMatches {
		t.Fatalf("premise: inside the window the target must still compare as a MATCH (got %q); if "+
			"it does not, this gate is proving the ordinary drift path instead of the divergence one", v)
	}

	canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
		Generation: r.gen, ServerID: r.sid, ToolName: r.tool,
	})
	r.assertLatched(t, "server_identity_drift")
}

// ── 20 ───────────────────────────────────────────────────────────────────────────────────────
// Every drift verdict the reviewed engine can produce is a KNOWN key in the evidence counter.
//
// noteCanaryPreAdmissionDrift folds an unrecognised code into "other" so a caller can never grow
// the map with arbitrary strings — correct, and the reason this needs a wall rather than a habit:
// adding a verdict without adding it to the allowlist silently renames the operator-visible cause.
// The abort still happens, so nothing fails; the evidence surface just stops saying why, which is
// the opposite of the "one fact, one dialect" rule the drift codes exist to serve.
//
// That is exactly what happened to reviewed_target_tenant_drift (Codex P2, PR #1360, round 6), and
// it is the same shape as the round-5 P1 — a new fact wired into some of its consumers. A wall is
// the only version of "remember to update both" that survives.
func TestReviewedBinding_C20_EveryDriftVerdictIsANamedEvidenceKey(t *testing.T) {
	// Enumerated from the ENGINE, not by hand. A hand-written list here would silently fail to
	// cover a verdict added later — the exact shape this wall exists to prevent — and the engine
	// has its own AST test requiring every declared verdict to be in one of the two sets.
	for _, v := range canary.DriftVerdicts() {
		if _, ok := canaryPreAdmissionDriftCodes[string(v)]; !ok {
			t.Fatalf("reviewed verdict %q is not a named key in canaryPreAdmissionDriftCodes, so an "+
				"abort charged to it is recorded as \"other\" — the experiment stops without the "+
				"evidence surface saying why", v)
		}
	}
	// CONTROL: the non-breach verdicts must NOT be evidence keys. Without this the test would pass
	// just as well if the allowlist were widened to everything, which would let a genuinely
	// unrecognised code through as a named cause.
	for _, v := range canary.NonBreachVerdicts() {
		if _, ok := canaryPreAdmissionDriftCodes[string(v)]; ok {
			t.Fatalf("non-breach verdict %q must not be an evidence key", v)
		}
	}
}

// ── 21 ───────────────────────────────────────────────────────────────────────────────────────
// A reviewed pair reassigned to another tenant latches at ADMISSION too, not only via the
// observation path.
//
// C17 covers the observation sink. This is the window after it: ownership changes A→B between the
// early observation and the live-gate callback, so mcpLiveTrustPrecheck finds the request's tenant
// (A) no longer owns the target. It used to report that as "nothing resolves", which discarded the
// very evidence the comparison needs — the target IS the reviewed pair, under a new owner — so
// admission issued a request-scoped denial, never compared, and reassigning back to A would resume
// the activation with nothing latched (Codex P1, PR #1360, round 6).
//
// The target is now carried across the tenant gate with Trusted false: nothing is authorized by it,
// and the reviewed comparison can still see what happened.
func TestReviewedBinding_C21_TenantReassignmentLatchesAtAdmission(t *testing.T) {
	r := newReviewedRig(t)
	republishUnderTenant(t, r.sid, r.tool, "other-tenant")

	// The precheck must now report the target as RESOLVED-but-ineligible for the original tenant.
	live := mcpLiveTrustPrecheck(ttTenant, r.sid, r.tool, r.fp1)
	if live.Eligible {
		t.Fatal("premise: the original tenant must no longer be eligible for the reassigned target")
	}
	if !live.Resolved {
		t.Fatal("SECURITY: the target still resolves — under a new owner — and discarding that is " +
			"what made the reassignment invisible to the reviewed comparison")
	}
	if live.Authoritative.Tenant == ttTenant {
		t.Fatalf("premise: the authoritative target must carry the NEW tenant, got %q", live.Authoritative.Tenant)
	}

	// Drive the real admission gate with a request from the ORIGINAL tenant.
	d := r.g.AdmitSideEffect(driftGateInput(r.sid, r.tool, r.fp1, r.now))
	if d.Release != nil {
		d.Release()
	}
	if d.Admit {
		t.Fatal("SECURITY: a request whose tenant no longer owns the target must not be admitted")
	}
	r.assertLatched(t, "reviewed_target_tenant_drift")
}

// CONTROL for C21: a tool that does not resolve AT ALL is still silent at admission — the
// fail-safe direction this path deliberately preserves, since an absence is indistinguishable from
// a transient inventory gap.
//
// Scope of this control, stated precisely because the obvious stronger claim is FALSE: it does NOT
// catch a mutation that reports every ineligible request as resolved. Measured — that form is
// behaviourally inert, because the zero ReviewedTarget it would carry compares as
// ReviewedOutOfScope and stays silent anyway. What this pins is the property that matters (an
// unresolvable tool never stops the experiment), not a claim about every wrong shape.
func TestReviewedBinding_C21Control_AnUnresolvableToolIsStillSilent(t *testing.T) {
	r := newReviewedRig(t)
	live := mcpLiveTrustPrecheck(ttTenant, r.sid, "no-such-tool", r.fp1)
	if live.Resolved || live.Eligible {
		t.Fatalf("premise: a non-existent tool must resolve to nothing, got %+v", live)
	}
	d := r.g.AdmitSideEffect(driftGateInput(r.sid, "no-such-tool", r.fp1, r.now))
	if d.Release != nil {
		d.Release()
	}
	if d.Admit {
		t.Fatal("a request for a non-existent tool must not be admitted")
	}
	if r.rt.abortedNow(r.capb) {
		t.Fatalf("SECURITY: a tool that does not resolve must not stop the experiment (code %q) — "+
			"this path cannot tell an absence from a transient inventory gap", r.rt.abortCodeNow(r.capb))
	}
}

// ── 22 ───────────────────────────────────────────────────────────────────────────────────────
// The recorded FIRST CAUSE is a property of the state, not of the transition window the request
// landed in.
//
// Registry.Repin and the catalog re-ingest that follows it are separate publications. C18/C19 cover
// the window BETWEEN them, where the two disagree and the divergence is charged as
// server_identity_drift. This is the window AFTER both have landed: the registry and the catalog
// now AGREE on the new identity, so registryPinDiverged is false and the precheck can see only that
// the request's decision fingerprint is stale — it says tool_fingerprint_drift. The activation's
// reviewed record still pins the ORIGINAL identity and says server_identity_drift, which the
// reviewed comparison deliberately ranks above a fingerprint move.
//
// The same physical event — a server identity rotation — was therefore recorded under two different
// causes depending on which side of the second publication the request arrived on, and the abort
// latches a first cause ONCE and never revises it. The cause the operator reads must be decided
// from the state (Codex P2, PR #1360, round 29).
func TestReviewedBinding_C22_FirstCauseDoesNotDependOnTheTransitionWindow(t *testing.T) {
	r := newReviewedRig(t)

	// Complete BOTH publications: the identity rotates and the catalog re-ingests against it.
	const schema = `{"type":"object"}`
	fp2 := republishWithIdentity(t, r.sid, r.tool, "rotated", schema)
	if fp2 == r.fp1 {
		t.Fatal("premise: the catalog fingerprint folds in the identity, so a rotation must move it")
	}
	cur := mcpCurrentAuthoritativeTarget(r.sid, r.tool)
	if !cur.Found || !cur.Usable {
		t.Fatalf("premise: the target must still resolve and be usable, got %+v", cur)
	}
	if cur.RegistryPinDiverged {
		t.Fatal("premise: this is the window AFTER the re-ingest — the registry and the catalog " +
			"agree, so there is no divergence for the precheck to charge")
	}
	if cur.Target.ServerIdentity != "rotated" {
		t.Fatalf("premise: the authoritative target must carry the rotated identity, got %q",
			cur.Target.ServerIdentity)
	}
	// The precheck, asked about a request still decided against F1, can only see the stale
	// fingerprint. This is the observation the transaction must NOT charge verbatim.
	if live := mcpLiveTrustPrecheck(ttTenant, r.sid, r.tool, r.fp1); live.DriftCode != "tool_fingerprint_drift" {
		t.Fatalf("premise: the probe alone must report the stale fingerprint, got %q", live.DriftCode)
	}

	if r.request(r.fp1, r.now) {
		t.Fatal("SECURITY: a request against a rotated server identity must not be admitted")
	}
	if !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: the reviewed server identity moved — the whole Canary must stop")
	}
	if code := r.rt.abortCodeNow(r.capb); code != "server_identity_drift" {
		t.Fatalf("first cause = %q, want \"server_identity_drift\". The reviewed record pins the "+
			"ORIGINAL identity and ranks an anchor move above a fingerprint move; charging the "+
			"probe's view instead makes the immutable evidence an artifact of which transition "+
			"window observed the breach", code)
	}
}

// C22, again through the OBSERVATION path. The pre-executor latch re-derives the drift from the
// same precheck, so it reaches the identical disagreement — and the two paths must not record two
// different causes for one state (the "same question, opposite answers" defect this matrix has
// closed twice before).
func TestReviewedBinding_C22B_TheObservationPathAgreesOnTheFirstCause(t *testing.T) {
	r := newReviewedRig(t)
	republishWithIdentity(t, r.sid, r.tool, "rotated", `{"type":"object"}`)
	if mcpCurrentAuthoritativeTarget(r.sid, r.tool).RegistryPinDiverged {
		t.Fatal("premise: both publications have landed, so nothing diverges")
	}
	canaryPreAdmissionDrift(r.capb.String(), mcpruntime.CanaryDriftTarget{
		Generation: r.gen, Tenant: ttTenant, ServerID: r.sid, ToolName: r.tool,
		DecisionFP: r.fp1, Code: "tool_fingerprint_drift",
	})
	if !r.rt.abortedNow(r.capb) {
		t.Fatal("SECURITY: the pre-executor path must latch a rotated server identity")
	}
	if code := r.rt.abortCodeNow(r.capb); code != "server_identity_drift" {
		t.Fatalf("first cause = %q, want \"server_identity_drift\" — the same state must produce the "+
			"same cause whichever path observed it", code)
	}
}

// CONTROL for C22: a fingerprint that moved with the identity UNCHANGED is still recorded as
// tool_fingerprint_drift.
//
// Without it, "let the reviewed record decide the cause" could be satisfied by a form that always
// reports server_identity_drift, or that drops the probe's code whenever the reviewed comparison
// has nothing to add. The rule is a SHARPENING, never a replacement: the reviewed verdict wins only
// when it is itself a drift, and ReviewedMatches leaves the probe's code standing.
func TestReviewedBinding_C22Control_AFingerprintOnlyMoveKeepsItsOwnCause(t *testing.T) {
	r := newReviewedRig(t)
	r.moveToF2(t) // schema moves, identity stays exactly as reviewed
	if cur := mcpCurrentAuthoritativeTarget(r.sid, r.tool); cur.Target.ServerIdentity != "id" {
		t.Fatalf("premise: the identity must be untouched, got %q", cur.Target.ServerIdentity)
	}
	if r.request(r.fp1, r.now) {
		t.Fatal("SECURITY: a request against a moved fingerprint must not be admitted")
	}
	r.assertLatched(t, "tool_fingerprint_drift")
}

// SECOND CONTROL for C22, and the one that pins the direction of the rule.
//
// C22Control proves the cause is not ALWAYS server_identity_drift. This proves the reviewed record
// never SILENCES a probe code it has nothing to say about. Reviewed and current are identical here
// — Compare returns ReviewedMatches — while the request carries a decision fingerprint that matches
// neither. The probe's tool_fingerprint_drift must stand.
//
// The wrong shape is not hypothetical: reading the rule as "the reviewed verdict decides the cause"
// rather than "a reviewed DRIFT sharpens it" makes the code empty here, the latch is skipped, and
// because the reviewed target really does still match and a live approval really does cover it, the
// request is ADMITTED — a stale-decision execution authorized by the very change meant to make the
// evidence sharper.
func TestReviewedBinding_C22Control2_AReviewedMatchNeverSilencesTheProbe(t *testing.T) {
	r := newReviewedRig(t)
	const staleFP = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if staleFP == r.fp1 {
		t.Fatal("premise: the decision fingerprint must differ from the reviewed one")
	}
	if cur := mcpCurrentAuthoritativeTarget(r.sid, r.tool); !cur.Found ||
		cur.Target.ServerIdentity != "id" {
		t.Fatalf("premise: the target must be exactly as reviewed, got %+v", cur)
	}
	if r.request(staleFP, r.now) {
		t.Fatal("SECURITY: a request decided against a fingerprint the target never carried must " +
			"not be admitted")
	}
	r.assertLatched(t, "tool_fingerprint_drift")
}

// ── 23 ───────────────────────────────────────────────────────────────────────────────────────
// CROSS-PATH CAUSE PARITY — one state, one recorded cause, whichever path observed it.
//
// This is the structural closure for the class that has produced four findings on this PR: a new
// fact taught to one consumer of the authoritative target and not the other (ServerUsable in round
// 26, RegistryPinDiverged in round 27, ReviewedTenantDrift's evidence key in round 28, and the
// first-cause ordering in round 29). Each was closed where it was found. Nothing held the general
// property, so the next instance was always free to appear.
//
// There are exactly two paths that can stop the experiment for a moved reviewed target, and they
// are reached by DISJOINT populations of requests — the admission transaction only sees requests
// that survive authentication, inspection, policy and rollout scope, and the observation sink is
// the only observer for every request that does not. An operator reads ONE abort code and cannot
// tell which path produced it, so a disagreement is not a cosmetic inconsistency: it means the
// recorded cause of an irreversible stop depends on facts about the request rather than about the
// state.
//
// The table is the state space this PR has had to reason about, each entry a real published
// transition rather than a synthetic struct.
func TestReviewedBinding_C23_BothLatchPathsRecordTheSameCause(t *testing.T) {
	cases := []struct {
		name string
		// move applies a real inventory transition and returns the decision fingerprint a request
		// arriving afterwards would carry.
		move func(t *testing.T, r *reviewedRig) string
		want string
	}{
		{
			name: "fingerprint moves, identity untouched",
			move: func(t *testing.T, r *reviewedRig) string { return r.moveToF2(t) },
			want: "tool_fingerprint_drift",
		},
		{
			name: "identity rotates and the catalog re-ingests (both publications landed)",
			move: func(t *testing.T, r *reviewedRig) string {
				republishWithIdentity(t, r.sid, r.tool, "rotated", `{"type":"object"}`)
				return r.fp1
			},
			want: "server_identity_drift",
		},
		{
			name: "registry repinned, catalog not yet re-ingested (inside the window)",
			move: func(t *testing.T, r *reviewedRig) string {
				reg, _ := mcpInventory.sharedInventory()
				if reg == nil {
					t.Fatal("premise: a shared registry must be published")
				}
				if _, err := reg.Repin(registry.ServerID(r.sid), registry.Identity("rotated"), canaryRuntimeTestNow); err != nil {
					t.Fatalf("repin: %v", err)
				}
				return r.fp1
			},
			want: "server_identity_drift",
		},
		{
			name: "the reviewed server is disabled",
			move: func(t *testing.T, r *reviewedRig) string {
				disableSeededServer(t, r.sid, r.tool)
				return r.fp1
			},
			want: "server_identity_drift",
		},
		{
			name: "the reviewed pair is reassigned to another tenant",
			move: func(t *testing.T, r *reviewedRig) string {
				republishUnderTenant(t, r.sid, r.tool, "other-tenant")
				return r.fp1
			},
			want: "reviewed_target_tenant_drift",
		},
	}

	for _, tc := range cases {
		t.Run("admission/"+tc.name, func(t *testing.T) {
			r := newReviewedRig(t)
			fp := tc.move(t, r)
			if r.request(fp, r.now) {
				t.Fatal("SECURITY: a moved reviewed target must not be admitted")
			}
			assertCause(t, r, tc.want)
		})
		t.Run("observation/"+tc.name, func(t *testing.T) {
			r := newReviewedRig(t)
			tc.move(t, r)
			canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
				Generation: r.gen, ServerID: r.sid, ToolName: r.tool,
			})
			assertCause(t, r, tc.want)
		})
	}
}

// assertCause proves the Canary stopped and names the single first cause it recorded.
func assertCause(t *testing.T, r *reviewedRig, want string) {
	t.Helper()
	if !r.rt.abortedNow(r.capb) {
		t.Fatalf("SECURITY: the reviewed target moved (%s) and the experiment did not stop", want)
	}
	if got := r.rt.abortCodeNow(r.capb); got != want {
		t.Fatalf("recorded cause = %q, want %q. The two latch paths serve disjoint populations of "+
			"requests and an operator reads only the code, so a disagreement makes the recorded "+
			"cause of an irreversible stop a property of the request rather than of the state", got, want)
	}
}

// ── 24 ───────────────────────────────────────────────────────────────────────────────────────
// COMBINED TRANSITIONS — anchor state outranks the comparison verdict on BOTH paths.
//
// C23 walks each transition on its own, and that is exactly what it misses: two of them at once.
// A reviewed pair reassigned A→B whose registry identity is THEN repinned before the catalog
// re-ingests leaves one published state that the two paths read differently. The observation sink
// checks the anchor facts before comparing and says server_identity_drift; the live precheck
// returned at the tenant gate before it ever looked at them, so admission compared the carried
// target and said reviewed_target_tenant_drift. Whichever request arrived first decided the
// immutable first cause (Codex P2, PR #1360, round 30).
//
// The ordering the observation path uses is the deliberate one, recorded at its own branch: an
// anchor that is no longer in force outranks whatever the target happens to compare as, because
// losing the trust anchor is the stronger statement about what the experiment was authorized
// against. The precheck now checks the same facts in the same order.
func TestReviewedBinding_C24_AnchorLossOutranksTenantDriftOnBothPaths(t *testing.T) {
	move := func(t *testing.T, r *reviewedRig) {
		t.Helper()
		republishUnderTenant(t, r.sid, r.tool, "other-tenant")
		reg, _ := mcpInventory.sharedInventory()
		if reg == nil {
			t.Fatal("premise: a shared registry must be published")
		}
		if _, err := reg.Repin(registry.ServerID(r.sid), registry.Identity("rotated"), canaryRuntimeTestNow); err != nil {
			t.Fatalf("repin: %v", err)
		}
		cur := mcpCurrentAuthoritativeTarget(r.sid, r.tool)
		if !cur.Found || !cur.RegistryPinDiverged {
			t.Fatalf("premise: both transitions must be live — found=%v diverged=%v", cur.Found, cur.RegistryPinDiverged)
		}
		if cur.Target.Tenant == ttTenant {
			t.Fatal("premise: the target must have changed hands")
		}
	}

	t.Run("admission", func(t *testing.T) {
		r := newReviewedRig(t)
		move(t, r)
		if r.request(r.fp1, r.now) {
			t.Fatal("SECURITY: a request against a reassigned, repinned target must not be admitted")
		}
		assertCause(t, r, "server_identity_drift")
	})
	t.Run("observation", func(t *testing.T) {
		r := newReviewedRig(t)
		move(t, r)
		canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
			Generation: r.gen, ServerID: r.sid, ToolName: r.tool,
		})
		assertCause(t, r, "server_identity_drift")
	})
}

// CONTROL for C24: with the anchor INTACT, a tenant reassignment still reports tenant drift on
// both paths. Without this, "anchor loss outranks the comparison" could be satisfied by a form
// that reports server_identity_drift for every wrong-tenant request, which would erase the
// tenant-drift verdict round 28 exists to produce.
func TestReviewedBinding_C24Control_AHealthyAnchorStillReportsTenantDrift(t *testing.T) {
	t.Run("admission", func(t *testing.T) {
		r := newReviewedRig(t)
		republishUnderTenant(t, r.sid, r.tool, "other-tenant")
		if mcpCurrentAuthoritativeTarget(r.sid, r.tool).RegistryPinDiverged {
			t.Fatal("premise: the anchor must be intact")
		}
		if r.request(r.fp1, r.now) {
			t.Fatal("SECURITY: a reassigned target must not be admitted")
		}
		assertCause(t, r, "reviewed_target_tenant_drift")
	})
	t.Run("observation", func(t *testing.T) {
		r := newReviewedRig(t)
		republishUnderTenant(t, r.sid, r.tool, "other-tenant")
		canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
			Generation: r.gen, ServerID: r.sid, ToolName: r.tool,
		})
		assertCause(t, r, "reviewed_target_tenant_drift")
	})
}

// publishVariant republishes the reviewed server/tool with every dimension the two latch paths can
// read stated explicitly. It is the state constructor C25 enumerates over.
func publishVariant(t *testing.T, sid, tool, tenant, identity, schema string, enabled bool) {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + tenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"` + identity + `","enabled":` +
		strconv.FormatBool(enabled) + `,
	   "tools":[{"name":"` + tool + `","input_schema":` + schema + `}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
}

// ── 25 ───────────────────────────────────────────────────────────────────────────────────────
// CROSS-PRODUCT PARITY — the two latch paths agree on EVERY reachable published state, not on a
// list of states someone thought to write down.
//
// This exists because C23 and C24 are both enumerations and both were defeated by the thing they
// did not enumerate. C23 walked each transition alone; round 30 needed two at once. C24 then
// covered exactly one of the ten pairs — the one that had already been found. Writing down pairs
// is the same error one level up, and the next combination would have been found by review rather
// than by a test again.
//
// So this enumerates the STATE SPACE rather than the transitions: every combination of the five
// facts the two paths can read — owning tenant, the identity the catalog record was ingested
// against, the tool's schema (hence its fingerprint), whether the server is enabled, and whether
// the registry pins something the catalog record does not. 32 states, each driven through BOTH
// paths from a fresh activation, each required to record the SAME first cause.
//
// It asserts PARITY rather than a per-state expected code, deliberately. The correct cause for a
// given state is a design decision that has moved three times during this PR (rounds 3, 4 and 30);
// pinning 32 of them here would freeze today's answers and turn a future correction into 32 test
// edits. What must never change is that ONE published state produces ONE recorded cause, whichever
// path observed it — an operator reads the code without knowing which path produced it, so a
// disagreement makes the evidence for an irreversible stop a property of the request rather than
// of the state. The known causes stay pinned by C14-C24, which are about specific verdicts.
// c25State is one point in the published-state space: which of the five facts the latch paths read
// deviate from what the activation reviewed.
type c25State struct {
	otherTenant bool
	rotatedID   bool
	movedFP     bool
	disabled    bool
	repinned    bool
}

func c25StateFromMask(mask int) c25State {
	return c25State{
		otherTenant: mask&1 != 0,
		rotatedID:   mask&2 != 0,
		movedFP:     mask&4 != 0,
		disabled:    mask&8 != 0,
		repinned:    mask&16 != 0,
	}
}

func (st c25State) deviates() bool {
	return st.otherTenant || st.rotatedID || st.movedFP || st.disabled || st.repinned
}

func (st c25State) name() string {
	parts := []string{}
	for _, d := range []struct {
		name string
		on   bool
	}{
		{"tenant", st.otherTenant}, {"identity", st.rotatedID}, {"fingerprint", st.movedFP},
		{"disabled", st.disabled}, {"repin", st.repinned},
	} {
		if d.on {
			parts = append(parts, d.name)
		}
	}
	if len(parts) == 0 {
		return "baseline"
	}
	return strings.Join(parts, "+")
}

// apply publishes the state. The baseline is left exactly as the rig seeded it, so a "no
// deviation" run really is the untouched reviewed target rather than a re-publish of it.
func (st c25State) apply(t *testing.T, r *reviewedRig) {
	t.Helper()
	const (
		baseSchema  = `{"type":"object"}`
		movedSchema = `{"type":"object","properties":{"moved":{"type":"string"}}}`
	)
	if st.deviates() {
		tenant, identity, schema := ttTenant, "id", baseSchema
		if st.otherTenant {
			tenant = "other-tenant"
		}
		if st.rotatedID {
			identity = "rotated"
		}
		if st.movedFP {
			schema = movedSchema
		}
		publishVariant(t, r.sid, r.tool, tenant, identity, schema, !st.disabled)
	}
	if !st.repinned {
		return
	}
	reg, _ := mcpInventory.sharedInventory()
	if reg == nil {
		t.Fatal("premise: a shared registry must be published")
	}
	// A pin the catalog record was NOT built against, whatever the record now carries.
	if _, err := reg.Repin(registry.ServerID(r.sid), registry.Identity("registry-only"), canaryRuntimeTestNow); err != nil {
		t.Fatalf("repin: %v", err)
	}
}

// c25Cause applies the state to a fresh activation, drives ONE latch path, and reports the cause
// that path recorded ("" when it latched nothing).
func c25Cause(t *testing.T, st c25State, viaAdmission bool) string {
	t.Helper()
	r := newReviewedRig(t)
	st.apply(t, r)
	if viaAdmission {
		if r.request(r.fp1, r.now) && st.deviates() {
			t.Fatal("SECURITY: a deviating published state must not be admitted")
		}
	} else {
		canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
			Generation: r.gen, ServerID: r.sid, ToolName: r.tool,
		})
	}
	if !r.rt.abortedNow(r.capb) {
		return ""
	}
	return r.rt.abortCodeNow(r.capb)
}

func TestReviewedBinding_C25_BothPathsAgreeOnEveryPublishedState(t *testing.T) {
	for mask := 0; mask < 32; mask++ {
		st := c25StateFromMask(mask)
		t.Run(st.name(), func(t *testing.T) {
			viaAdmission := c25Cause(t, st, true)
			viaObservation := c25Cause(t, st, false)

			// Non-vacuity: parity alone would be satisfied by two paths that both stayed silent.
			// Every deviating state here moves the reviewed record in at least one dimension the
			// review bound, so every one of them must stop the experiment.
			if st.deviates() && viaAdmission == "" {
				t.Fatal("SECURITY: a published state that deviates from the reviewed record did not " +
					"stop the experiment on EITHER path — parity held only because both were silent")
			}
			if viaAdmission != viaObservation {
				t.Fatalf("the two latch paths disagree on ONE published state: admission recorded %q, "+
					"the observation sink recorded %q. An operator reads one abort code and cannot tell "+
					"which path produced it, so the cause of an irreversible stop must be a property of "+
					"the state, not of which request happened to observe it",
					nameOrSilent(viaAdmission), nameOrSilent(viaObservation))
			}
		})
	}
}

func nameOrSilent(code string) string {
	if code == "" {
		return "(no latch)"
	}
	return code
}

// publishTwoToolsDisabled republishes the reviewed server carrying BOTH the reviewed tool and an
// unrelated sibling, with the server DISABLED — the anchor-loss state, reached by a request that
// names the sibling.
func publishTwoToolsDisabled(t *testing.T, sid, reviewedTool, otherTool string) {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"id","enabled":false,
	   "tools":[{"name":"` + reviewedTool + `","input_schema":{"type":"object"}},
	            {"name":"` + otherTool + `","input_schema":{"type":"object","properties":{"z":{"type":"string"}}}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
}

// ── 26 ───────────────────────────────────────────────────────────────────────────────────────
// SCOPE DECIDES WHETHER TO LATCH; ANCHOR STATE DECIDES WHICH CAUSE.
//
// Both latch paths checked the anchor facts BEFORE the reviewed comparison, so a resolvable tool
// the activation was never reviewed for, on a server that is merely disabled or repinned, aborted
// the whole Canary before Compare could return ReviewedOutOfScope. That is the round-15 rule
// inverted — "a catalog change to a tool the experiment never reviewed must not abort it" — and
// round 26's server-unavailable pipeline hook is what made it reachable: an authenticated request
// for ANY disabled server with retained catalog records reaches the observation sink even when the
// server is outside the rollout scope entirely (Codex P1, PR #1360, round 31).
//
// The ordering rounds 3/4/30 established is still right, but it was stated one step too early. The
// reviewed set decides WHETHER this activation may be stopped at all; only then does anchor state
// outrank whatever the target compares as.
func TestReviewedBinding_C26_AnchorLossOnAnUnreviewedTargetLatchesNothing(t *testing.T) {
	const sibling = "sibling"

	t.Run("observation", func(t *testing.T) {
		r := newReviewedRig(t)
		publishTwoToolsDisabled(t, r.sid, r.tool, sibling)
		cur := mcpCurrentAuthoritativeTarget(r.sid, sibling)
		if !cur.Found || cur.Usable {
			t.Fatalf("premise: the sibling must resolve on a disabled server, got %+v", cur)
		}
		canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
			Generation: r.gen, ServerID: r.sid, ToolName: sibling,
		})
		if r.rt.abortedNow(r.capb) {
			t.Fatalf("SECURITY: a tool this activation never reviewed stopped the experiment (%q). "+
				"Traffic to any disabled server with retained catalog records could halt an "+
				"otherwise healthy Canary", r.rt.abortCodeNow(r.capb))
		}
	})

	t.Run("admission", func(t *testing.T) {
		r := newReviewedRig(t)
		publishTwoToolsDisabled(t, r.sid, r.tool, sibling)
		d := r.g.AdmitSideEffect(driftGateInput(r.sid, sibling, r.fp1, r.now))
		if d.Release != nil {
			d.Release()
		}
		if d.Admit {
			t.Fatal("a request for an unreviewed tool on a disabled server must not be admitted")
		}
		if r.rt.abortedNow(r.capb) {
			t.Fatalf("SECURITY: admission latched on an unreviewed target (%q)", r.rt.abortCodeNow(r.capb))
		}
	})
}

// CONTROL for C26: the REVIEWED target on that same disabled server still latches, and still as
// anchor loss. Without it, "filter unreviewed targets first" could be satisfied by a form that
// stopped latching anchor loss altogether — which is the round-3 defect restored.
func TestReviewedBinding_C26Control_TheReviewedTargetStillLatchesAnchorLoss(t *testing.T) {
	const sibling = "sibling"
	for _, tc := range []struct{ name, via string }{{"observation", "obs"}, {"admission", "adm"}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReviewedRig(t)
			publishTwoToolsDisabled(t, r.sid, r.tool, sibling)
			if tc.via == "obs" {
				canaryReviewedTargetObserved(r.capb.String(), mcpruntime.CanaryTargetObservation{
					Generation: r.gen, ServerID: r.sid, ToolName: r.tool,
				})
			} else if r.request(r.fp1, r.now) {
				t.Fatal("the reviewed target on a disabled server must not be admitted")
			}
			if !r.rt.abortedNow(r.capb) {
				t.Fatal("SECURITY: the REVIEWED target lost its trust anchor — the experiment must stop")
			}
			if code := r.rt.abortCodeNow(r.capb); code != "server_identity_drift" {
				t.Fatalf("first cause = %q, want \"server_identity_drift\"", code)
			}
		})
	}
}

// ── 27 ───────────────────────────────────────────────────────────────────────────────────────
// THE EVIDENCE COUNTER RECORDS THE CAUSE THAT WAS ACTUALLY LATCHED.
//
// canaryPreAdmissionDrift counted the runtime's own pre-lock observation and then ignored what the
// re-derivation under the lock decided. Once reviewedFirstCause could sharpen a stale-fingerprint
// observation into server_identity_drift, the admin evidence surface reported tool-fingerprint
// drift for an event auto_stop recorded as server-identity drift — the two surfaces disagreeing
// about one event, which is the shape of this entire PR (Codex P2, PR #1360, round 31).
func TestReviewedBinding_C27_EvidenceCounterRecordsTheLatchedCause(t *testing.T) {
	r := newReviewedRig(t)
	before := canaryPreAdmissionDriftCounts(r.capb.String())

	// Identity rotation with re-ingest: the probe sees only the stale decision fingerprint, the
	// reviewed record says the anchor moved.
	republishWithIdentity(t, r.sid, r.tool, "rotated", `{"type":"object"}`)
	canaryPreAdmissionDrift(r.capb.String(), mcpruntime.CanaryDriftTarget{
		Generation: r.gen, Tenant: ttTenant, ServerID: r.sid, ToolName: r.tool,
		DecisionFP: r.fp1, Code: "tool_fingerprint_drift",
	})

	latched := r.rt.abortCodeNow(r.capb)
	if latched != "server_identity_drift" {
		t.Fatalf("premise: the re-derivation must sharpen the cause, got %q", latched)
	}
	after := canaryPreAdmissionDriftCounts(r.capb.String())
	if after[latched] <= before[latched] {
		t.Fatalf("the evidence counter did not record the cause that was latched (%q): before=%v after=%v. "+
			"An operator reading the rollout surface would see a different reason than auto_stop recorded",
			latched, before, after)
	}
	if after["tool_fingerprint_drift"] > before["tool_fingerprint_drift"] {
		t.Fatalf("the counter recorded the pre-lock observation as well, so one event appears twice "+
			"under two causes: before=%v after=%v", before, after)
	}
}

// ── 28 ───────────────────────────────────────────────────────────────────────────────────────
// A PROBE-ESTABLISHED DRIFT CODE ALWAYS CARRIES THE TARGET IT DRIFTED FROM.
//
// Round 31 made the reviewed set decide whether a cause may stop the activation at all, so an
// observation with no resolved target latches nothing — there is no way to establish scope for it,
// and latching anyway is the round-15 rule inverted. That is only safe if production never
// produces a drift code WITHOUT a target, because such an observation would now be silently
// dropped rather than refused loudly.
//
// This is checked structurally rather than by behaviour, because the property is about every
// return statement in the function — including ones no test drives today and ones added later. A
// behavioural gate can only cover the shapes someone thought to construct, which is precisely how
// the three defects this matrix was built for survived.
func TestReviewedBinding_C28_ADriftCodeAlwaysCarriesItsTarget(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "mcp_live_gate.go", nil, 0)
	if err != nil {
		t.Fatalf("parse mcp_live_gate.go: %v", err)
	}
	checked := 0
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		id, ok := lit.Type.(*ast.Ident)
		if !ok || id.Name != "liveTrustPrecheck" {
			return true
		}
		var hasCode, hasResolved bool
		for _, e := range lit.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			switch key.Name {
			case "DriftCode":
				hasCode = true
			case "Resolved":
				if b, ok := kv.Value.(*ast.Ident); ok && b.Name == "true" {
					hasResolved = true
				}
			}
		}
		if hasCode {
			checked++
			if !hasResolved {
				t.Errorf("%s: a liveTrustPrecheck carrying DriftCode must also carry Resolved:true. "+
					"Since round 31 an observation with no resolved target latches NOTHING (scope "+
					"cannot be established for it), so a code without a target would be dropped "+
					"silently instead of stopping the experiment",
					fset.Position(lit.Pos()))
			}
		}
		return true
	})
	if checked == 0 {
		t.Fatal("the wall matched no liveTrustPrecheck literal carrying a DriftCode — the selector " +
			"has gone stale and this test now proves nothing")
	}
}
