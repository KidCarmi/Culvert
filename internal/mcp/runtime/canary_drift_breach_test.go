package runtime

// canary_drift_breach_test.go — a tool rug-pull refused BEFORE the executor is an authoritative
// whole-Canary breach, not merely a stale decision (First Controlled Canary review, blocker #7;
// Codex round 14).

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// breachReport is one reported pre-executor breach: the code AND the activation generation it was
// charged to. The generation is half the contract — a breach charged to the wrong activation stops
// an experiment that never saw the fault — so the recorder keeps both.
type breachReport struct {
	gen  uint64
	code string
}

// breachRecorder captures what the pipeline reported through the optional Canary seam.
type breachRecorder struct {
	mu   sync.Mutex
	seen []breachReport
}

func (r *breachRecorder) report(_ string, gen uint64, code string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, breachReport{gen: gen, code: code})
}

func (r *breachRecorder) codes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.seen))
	for _, b := range r.seen {
		out = append(out, b.code)
	}
	return out
}

func (r *breachRecorder) reports() []breachReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]breachReport(nil), r.seen...)
}

// driftFixture ingests one tool and returns a pipeline plus a DecisionInput whose fingerprint no
// longer matches the live catalog — the exact shape refuseOnToolDrift exists to refuse.
func driftFixture(t *testing.T, rec *breachRecorder) (p *pipeline, stale, fresh policy.DecisionInput) {
	t.Helper()
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	live := ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object"}`)
	if rec != nil {
		deps.CanaryBreach = rec.report
	}
	pl := newGatewayPipeline(t, deps)

	liveRec, ok := deps.Catalog.Current().Get(catalog.ToolKey{
		Server: registry.ServerID(testServerID), Name: "x",
	})
	if !ok {
		t.Fatal("the ingested tool is not in the catalog")
	}
	disp, drift := policyDisposition(liveRec.Eligibility)
	mk := func(fp string) policy.DecisionInput {
		return policy.DecisionInput{
			Capability: policy.CapGateway,
			Tool: &policy.Tool{
				Name: "x", ServerID: testServerID, FingerprintHash: fp,
				Disposition: disp, Drift: drift,
			},
		}
	}
	return pl, mk("stale" + live), mk(live)
}

// TestCanaryBreach_PreExecutorToolDriftIsReported pins the PRE-EXECUTOR half of the drift funnel.
//
// This refusal happens before the composition-layer admission gate is ever reached, so the gate's
// own drift classifier cannot see it. Left unreported, a rug-pull landing in that window failed the
// request and left the Canary holding execution authority — and every later request against the new
// fingerprint then merely failed approval validation, which looks like ordinary denial rather than
// proof the experiment's premise no longer holds (Codex round 14).
func TestCanaryBreach_PreExecutorToolDriftIsReported(t *testing.T) {
	rec := &breachRecorder{}
	p, stale, _ := driftFixture(t, rec)

	rb := p.newRecord(Request{}, fixedClock())
	if _, refused := p.refuseOnToolDrift(rb, stale, jsonrpc.ID{}, true, testCanaryGen); !refused {
		t.Fatal("premise: a stale fingerprint must be refused here")
	}

	got := rec.codes()
	if len(got) != 1 || got[0] != "tool_fingerprint_drift" {
		t.Fatalf("SECURITY: a rug-pull refused before the executor must also stop the whole "+
			"Canary — the request failing is not the same as the experiment stopping; reported=%v", got)
	}
}

// THE CONTROL: a CURRENT fingerprint reports nothing. Without it the fix is satisfiable by
// reporting a breach on every request, which would stop a healthy Canary immediately.
func TestCanaryBreach_CurrentFingerprintReportsNothing(t *testing.T) {
	rec := &breachRecorder{}
	p, _, fresh := driftFixture(t, rec)

	rb := p.newRecord(Request{}, fixedClock())
	if _, refused := p.refuseOnToolDrift(rb, fresh, jsonrpc.ID{}, true, testCanaryGen); refused {
		t.Fatal("premise: a current fingerprint must not be refused")
	}
	if got := rec.codes(); len(got) != 0 {
		t.Fatalf("an undrifted decision must report no breach, got %v", got)
	}
}

// A pipeline with NO seam composed — every non-Canary posture, including the shipped default —
// behaves exactly as before: it refuses, and reports nowhere. The nil check is the disabled-by-
// default guarantee, so it gets its own gate rather than being assumed.
func TestCanaryBreach_NoSeamComposedIsAPlainRefusal(t *testing.T) {
	p, stale, _ := driftFixture(t, nil)

	rb := p.newRecord(Request{}, fixedClock())
	if _, refused := p.refuseOnToolDrift(rb, stale, jsonrpc.ID{}, true, testCanaryGen); !refused {
		t.Fatal("a stale fingerprint must still be refused with no seam composed")
	}
}

// TestCanaryBreach_ShadowEvaluationDoesNotStopTheCanary pins the SCOPE binding, and it guards the
// direction a safety control must never err in.
//
// With Shadow fallback enabled, an OUT-OF-SCOPE request under Canary mode resolves to a shadow
// evaluation and still reaches this refusal. Reported unconditionally, a catalog change for a tool
// the experiment never reviewed would abort the whole Canary — and to an operator, a healthy
// experiment stopped for something outside its own blast radius is indistinguishable from the
// control being broken (Codex round 15).
func TestCanaryBreach_ShadowEvaluationDoesNotStopTheCanary(t *testing.T) {
	rec := &breachRecorder{}
	p, stale, _ := driftFixture(t, rec)

	rb := p.newRecord(Request{}, fixedClock())
	// canaryScoped=false is what dispatchExecute passes for a shadow evaluation.
	if _, refused := p.refuseOnToolDrift(rb, stale, jsonrpc.ID{}, false, testCanaryGen); !refused {
		t.Fatal("premise: the request must still be REFUSED — only the whole-Canary stop is scoped")
	}
	if got := rec.codes(); len(got) != 0 {
		t.Fatalf("SECURITY: drift on traffic outside the Canary's reviewed scope stopped the whole "+
			"experiment, reported=%v", got)
	}
}

// TestCanaryBreach_EligibilityDriftIsNotCalledFingerprintDrift pins the drift CLASS.
//
// toolHasDrifted is true for two different facts: the fingerprint moved, and the eligibility moved
// with the fingerprint unchanged (catalog.DisableServer, a quarantine, a review requirement).
// Hard-coding tool_fingerprint_drift told an operator the tool's SHAPE changed when what happened
// was their own DisableServer — and because the admission-time classifier calls that same condition
// server_identity_drift, the immutable first cause depended on which detection window won the race
// (Codex round 15). Two windows must not disagree about what one fact is called.
func TestCanaryBreach_EligibilityDriftIsNotCalledFingerprintDrift(t *testing.T) {
	rec := &breachRecorder{}
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	live := ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object"}`)
	deps.CanaryBreach = rec.report
	p := newGatewayPipeline(t, deps)

	liveRec, ok := deps.Catalog.Current().Get(catalog.ToolKey{
		Server: registry.ServerID(testServerID), Name: "x",
	})
	if !ok {
		t.Fatal("the ingested tool is not in the catalog")
	}
	disp, drift := policyDisposition(liveRec.Eligibility)

	// The decision carries the CURRENT fingerprint; only the eligibility axis will move.
	in := policy.DecisionInput{
		Capability: policy.CapGateway,
		Tool: &policy.Tool{
			Name: "x", ServerID: testServerID, FingerprintHash: live,
			Disposition: disp, Drift: drift,
		},
	}
	rb := p.newRecord(Request{}, fixedClock())
	if _, refused := p.refuseOnToolDrift(rb, in, jsonrpc.ID{}, true, testCanaryGen); refused {
		t.Fatal("premise: nothing has drifted yet")
	}

	// The operator disables the server. The fingerprint is deliberately preserved by the catalog.
	deps.Catalog.DisableServer(registry.ServerID(testServerID))
	after, ok := deps.Catalog.Current().Get(catalog.ToolKey{
		Server: registry.ServerID(testServerID), Name: "x",
	})
	if !ok {
		t.Fatal("premise: the record must still exist, only its eligibility changes")
	}
	sum := after.Fingerprint.Sum()
	if hex.EncodeToString(sum[:]) != live {
		t.Fatal("premise: DisableServer must preserve the fingerprint, or this test proves nothing")
	}

	if _, refused := p.refuseOnToolDrift(rb, in, jsonrpc.ID{}, true, testCanaryGen); !refused {
		t.Fatal("an eligibility change must still be refused")
	}
	got := rec.codes()
	if len(got) != 1 || got[0] != "server_identity_drift" {
		t.Fatalf("SECURITY: an eligibility change must be reported as server_identity_drift — the "+
			"fingerprint did not move, and the admission-time classifier calls this same condition "+
			"by that name; reported=%v", got)
	}
}

// testCanaryGen is the activation generation the fixtures pretend resolved the request. It is
// deliberately NOT 1 and NOT 0: a zero would be indistinguishable from "no activation", and the
// point of the round-16 contract is that a SPECIFIC generation travels from the resolution point
// to the report unchanged.
const testCanaryGen uint64 = 7

// TestCanaryBreach_PreExecutorDriftCarriesTheResolvedGeneration pins Codex round 16's P1.
//
// The seam used to take no generation, and the composition adapter resolved "the activation
// admitting right now" at REPORT time. The premise was that a request with no reservation was
// never admitted under an activation, so any generation would do. It was RESOLVED under one — and
// between resolution and this refusal a demote-and-reactivate can intervene, at which point the
// old request's drift observation was charged to, and stopped, the NEW experiment.
//
// This is the round-1 finding ("safety reports carried no activation generation") reappearing in a
// seam introduced five rounds later, and it is the more dangerous direction: a healthy experiment
// stopped by a fault it never saw. The generation now travels with the request.
func TestCanaryBreach_PreExecutorDriftCarriesTheResolvedGeneration(t *testing.T) {
	rec := &breachRecorder{}
	p, stale, _ := driftFixture(t, rec)
	rb := p.newRecord(Request{}, fixedClock())

	if _, refused := p.refuseOnToolDrift(rb, stale, jsonrpc.ID{}, true, testCanaryGen); !refused {
		t.Fatal("a drifted decision must still be refused")
	}
	got := rec.reports()
	if len(got) != 1 {
		t.Fatalf("expected exactly one breach, got %d: %+v", len(got), got)
	}
	if got[0].gen != testCanaryGen {
		t.Fatalf("SECURITY: the breach must be charged to the generation that RESOLVED the request "+
			"(%d), not one re-read at report time; got %d — a request that outlived its activation "+
			"can otherwise stop the experiment that replaced it", testCanaryGen, got[0].gen)
	}
	if got[0].code != "tool_fingerprint_drift" {
		t.Fatalf("unexpected code %q", got[0].code)
	}
}

// TestCanaryBreach_NoActivationReportsGenerationZero is the companion control. With nothing
// activated the pipeline still reports — the funnel, not the pipeline, decides that a zero
// generation stops nothing — so a future change that made the pipeline silently swallow the report
// (rather than the authority discard it) would remove a breach the authority never saw.
func TestCanaryBreach_NoActivationReportsGenerationZero(t *testing.T) {
	rec := &breachRecorder{}
	p, stale, _ := driftFixture(t, rec)
	rb := p.newRecord(Request{}, fixedClock())

	if _, refused := p.refuseOnToolDrift(rb, stale, jsonrpc.ID{}, true, 0); !refused {
		t.Fatal("a drifted decision must still be refused")
	}
	got := rec.reports()
	if len(got) != 1 || got[0].gen != 0 {
		t.Fatalf("expected one report carrying generation 0, got %+v", got)
	}
}

// straddlingExec advances the activation generation DURING Resolve, reproducing a
// demote-and-reactivate that lands between the resolution and the generation read.
type straddlingExec struct{ gen *uint64 }

func (e *straddlingExec) Resolve(ExecInput) rollout.Resolution {
	*e.gen++ // a new activation took over while this request was being resolved
	return rollout.Resolution{Disposition: rollout.EffectExecute}
}

func (e *straddlingExec) Execute(_ context.Context, _ ExecInput, _ rollout.Resolution) ExecOutput {
	return ExecOutput{Status: 200, Disposition: DispObserveOnly, ExecutionState: "not_implemented"}
}
func (e *straddlingExec) KillActive() bool { return false }

// TestCanaryBreach_GenerationStraddlingAnActivationChangeIsAttributedToNone pins Codex round 17.
//
// Round 16 moved the generation read from report time to immediately after the resolution. That
// NARROWED the window — from "resolution → drift refusal", which spans inspection, the durable
// commit and credential planning — to two adjacent statements. It did not CLOSE it: a
// demote-and-reactivate landing in between still returns the NEW generation, which the
// generation-strict funnel then accepts, aborting an experiment that never observed the drift.
//
// A shared lock is not available (the rollout state and the canary generation are different objects
// under different locks), so the guarantee comes from MONOTONICITY: reading either side and
// requiring equality proves the generation held throughout, because it can never recur. A mismatch
// means the request belongs to neither activation with certainty, so it is attributed to none.
func TestCanaryBreach_GenerationStraddlingAnActivationChangeIsAttributedToNone(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	gen := uint64(7)
	deps.CanaryGeneration = func(string) uint64 { return gen }
	deps.Executor = &straddlingExec{gen: &gen}
	p := newGatewayPipeline(t, deps)

	res, got := p.resolveUnderStableGeneration(ExecInput{})
	if res.Disposition != rollout.EffectExecute {
		t.Fatalf("premise: the fixture must resolve to an enforcing disposition, got %v", res.Disposition)
	}
	if gen != 8 {
		t.Fatalf("premise: the fixture must advance the generation during Resolve, got %d", gen)
	}
	if got != 0 {
		t.Fatalf("SECURITY: a request that straddled an activation change was attributed to "+
			"generation %d; it belongs to neither activation, and charging the new one aborts an "+
			"experiment that never saw the drift", got)
	}
}

// TestCanaryBreach_StableGenerationIsCarriedWhenNothingChanges is the control. Without it, a fix
// that simply always returned 0 would satisfy the test above while silently disabling every
// pre-executor breach.
func TestCanaryBreach_StableGenerationIsCarriedWhenNothingChanges(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	deps.CanaryGeneration = func(string) uint64 { return testCanaryGen }
	deps.Executor = &recordingExec{}
	p := newGatewayPipeline(t, deps)

	if _, got := p.resolveUnderStableGeneration(ExecInput{}); got != testCanaryGen {
		t.Fatalf("control: a stable activation must carry its generation through, want %d got %d",
			testCanaryGen, got)
	}
}
