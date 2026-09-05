package runtime

// canary_drift_breach_test.go — a tool rug-pull refused BEFORE the executor is an authoritative
// whole-Canary breach, not merely a stale decision (First Controlled Canary review, blocker #7;
// Codex round 14).

import (
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// breachRecorder captures what the pipeline reported through the optional Canary seam.
type breachRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *breachRecorder) report(_, code string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, code)
}

func (r *breachRecorder) codes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
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
	if _, refused := p.refuseOnToolDrift(rb, stale, jsonrpc.ID{}); !refused {
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
	if _, refused := p.refuseOnToolDrift(rb, fresh, jsonrpc.ID{}); refused {
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
	if _, refused := p.refuseOnToolDrift(rb, stale, jsonrpc.ID{}); !refused {
		t.Fatal("a stale fingerprint must still be refused with no seam composed")
	}
}
