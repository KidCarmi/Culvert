package shadowmetrics

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Conformance is pinned here, not in production code: the execution-posture wall
// forbids this package from importing internal/mcp/execution.
var _ execution.Metrics = (*Sink)(nil)

// seededSink gives every outcome a distinct count (1..9, the 9th an unknown
// outcome routed to "other") and 11 fail-closed blocks, so any label permutation
// changes at least one emitted row.
func seededSink() *Sink {
	s := &Sink{}
	outcomes := []string{
		"would_execute", "would_block", "would_require_approval",
		"would_require_confirmation", "would_fail_credential_readiness",
		"would_fail_inspection", "would_fail_stale_decision",
		"would_fail_hard_control", "zzz",
	}
	for i, o := range outcomes {
		for j := 0; j <= i; j++ {
			s.ObserveShadowOutcome("gateway", o)
		}
	}
	for i := 0; i < 11; i++ {
		s.ObserveBlock("gateway", mcperr.ReasonUpstreamCallFailed)
	}
	return s
}

// Captured from writeMCPShadowMetrics at main 348a2cf with the seededSink inputs.
const wantPrometheus = `# HELP culvert_mcp_shadow_evaluations_total MCP non-executing Shadow evaluations by Model-1 outcome.
# TYPE culvert_mcp_shadow_evaluations_total counter
culvert_mcp_shadow_evaluations_total{capability="gateway",outcome="would_execute"} 1
culvert_mcp_shadow_evaluations_total{capability="gateway",outcome="would_block"} 2
culvert_mcp_shadow_evaluations_total{capability="gateway",outcome="would_require_approval"} 3
culvert_mcp_shadow_evaluations_total{capability="gateway",outcome="would_require_confirmation"} 4
culvert_mcp_shadow_evaluations_total{capability="gateway",outcome="would_fail_credential_readiness"} 5
culvert_mcp_shadow_evaluations_total{capability="gateway",outcome="would_fail_inspection"} 6
culvert_mcp_shadow_evaluations_total{capability="gateway",outcome="would_fail_stale_decision"} 7
culvert_mcp_shadow_evaluations_total{capability="gateway",outcome="would_fail_hard_control"} 8
culvert_mcp_shadow_evaluations_total{capability="gateway",outcome="other"} 9
# HELP culvert_mcp_shadow_evaluation_errors_total MCP Shadow evaluations that failed closed (durability/kill/invalid mode).
# TYPE culvert_mcp_shadow_evaluation_errors_total counter
culvert_mcp_shadow_evaluation_errors_total{capability="gateway"} 11
`

// Captured from json.Marshal(snapshot()) at main 348a2cf with the seededSink inputs.
const wantViewJSON = `{"evaluations":45,"would_execute":1,"would_block":2,"would_require_approval":3,"would_require_confirmation":4,"would_fail_credential_readiness":5,"would_fail_inspection":6,"would_fail_stale_decision":7,"would_fail_hard_control":8,"would_other":9,"evaluation_errors":11}`

func TestShadowMetrics_PrometheusBytesUnchanged(t *testing.T) {
	var b strings.Builder
	seededSink().WritePrometheus(&b)
	if b.String() != wantPrometheus {
		t.Fatalf("culvert_mcp_shadow_* bytes changed:\n got: %q\nwant: %q", b.String(), wantPrometheus)
	}
}

func TestShadowMetrics_StatusJSONUnchanged(t *testing.T) {
	js, err := json.Marshal(seededSink().Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if string(js) != wantViewJSON {
		t.Fatalf("status metrics JSON changed:\n got: %s\nwant: %s", js, wantViewJSON)
	}
}

// A zero Sink is armed-but-idle: it still emits every row (at 0). The "emit
// nothing" decision for a never-armed node belongs to main's nil gate.
func TestShadowMetrics_ZeroSinkEmitsAllRows(t *testing.T) {
	var b strings.Builder
	(&Sink{}).WritePrometheus(&b)
	if got := strings.Count(b.String(), "culvert_mcp_shadow_evaluations_total{"); got != 9 {
		t.Fatalf("outcome rows = %d, want 9", got)
	}
	if !strings.Contains(b.String(), `culvert_mcp_shadow_evaluation_errors_total{capability="gateway"} 0`+"\n") {
		t.Fatalf("missing zero evaluation_errors row: %q", b.String())
	}
	if (&Sink{}).Snapshot() != (View{}) {
		t.Fatal("zero sink snapshot must be the zero View")
	}
}

// A fail-closed block is an evaluation error, not a would_block verdict, and is
// not counted as an evaluation.
func TestShadowMetrics_BlockIsNotAnOutcome(t *testing.T) {
	s := &Sink{}
	s.ObserveBlock("gateway", mcperr.ReasonUpstreamCallFailed)
	if got := s.Snapshot(); got != (View{EvaluationErrors: 1}) {
		t.Fatalf("block accounting = %+v", got)
	}
}

// Resolution and every live-execution observation are no-ops: Shadow counts the
// evaluation once via ObserveShadowOutcome and can never execute.
func TestShadowMetrics_LiveObservationsAreNoOps(t *testing.T) {
	s := &Sink{}
	s.ObserveResolution("gateway", rollout.Resolution{})
	s.ObserveExecution("gateway", true)
	s.ObserveExecution("gateway", false)
	s.ObserveUpstream("gateway", "ok")
	s.ObserveDLPBlock("gateway", true)
	s.ObserveOutcomeEvidenceLoss("gateway")
	if got := s.Snapshot(); got != (View{}) {
		t.Fatalf("a live/resolution observation moved a shadow counter: %+v", got)
	}
}

func TestShadowMetrics_InstancesAreIndependent(t *testing.T) {
	a, b := &Sink{}, &Sink{}
	a.ObserveShadowOutcome("gateway", "would_block")
	if b.Snapshot() != (View{}) {
		t.Fatalf("second instance observed the first's write: %+v", b.Snapshot())
	}
	if a.Snapshot() != (View{Evaluations: 1, WouldBlock: 1}) {
		t.Fatalf("first instance = %+v", a.Snapshot())
	}
}

func TestShadowMetrics_ConcurrentObservationsAreCounted(t *testing.T) {
	s := &Sink{}
	const workers, per = 8, 250
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				s.ObserveShadowOutcome("gateway", "would_execute")
				s.ObserveBlock("gateway", mcperr.ReasonUpstreamCallFailed)
				_ = s.Snapshot()
			}
		}()
	}
	wg.Wait()
	want := View{Evaluations: workers * per, WouldExecute: workers * per, EvaluationErrors: workers * per}
	if got := s.Snapshot(); got != want {
		t.Fatalf("concurrent accounting = %+v, want %+v", got, want)
	}
}
