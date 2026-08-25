package execution

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// TestShadow_MakesNoUpstreamCall is the execution-level mutation guard for SH-INV-1:
// in Shadow mode NO upstream call is made for ANY policy action — allow or deny.
//
// Mutation coverage: (a) reverting resolveShadow to EffectExecute, or (b) routing the
// EffectShadowEvaluate dispatch case into runExecute, makes up.calls == 1 and fails
// this test.
func TestShadow_MakesNoUpstreamCall(t *testing.T) {
	for _, action := range []policy.Action{policy.ActionAllow, policy.ActionDeny} {
		up := &fakeUpstream{}
		e := newExec(t, stateForMode(t, rollout.ModeShadow), up, realEvents(t, nil))
		out := e.Execute(context.Background(), execInput(action, false))
		if up.calls != 0 {
			t.Fatalf("action %v: shadow made %d upstream call(s) — it must never cross the side-effect boundary", action, up.calls)
		}
		if out.Executed {
			t.Fatalf("action %v: shadow output marked executed", action)
		}
		if out.ExecutionState != "shadow_evaluated" {
			t.Fatalf("action %v: shadow execution_state = %q, want shadow_evaluated", action, out.ExecutionState)
		}
	}
}

// TestShadow_ControlCanaryDoesCallUpstream proves the guard above is discriminating:
// the SAME harness reaches upstream when the mode is meant to execute (Canary ALLOW).
func TestShadow_ControlCanaryDoesCallUpstream(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.Execute(context.Background(), execInput(policy.ActionAllow, false))
	if up.calls != 1 {
		t.Fatalf("control: canary ALLOW must call upstream once, got %d", up.calls)
	}
}

// TestShadow_CredentialPathNeverReachesUpstream proves that even a request carrying a
// credential profile — the path that in a live mode would materialize a real secret
// and send it upstream — makes no upstream call in Shadow. Combined with the source
// guard below (no Materialize reachable from shadowEvaluate), this shows Shadow derives
// credential readiness from Plan alone and never materializes.
func TestShadow_CredentialPathNeverReachesUpstream(t *testing.T) {
	b, id := credDriftSetup(t) // real materializing broker + resolved identity
	up := &fakeUpstream{}
	e := credDriftExecutorForState(t, b, up, credDriftStateMode(t, rollout.ModeShadow))
	in := credDriftInput(id, func() bool { return true })
	out := e.Execute(context.Background(), in)
	if up.calls != 0 {
		t.Fatalf("shadow credential path made %d upstream call(s) — no secret may be sent upstream in Shadow", up.calls)
	}
	if up.lastAuth != "" {
		t.Fatalf("a materialized credential reached the upstream slot in Shadow: %q", up.lastAuth)
	}
	if out.Executed || out.ExecutionState != "shadow_evaluated" {
		t.Fatalf("shadow credential path output not a non-executed evaluation: executed=%v state=%q", out.Executed, out.ExecutionState)
	}
}

// TestShadow_SourceHasNoExecuteCapability is a build-test structural guard (mirroring
// the mcp_execution_posture_test.go AST discipline): the Shadow evaluator SOURCE must
// contain no reference to the side-effect capability — no selector named `Call`,
// `Materialize`, or `Upstream` — anywhere in shadow.go. Comments are excluded (the AST
// carries no comment text), so the explanatory prose that names those symbols does not
// trip the guard; only real code does. Adding `e.cfg.Upstream.Call(...)` or a
// `Materialize` call to the Shadow path fails here regardless of runtime coverage.
func TestShadow_SourceHasNoExecuteCapability(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "shadow.go", nil, 0) // no ParseComments: comment text is not in the AST
	if err != nil {
		t.Fatalf("parse shadow.go: %v", err)
	}
	forbidden := map[string]bool{"Call": true, "Materialize": true, "Upstream": true}
	var offenders []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if forbidden[x.Sel.Name] {
				offenders = append(offenders, x.Sel.Name)
			}
		case *ast.Ident:
			if forbidden[x.Name] {
				offenders = append(offenders, x.Name)
			}
		}
		return true
	})
	if len(offenders) != 0 {
		t.Fatalf("shadow.go references side-effect capability in code (not comments): %v — a Shadow evaluation must possess no path to Upstream.Call or Materialize", offenders)
	}
}
