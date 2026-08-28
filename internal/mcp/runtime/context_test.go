package runtime

import (
	"context"
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// countingKeys wraps a key resolver and records whether it was ever consulted.
// JWT validation is the first genuinely expensive stage of the pipeline, so "the
// resolver was never asked" is direct evidence the deadline stopped the request
// before the work it was supposed to bound.
type countingKeys struct {
	inner  authn.KeyResolver
	called int
}

func (c *countingKeys) ResolveKey(issuer, kid, alg string) (crypto.PublicKey, error) {
	c.called++
	return c.inner.ResolveKey(issuer, kid, alg)
}

// SEC-MCP-02. RequestDeadline must bound the WHOLE request, not just admission.
// Before the fix the listener built a deadline context, used it only to acquire a
// worker slot, and then ran authentication, policy evaluation, inspection and
// durable event commits with no deadline at all — so an expired budget bounded
// nothing that actually costs anything.
func TestContext_ExpiredDeadlineStopsTheRequestBeforeAuthentication(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	ck := &countingKeys{inner: deps.Keys}
	deps.Keys = ck
	p := newGatewayPipeline(t, deps)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the request budget is already gone

	out := p.Process(ctx, gwRequest(gwToken(k), initializeBody(1)), fixedClock())
	if out.Disposition != DispRejected {
		t.Fatalf("expired deadline must reject, got disposition %v (status %d)", out.Disposition, out.Status)
	}
	if out.Reason != mcperr.ReasonRequestDeadlineExceeded {
		t.Fatalf("reason = %v, want request_deadline_exceeded", out.Reason)
	}
	if ck.called != 0 {
		t.Fatalf("token validation ran %d time(s) after the deadline expired; the deadline bounded nothing", ck.called)
	}
	if p.sessions.SessionCount() != 0 {
		t.Fatalf("an out-of-budget request must not leave a session behind (%d live)", p.sessions.SessionCount())
	}
}

// A live budget must be completely transparent: the deadline check may only ever
// SUBTRACT work, never change the outcome of a request that is inside its budget.
func TestContext_LiveBudgetIsTransparent(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	out := p.Process(ctx, gwRequest(gwToken(k), initializeBody(1)), fixedClock())
	if out.Disposition != DispKernelTerminal || out.Status != 200 {
		t.Fatalf("in-budget initialize must succeed, got %v / %d (%v)", out.Disposition, out.Status, out.Reason)
	}
	if !out.NewSession || out.SessionID == "" {
		t.Fatal("in-budget initialize must still open a session")
	}
}

// recordingExecutor captures the context the runtime hands the guarded executor.
type recordingExecutor struct{ got context.Context }

func (e *recordingExecutor) Execute(ctx context.Context, _ ExecInput, _ rollout.Resolution) ExecOutput {
	e.got = ctx
	return ExecOutput{Status: 200, Disposition: DispObserveOnly, ExecutionState: "not_implemented"}
}

// Resolve returns a non-record-only disposition so the runtime always reaches Execute
// (this fixture exists to observe the context the runtime hands the executor).
func (e *recordingExecutor) Resolve(ExecInput) rollout.Resolution {
	return rollout.Resolution{Disposition: rollout.EffectShadowEvaluate}
}

// KillActive: these fixtures never engage the kill switch.
func (e *recordingExecutor) KillActive() bool { return false }

// SEC-MCP-03. The guarded executor performs the real upstream side effect. It must
// inherit the request's cancellation and deadline: `context.Background()` there
// means a disconnected client, an exceeded budget or a shutdown cannot stop an
// in-flight upstream call, and every downstream stage that honours a context
// (upstream dial, TLS, response read, response inspection) silently loses its
// bound. This is checked NOW, while execution is still dormant, because it is a
// precondition of ever arming it.
func TestContext_ExecutorInheritsRequestCancellation(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	ex := &recordingExecutor{}
	deps.Executor = ex
	deps.Policy = fakePolicy{gw: gwPolicySnap(t, `{"id":"ALLOW_ALL","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}
	p := newGatewayPipeline(t, deps)

	// Open a session first (initialize is kernel-terminal and never reaches the
	// executor), then drive a decision-point method through the same session.
	tok, sid := driveToDecisionPoint(t, p, k)
	call := withSession(gwRequest(tok, toolsListBody(2)), sid)

	ctx, cancel := context.WithCancel(context.Background())
	p.Process(ctx, call, fixedClock())
	if ex.got == nil {
		t.Fatal("executor was not reached; the fixture no longer exercises the execute path")
	}
	if ex.got == context.Background() {
		t.Fatal("executor received context.Background(): request cancellation is discarded")
	}
	cancel()
	select {
	case <-ex.got.Done():
	default:
		t.Fatal("cancelling the request did not cancel the executor's context")
	}
}

// Anti-weakening. `context.Background()` inside the REQUEST path is exactly the
// defect above; it is legitimate only where no request exists (socket bind). This
// pins the boundary structurally, so a future stage cannot quietly re-introduce a
// detached context in a file the behavioural tests do not happen to cover.
func TestContext_NoDetachedContextInTheRequestPath(t *testing.T) {
	// listener.go:bind() opens the socket before any request exists.
	allowed := map[string]int{"listener.go": 1}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if got := strings.Count(string(src), "context.Background()"); got > allowed[name] {
			t.Fatalf("%s uses context.Background() %d time(s), allowance %d — "+
				"a request-path stage must inherit the request context", name, got, allowed[name])
		}
	}
}
