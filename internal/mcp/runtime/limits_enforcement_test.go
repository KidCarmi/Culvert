package runtime

import (
	"context"
	"crypto"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// blockingKeys is a key resolver that parks inside ResolveKey until released, so a
// test can observe how many authentications the pipeline lets run at once.
type blockingKeys struct {
	inner   authn.KeyResolver
	entered chan struct{}
	release chan struct{}
	peak    atomic.Int64
	cur     atomic.Int64
}

func (b *blockingKeys) ResolveKey(issuer, kid, alg string) (crypto.PublicKey, error) {
	n := b.cur.Add(1)
	for {
		p := b.peak.Load()
		if n <= p || b.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	b.cur.Add(-1)
	return b.inner.ResolveKey(issuer, kid, alg)
}

// limitsWithAuthConcurrency returns the default bounds with AuthConcurrency (and
// the DPoP bound) narrowed to n.
func limitsWithAuthConcurrency(t testing.TB, n int) Limits {
	t.Helper()
	c := LimitConfig{
		MaxConns: 1024, MaxConcurrent: 64, QueueDepth: 256, MaxSessions: 4096,
		MaxOutstanding: 8192, MaxHeaderBytes: 64 << 10, MaxBodyBytes: 1 << 20,
		MaxResponseBytes: 1 << 20, AuthConcurrency: n, DPoPConcurrency: n,
		MaxObservations: 4096, AdmissionBudget: 256, CleanupPerOp: 256,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		HandshakeTimeout: 5 * time.Second, RequestDeadline: 30 * time.Second,
		SessionTTL: 5 * time.Minute, ShutdownTimeout: 20 * time.Second,
	}
	l, err := NewLimits(c)
	if err != nil {
		t.Fatalf("NewLimits: %v", err)
	}
	return l
}

// countingEvents records denial-lane routing without committing anything.
type countingEvents struct{ denials atomic.Int64 }

func (c *countingEvents) CommitDecision(events.DecisionFacts) (spool.CommitReceipt, error) {
	return spool.CommitReceipt{}, nil
}
func (c *countingEvents) ObserveDenial(events.DenialInput)             { c.denials.Add(1) }
func (c *countingEvents) WriteAllowedCritical(evmodel.Capability) bool { return true }

// SEC-MCP-05. AuthConcurrency is a validated, ceiling-checked, operator-facing
// bound on the most CPU-expensive attacker-reachable stage (signature verification
// / token introspection). It had NO enforcement call site at all: the value was
// validated at construction and then never read, so an operator who set it to
// throttle authentication got nothing. A configuration knob with no enforcement
// point is a false control.
func TestLimits_AuthConcurrencyIsEnforced(t *testing.T) {
	const capacity = 2
	const callers = 8

	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	bk := &blockingKeys{inner: deps.Keys, entered: make(chan struct{}, callers), release: make(chan struct{})}
	deps.Keys = bk

	cfg := gwListenerConfig(t)
	cfg.Limits = limitsWithAuthConcurrency(t, capacity)
	ctr := &counters{}
	p, err := newPipeline(cfg, deps, "lim-gw", ctr, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}

	var wg sync.WaitGroup
	tok := gwToken(k)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p.Process(context.Background(), gwRequest(tok, initializeBody(i+1)), fixedClock())
		}(i)
	}
	// Let the racers pile up against the semaphore, then release everything.
	deadline := time.After(2 * time.Second)
	for i := 0; i < capacity; i++ {
		select {
		case <-bk.entered:
		case <-deadline:
			t.Fatal("no authentication reached the key resolver")
		}
	}
	time.Sleep(50 * time.Millisecond) // give any unbounded extras time to pile in
	peak := bk.peak.Load()
	close(bk.release)
	wg.Wait()

	if peak > capacity {
		t.Fatalf("peak concurrent authentications = %d, AuthConcurrency cap = %d", peak, capacity)
	}
	if peak == 0 {
		t.Fatal("no authentication observed; the fixture does not exercise the bound")
	}
}

// SEC-MCP-06. The credential must be checked for PRESENCE and SHAPE before the
// pipeline spends anything on an unauthenticated caller. Before the fix, a
// credential-less request still drove a registry lookup, a full body buffer (up to
// MaxBodyBytes), a strict JSON-RPC decode and a session open+close — and the
// registry lookup made the response an unauthenticated ORACLE: 404 for an unknown
// server id vs 401 for a registered one.
func TestSecurity_CredentiallessRequestIsRejectedBeforeServerResolution(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))

	known := gwRequest("", initializeBody(1))
	known.AuthorizationHeaders = nil
	unknown := known
	unknown.ServerID = "srv-does-not-exist"
	unknown.Path = "/mcp/gateway/srv-does-not-exist"

	outKnown := p.Process(context.Background(), known, fixedClock())
	outUnknown := p.Process(context.Background(), unknown, fixedClock())

	if outKnown.Status != outUnknown.Status || outKnown.Reason != outUnknown.Reason {
		t.Fatalf("unauthenticated server-existence oracle: known=%d/%v unknown=%d/%v",
			outKnown.Status, outKnown.Reason, outUnknown.Status, outUnknown.Reason)
	}
	if outKnown.Reason != mcperr.ReasonCredentialMissing {
		t.Fatalf("reason = %v, want credential_missing", outKnown.Reason)
	}
	if p.sessions.SessionCount() != 0 {
		t.Fatalf("a credential-less request opened %d session(s)", p.sessions.SessionCount())
	}
}

// The pre-check must not swallow the denial-lane routing or the auth-failure
// counter that the later stage used to own — moving a rejection earlier must not
// make it invisible.
func TestSecurity_EarlyCredentialRejectionStillObserved(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	ev := &countingEvents{}
	deps.Events = ev
	ctr := &counters{}
	p, err := newPipeline(gwListenerConfig(t), deps, "obs-gw", ctr, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	req := gwRequest("", initializeBody(1))
	req.AuthorizationHeaders = nil
	p.Process(context.Background(), req, fixedClock())

	if ctr.authFailures.Load() != 1 {
		t.Fatalf("authFailures = %d, want 1", ctr.authFailures.Load())
	}
	if ev.denials.Load() != 1 {
		t.Fatalf("denial-lane observations = %d, want 1", ev.denials.Load())
	}
}

// A credential-carrying request must be entirely unaffected by the pre-check: it
// may only ever reject earlier, never change an admitted request's outcome.
func TestSecurity_PrecheckIsTransparentToValidCredentials(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	out := p.Process(context.Background(), gwRequest(gwToken(k), initializeBody(1)), fixedClock())
	if out.Status != 200 || out.Disposition != DispKernelTerminal {
		t.Fatalf("valid request must still succeed: %d / %v / %v", out.Status, out.Disposition, out.Reason)
	}
}
