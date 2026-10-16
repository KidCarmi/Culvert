package execution

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// presend_refusal_carrier_test.go — a pre-send refusal raised on ANOTHER GOROUTINE must still be
// classified, and must be carried by the error rather than by a captured variable.
//
// WHY THE GOROUTINE MATTERS. CallOptions.PreSend is re-asked at two sites inside the upstream
// client, and one of them is the TLS dialer (pinnedDialTLS), which net/http may run on a goroutine
// of its own — the client's own preSendRefusalErr exists for exactly that reason, and says so.
// The executor side originally read the refusal back out of two variables the closure had written,
// which reintroduces the shape the client had just avoided one layer up:
//
//   - a data race, since the dialer's write and this function's read after Call returns have no
//     happens-before edge of their own; and
//   - a mis-attribution, because a dial ABANDONED when the request context ends can still finish
//     its handshake, run the predicate, and write a refusal for a request that failed for an
//     entirely unrelated reason.
//
// Carrying both facts in the returned error fixes both at once: net/http hands the dial's error
// back through a channel, so it is ordered before Call returns, and an abandoned dial's error is
// discarded rather than read.
//
// WHAT THESE GATES DO AND DO NOT PROVE, stated plainly. They assert the OBSERVABLE contract: a
// refusal raised on another goroutine is still diagnosed as the gate's own bounded reason, and a
// refusal from an ABANDONED dial is not attributed to the request at all. The second of those is
// the DEFECT GATE — it fails against the captured-variable shape deterministically, with no timing
// dependence.
//
// They do NOT detect the data race, and the fixture is why: it JOINS the goroutine it starts, which
// creates the happens-before edge the real abandoned-dial case lacks, so the captured shape passes
// them under -race too. Reproducing the race would mean scheduling an interleaving a test cannot
// schedule, and this repo's standing rule is that a gate which can flake gets muted — so the
// deterministic half is what is gated, and the carrier removes the race by having nothing to share.

// presendUpstream is a fake upstream that runs the caller's PreSend hook the way the real TLS
// dialer can: on a separate goroutine, joined before Call returns. It returns the hook's error
// verbatim, so the executor sees exactly what the real client's roundTrip hands back for a
// dialer-site refusal.
type presendUpstream struct {
	mu      sync.Mutex
	calls   int
	asked   atomic.Int32
	refused atomic.Int32
	// beforeAsk runs immediately before the predicate is re-asked. It stands in for whatever
	// lands while the request waits for a pool slot or a handshake — a demotion, a scope
	// replacement, an approval revocation — so the withdrawal is observed by the pre-send
	// re-ask and by nothing earlier.
	beforeAsk func()
	// abandonWith models an ABANDONED dial: the predicate is asked and refuses, but its verdict
	// never reaches the caller because the leg failed for an unrelated reason first (the request
	// context ended while the handshake was finishing, so net/http discards the dial's result).
	// Call returns this error instead of the refusal.
	abandonWith error
}

func (u *presendUpstream) Call(_ context.Context, _ upstreamclient.Target, _ string, _ json.RawMessage, opts upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	if opts.PreSend != nil {
		if u.beforeAsk != nil {
			u.beforeAsk()
		}
		// One goroutine, joined before returning — the narrowest faithful model of net/http's
		// dial goroutine. A captured-variable implementation races HERE, which is the point.
		var perr error
		done := make(chan struct{})
		go func() {
			defer close(done)
			u.asked.Add(1)
			perr = opts.PreSend()
		}()
		<-done
		if perr != nil {
			u.refused.Add(1)
			if u.abandonWith != nil {
				return nil, u.abandonWith // the refusal is discarded with the abandoned dial
			}
			return nil, perr
		}
	}
	if u.abandonWith != nil {
		return nil, u.abandonWith
	}
	u.mu.Lock()
	u.calls++
	u.mu.Unlock()
	res := `{"ok":true}`
	return &upstreamclient.Response{ID: jsonrpc.ID{Kind: jsonrpc.IDString, Str: "u"}, Result: json.RawMessage(res), RawBytes: []byte(res)}, nil
}

func (u *presendUpstream) sends() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

// lateWithdrawGate admits the side effect and answers every boundary re-check from a flag, so a
// test controls exactly WHEN the authority goes away. Permitting until the flag is set means the
// pre-call guard passes and only the pre-send re-ask sees the withdrawal — the production sequence
// this mechanism exists for, rather than a refusal the earlier guard would have caught anyway.
type lateWithdrawGate struct {
	reason    mcperr.Reason
	withdrawn atomic.Bool
	asks      atomic.Int32
	released  atomic.Int32
}

func (g *lateWithdrawGate) withdraw() { g.withdrawn.Store(true) }

func (g *lateWithdrawGate) AdmitSideEffect(LiveGateInput) LiveGateDecision {
	return LiveGateDecision{
		Admit: true,
		Revalidate: func() mcperr.Reason {
			g.asks.Add(1)
			if g.withdrawn.Load() {
				return g.reason
			}
			return mcperr.ReasonNone
		},
		Release: func() { g.released.Add(1) },
		// A side-effect admission carries the reservation identity the attempt record is
		// bound to; without it the request fails at the durable-attempt stage and never
		// reaches the boundary these gates are about.
		ReservationID: "rsv_presend", ActivationGeneration: 4,
	}
}

func (g *lateWithdrawGate) AdmitAuxiliary(in LiveGateInput) LiveGateDecision {
	return g.AdmitSideEffect(in)
}

// THE GATE. A withdrawal detected by the pre-send re-ask on another goroutine is still reported as
// the gate's own bounded reason, and no request bytes are sent.
//
// The reason is the assertion that matters: the refusal reaching the outcome as a transport or
// durability fault — or as ReasonNone — is what a lost classification looks like, and it is what an
// operator would read during an incident.
func TestPreSendRefusal_FromAnotherGoroutineIsStillClassified(t *testing.T) {
	gate := &lateWithdrawGate{reason: mcperr.ReasonRolloutOutOfScope}
	up := &presendUpstream{beforeAsk: gate.withdraw}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.LiveGate = gate

	out := e.Execute(context.Background(), execInput(policy.ActionAllow, false),
		rollout.Resolution{Disposition: rollout.EffectExecute})

	if up.asked.Load() == 0 {
		t.Fatal("the pre-send predicate was never asked; this gate would then prove nothing")
	}
	if up.refused.Load() == 0 {
		t.Fatal("the pre-send predicate never refused; the fixture did not reproduce a late withdrawal")
	}
	if up.sends() != 0 {
		t.Fatalf("SECURITY: %d request(s) were sent after the authority was withdrawn mid-flight", up.sends())
	}
	if out.Executed {
		t.Fatal("SECURITY: a pre-send refusal reported Executed")
	}
	if out.Reason != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("a pre-send refusal must surface the gate's own bounded reason %v, got %v — a refusal "+
			"diagnosed as a transport/durability fault is a lost classification",
			mcperr.ReasonRolloutOutOfScope, out.Reason)
	}
	if out.Reason == mcperr.ReasonNone {
		t.Fatal("a pre-send refusal must never surface as ReasonNone")
	}
	if gate.released.Load() == 0 {
		t.Fatal("the admitted budget slot was not released; a quiesce drain would hang forever")
	}
}

// THE DEFECT GATE for the other half of the same defect: a refusal raised by a dial that was
// ABANDONED must NOT be attributed to the request.
//
// net/http can return from Do — the request context ended, say — while a dial it started is still
// finishing its handshake. That dial then runs the predicate and its verdict is discarded along with
// the connection, because the leg already failed for an unrelated reason. A captured variable cannot
// tell the two apart: it holds "a refusal happened somewhere", so the request is diagnosed as a
// withdrawn-authority refusal when what actually failed was the transport. An error can only ever
// describe the leg that returned it.
//
// This is the deterministic half of the carrier's value and it fails against the captured shape with
// no timing dependence at all; the data race is the other half, and the same carrier removes it by
// having nothing to share.
func TestPreSendRefusal_AnAbandonedDialsRefusalIsNotAttributedToTheRequest(t *testing.T) {
	transportFailure := mcperr.New(mcperr.ReasonUpstreamCallFailed, "test", "transport failed first")
	gate := &lateWithdrawGate{reason: mcperr.ReasonRolloutOutOfScope}
	up := &presendUpstream{beforeAsk: gate.withdraw, abandonWith: transportFailure}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.LiveGate = gate

	out := e.Execute(context.Background(), execInput(policy.ActionAllow, false),
		rollout.Resolution{Disposition: rollout.EffectExecute})

	if up.refused.Load() == 0 {
		t.Fatal("the abandoned dial's predicate never refused; the fixture did not reproduce the case")
	}
	if out.Executed {
		t.Fatal("a failed leg must not report Executed")
	}
	if out.Reason == mcperr.ReasonRolloutOutOfScope {
		t.Fatal("SECURITY/CORRECTNESS: the refusal of an ABANDONED dial was attributed to a request " +
			"that failed for an unrelated transport reason — the verdict must travel in the error of " +
			"the leg that returned it, never in a variable shared with a goroutine whose result was " +
			"discarded")
	}
}

// THE CONTROL. A predicate that permits — asked from the same other goroutine — must leave the call
// untouched: the carrier must not turn a permitted pre-send into a refusal, and the ordinary
// executing path stays exactly as it was.
func TestPreSendRefusal_PermittingPredicateStillSends(t *testing.T) {
	up := &presendUpstream{}
	gate := &countingGate{admit: true}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	e.cfg.LiveGate = gate

	out := e.Execute(context.Background(), execInput(policy.ActionAllow, false),
		rollout.Resolution{Disposition: rollout.EffectExecute})

	if up.asked.Load() == 0 {
		t.Fatal("the pre-send predicate was never asked")
	}
	if up.refused.Load() != 0 {
		t.Fatal("a permitting predicate must not be read as a refusal")
	}
	if up.sends() != 1 {
		t.Fatalf("a permitted request must reach the upstream exactly once, got %d", up.sends())
	}
	if !out.Executed {
		t.Fatalf("a permitted request must report Executed (reason=%v)", out.Reason)
	}
}
