package execution

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// THE PRE-SEND RE-ASK CROSSES A GOROUTINE BOUNDARY THE EXECUTOR DOES NOT OWN, SO ITS VERDICT
// COMES BACK ON THE ERROR AND NOWHERE ELSE.
//
// runExecute hands its boundary predicate to the upstream client as CallOptions.PreSend, and one
// of the client's two re-ask sites sits inside the TLS dialer — which net/http runs on its OWN
// goroutine (Transport.queueForDial -> go dialConnFor). That goroutine is not joined to the
// request: when the request goroutine stops waiting for the dial (an ordinary context
// cancellation — a client disconnect, a request timeout), Call unwinds while the dial goroutine
// completes its handshake and calls the hook. The property is pinned against the REAL transport
// by TestPreSend_MayStillBeRunningAfterCallReturns (internal/mcp/upstreamclient).
//
// Two shapes were rejected before the one these gates pin:
//
//	captured locals  — a data race, reproduced under -race with the write attributed to
//	                   pinnedDialTLS on net/http's dial goroutine;
//	a mutex-guarded record — race-free but NOT A HAND-OFF: a late hook can still record after
//	                   the only reader has gone, leaving the classification and the
//	                   Safety.Breach signal scheduling-dependent (Codex P2, PR #1411).
//
// So the hook is a PURE PREDICATE and the refusal is read back from Call's own error. That is a
// real hand-off in the memory-model sense — an error that reached this goroutine happened-before
// this goroutine reads it — and it classifies the refusal exactly when it GOVERNED the leg.

// refusingUpstream models the client's actual contract for a refusal that governs the leg: it
// invokes PreSend on the calling goroutine and, when the hook refuses, returns that error
// verbatim (roundTrip returns it directly; the dialer site rides out through preSendRefusalErr).
type refusingUpstream struct {
	calls   int
	beforeP func()
}

func (f *refusingUpstream) Call(_ context.Context, _ upstreamclient.Target, _ string, _ json.RawMessage, opts upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	f.calls++
	if f.beforeP != nil {
		f.beforeP()
	}
	if opts.PreSend != nil {
		if err := opts.PreSend(); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("upstream not reached in this test")
}

// A DRIFT SEEN ONLY AT THE PRE-SEND RE-ASK MUST STILL REACH Safety.Breach — DETERMINISTICALLY.
//
// This is the exact signal Codex's P2 said a mutex-guarded record left scheduling-dependent. The
// tool is current at the pre-call guard and drifts, with the kill engaged in the same pass, only
// once the call is under way. The kill wins the REASON the client is told (round 15's rule), and
// the drift must still latch the experiment — carried on the error, since the record is gone.
func TestPreSendRefusal_DriftAtTheReSendSiteStillReachesSafetyBreach(t *testing.T) {
	var releases int32
	sfy := &breachOrderSafety{releases: &releases}
	st := stateForMode(t, rollout.ModeCanary)

	var asks int
	up := &refusingUpstream{}
	e := newExec(t, st, up, realEvents(t, nil))
	e.cfg.Safety = sfy
	e.cfg.LiveGate = releaseOrderGate{reservationID: "rsv_presend", generation: 7, releases: &releases}

	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = func() bool {
		asks++
		if asks == 1 {
			return true // the pre-call guard: nothing wrong yet, so the call proceeds
		}
		st.EngageKillSwitch("test", 1) // the pre-send re-ask: both facts in one pass
		return false
	}

	out := e.Execute(context.Background(), in, e.Resolve(in))

	if asks < 2 {
		t.Fatalf("premise: the pre-send re-ask never ran (%d ask(s)), so this proves nothing", asks)
	}
	if out.Executed {
		t.Fatal("SECURITY: a boundary refusal at the pre-send re-ask must not report Executed=true")
	}
	if out.Reason != mcperr.ReasonRolloutEmergencyActive {
		t.Fatalf("the CLIENT must be told the emergency kill is the reason, got %v", out.Reason)
	}
	codes, _ := sfy.seen()
	if len(codes) != 1 || codes[0] != "tool_fingerprint_drift" {
		t.Fatalf("SECURITY: a drift observed at the pre-send re-ask must latch the experiment — "+
			"carried on the error, since the hook may run on a goroutine that cannot hand anything "+
			"back; breaches=%v", codes)
	}
}

// abandonedPreSendUpstream models net/http's abandoned dialer exactly: it invokes PreSend on a
// goroutine that is NOT joined to Call, and Call fails for its own reason. It returns as soon as
// that goroutine EXISTS, never once it has finished — waiting would create the happens-before
// edge the production path does not have, and the gate would prove nothing.
type abandonedPreSendUpstream struct {
	calls int
	done  chan struct{}
}

func (f *abandonedPreSendUpstream) Call(_ context.Context, _ upstreamclient.Target, _ string, _ json.RawMessage, opts upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	f.calls++
	started := make(chan struct{})
	go func() {
		close(started)
		if opts.PreSend != nil {
			_ = opts.PreSend()
		}
		close(f.done)
	}()
	<-started
	return nil, errors.New("upstream call abandoned")
}

// A HOOK ON AN ABANDONED CONNECTION CLASSIFIES NOTHING, AND RACES NOTHING.
//
// Run under -race this is the regression gate for the original defect: with captured locals the
// detector reported two races here, one per variable. It is also the gate for the SECOND shape —
// nothing the late hook produces is consumed, so the outcome cannot depend on whether it finished
// before or after Call returned. Losing that observation costs the experiment nothing: the
// pre-call guard runs on the request goroutine before EVERY call, so a kill, a drift or a
// withdrawal that persists is caught there on the very next request.
func TestPreSendRefusal_AbandonedHookClassifiesNothingAndDoesNotRace(t *testing.T) {
	var releases int32
	sfy := &breachOrderSafety{releases: &releases}
	st := stateForMode(t, rollout.ModeCanary)

	var asks atomic.Int64
	up := &abandonedPreSendUpstream{done: make(chan struct{})}
	e := newExec(t, st, up, realEvents(t, nil))
	e.cfg.Safety = sfy
	e.cfg.LiveGate = releaseOrderGate{reservationID: "rsv_orphan", generation: 7, releases: &releases}

	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = func() bool { return asks.Add(1) == 1 }

	out := e.Execute(context.Background(), in, e.Resolve(in))
	<-up.done // let the abandoned hook finish before the test ends, so nothing leaks

	if up.calls != 1 {
		t.Fatalf("premise: the boundary must have been reached exactly once, got %d", up.calls)
	}
	if out.Executed {
		t.Fatal("SECURITY: an abandoned upstream leg must not report Executed=true")
	}
	if codes, _ := sfy.seen(); len(codes) != 0 {
		t.Fatalf("a hook whose connection was abandoned stopped nothing and must latch nothing, got %v", codes)
	}
}

// The error is now the ONLY carrier, so it must carry the whole diagnosis. These pin the decoder
// so a future refusal cannot be added with its observation left behind.
func TestBoundaryRefusalError_CarriesItsOwnDiagnosis(t *testing.T) {
	t.Run("the kill sentinel chain is unchanged", func(t *testing.T) {
		if !errors.Is(killedAtBoundary(true), errKilledAtBoundary) ||
			!errors.Is(killedAtBoundary(false), errKilledAtBoundary) {
			t.Fatal("killedAtBoundary must stay matchable as errKilledAtBoundary — every " +
				"classification in this package is keyed on that sentinel")
		}
	})
	t.Run("drift observed alongside a kill survives on the error", func(t *testing.T) {
		if !driftObservedAtBoundary(killedAtBoundary(true)) {
			t.Fatal("SECURITY: a drift seen in the same pass as a kill must still latch — " +
				"a kill can be cleared, and the activation would resume unlatched")
		}
		if driftObservedAtBoundary(killedAtBoundary(false)) {
			t.Fatal("a kill with no drift must not fabricate one")
		}
	})
	t.Run("the other refusals report their own drift truthfully", func(t *testing.T) {
		if !driftObservedAtBoundary(errToolDriftedBeforeCall) {
			t.Fatal("the drift refusal IS a drift observation")
		}
		if driftObservedAtBoundary(withdrawnAtBoundary(mcperr.ReasonRolloutOutOfScope)) {
			t.Fatal("a withdrawn authority is not a tool drift")
		}
		if driftObservedAtBoundary(nil) || driftObservedAtBoundary(errors.New("transport")) {
			t.Fatal("only a boundary refusal may report a drift observation")
		}
	})
	t.Run("only a boundary refusal is classified", func(t *testing.T) {
		for _, err := range []error{
			errToolDriftedBeforeCall,
			killedAtBoundary(false),
			withdrawnAtBoundary(mcperr.ReasonRolloutOutOfScope),
		} {
			if !isBoundaryRefusal(err) {
				t.Fatalf("%v must be classified as a boundary refusal", err)
			}
		}
		for _, err := range []error{nil, context.Canceled, errors.New("transport")} {
			if isBoundaryRefusal(err) {
				t.Fatalf("SECURITY: %v must NOT be read as a boundary refusal — a transport or "+
					"cancellation fault would then be diagnosed as a rollout refusal", err)
			}
		}
	})
	t.Run("the drift decoder is concurrency-safe", func(t *testing.T) {
		err := killedAtBoundary(true)
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _ = driftObservedAtBoundary(err) }()
		}
		wg.Wait()
	})
}
