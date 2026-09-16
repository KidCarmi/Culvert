package execution

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// THE PRE-SEND REFUSAL CROSSES A GOROUTINE BOUNDARY THE EXECUTOR DOES NOT OWN.
//
// runExecute hands its boundary predicate to the upstream client as CallOptions.PreSend, and one
// of the client's two re-ask sites sits inside the TLS dialer — which net/http runs on its OWN
// goroutine (Transport.queueForDial -> go dialConnFor). That goroutine is not joined to the
// request: when the request goroutine stops waiting for the dial (an ordinary context
// cancellation — a client disconnect, a request timeout), Call unwinds while the dial goroutine
// completes its handshake and calls the hook. The property is pinned against the REAL transport
// by TestPreSend_MayStillBeRunningAfterCallReturns (internal/mcp/upstreamclient).
//
// So whatever the hook records for the block record is written by a goroutine that can outlive
// Call, and read by the request goroutine immediately after Call returns. Plain captured
// variables made that a DATA RACE — reproduced under -race, the write attributed to
// pinnedDialTLS. It is not a fail-open: the dialer still closes the socket with nothing written.
// What it corrupts is the block record itself — whether the attempt is classified as a boundary
// refusal, under which bounded reason, and whether a drift observed at the boundary reaches
// Safety.Breach — and a security control's telemetry is part of the control.
//
// These gates are the regression wall. Run them under -race: against the captured-variable shape
// they were verified to report the race; against the synchronised record they are clean.

// orphanPreSendUpstream models net/http's abandoned dialer exactly: it invokes PreSend on a
// goroutine that is NOT joined to Call, so the hook's write to the executor's refusal record
// happens concurrently with the executor's read of it.
type orphanPreSendUpstream struct {
	calls int
	done  chan struct{}
}

func (f *orphanPreSendUpstream) Call(_ context.Context, _ upstreamclient.Target, _ string, _ json.RawMessage, opts upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	f.calls++
	started := make(chan struct{})
	go func() {
		close(started)
		if opts.PreSend != nil {
			_ = opts.PreSend() // may refuse; the real client aborts the leg on a non-nil error
		}
		close(f.done)
	}()
	// Return as soon as the hook goroutine EXISTS, never once it has finished — that is the
	// whole shape being modelled. Waiting for f.done here would create the happens-before edge
	// the production path does not have, and the gate would prove nothing.
	<-started
	return nil, errors.New("upstream call abandoned")
}

// withdrawAfterFirstAsk lets the PRE-CALL guard pass and the PRE-SEND re-ask refuse, which is
// the only ordering that reaches the hand-off under test: a refusal at the pre-call guard aborts
// before Upstream.Call and PreSend is never invoked.
func withdrawAfterFirstAsk() func() mcperr.Reason {
	var mu sync.Mutex
	asked := 0
	return func() mcperr.Reason {
		mu.Lock()
		defer mu.Unlock()
		asked++
		if asked == 1 {
			return mcperr.ReasonNone
		}
		return mcperr.ReasonRolloutOutOfScope
	}
}

// The hand-off must be race-free when the hook outlives the call.
func TestPreSendRefusal_HandoffIsRaceFreeWhenTheHookOutlivesTheCall(t *testing.T) {
	st := stateForMode(t, rollout.ModeCanary)
	up := &orphanPreSendUpstream{done: make(chan struct{})}
	gate := &orderingGate{admit: true, revalidate: withdrawAfterFirstAsk()}
	e := newGatedExec(t, st, up, gate)

	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = func() bool { return true }

	out := runExec(e, context.Background(), in)

	<-up.done // let the orphan finish before the test ends, so nothing leaks into the next one

	if up.calls != 1 {
		t.Fatalf("the boundary must have been reached exactly once, got %d upstream call(s)", up.calls)
	}
	if out.Executed {
		t.Fatal("SECURITY: a withdrawn authority at the pre-send re-ask must not report Executed=true")
	}
}

// record/taken are the two halves of the hand-off; these pin the semantics the captured
// variables had, so the race fix cannot quietly become a behaviour change.
func TestPreSendRefusalRecord_Semantics(t *testing.T) {
	t.Run("empty when nothing refused", func(t *testing.T) {
		var r preSendRefusalRecord
		if err, drift := r.taken(); err != nil || drift {
			t.Fatalf("an unrecorded refusal must read (nil,false), got (%v,%v)", err, drift)
		}
	})
	t.Run("a successful re-ask never erases a recorded refusal", func(t *testing.T) {
		var r preSendRefusalRecord
		want := errors.New("withdrawn")
		r.record(want, true)
		r.record(nil, false) // a later leg's re-ask that passed
		err, drift := r.taken()
		if !errors.Is(err, want) || !drift {
			t.Fatalf("a nil re-ask must not clear the refusal, got (%v,%v)", err, drift)
		}
	})
	t.Run("last refusal wins, as the captured variables had it", func(t *testing.T) {
		var r preSendRefusalRecord
		first, second := errors.New("first"), errors.New("second")
		r.record(first, true)
		r.record(second, false)
		err, drift := r.taken()
		if !errors.Is(err, second) || drift {
			t.Fatalf("last-write-wins must be preserved exactly, got (%v,%v)", err, drift)
		}
	})
	t.Run("concurrent writers and a reader", func(t *testing.T) {
		var r preSendRefusalRecord
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); r.record(errors.New("withdrawn"), true) }()
		}
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, _ = r.taken() }()
		}
		wg.Wait()
		if err, _ := r.taken(); err == nil {
			t.Fatal("a refusal recorded concurrently must still be readable")
		}
	})
}
