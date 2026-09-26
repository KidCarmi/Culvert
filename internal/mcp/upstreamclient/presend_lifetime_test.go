package upstreamclient

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// THE LIFETIME OF CallOptions.PreSend IS NOT THE LIFETIME OF Call, AND A CALLER THAT ASSUMES
// OTHERWISE HAS A DATA RACE.
//
// The second re-ask site is inside pinnedDialTLS, and net/http runs a dial on its OWN goroutine
// (Transport.queueForDial -> go dialConnFor). That goroutine is not joined to the request: when
// the request goroutine stops waiting for the dial — an ordinary context cancellation, which is
// what a client disconnect or a request timeout produces — getConn returns at once and Call
// unwinds, while the dial goroutine completes its handshake and calls the hook.
//
// The executor needs each refusal for its block record. Reading it from captured variables after
// Call returns races the abandoned dial goroutine's write (reproduced under -race, the write
// attributed to pinnedDialTLS), and synchronising those variables removes the race without
// establishing a hand-off — a late hook can still write after the only reader has gone. So
// internal/mcp/execution writes NOTHING from the hook: it returns the verdict inside the error
// (preSendGuardErr) and reads it back off Call's own error with errors.As.
//
// That design is correct only while THIS property holds, and nothing else asserts it: the
// executor's own gates run against a fixture that joins the hook's goroutine, which is exactly
// the happens-before edge production lacks. This test pins the property against the REAL
// transport, so the premise the carrier rests on cannot quietly stop being true — if a future
// net/http or client change made the hook complete before Call returns, the carrier's
// justification would silently become false and no other test would notice.
//
// It is DETERMINISTIC rather than timing-based: the hook is parked on a channel at the exact
// moment the test needs it parked, so "the hook has not finished" is observed, never sampled.
//
// WHAT IT ASSERTS IS THE HAZARD, NOT THE SCHEDULE. The property the carrier rests on is that
// the hook MAY outlive Call, so nothing it writes may be read back through shared state. It is
// deliberately NOT an assertion that the hook DOES outlive Call: a transport that narrows the
// hook's lifetime by joining its dial goroutine leaves the carrier correct — conservative
// rather than required — so this gate SKIPS with that finding instead of failing, and only a
// Call that will not return even once the hook is released is a real failure. Asserting the
// looser direction would make a safe narrowing look like a regression (Codex review, PR #1411).
func TestPreSend_MayStillBeRunningAfterCallReturns(t *testing.T) {
	c, tgt, _, _, stop := pinnedTestServerCounting(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"c1","result":{}}`)
	})
	defer stop()

	var calls atomic.Int64
	var once sync.Once
	entered := make(chan struct{})  // closed by the hook, at the dialer site
	release := make(chan struct{})  // closed by the test, to let the hook finish
	finished := make(chan struct{}) // closed by the hook, after it is released

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	preSend := func() error {
		// Invocation 1 is the roundTrip site, on the request goroutine. Invocation 2 is the
		// dialer site: connected, handshaken, nothing written. A later leg must NOT park, or
		// the request goroutine would block here and the test could not distinguish "Call
		// returned while the hook ran" from "Call is waiting on the hook".
		if calls.Add(1) != 2 {
			return nil
		}
		once.Do(func() {
			close(entered)
			<-release
			close(finished)
		})
		return nil
	}

	callReturned := make(chan struct{})
	go func() {
		_, _ = c.Call(ctx, tgt, "tools/list", nil, CallOptions{
			Idempotent: true, WireID: "c1", PreSend: preSend,
		})
		close(callReturned)
	}()

	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the dialer-site PreSend never ran; the re-ask after the TLS handshake is gone")
	}

	// The request goroutine abandons the in-flight dial, exactly as a client disconnect or a
	// request-timeout does.
	cancel()

	select {
	case <-callReturned:
		// Fall through to the proof below.
	case <-time.After(30 * time.Second):
		// Call has NOT returned while the hook is parked. There are two reasons for
		// that and they call for opposite verdicts, so they must be distinguished
		// rather than both reported as this gate failing.
		//
		// The benign one is that the transport now JOINS its in-flight dial
		// goroutine — a NARROWING of the hook's lifetime, and a safe one. The
		// carrier in internal/mcp/execution stays correct under it: carrying the
		// verdict on the error is then merely CONSERVATIVE rather than required.
		// So this gate must not fail for it; asserting that the hook DOES outlive
		// Call would make a valid transport improvement look like a regression,
		// and would do it as a 30-second deadlock (Codex review, PR #1411).
		//
		// What this gate exists to prevent is the opposite mistake: someone
		// DELETING the carrier on the belief that the hook cannot outlive Call.
		// A skip that names the property is what that reader needs; silence is not.
		//
		// Releasing the hook separates the two: if Call was only waiting for it,
		// it returns at once.
		close(release)
		select {
		case <-callReturned:
			<-finished
			t.Skip("premise no longer holds: Call now waits for the dialer-site PreSend, " +
				"so the hook can no longer outlive Call. The execution-side error carrier " +
				"stays CORRECT under this (conservative, not required) — but re-derive the " +
				"note on CallOptions.PreSend before anything starts relying on the narrower " +
				"lifetime, and do not delete the carrier on the strength of this skip alone.")
		case <-time.After(30 * time.Second):
			t.Fatal("Call did not return even after the dialer-site PreSend was released; " +
				"neither the hook's lifetime nor the release explains this, so something " +
				"unrelated is wedged")
		}
	}

	select {
	case <-finished:
		t.Fatal("inconclusive: the hook completed before Call returned, so this run proved nothing")
	default:
		// PROVEN: Call has returned and the hook is still executing on net/http's dial
		// goroutine. Anything the hook writes for the caller must therefore be synchronised.
	}
	close(release)
	<-finished
}
