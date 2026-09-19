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
// internal/mcp/execution keeps the hook a PURE PREDICATE and reads the verdict off Call's own
// error instead. This test is the reason it must: it pins the PROPERTY, against the real
// transport, so the contract cannot quietly stop being true.
//
// It is DETERMINISTIC rather than timing-based: the hook is parked on a channel at the exact
// moment the test needs it parked, so "the hook has not finished" is observed, never sampled.
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
	case <-time.After(30 * time.Second):
		close(release)
		t.Fatal("Call did not return while the dialer-site PreSend was parked")
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
