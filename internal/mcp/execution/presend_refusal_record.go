package execution

import "sync"

// presend_refusal_record.go — the cross-goroutine hand-off for a refusal observed by a
// PRE-SEND re-ask.
//
// WHY THIS TYPE EXISTS RATHER THAN TWO LOCAL VARIABLES.
//
// runExecute hands its boundary predicate to the upstream client as
// CallOptions.PreSend so the guards are re-asked at every point where an unbounded
// wait has just ended and nothing is yet written. One of those points — the second,
// after the TCP connect and the TLS handshake — lives inside the transport's TLS
// dialer, and net/http RUNS A DIAL ON ITS OWN GOROUTINE
// (Transport.queueForDial -> go dialConnFor).
//
// That goroutine is not joined to the request. When the request goroutine stops
// waiting for the dial — an ordinary context cancellation, which is what a client
// disconnect or a request-timeout produces — getConn returns immediately and Call
// unwinds, while the dial goroutine keeps going, completes its handshake and calls
// the hook. So the hook can still be RUNNING after Call has returned; it is proved
// deterministically, against the real transport, by
// TestPreSend_MayStillBeRunningAfterCallReturns (internal/mcp/upstreamclient).
//
// Recording the refusal into plain captured variables and reading them right after
// Call returns is therefore a data race between the request goroutine's read and
// the abandoned dial goroutine's write — reproduced under -race, with the write
// attributed to pinnedDialTLS on net/http's dial goroutine. It is not a fail-open:
// the refusal still closes the socket with nothing written, and the physical send
// is still refused by the dialer itself. What it corrupts is the BLOCK RECORD —
// whether this attempt is classified as a boundary refusal, with which bounded
// reason, and whether a drift observed at the boundary reaches Safety.Breach — and
// a security control's telemetry is part of the control.
//
// The fix is synchronisation, not a change of source: the refusal the client
// returns is the same fact (the sentinel rides out through Call's error), but
// classifying from THIS record keeps the drift observation, which the error does
// not carry. LAST-WRITE-WINS is preserved exactly as the captured variables had it,
// so this is a race fix and nothing else.
type preSendRefusalRecord struct {
	mu    sync.Mutex
	err   error
	drift bool
}

// record stores a refusal. A nil error is not a refusal and is ignored, so a
// successful re-ask can never erase an earlier leg's recorded one.
//
// Safe to call from any goroutine, including one net/http has abandoned: a write
// that lands after taken() has already run simply has no reader.
func (b *preSendRefusalRecord) record(err error, drift bool) {
	if err == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.err, b.drift = err, drift
}

// taken reports the recorded refusal, or (nil, false) when no re-ask refused.
func (b *preSendRefusalRecord) taken() (error, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err, b.drift
}
