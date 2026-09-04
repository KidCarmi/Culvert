package upstreamclient

import "errors"

// legFacts is what is KNOWN about ONE physical HTTP leg, independent of whether that
// leg produced a usable response. The two facts are genuinely independent and must
// not be collapsed into one another:
//
//   - preResponse says the failure happened BEFORE any response, so an idempotent
//     read MAY be retried. It is false for failures that never sent anything at all
//     (a request that could not be built), which is safe for retry classification —
//     nothing was sent, so nothing is re-sent — but is exactly why it cannot double
//     as evidence of receipt.
//   - responseObserved says the PEER ANSWERED: response headers arrived. It is set
//     only after client.Do returns without error, so it can never be true for a leg
//     that failed before or during the send.
type legFacts struct {
	preResponse      bool
	responseObserved bool
}

// observedErr carries the observed-response fact alongside a call failure.
//
// It exists because Call's signature is fixed by the UpstreamCaller interface the
// executor holds, and widening that interface to pass one bool would ripple through
// every implementation and test double — where a default-false in a double would
// silently be a claim of NON-receipt. Riding on the error keeps the fact attached to
// the only value that reaches the caller on a failure, and absent by default in the
// only direction that is safe: an unwrapped error means "not known to have been
// received", never "known not to have been received".
type observedErr struct{ err error }

func (e *observedErr) Error() string { return e.err.Error() }
func (e *observedErr) Unwrap() error { return e.err }

// markResponseObserved wraps err when the peer demonstrably answered, and returns it
// unchanged otherwise. A nil error is never wrapped — success already carries the
// response itself.
func markResponseObserved(err error, facts legFacts) error {
	if err == nil || !facts.responseObserved {
		return err
	}
	return &observedErr{err: err}
}

// ResponseObserved reports whether a failed Call nevertheless observed a response
// from the peer — a non-200 status, an unreadable body, or bytes that would not
// decode. It is the difference between "the invocation may have reached the peer"
// and "it demonstrably did", and it is an INCREASE in knowledge only: an error this
// returns false for keeps whatever uncertainty the caller already had.
//
// The unwrapped Reason is preserved, so mcperr classification is unaffected.
func ResponseObserved(err error) bool {
	var oe *observedErr
	return errors.As(err, &oe)
}
