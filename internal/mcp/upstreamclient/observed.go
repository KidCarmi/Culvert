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
//   - neverSent says the leg provably never began: the failure happened before
//     client.Do was reached, so no request bytes exist on any connection. It is
//     DISTINCT from preResponse and cannot be derived from it — a DNS resolve failure
//     sets preResponse true and never sent anything, while a peer that reads the whole
//     request and hangs up also sets preResponse true and demonstrably did.
type legFacts struct {
	preResponse      bool
	responseObserved bool
	neverSent        bool
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

// notSentErr carries the never-sent fact, the mirror of observedErr. Both ride on the
// error for the same reason, and both are ABSENT BY DEFAULT in the safe direction: an
// unwrapped error means "not known to have been sent AND not known to have been
// received", which is exactly the uncertainty may_have_been_sent expresses.
type notSentErr struct{ err error }

func (e *notSentErr) Error() string { return e.err.Error() }
func (e *notSentErr) Unwrap() error { return e.err }

// markLegFacts wraps err with whichever positive fact the leg established. The two are
// mutually exclusive by construction — a leg that observed a response necessarily
// started — and responseObserved wins if both were somehow set, because claiming a
// send did not happen when the peer answered is the one direction that loses a real
// physical effect.
func markLegFacts(err error, facts legFacts) error {
	switch {
	case err == nil:
		return nil
	case facts.responseObserved:
		return &observedErr{err: err}
	case facts.neverSent:
		return &notSentErr{err: err}
	}
	return err
}

// markNeverSent wraps a failure that Call itself produced before any leg began —
// method not admitted, an invalid target, or pool admission refused. No connection
// exists in any of those cases.
func markNeverSent(err error) error {
	if err == nil {
		return nil
	}
	return &notSentErr{err: err}
}

// SendNeverStarted reports whether a failed Call provably never put request bytes on
// a connection. Like ResponseObserved it is an INCREASE in knowledge only: an error
// this returns false for keeps whatever uncertainty the caller already had, so a
// caller that has not been taught about this fact — or a test double that returns a
// bare error — stays at the conservative may_have_been_sent.
//
// It is the ONLY way definitely_not_sent becomes reachable from inside Call, and the
// evidence has to be that strong: it is the strongest claim in the send-state lattice
// and the one an operator would act on by re-running the invocation.
func SendNeverStarted(err error) bool {
	var ne *notSentErr
	return errors.As(err, &ne)
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

// MarkNeverSentForTest exposes the never-sent marker to tests in other packages, so an
// executor-side double can reproduce the exact error shape the production client
// produces when a call is refused before any leg begins. It is a test seam only:
// production marking happens inside Call and roundTrip, where the evidence lives.
func MarkNeverSentForTest(err error) error { return markNeverSent(err) }
