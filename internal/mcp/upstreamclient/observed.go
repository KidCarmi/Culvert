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

// foldLegFacts folds ONE leg's facts into the facts known about the WHOLE Call.
//
// Call owns a retry loop, so a Call is not a leg. The two evidence facts therefore
// aggregate in OPPOSITE directions, and in each case that direction is the
// conservative one:
//
//   - responseObserved is a DISJUNCTION. Any leg that saw the peer answer proves the
//     invocation reached it, and no later leg can un-prove that.
//   - neverSent is a CONJUNCTION. It is the strongest claim in the send-state lattice
//     and the one an operator would act on by re-running the invocation, so it
//     requires UNANIMITY: only if EVERY attempted leg provably put no bytes on a
//     connection did the Call as a whole send nothing.
//
// Carrying out the LAST leg's facts instead is how a false certainty gets
// manufactured, and the shape is ordinary rather than contrived: an initial leg can
// be read in full by the peer and then fail before a response (transport.go's
// preResponse leg), which is exactly the classification that authorizes a re-send;
// a retry can then fail at resolve, which sets neverSent AND preResponse together.
// The caller would record definitely_not_sent for an invocation that may already
// have executed at the peer — uncertainty converted into executed=false, which is
// the one conversion this whole accounting exists to prevent (Codex round 15).
//
// preResponse is deliberately NOT folded. It is a per-leg input to retry
// CLASSIFICATION, not evidence carried out to the caller, and folding it would make
// it describe some leg other than the one being classified.
func foldLegFacts(call, leg legFacts) legFacts {
	return legFacts{
		responseObserved: call.responseObserved || leg.responseObserved,
		neverSent:        call.neverSent && leg.neverSent,
	}
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

// MarkResponseObservedForTest is the mirror seam: it produces the exact error shape the production
// client returns when the PEER ANSWERED but the answer was unusable — a non-200, an unreadable body,
// undecodable bytes. Without it an executor-side double cannot reproduce the case at all, because a
// bare error stays at the conservative may_have_been_sent and every predicate that distinguishes
// "the peer failed" from "we never heard back" reads the same on both. That gap let a health-detector
// defect ship: a gate written with a bare error passed against the defective predicate AND the fixed
// one, proving nothing (Codex round 5). Test seam only; production marking happens in markLegFacts.
func MarkResponseObservedForTest(err error) error {
	return markLegFacts(err, legFacts{responseObserved: true})
}
