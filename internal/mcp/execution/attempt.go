package execution

// attempt.go — physical attempt identity for Canary effect accounting
// (First Controlled Canary review §5).
//
// An AttemptID names ONE POTENTIAL PHYSICAL TOOL INVOCATION. It is deliberately
// none of the identifiers that already exist:
//
//   - not an execution id — one execution may be denied before any send, so an
//     execution id cannot answer "how many effects did the peer see?";
//   - not a server id — the transport's wire id is `"u-" + ServerID`, shared by
//     every request AND every retry to that server, so it cannot separate three
//     reservations from one reservation retried three times;
//   - not a JSON-RPC request id — that is a protocol framing detail the peer may
//     reuse or ignore.
//
// Exactly one AttemptID corresponds to at most one side-effect-bearing tool send.
// That one-to-one binding is what makes independent witness reconciliation
// possible: the controlled upstream can report which attempts it actually
// received, and Culvert can compare that to the attempts it authorized.

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// attemptIDBytes is the entropy width. 128 bits makes collision across a bounded
// Canary corpus (single-digit attempts) not merely unlikely but irrelevant, while
// keeping the identifier short enough to log and to carry in evidence.
const attemptIDBytes = 16

// attemptIDPrefix makes the identifier self-describing in logs and witness records
// so it can never be confused with an execution, server or wire id.
const attemptIDPrefix = "att_"

// newAttemptID mints a fresh attempt identity from the system CSPRNG.
//
// It is NON-SECRET (it appears in evidence and at the controlled upstream) but it
// is never derived from request content: deriving it from user input would let a
// caller force two distinct physical attempts to share one identity, collapsing
// them in the witness and hiding a duplicate effect. It fails CLOSED — a caller
// that cannot mint an identity must not send, because an unattributable physical
// invocation is exactly what this mechanism exists to prevent.
func newAttemptID() (string, error) {
	b := make([]byte, attemptIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", mcperr.New(mcperr.ReasonEventEvidenceMissing, "execution.attempt", "attempt identity unavailable")
	}
	return attemptIDPrefix + hex.EncodeToString(b), nil
}

// validAttemptID reports whether s has the exact minted shape. Used by recovery and
// by evidence validation so a malformed or foreign identifier cannot enter the
// reconciliation set.
func validAttemptID(s string) bool {
	if len(s) != len(attemptIDPrefix)+2*attemptIDBytes {
		return false
	}
	if s[:len(attemptIDPrefix)] != attemptIDPrefix {
		return false
	}
	_, err := hex.DecodeString(s[len(attemptIDPrefix):])
	return err == nil
}
