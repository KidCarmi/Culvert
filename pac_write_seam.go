package main

import "net/http"

// pacWriteStateDecisionHook is a TEST-ONLY interleaving seam for the PAC
// mutation handlers (the 2E-C policyWriteStateDecisionHook precedent). The
// handlers call pacWriteStateDecision at two stages:
//
//   - "resolved": the request body has been decoded and the caller-supplied
//     precondition token captured, but the mutation mutex is NOT yet held;
//   - "fence":    inside the mutation mutex, immediately after the
//     precondition decision (stale / missing / vanished) has been taken.
//
// A test may park one request at "resolved" while a competitor runs to
// completion, then release it — a deterministic proof (channels, no sleeps)
// that the fence is evaluated INSIDE the serialized section against the
// authoritative state, never against the state the caller read earlier.
// Production leaves the hook nil; the call is then a single nil check.
var pacWriteStateDecisionHook func(r *http.Request, stage string)

func pacWriteStateDecision(r *http.Request, stage string) {
	if h := pacWriteStateDecisionHook; h != nil {
		h(r, stage)
	}
}
