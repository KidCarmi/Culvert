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

// pacLifecycleStageHook is a TEST-ONLY seam for the publish/rollback path
// (2F-B). It is invoked at the persistence boundaries of a lifecycle
// mutation so a test can observe or snapshot the on-disk state at exactly
// that point (a deterministic "crash here" without sleeps):
//
//   - "intent_persisted":  the operation intent is durable, the active
//     store has NOT been mutated yet;
//   - "active_committed":  the authoritative active store has been mutated
//     (durably), history is NOT finalized yet;
//   - "finalized":         the lifecycle history has been finalized.
//
// Production leaves the hook nil.
var pacLifecycleStageHook func(stage string)

func pacLifecycleStage(stage string) {
	if h := pacLifecycleStageHook; h != nil {
		h(stage)
	}
}

// pacLifecyclePersistHook is a TEST-ONLY fault-injection seam consulted
// immediately before each durable lifecycle write on the publish/rollback
// path ("intent", "finalize"); a non-nil error is treated exactly like the
// underlying write failing. Production leaves the hook nil.
var pacLifecyclePersistHook func(stage string) error

func pacLifecyclePersist(stage string) error {
	if h := pacLifecyclePersistHook; h != nil {
		return h(stage)
	}
	return nil
}
