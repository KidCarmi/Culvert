package main

// Policy Learning Mode singleton (ADR-0025, slice M1). nil = disabled — the
// production posture in M1 (see policy_learning_startup_config.go). Held in an
// atomic.Pointer so a future runtime enable/disable (and the test swap seam)
// can never race a reader; every consumer must nil-check:
//
//	if eng := policyLearnEngine.Load(); eng != nil { ... }

import (
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

var policyLearnEngine atomic.Pointer[policylearn.Engine]
