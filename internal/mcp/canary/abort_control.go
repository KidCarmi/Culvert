package canary

import (
	"sync"
	"time"
)

// Whole-Canary automatic abort controller (§4, Canary Activation Gate). AbortConditions() (abort.go)
// is the fixed classification of every safety trip as AbortRequest (fail THIS request closed; the
// Canary continues) or AbortCanary (STOP the whole Canary). AbortController is the RUNTIME state
// machine that acts on that taxonomy: it is a small, generation-bound, MONOTONIC latch. A single
// occurrence of any whole-Canary breach code latches it aborted for that activation generation;
// once latched it stays latched (no automatic clear), so future execution is immediately and
// permanently ineligible for that generation — resuming requires a new activation/review cycle
// (structurally: a new generation with a fresh controller).
//
// The taxonomy distinction is load-bearing and enforced HERE: a per-request AbortRequest code (a
// policy deny, a stale decision, an inspection block, a per-request kill) NEVER latches the
// controller. Conflating the two — tearing down the Canary on an ordinary per-request fail-closed —
// is exactly the mistake this controller prevents (request-fails-closed ≠ Canary-stops).

// abortScopeByCode is the code→scope index built once from the fixed AbortConditions() taxonomy, so
// the controller and the taxonomy can never drift.
var abortScopeByCode = func() map[string]AbortScope {
	m := make(map[string]AbortScope, len(AbortConditions()))
	for _, c := range AbortConditions() {
		m[c.Code] = c.Scope
	}
	return m
}()

// AbortScopeForCode returns the blast radius the taxonomy assigns a code. An UNKNOWN code fails
// closed to the STRONGER action (AbortCanary): a trip the taxonomy does not recognise must never be
// silently downgraded to a per-request fault (abort.go's AbortScopeUnset doctrine).
func AbortScopeForCode(code string) AbortScope {
	if s, ok := abortScopeByCode[code]; ok && s != AbortScopeUnset {
		return s
	}
	return AbortCanary
}

// TripResult is the outcome of feeding a safety-trip code to the controller.
type TripResult uint8

const (
	// TripRequestScoped — a per-request fail-closed code; the Canary CONTINUES (no latch).
	TripRequestScoped TripResult = iota
	// TripCanaryLatched — a whole-Canary breach; the Canary is now (or was already) aborted.
	TripCanaryLatched
	// TripGenerationMismatch — the trip carried a stale generation; refused (no state change).
	TripGenerationMismatch
)

// String returns a stable token.
func (r TripResult) String() string {
	switch r {
	case TripRequestScoped:
		return "request_scoped"
	case TripCanaryLatched:
		return "canary_latched"
	case TripGenerationMismatch:
		return "generation_mismatch"
	default:
		return "unknown"
	}
}

// AbortController is the generation-bound, monotonic whole-Canary abort latch for one activation.
// Construct via NewAbortController (fresh activation) or RestoreAbortController (restart). Safe for
// concurrent use.
type AbortController struct {
	generation uint64

	mu      sync.Mutex
	aborted bool
	code    string // the whole-Canary code that latched it (first winner)
	atNanos int64
}

// NewAbortController arms a fresh (not-aborted) controller for activation generation gen (which MUST
// be ≥1 — generation 0 is the "no activation" sentinel and yields nil).
func NewAbortController(generation uint64) *AbortController {
	if generation == 0 {
		return nil
	}
	return &AbortController{generation: generation}
}

// Generation returns the activation generation this controller is bound to.
func (c *AbortController) Generation() uint64 {
	if c == nil {
		return 0
	}
	return c.generation
}

// Trip feeds a safety-trip code to the controller for activation generation gen at now. A
// whole-Canary code latches the abort (monotonically — the first code wins and later codes do not
// overwrite it); a per-request code returns TripRequestScoped WITHOUT latching; a stale generation
// is refused. An UNKNOWN code fails closed to a whole-Canary latch (AbortScopeForCode). A nil
// controller fails closed to TripCanaryLatched (there is no Canary to protect, but the caller must
// never read "request-scoped, continue").
func (c *AbortController) Trip(code string, gen uint64, now time.Time) TripResult {
	if c == nil {
		return TripCanaryLatched
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if gen != c.generation {
		return TripGenerationMismatch
	}
	if AbortScopeForCode(code) == AbortRequest {
		return TripRequestScoped
	}
	// Whole-Canary breach: latch monotonically (first code wins; an already-aborted controller
	// keeps its original code/time).
	if !c.aborted {
		c.aborted = true
		c.code = code
		c.atNanos = now.UnixNano()
	}
	return TripCanaryLatched
}

// Aborted reports whether the controller is latched aborted for activation generation gen. A
// generation mismatch returns false — the latch belongs to a different activation (this method
// answers "is THIS generation aborted").
func (c *AbortController) Aborted(gen uint64) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return gen == c.generation && c.aborted
}

// ExecutionEligible reports whether execution may proceed for activation generation gen: the
// controller must be THIS generation AND not aborted. A stale generation is ineligible (fail
// closed — the controller belongs to a superseded activation), and a nil controller is ineligible.
func (c *AbortController) ExecutionEligible(gen uint64) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return gen == c.generation && !c.aborted
}

// AbortCode returns the whole-Canary code that latched the abort ("" if not aborted).
func (c *AbortController) AbortCode() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.code
}

// AbortSnapshot is the restart-durable abort state for one activation generation. Scalars only —
// never a tenant/subject/secret.
type AbortSnapshot struct {
	Generation uint64 `json:"generation"`
	Aborted    bool   `json:"aborted"`
	Code       string `json:"code,omitempty"`
	AtUnixNano int64  `json:"at_unix_nano,omitempty"`
}

// Snapshot returns the durable abort state so the composition layer can persist it. An abort MUST
// survive a restart (the safe direction), so a latched controller snapshots aborted=true.
func (c *AbortController) Snapshot() AbortSnapshot {
	if c == nil {
		return AbortSnapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return AbortSnapshot{Generation: c.generation, Aborted: c.aborted, Code: c.code, AtUnixNano: c.atNanos}
}

// RestoreAbortController rebuilds a controller for activation generation gen from a durable
// snapshot. It is fail-closed and generation-strict: a snapshot for a DIFFERENT generation does NOT
// transfer (a stale abort never carries into a new activation, and — the mutation this blocks — a
// new activation can never reuse an older generation's cleared/aborted state), so a mismatch yields
// a FRESH not-aborted controller for gen. A matching snapshot restores the aborted latch exactly,
// so an abort survives a restart. gen 0 yields nil.
func RestoreAbortController(gen uint64, snap AbortSnapshot) *AbortController {
	if gen == 0 {
		return nil
	}
	if snap.Generation != gen {
		// Stale/foreign snapshot: it does not describe THIS activation generation. Return a fresh
		// controller — the abort neither transfers to nor is reusable by a different generation.
		return &AbortController{generation: gen}
	}
	return &AbortController{generation: gen, aborted: snap.Aborted, code: snap.Code, atNanos: snap.AtUnixNano}
}
