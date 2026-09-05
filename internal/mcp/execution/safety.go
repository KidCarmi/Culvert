package execution

// safety.go — the narrow seam by which the execution engine reports AUTHORITATIVE whole-Canary
// safety facts to the composition layer (First Controlled Canary review, blocker #7).
//
// WHY THIS IS NOT Metrics. Metrics is observability: a nil sink is replaced by a no-op, discarding
// an observation is correct, and nothing downstream changes behaviour. This seam carries CONTROL
// semantics — what it reports can revoke the experiment's authority to change reality — so
// overloading Metrics with it would put a safety decision behind an interface whose whole contract
// is that dropping data is fine. The production Metrics implementation for the MCP tier is in fact
// an empty method body, which is exactly how outcome_evidence_loss came to have a real signal in
// #1306 and still stop nothing.
//
// WHAT IT IS NOT. It is not a second abort authority. It reports FACTS; the composition layer
// classifies them and calls the one trip function, which reaches the one AbortController. The
// engine deliberately cannot latch anything itself: it does not know the activation generation, and
// a breach reported by an engine that outlived its activation must not stop a later one.
//
// A nil seam means "no Canary is composed" — not "discard". Shadow and the default disabled posture
// pass nil and are byte-identical to having no seam at all.

import "time"

// CanarySafety receives authoritative safety facts from the execution engine.
type CanarySafety interface {
	// Breach reports that an authoritative whole-Canary breach OCCURRED. code is a
	// canary.AbortConditions() taxonomy code; an unrecognised code fails closed to a
	// whole-Canary latch at the controller, so a typo can only ever stop the experiment, never
	// silently continue it.
	Breach(capability string, code string)

	// AttemptSettled reports ONE settled post-admission attempt so the composition layer's
	// population detectors (elevated error rate, latency pathology) can judge. failed is an
	// ordinary execution failure; latency is the observed attempt duration.
	//
	// The engine reports only ADMITTED attempts that settled. It does NOT report request-scoped
	// denials — a policy deny, a scope refusal, an allowance already consumed — because those are
	// what a healthy Canary does all day, and counting them would let a Canary abort itself for
	// correctly refusing requests. Conditions carrying their own immediate whole-Canary
	// classification are likewise not laundered through a rate: they trip directly.
	AttemptSettled(capability string, failed bool, latency time.Duration)
}

// noopCanarySafety is the nil-seam stand-in. It exists so call sites never branch on nil.
type noopCanarySafety struct{}

// Breach discards the report: with no funnel composed there is no activation to stop.
func (noopCanarySafety) Breach(string, string) {}

// AttemptSettled discards the sample: the detectors are generation-bound and live in the
// composition layer, so with nothing composed there is no population to accumulate into.
func (noopCanarySafety) AttemptSettled(string, bool, time.Duration) {}
