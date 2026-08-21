package broker

import "context"

// GateDecision is the pre-materialization gate's verdict. Permit gates whether the
// broker may proceed to touch the cache/provider at all. DurableConfirmed reports
// whether the authorization decision event for this plan was DURABLY COMMITTED
// before materialization — required for critical (high-risk) operations.
type GateDecision struct {
	Permit           bool
	DurableConfirmed bool
}

// PreMaterializationGate is the injected policy/durability boundary invoked BEFORE
// any cache decrypt or provider fetch. PR-4 defines the interface only; later
// slices supply the policy engine (PR-6) and the durable event spool (PR-8)
// implementations. It must be able to confirm the plan is still current, that the
// authorization decision permits the operation, and — for a critical operation —
// that the decision event was durably committed first.
//
// A denied, stale, unavailable, or erroring gate causes the broker to fail closed:
// the provider is NOT called, the cache is NOT decrypted, no plaintext is created,
// and previous broker state is unchanged. No exported Materialize overload bypasses
// this gate.
type PreMaterializationGate interface {
	Authorize(ctx context.Context, plan CredentialPlan) (GateDecision, error)
}
