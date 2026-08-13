package main

// M2 — the ONE runtime→learning adapter (ADR-0025). handleRequest calls
// learnObserveDecision once per policy decision; this is the only reference
// the request path holds to the learning subsystem (pinned by
// policylearn_wall_test.go). The transport is strictly one-way: runtime →
// observation → learning. Learning has no path back into enforcement.
//
// Disabled posture (the production default until the governed enablement
// slice lands): the singleton is nil, so this costs one atomic load and a
// predicted branch — no allocation, no goroutine, no I/O (benchgate-pinned).

import (
	"fmt"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

// learnObserveDecision emits one server-derived observation for a Stage-2
// policy decision. Every field comes from typed server-side state (the F6
// contract): the resolved auth context and the policy match — never a header
// or any client-supplied value. Non-blocking under every condition.
// learnObservePreDispatch emits one observation for a request blocked BEFORE
// policy evaluation (threat feed / blocklist / plugin / global file-extension
// gate). Context/negative evidence only — the aggregation model classifies
// these by their status and they can never contribute positive ALLOW evidence.
func learnObservePreDispatch(auth authOutcome, host, method, status string) {
	eng := policyLearnEngine.Load()
	if eng == nil {
		return // learning disabled — zero-cost gate
	}
	eng.Observe(policylearn.Observation{
		Subject:    auth.identity,
		AuthSource: auth.source,
		Groups:     auth.groups,
		Host:       host,
		Method:     method,
		Action:     "predispatch",
		Status:     status,
	})
}

// learnCategoryEpoch composes the opaque category-generation identity the
// learning engine pins per session (ADR-0025 §6): the signed SaaS feed's
// generation + overrides revision (atomically-swapped immutable view) and the
// admin taxonomy revision. Opaque — the engine only compares equality. The
// community UT1 DB carries no generation identity today (recorded M3 finding);
// its churn is NOT represented here.
func learnCategoryEpoch() string {
	saas := "none"
	if v := saasEffectiveView.Current(); v != nil {
		saas = v.GenerationID + ":" + v.ConfigRevision
	}
	return fmt.Sprintf("saas:%s|admin:%d", saas, catStore.Revision())
}

func learnObserveDecision(auth authOutcome, host, method string, match *PolicyMatch, status, sslAction string) {
	eng := policyLearnEngine.Load()
	if eng == nil {
		return // learning disabled — zero-cost gate
	}
	ruleID := ""
	var action string
	if match != nil && match.Rule != nil {
		ruleID = match.Rule.ID
		action = string(match.Action)
	} else if defaultPolicyAction() == "allow" {
		action = "default:allow" // static literals: no concat allocation on the hot path
	} else {
		action = "default:deny"
	}
	eng.Observe(policylearn.Observation{
		Subject:    auth.identity,
		AuthSource: auth.source, // verbatim opaque provenance
		Groups:     auth.groups, // engine makes the bounded copy
		Host:       host,
		Method:     method,
		RuleID:     ruleID,
		Action:     action,
		Status:     status,
		SSLAction:  sslAction,
	})
}
