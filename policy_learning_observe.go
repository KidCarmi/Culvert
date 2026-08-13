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

import "github.com/KidCarmi/Culvert/internal/policylearn"

// learnObserveDecision emits one server-derived observation for a Stage-2
// policy decision. Every field comes from typed server-side state (the F6
// contract): the resolved auth context and the policy match — never a header
// or any client-supplied value. Non-blocking under every condition.
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
