package main

// diagnostics_upstream_egress.go — operator-contract row for a configured
// parent-proxy chain that currently has no eligible parent.
//
// When every configured parent is unhealthy, circuit-open or
// credential-ineligible, plain-HTTP requests that should be chained fail open
// to DIRECT egress (PX-2 posture, CHAOS-11). The pool already knows this: it
// fires one upstream_pool_down alert per transition, logs one line, exports
// culvert_upstream_direct_fallback_active and shows the effective mode on
// Network → Upstream Proxies. But the one-page Diagnostics report — where an
// operator checks "is this node healthy" — stayed green while egress bypassed
// the configured chain, so an operator without a metrics stack or a webhook
// receiver had to find the Upstream page or read the log.
//
// Report-only: derived from the same in-memory upstreamPool.List() eligibility
// and DirectFallback() latch the Upstream page and metrics read. It never
// probes, dials or retries, and it does not call Effective() (which stamps the
// mode-since clock). Counts only: no authority, URL, username or credential.
// Contributes nothing when no pool is configured or at least one parent is
// eligible. Selection, fail-open behavior and alerting are unchanged.

import "fmt"

// checkUpstreamEgress returns a WARN row when a configured parent-proxy pool
// has zero eligible parents.
func checkUpstreamEgress() []OperatorContractCheck {
	list := upstreamPool.List()
	if len(list) == 0 {
		return nil
	}
	for i := range list {
		if list[i].Eligible {
			return nil
		}
	}
	active, total := upstreamPool.DirectFallback()
	msg := fmt.Sprintf("No parent proxy is eligible (0 of %d configured): ", len(list))
	if active {
		msg += fmt.Sprintf("plain-HTTP requests are egressing DIRECT, bypassing the parent-proxy chain (mode direct_fallback; %d request(s) have fallen back since startup)", total)
	} else {
		msg += "the next plain-HTTP request that needs a parent will egress DIRECT, bypassing the parent-proxy chain (mode no_eligible_parent)"
	}
	return []OperatorContractCheck{{
		Code:    "upstream_egress",
		Status:  diagWarn,
		Message: msg,
		OperatorAction: "Open Network → Upstream Proxies to see why each parent is ineligible (health probe, circuit breaker, credential state) and run Check health after fixing reachability or credentials. " +
			"The row clears as soon as one parent is eligible again; the upstream_pool_down alert and culvert_upstream_direct_fallback_active metric track the same state.",
	}}
}
