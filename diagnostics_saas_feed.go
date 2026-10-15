package main

// diagnostics_saas_feed.go — operator-contract row for the signed SaaS feed.
//
// The signed-feed state machine already derives stale / degraded / waiting /
// critical (saas_feed_status.go) and reports it on /ready and
// /api/saas-feed/status. The one-page diagnostics report, which is where an
// operator checks "is this node healthy", did not carry it: a feed stuck on an
// expired last-known-good generation read as an all-clear.
//
// Report-only: reads the cached status snapshot, performs no I/O, and changes
// no serving behavior (the embedded baseline / last-known-good keeps serving).
// Contributes nothing in a healthy or not-in-use state, so a node that does not
// use the signed feed carries no extra row. The message carries only the
// bounded state/error-class enums, never URLs, paths or raw error text.

import "fmt"

const saasFeedDiagAction = "Open Objects → URL Categories → Signed SaaS Feed tab to see the last error and next attempt, then use Refresh once the origin or network path is reachable."

// checkSaaSFeed returns zero or one row for the signed SaaS feed.
func checkSaaSFeed() []OperatorContractCheck {
	snap := globalSaaSFeedStatus.Snapshot()
	var status, msg, action string
	switch snap.State {
	case saasFeedStateCritical:
		status = diagFail
		msg = "signed SaaS feed is in a critical state (corruption, equivocation or lost authority) — the embedded baseline is serving and signed updates are not being applied"
		action = "Open Objects → URL Categories → Signed SaaS Feed to see the state, then correct the feed authority or configuration; a manual refresh will not clear a critical state."
	case saasFeedStateWaitingForAuthority:
		status = diagWarn
		msg = "signed SaaS feed is waiting for a valid authoritative configuration from the control plane — the embedded baseline is serving"
		action = "Confirm this node is enrolled and receiving configuration from its control plane (Cluster panel); the feed resumes on its own once authority arrives."
	case saasFeedStateStale:
		status = diagWarn
		msg = "signed SaaS feed is serving an expired last-known-good generation — category data is older than its signed expiry" + feedErrSuffix(snap)
		action = saasFeedDiagAction
	case saasFeedStateDegraded:
		status = diagWarn
		msg = fmt.Sprintf("signed SaaS feed refresh is failing (%d consecutive failures) — the last-known-good generation is still serving%s",
			snap.ConsecutiveFailures, feedErrSuffix(snap))
		action = saasFeedDiagAction
	default:
		return nil
	}
	return []OperatorContractCheck{{Code: "saas_feed", Status: status, Message: msg, OperatorAction: action}}
}

// feedErrSuffix renders the bounded last_error_class enum, or "" when none.
func feedErrSuffix(snap saasFeedStatusSnapshot) string {
	if snap.LastErrorClass == "" {
		return ""
	}
	return fmt.Sprintf(" (last error class: %s)", snap.LastErrorClass)
}
