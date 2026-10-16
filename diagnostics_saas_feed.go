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
// use the signed feed carries no extra row. The message carries only bounded
// enums and integers (state, source, error class, critical reason, version,
// failure count), never URLs, paths or raw error text.
//
// Every claim about what is serving is derived from the snapshot
// (ActiveFeedVersion / ActiveSource), never assumed from the state: a managed
// node waiting for authority, or one in a critical state, can still be serving
// a cached signed generation.

import "fmt"

const saasFeedDiagTab = "Open Objects → URL Categories → Signed SaaS Feed tab to see the last error and next attempt"

// checkSaaSFeed returns zero or one row for the signed SaaS feed.
func checkSaaSFeed() []OperatorContractCheck {
	snap := globalSaaSFeedStatus.Snapshot()
	serving := saasFeedServing(snap)
	var status, msg, action string
	switch snap.State {
	case saasFeedStateCritical:
		if snap.CriticalReason == recoveryStaleServed.String() && snap.Stale && snap.ActiveFeedVersion > 0 {
			// Restart recovery of a committed generation past its expiry
			// (recoveryStaleServed) sets Critical alongside Stale, but the feed
			// contract never fails closed on age: it is the stale condition,
			// and the next successful activation clears it. Keyed on the
			// recovery reason, not on Stale alone: fail-closed recovery
			// (equivocation / embedded_degraded) can keep a stale generation
			// and is a genuine critical state.
			return []OperatorContractCheck{saasFeedStaleRow(snap, serving)}
		}
		status = diagFail
		msg = "signed SaaS feed is in a critical state (corruption, equivocation or lost authority" + saasFeedReason(snap) + ") — " + serving + " and signed updates are not being applied"
		action = "Open Objects → URL Categories → Signed SaaS Feed to see the state, then correct the feed authority, publisher or configuration; the state clears once a valid signed generation activates."
	case saasFeedStateWaitingForAuthority:
		status = diagWarn
		msg = "signed SaaS feed is waiting for a valid authoritative configuration from the control plane — " + serving
		action = "Confirm this node is enrolled and receiving configuration from its control plane (Cluster panel); the feed resumes on its own once authority arrives."
	case saasFeedStateStale:
		return []OperatorContractCheck{saasFeedStaleRow(snap, serving)}
	case saasFeedStateDegraded:
		status = diagWarn
		msg = fmt.Sprintf("signed SaaS feed refresh is failing (%d consecutive failures) — %s%s",
			snap.ConsecutiveFailures, serving, feedErrSuffix(snap))
		action = saasFeedDiagAction(snap)
	case saasFeedStateEmbedded:
		// An explicitly enabled feed that has never activated reads as the
		// clean embedded state even while every attempt fails (degraded needs
		// an active generation), so the failure streak is checked here.
		if snap.ConsecutiveFailures == 0 {
			return nil
		}
		status = diagWarn
		msg = fmt.Sprintf("signed SaaS feed has not activated a signed generation and refresh is failing (%d consecutive failures) — %s%s",
			snap.ConsecutiveFailures, serving, feedErrSuffix(snap))
		action = saasFeedDiagAction(snap)
	default:
		return nil
	}
	return []OperatorContractCheck{{Code: "saas_feed", Status: status, Message: msg, OperatorAction: action}}
}

func saasFeedStaleRow(snap saasFeedStatusSnapshot, serving string) OperatorContractCheck {
	return OperatorContractCheck{
		Code:           "saas_feed",
		Status:         diagWarn,
		Message:        "signed SaaS feed generation is past its signed expiry — " + serving + " as the last-known-good, so category data may be out of date" + feedErrSuffix(snap),
		OperatorAction: saasFeedDiagAction(snap),
	}
}

// saasFeedServing describes the content actually serving, from the snapshot.
func saasFeedServing(snap saasFeedStatusSnapshot) string {
	if snap.ActiveFeedVersion > 0 {
		src := snap.ActiveSource
		if src == "" {
			src = "signed"
		}
		return fmt.Sprintf("signed generation %d (%s) is serving", snap.ActiveFeedVersion, src)
	}
	return "the embedded baseline is serving"
}

// saasFeedDiagAction keys the remedy on the bounded last_error_class: only a
// transport (fetch) failure is fixed by the origin or network path becoming
// reachable. An http failure proves the origin answered, and no class at all
// (for example a stale generation recovered at startup) implies no network
// fault; the other classes persist after the network recovers.
func saasFeedDiagAction(snap saasFeedStatusSnapshot) string {
	switch snap.LastErrorClass {
	case saasFeedErrNone:
		return saasFeedDiagTab + ", then use Refresh to fetch a current generation."
	case saasFeedErrFetch:
		return saasFeedDiagTab + ", then use Refresh once the origin or network path is reachable."
	case saasFeedErrHTTP:
		status := "an error status"
		if snap.LastHTTPStatus > 0 {
			status = fmt.Sprintf("HTTP %d", snap.LastHTTPStatus)
		}
		return saasFeedDiagTab + ", then check the feed URL and that the publisher is serving the feed: the origin was reached but answered " + status + ". Use Refresh after it is corrected."
	case saasFeedErrPersist:
		return saasFeedDiagTab + ", then restore free space and write access on this node's data directory before using Refresh: the feed cannot record a new generation."
	case saasFeedErrVerify, saasFeedErrParse, saasFeedErrFreshness, saasFeedErrFloor:
		return saasFeedDiagTab + ", then correct what the reported class names (published feed signature or format, the node clock for expiry, or a rollback below the accepted version) before using Refresh: the origin is reachable but its feed is rejected."
	case saasFeedErrConfig:
		return saasFeedDiagTab + ", then correct the feed configuration or its control-plane authority before using Refresh."
	default:
		return saasFeedDiagTab + ", then correct the reported failure class before using Refresh."
	}
}

// saasFeedReason renders the bounded critical-reason enum, or "".
func saasFeedReason(snap saasFeedStatusSnapshot) string {
	if snap.CriticalReason == "" {
		return ""
	}
	return ": " + snap.CriticalReason
}

// feedErrSuffix renders the bounded last_error_class enum, or "" when none.
func feedErrSuffix(snap saasFeedStatusSnapshot) string {
	if snap.LastErrorClass == "" {
		return ""
	}
	return fmt.Sprintf(" (last error class: %s)", snap.LastErrorClass)
}
