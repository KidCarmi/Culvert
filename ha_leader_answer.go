package main

// ha_leader_answer.go — what one standby sync round proved about the leader.
//
// The control plane's early listener (cp_starting_listener.go, ADR-0065) makes
// a restarting leader ANSWER while its stores load. That is only worth
// anything if the standby reads the answer as what it is. Counted as a failed
// round — which is what any non-reply was — a store load longer than three
// ticks promotes a legacy standby under a live leader, and the leader then
// resumes too: two unfenced leaders, on a routine restart.
//
// So, in LEGACY mode, a "starting" answer is an answered round: it does not
// count toward the leader-unreachable threshold. It is not a sync either — it
// never refreshes the last-sync time. And it is bounded: after haStartingGrace
// of an unbroken run of such answers they count as failures again, so a
// leader hung in start-up cannot block failover forever.
//
// LEASE mode is unchanged: every round that does not apply counts, and the
// lease arbitrates the promotion (ADR-0005).
//
// The names and semantics here are shared with the HA authority change (the
// legacy restart revalidation and publication gate), which extends
// haLeaderAnswerOf.

import "time"

// haLeaderAnswer classifies what a sync round proved about the leader.
type haLeaderAnswer int

const (
	haNoAnswer         haLeaderAnswer = iota // nothing: transport failure or an unclassified refusal
	haAnsweredReply                          // a bundle came back (applied or not)
	haAnsweredStarting                       // "I am starting" — alive, bounded by haStartingGrace
	haAnsweredHolding                        // "publication not authorized" — a live leader deliberately holding
)

// haStartingGrace bounds how long an unbroken run of "starting" answers is
// taken as proof that the leader is alive. Half the freshness window keeps a
// standby that was synced when the leader went down eligible to promote when
// the grace ends (leaseAutoPromote and the legacy sync-eligibility check both
// refuse a standby whose last sync is older than haPromoteFreshnessWindow).
const haStartingGrace = haPromoteFreshnessWindow / 2

// haStartingNow is the clock the grace is measured on: the standby's own,
// from the first starting answer of the current run — never the leader's
// self-reported elapsed time alone. A variable so a test can move it.
var haStartingNow = time.Now

// haLeaderAnswerOf classifies a FAILED HASync. A standby's own refusal ("not
// the HA leader") is Unavailable without a marker and stays haNoAnswer: that
// peer does not lead.
func haLeaderAnswerOf(err error) haLeaderAnswer {
	switch {
	case isCPStartingStatus(err):
		return haAnsweredStarting
	case isCPPublishNotAuthorizedStatus(err):
		return haAnsweredHolding
	}
	return haNoAnswer
}
