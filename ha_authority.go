package main

// ha_authority.go — leadership and publication authority, as SEPARATE
// questions (ADR-0064; node_lifecycle.go lists the consumers). Keep every
// consumer on these functions; do not re-derive an answer anywhere else.
//
//	haLeadershipHeld       the lease (lease mode) or the legacy restart
//	                       revalidation (ha_legacy_authority.go)
//	haPublishAuthorized    the publication safety gate (ha_publish_gate.go)
//	haDistributionRefused  the narrow case in which nothing at all may be
//	                       handed out: a leader role without the lease

// haLeadershipHeld reports whether this node holds HA leadership for
// leadership-dependent operations: the leader role, and in lease mode the
// fence. A standalone (HA off) control plane holds it trivially. It is one of
// the two predicates the node-lifecycle surface reads (ADR-0064); the other is
// haPublishAuthorized.
func haLeadershipHeld() bool {
	if _, gated := globalHA.intentGate(); gated {
		return false
	}
	st := globalHA.Status()
	if !st.Enabled {
		return true
	}
	return st.Role == "leader" && globalHA.WriteAllowed()
}

// haPublishAuthorized is the ONE publishing-authorization predicate (ADR-0064):
// leadership is haLeadershipHeld; this is whether a leader may distribute new
// content and accept configuration changes. The state-authority contract's declared-emptying check
// is to be consulted here as well, not in a second gate.
func haPublishAuthorized() (ok bool, reason string) {
	if reason, refused := haDistributionRefused(); refused {
		return false, reason
	}
	if !publishGateApplies() {
		return true, ""
	}
	publishGate.mu.Lock()
	defer publishGate.mu.Unlock()
	loadPublishGateLocked()
	if publishGate.st.Armed && publishGate.st.Held {
		return false, publishGate.st.HoldReason
	}
	return true, ""
}

// haDistributionRefused reports whether this node must hand out NO
// configuration at all — to data planes or to a standby. That is narrower than
// "not publish-authorized": during a publication hold the gate answers each
// data plane itself (consistent ones are served, ahead ones keep their state)
// and HASync stays served. Here the node has no authority to distribute
// anything: it holds the leader ROLE without the fencing lease (a resume the
// lease denied, with no standby to join — the ADR-0005 S2 stance). The lease
// is the authority, so a node without it is a stale leader as far as anyone
// else can tell, and its configuration must not reach the fleet. Data planes
// keep their last-good configuration, as on any failed poll.
//
// The listener's blanket CULVERT_PUBLISH_NOT_AUTHORIZED refusal keys on THIS
// predicate, not on haPublishAuthorized.
func haDistributionRefused() (reason string, refused bool) {
	if globalHA.unfencedLeader() {
		return "this node holds the HA leader role without the fencing lease, so it is not authorized to distribute configuration", true
	}
	return "", false
}

// haPromotionCommitting reports whether a promotion of this node is in flight:
// the once-guard is taken and the node has not yet taken the leader role. Its
// activation publish must commit before leadership is exposed (ADR-0005), so
// it is the one publish made without haLeadershipHeld.
func haPromotionCommitting() bool {
	return globalHA.promoted.Load() && globalHA.Status().Role == "standby"
}
