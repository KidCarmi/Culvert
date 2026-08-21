package broker

import (
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
)

// rotationState is the explicit per-profile rotation/lifecycle state.
type rotationState uint8

const (
	stActive rotationState = iota
	stRotationPending
	stSuccessorValidating
	stSuccessorActive
	stPreviousInGrace
	stRotationFailed
	stRevoked
	stExpired
)

func (s rotationState) String() string {
	switch s {
	case stActive:
		return "active"
	case stRotationPending:
		return "rotation_pending"
	case stSuccessorValidating:
		return "successor_validating"
	case stSuccessorActive:
		return "successor_active"
	case stPreviousInGrace:
		return "previous_in_grace"
	case stRotationFailed:
		return "rotation_failed"
	case stRevoked:
		return "revoked"
	case stExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// profileState is the per-profile lifecycle state. Its lock is a LEAF lock: the
// broker never holds it across a provider call or a materialization callback (both
// happen with no lock held), so there is no ABBA cycle and no provider/callback runs
// under a broker lock. Different profiles have independent states, so rotations for
// different profiles never block each other.
type profileState struct {
	mu                 sync.Mutex
	id                 profile.ID
	state              rotationState
	hasCurrent         bool
	currentVersion     profile.CredentialVersion
	previousVersion    profile.CredentialVersion
	previousGraceUntil time.Time
	tombstones         map[profile.CredentialVersion]struct{}
	revoked            bool // whole-profile revocation
	rotating           bool
}

// isRevoked reports whether a specific version is tombstoned or the whole profile is
// revoked. Caller holds mu.
func (s *profileState) isRevoked(v profile.CredentialVersion) bool {
	if s.revoked {
		return true
	}
	_, dead := s.tombstones[v]
	return dead
}

// usableVersion returns the version that may be materialized now, honoring
// tombstones, whole-profile revocation, and the bounded previous-version grace.
// Caller holds mu.
func (s *profileState) usableVersion(now time.Time) (profile.CredentialVersion, bool) {
	if s.revoked || !s.hasCurrent {
		// A previous version in grace may still be usable even mid-lifecycle, but a
		// whole-profile revocation blocks everything.
		if s.revoked {
			return "", false
		}
	}
	if s.hasCurrent && !s.isRevoked(s.currentVersion) {
		return s.currentVersion, true
	}
	// Previous version, only inside the bounded grace window and not tombstoned.
	if s.previousVersion != "" && now.Before(s.previousGraceUntil) && !s.isRevoked(s.previousVersion) {
		return s.previousVersion, true
	}
	return "", false
}

// setCurrent records a freshly fetched/validated current version. Caller holds mu.
func (s *profileState) setCurrent(v profile.CredentialVersion) {
	s.currentVersion = v
	s.hasCurrent = true
	if s.state == stRotationFailed || s.state == stExpired {
		s.state = stActive
	}
	if s.state == stActive || s.state == 0 {
		s.state = stActive
	}
}

// snapshotState returns the current rotation state under the lock.
func (s *profileState) snapshotState() rotationState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// snapshotRevoked reports whole-profile revocation under the lock.
func (s *profileState) snapshotRevoked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked
}

// snapshotRevokedVersion reports whether a version is tombstoned/revoked under the
// lock.
func (s *profileState) snapshotRevokedVersion(v profile.CredentialVersion) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isRevoked(v)
}

// tombstoneCount bounds the tombstone set (attacker/churn resistance). Caller holds
// mu. Oldest-insertion pruning is unnecessary because revocation is admin-driven and
// bounded by MaxTombstones; on overflow we refuse further distinct tombstones by
// collapsing to whole-profile revocation (fail closed).
func (s *profileState) addTombstone(v profile.CredentialVersion, maxTombstones int) {
	if _, ok := s.tombstones[v]; ok {
		return
	}
	if len(s.tombstones) >= maxTombstones {
		// Fail closed: too many distinct tombstones ⇒ revoke the whole profile.
		s.revoked = true
		s.state = stRevoked
		return
	}
	s.tombstones[v] = struct{}{}
}
