// Package publication implements the Control-Plane publication, acknowledgement
// tracking, and rollback coordinator for signed MCP snapshots. It reuses the PR-9
// four-eyes approval + exact candidate binding (via injected callbacks), the HA
// lease/write-authority gate (injected), the PR-8 durable P-CRIT commit (injected,
// commit-before-side-effect), the accepted PR-10 signer/envelope, and the existing
// CP/DP transport (injected). It never signs, installs, pushes, or swaps anything
// before the PR-8 configuration-publication event is durably committed.
package publication

import (
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// DistributionState is the truthful state of a capability's distribution. It is
// derived from acknowledgements, never from the mere fact that the CP signed or
// stored a snapshot.
type DistributionState string

const (
	// StateLocalOnly — no signed CP→DP distribution is configured/active (node-local).
	StateLocalOnly DistributionState = "local_only"
	// StatePendingDistribution — signed, installed, pushed; acknowledgements not yet in.
	StatePendingDistribution DistributionState = "pending_distribution"
	// StatePartiallyAcknowledged — some intended compatible DPs applied, not all.
	StatePartiallyAcknowledged DistributionState = "partially_acknowledged"
	// StateFullyAcknowledged — every intended compatible DP applied.
	StateFullyAcknowledged DistributionState = "fully_acknowledged"
	// StateRejectedByAll — every intended DP rejected the snapshot.
	StateRejectedByAll DistributionState = "rejected_by_all"
	// StateDistributionDegraded — some DPs unavailable while others applied.
	StateDistributionDegraded DistributionState = "distribution_degraded"
	// StateRollbackPending — a rollback is signed/pushed, awaiting acknowledgements.
	StateRollbackPending DistributionState = "rollback_pending"
	// StateRolledBack — every intended DP acknowledged the rollback.
	StateRolledBack DistributionState = "rolled_back"
)

// DistributionCounts is the safe per-capability distribution tally.
type DistributionCounts struct {
	Intended     int `json:"intended"`
	Applied      int `json:"applied"`
	RolledBack   int `json:"rolled_back"`
	Rejected     int `json:"rejected"`
	Incompatible int `json:"incompatible"`
	Unavailable  int `json:"unavailable"`
}

// DeriveState maps distribution counts for a specific published hash to a truthful
// DistributionState. It is the exported entry point for read-only admin models
// (e.g. the acknowledgement read model); it never infers a state from anything but
// the real counts.
func DeriveState(c DistributionCounts) DistributionState { return deriveState(c) }

// deriveState maps the counts for a specific published hash to a truthful state.
func deriveState(c DistributionCounts) DistributionState {
	if c.Intended == 0 {
		return StateLocalOnly
	}
	// Rollback outcomes the forward branches below cannot represent (they would
	// fold an all-rolled-back fleet into pending_distribution). A forward publish of
	// a hash never yields rolled_back acks for that same hash, so RolledBack==0 on
	// the forward path and this block is byte-identical there; it only fires for a
	// hash a rollback has targeted. A rolled_back ack mixed with competing
	// applies/rejects is NOT a clean rollback, so it falls through to the
	// degraded/partial branches rather than masking them.
	if c.RolledBack == c.Intended {
		return StateRolledBack
	}
	if c.RolledBack > 0 && c.Applied == 0 && c.Rejected == 0 {
		return StateRollbackPending
	}
	if c.Applied == c.Intended {
		return StateFullyAcknowledged
	}
	if c.Applied == 0 && c.Rejected == c.Intended {
		return StateRejectedByAll
	}
	if c.Applied == 0 && c.Rejected == 0 {
		return StatePendingDistribution
	}
	if c.Unavailable > 0 && c.Applied > 0 {
		return StateDistributionDegraded
	}
	return StatePartiallyAcknowledged
}

// AckTracker tracks acknowledgements per (node × capability × content hash). It is
// bounded, idempotent, and refuses to regress a newer state or accept an ack for
// an unknown hash or a mismatched node/capability.
type AckTracker struct {
	mu         sync.Mutex
	capability cpdp.Capability
	limits     cpdp.Limits
	// known content hashes the CP has published (only acks for these are accepted).
	known map[string]bool
	// key: node|hash → the latest ack.
	acks map[string]cpdp.Acknowledgement
}

// NewAckTracker returns a bounded tracker for a capability.
func NewAckTracker(capability cpdp.Capability, limits cpdp.Limits) *AckTracker {
	return &AckTracker{
		capability: capability, limits: limits,
		known: make(map[string]bool), acks: make(map[string]cpdp.Acknowledgement),
	}
}

// MarkKnown registers a content hash the CP has published (so acknowledgements for
// it are accepted). An ack for an unknown hash is rejected.
func (t *AckTracker) MarkKnown(contentHash string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.known) < t.limits.MaxAckHistory() {
		t.known[contentHash] = true
	}
}

func ackKey(node, hash string) string { return node + "|" + hash }

// ackRank orders ack states so a stale state cannot regress a newer one.
func ackRank(s cpdp.AckState) int {
	switch s {
	case cpdp.AckReceived:
		return 1
	case cpdp.AckValidated:
		return 2
	case cpdp.AckRejected:
		return 3
	case cpdp.AckApplied:
		return 4
	case cpdp.AckRolledBack:
		return 5
	default:
		return 0
	}
}

// Record ingests an acknowledgement. The ack must carry an authenticated node id
// (the caller has already authenticated the enrolled node and MUST pass its
// verified identity as authNodeID), match this capability, and reference a known
// content hash. A duplicate identical ack is idempotent; a stale state cannot
// regress a newer one.
func (t *AckTracker) Record(authNodeID string, a cpdp.Acknowledgement) error {
	if authNodeID == "" {
		return mcperr.New(mcperr.ReasonAckUnauthenticated, "cpdp.pub.ack", "unauthenticated acknowledgement")
	}
	if err := a.Validate(); err != nil {
		return err
	}
	if a.NodeID != authNodeID {
		return mcperr.New(mcperr.ReasonAckInvalid, "cpdp.pub.ack", "ack node id does not match authenticated identity")
	}
	if a.Capability != t.capability {
		return mcperr.New(mcperr.ReasonAckInvalid, "cpdp.pub.ack", "ack capability mismatch")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.known[a.ContentHash] {
		return mcperr.New(mcperr.ReasonAckInvalid, "cpdp.pub.ack", "ack references an unknown content hash")
	}
	key := ackKey(a.NodeID, a.ContentHash)
	if prev, ok := t.acks[key]; ok && ackRank(a.State) < ackRank(prev.State) {
		return nil // stale state cannot regress a newer one (idempotent no-op)
	}
	if len(t.acks) >= t.limits.MaxAcksPerNodeCap() {
		if _, exists := t.acks[key]; !exists {
			return mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.pub.ack", "acknowledgement table full")
		}
	}
	t.acks[key] = a
	return nil
}

// Counts tallies acknowledgements for a published hash against the intended node
// set. incompatible is the subset of rejections whose reason is a min-version
// mismatch.
func (t *AckTracker) Counts(contentHash string, intended []string) DistributionCounts {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := DistributionCounts{Intended: len(intended)}
	for _, node := range intended {
		a, ok := t.acks[ackKey(node, contentHash)]
		if !ok {
			c.Unavailable++
			continue
		}
		switch a.State {
		case cpdp.AckApplied:
			c.Applied++
		case cpdp.AckRolledBack:
			c.RolledBack++
		case cpdp.AckRejected:
			c.Rejected++
			if a.RejectReason == mcperr.ReasonSnapshotMinVersionUnmet.Code() {
				c.Incompatible++
			}
		default:
			c.Unavailable++
		}
	}
	return c
}

// AckFor returns the latest recorded acknowledgement for (node, contentHash) and
// whether one exists. It is a bounded, read-only accessor (a defensive copy of the
// stored value) so an admin read model can render per-DP rows without mutating or
// exposing the tracker's internal maps. The ABSENCE of an ack (ok=false) is the
// truthful "no acknowledgement yet" state - the caller must render it as such
// (e.g. "unavailable"), never as a benign default.
func (t *AckTracker) AckFor(node, contentHash string) (cpdp.Acknowledgement, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.acks[ackKey(node, contentHash)]
	return a, ok
}
