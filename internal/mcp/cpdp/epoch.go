package cpdp

import (
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// EpochRatchet is a pure, in-memory monotonic fencing-epoch ratchet that splits
// the existing dpObserveEpoch check-and-commit into two explicit operations, as
// PR-10 requires: a NON-mutating preliminary stale check (CheckEpoch), used before
// signature/schema validation; and a mutating ratchet (CommitObservedEpoch), used
// only AFTER authenticity is proven. This ordering is what prevents a malicious or
// corrupt high-epoch envelope from permanently fencing out the currently trusted
// CP before authenticity is established (MCP-HA-001).
//
// It preserves the two special rejects of the root dpObserveEpoch: an epoch below
// the last-seen epoch is stale, and a zero/unfenced epoch after a positive epoch
// has already been seen is a zombie signal. The ratchet is seeded at startup from
// the DP's durable last-seen epoch and never regresses.
type EpochRatchet struct {
	mu   sync.Mutex
	last int64
}

// NewEpochRatchet returns a ratchet seeded to seed (the DP's durable last-seen
// trusted epoch; 0 means unseeded/legacy).
func NewEpochRatchet(seed int64) *EpochRatchet {
	if seed < 0 {
		seed = 0
	}
	return &EpochRatchet{last: seed}
}

// Last returns the highest observed trusted epoch.
func (r *EpochRatchet) Last() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last
}

// CheckEpoch performs the NON-mutating preliminary check. It rejects:
//
//   - an epoch below the last-seen epoch (a stale/zombie Control Plane); and
//   - a zero/unfenced epoch once a positive epoch has already been seen.
//
// It NEVER advances the ratchet — a snapshot that passes CheckEpoch must still be
// authenticated (signature/schema/revisions/min-version) before CommitObservedEpoch
// is called. A same-or-higher trusted epoch returns nil.
func (r *EpochRatchet) CheckEpoch(epoch int64) error {
	r.mu.Lock()
	last := r.last
	r.mu.Unlock()
	if epoch <= 0 {
		if last == 0 {
			return nil // pure-legacy: unfenced is acceptable until a positive epoch is seen
		}
		return mcperr.New(mcperr.ReasonSnapshotEpochInvalid, "cpdp.epoch",
			"unfenced/zero epoch after a positive epoch was observed")
	}
	if epoch < last {
		return mcperr.New(mcperr.ReasonSnapshotEpochStale, "cpdp.epoch",
			"epoch below the last-seen trusted epoch")
	}
	return nil
}

// CommitObservedEpoch ratchets the trusted epoch forward to epoch, returning true
// if the ratchet advanced (so the caller can persist the new durable last-seen
// epoch). It MUST be called only after the snapshot's authenticity has been
// proven. It re-applies the stale/zombie guards under the lock so a racing lower
// or zero epoch can never win. A same epoch is accepted (idempotent) but does not
// advance; a higher epoch advances.
func (r *EpochRatchet) CommitObservedEpoch(epoch int64) (advanced bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if epoch <= 0 {
		if r.last == 0 {
			return false, nil // legacy: nothing to ratchet
		}
		return false, mcperr.New(mcperr.ReasonSnapshotEpochInvalid, "cpdp.epoch",
			"refuse to ratchet to an unfenced/zero epoch")
	}
	if epoch < r.last {
		return false, mcperr.New(mcperr.ReasonSnapshotEpochStale, "cpdp.epoch",
			"refuse to ratchet below the last-seen epoch")
	}
	if epoch == r.last {
		return false, nil
	}
	r.last = epoch
	return true, nil
}
