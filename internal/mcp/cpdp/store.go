package cpdp

import (
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// ActiveStore is a capability-local holder of the current and previous signed
// snapshots. The request/tool-call path reads the current active pointer LOCK-FREE
// (an atomic load) and never blocks on the CP, the signer, an acknowledgement
// service, or storage (MCP-HA-001). Swaps and rollbacks are serialized by a mutex
// that the request path never touches.
//
// One ActiveStore instance serves exactly one capability; a Gateway store can
// never hold or activate Management state and vice versa.
type ActiveStore struct {
	capability Capability

	current  atomic.Pointer[Envelope] // lock-free read by the request path
	previous atomic.Pointer[Envelope]

	swapMu sync.Mutex // serializes Activate/Revert; never held by the request path
}

// NewActiveStore returns an empty capability-local store. Until a valid snapshot
// is activated, Active returns nil (the DP stays disabled / fails closed for that
// capability).
func NewActiveStore(capability Capability) *ActiveStore {
	return &ActiveStore{capability: capability}
}

// Capability returns the capability this store serves.
func (s *ActiveStore) Capability() Capability { return s.capability }

// Active returns the current active snapshot, or nil if none is active. This is
// the lock-free read the request path uses.
func (s *ActiveStore) Active() *Envelope { return s.current.Load() }

// Previous returns the retained previous snapshot, or nil.
func (s *ActiveStore) Previous() *Envelope { return s.previous.Load() }

// ActiveHash returns the current active content hash, or "" if none.
func (s *ActiveStore) ActiveHash() string {
	if e := s.current.Load(); e != nil {
		return e.ContentHash
	}
	return ""
}

// PreviousHash returns the retained previous content hash, or "".
func (s *ActiveStore) PreviousHash() string {
	if e := s.previous.Load(); e != nil {
		return e.ContentHash
	}
	return ""
}

// Activate atomically installs env as the current snapshot, moving the prior
// current to previous. The caller MUST have already validated env (whole-snapshot
// validation) and durably persisted it BEFORE calling Activate — this is the swap
// step of persist-before-swap, not the validation or persistence step.
//
// Semantics:
//
//   - env's capability must match the store's, else it fails closed.
//   - If env's content hash equals the current active hash, the activation is
//     idempotent: the store is unchanged and (false, nil) is returned.
//   - If env carries the SAME config revision+epoch as the current active snapshot
//     but a DIFFERENT content hash, it is rejected (same revision, different
//     content) — a revision must never name two different contents.
//   - Otherwise the swap advances: previous ← current, current ← env, and
//     (true, nil) is returned.
func (s *ActiveStore) Activate(env *Envelope) (swapped bool, err error) {
	if env == nil {
		return false, mcperr.New(mcperr.ReasonSnapshotMalformed, "cpdp.store", "nil envelope")
	}
	if env.Manifest.Capability != s.capability {
		return false, mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.store", "envelope capability does not match store")
	}
	s.swapMu.Lock()
	defer s.swapMu.Unlock()

	cur := s.current.Load()
	if cur != nil {
		if cur.ContentHash == env.ContentHash {
			return false, nil // idempotent: already active
		}
		// Same config revision + epoch but different content ⇒ reject.
		if cur.Manifest.Epoch == env.Manifest.Epoch &&
			cur.Manifest.Revisions.Config == env.Manifest.Revisions.Config {
			return false, mcperr.New(mcperr.ReasonSnapshotRevisionRegression, "cpdp.store",
				"same revision with a different content hash")
		}
		s.previous.Store(cur)
	}
	s.current.Store(env)
	return true, nil
}

// Revert atomically reverts the current pointer to a retained target snapshot
// identified by targetHash. The target MUST be the retained previous snapshot
// (the only retained rollback target in the current+previous retention model).
// The caller has already verified the signed rollback directive AND re-verified
// the target snapshot's signature/hash before calling Revert. On success the prior
// current becomes previous (so the operation is itself reversible) and (true, nil)
// is returned. A missing/mismatched target fails closed and leaves the current
// pointer UNCHANGED.
func (s *ActiveStore) Revert(targetHash string) (reverted bool, err error) {
	s.swapMu.Lock()
	defer s.swapMu.Unlock()

	prev := s.previous.Load()
	if prev == nil || prev.ContentHash != targetHash {
		return false, mcperr.New(mcperr.ReasonRollbackTargetMissing, "cpdp.store", "rollback target not retained")
	}
	cur := s.current.Load()
	// Swap: current ← previous target, previous ← prior current.
	s.current.Store(prev)
	if cur != nil {
		s.previous.Store(cur)
	}
	return true, nil
}

// Restore reinstalls a validated (current, previous) pair at startup recovery. Both
// envelopes must already be signature/hash-verified and match the store's
// capability. current may be nil only if previous is also nil.
func (s *ActiveStore) Restore(current, previous *Envelope) error {
	s.swapMu.Lock()
	defer s.swapMu.Unlock()
	if current == nil && previous != nil {
		return mcperr.New(mcperr.ReasonSnapshotMalformed, "cpdp.store", "previous without current")
	}
	if current != nil && current.Manifest.Capability != s.capability {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.store", "current capability mismatch")
	}
	if previous != nil && previous.Manifest.Capability != s.capability {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.store", "previous capability mismatch")
	}
	s.current.Store(current)
	s.previous.Store(previous)
	return nil
}
