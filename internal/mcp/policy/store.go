package policy

import (
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Store is a bounded, capability-local holder of the CURRENT immutable policy
// snapshot. Reads are lock-free (an atomic pointer load); publication is
// serialized by a leaf mutex that enforces monotonic revisions and optimistic
// (stale-base) concurrency. It keeps NO unbounded history, performs NO filesystem/
// database persistence, spawns NO background goroutine, and does NO signed CP→DP
// distribution (that is PR-10). A reader always sees a fully-published snapshot or
// none — never partial state.
type Store struct {
	capability Capability
	cur        atomic.Pointer[Snapshot]
	mu         sync.Mutex // serializes Publish only; never held during a read
}

// NewStore returns an empty capability-local store (no snapshot published yet).
func NewStore(capability Capability) *Store {
	return &Store{capability: capability}
}

// Capability returns the store's capability namespace.
func (s *Store) Capability() Capability { return s.capability }

// Current returns the current published snapshot, or nil if none is published.
// Lock-free.
func (s *Store) Current() *Snapshot { return s.cur.Load() }

// CurrentRevision returns the current published revision, or 0 if none.
func (s *Store) CurrentRevision() Revision {
	if c := s.cur.Load(); c != nil {
		return c.revision
	}
	return 0
}

func storeErr(r mcperr.Reason, detail string) error {
	return mcperr.New(r, "policy.store", detail)
}

// Publish atomically installs snap as the current snapshot. base is the revision
// the caller believes is current (optimistic concurrency): a base that does not
// equal the live current revision is rejected as stale (a concurrent publish won),
// and NOTHING is published. The new revision must be strictly greater than the
// current one, and the snapshot's capability must match the store. A rejected
// publish leaves the current snapshot unchanged.
func (s *Store) Publish(base Revision, snap *Snapshot) error {
	if snap == nil {
		return storeErr(mcperr.ReasonPolicySnapshotInvalid, "cannot publish a nil snapshot")
	}
	if snap.capability != s.capability {
		return storeErr(mcperr.ReasonPolicyNamespaceMismatch, "snapshot capability does not match the store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.cur.Load()
	curRev := Revision(0)
	if cur != nil {
		curRev = cur.revision
	}
	if base != curRev {
		return storeErr(mcperr.ReasonPolicyStaleRevision, "publish base revision is stale")
	}
	if snap.revision <= curRev {
		return storeErr(mcperr.ReasonPolicyStaleRevision, "new revision must exceed the current revision")
	}
	s.cur.Store(snap) // atomic single-pointer publication (readers never see partial state)
	return nil
}
