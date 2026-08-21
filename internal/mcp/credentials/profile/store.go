package profile

import (
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// Snapshot is an immutable set of credential profiles at a revision. Its map is
// never mutated after publication, so any number of readers use it lock-free while
// a writer publishes a newer one (copy-on-write).
type Snapshot struct {
	revision uint64
	byID     map[ID]*Profile
}

// Revision returns the monotonically increasing snapshot revision.
func (s *Snapshot) Revision() uint64 { return s.revision }

// Len returns the number of profiles.
func (s *Snapshot) Len() int { return len(s.byID) }

// Get returns the profile for id and whether it is present. The returned Profile is
// immutable (its slices/maps are reachable only through copying accessors).
func (s *Snapshot) Get(id ID) (Profile, bool) {
	p, ok := s.byID[id]
	if !ok {
		return Profile{}, false
	}
	return *p, true
}

// Store holds credential profiles as immutable snapshots. Writers serialize on mu
// and publish a new snapshot via an atomic pointer; readers load the current
// snapshot without locking. A failed update leaves the current snapshot unchanged
// (no partial publication).
type Store struct {
	mu  sync.Mutex
	cur atomic.Pointer[Snapshot]
	lim limits.CredentialLimits
}

// NewStore returns an empty profile store bounded by lim.
func NewStore(lim limits.CredentialLimits) *Store {
	s := &Store{lim: lim}
	s.cur.Store(&Snapshot{revision: 0, byID: make(map[ID]*Profile)})
	return s
}

// Current returns the current immutable snapshot.
func (s *Store) Current() *Snapshot { return s.cur.Load() }

// Add validates in against reg and the store's limits and publishes a new snapshot
// containing the profile. It rejects a duplicate/conflicting id, and global /
// per-tenant / per-server capacity exhaustion. On any error the current snapshot is
// unchanged.
func (s *Store) Add(in Input, reg *registry.Snapshot) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.cur.Load()
	if err := validID("profile id", string(in.ID)); err != nil {
		return Profile{}, err
	}
	if _, exists := old.byID[in.ID]; exists {
		return Profile{}, mcperr.New(mcperr.ReasonCredentialProfileAmbiguous, "credentials.profile", "a profile with this id already exists")
	}
	if len(old.byID) >= s.lim.MaxProfiles() {
		return Profile{}, mcperr.New(mcperr.ReasonResourceLimit, "credentials.profile", "profile capacity exhausted")
	}
	if s.countTenant(old, in.Tenant) >= s.lim.MaxProfilesPerTenant() {
		return Profile{}, mcperr.New(mcperr.ReasonResourceLimit, "credentials.profile", "per-tenant profile capacity exhausted")
	}
	if s.countServer(old, in.Server) >= s.lim.MaxProfilesPerServer() {
		return Profile{}, mcperr.New(mcperr.ReasonResourceLimit, "credentials.profile", "per-server profile capacity exhausted")
	}
	rev := old.revision + 1
	p, err := NewProfile(in, reg, s.lim, rev)
	if err != nil {
		return Profile{}, err
	}
	next := cloneMap(old.byID)
	stored := p
	next[p.id] = &stored
	s.cur.Store(&Snapshot{revision: rev, byID: next})
	return p, nil
}

// SetEnabled toggles a profile's enabled state, publishing a new snapshot. baseRev
// must equal the current snapshot revision (optimistic concurrency): a stale base
// is rejected so a concurrent update cannot be silently clobbered.
func (s *Store) SetEnabled(id ID, enabled bool, baseRev uint64) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.cur.Load()
	if baseRev != old.revision {
		return Profile{}, mcperr.New(mcperr.ReasonCredentialVersionStale, "credentials.profile", "stale base revision")
	}
	p, ok := old.byID[id]
	if !ok {
		return Profile{}, mcperr.New(mcperr.ReasonCredentialProfileMissing, "credentials.profile", "profile not found")
	}
	rev := old.revision + 1
	updated := p.withEnabled(enabled).withRevision(rev)
	next := cloneMap(old.byID)
	next[id] = &updated
	s.cur.Store(&Snapshot{revision: rev, byID: next})
	return updated, nil
}

func (s *Store) countTenant(snap *Snapshot, t identity.TenantID) int {
	n := 0
	for _, p := range snap.byID {
		if p.tenant == t {
			n++
		}
	}
	return n
}

func (s *Store) countServer(snap *Snapshot, srv registry.ServerID) int {
	n := 0
	for _, p := range snap.byID {
		if p.server == srv {
			n++
		}
	}
	return n
}

func cloneMap(m map[ID]*Profile) map[ID]*Profile {
	out := make(map[ID]*Profile, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}
