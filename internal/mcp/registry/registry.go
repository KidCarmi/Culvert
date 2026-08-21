package registry

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Snapshot is an immutable point-in-time view of the registry. Its maps are never
// mutated after publication, so any number of readers may use a Snapshot
// concurrently with no lock while writers publish newer ones (copy-on-write).
type Snapshot struct {
	revision uint64
	byID     map[ServerID]*ServerRecord
	byEndpt  map[Endpoint]ServerID
}

// Revision returns the monotonically increasing snapshot revision.
func (s *Snapshot) Revision() uint64 { return s.revision }

// Len returns the number of registered servers.
func (s *Snapshot) Len() int { return len(s.byID) }

// Get returns a COPY of the record for id and whether it is present. Callers
// receive a value, never the stored pointer, so they cannot mutate the snapshot.
func (s *Snapshot) Get(id ServerID) (ServerRecord, bool) {
	r, ok := s.byID[id]
	if !ok {
		return ServerRecord{}, false
	}
	return *r, true
}

// Servers returns copies of all records in deterministic ServerID order.
func (s *Snapshot) Servers() []ServerRecord {
	out := make([]ServerRecord, 0, len(s.byID))
	for _, r := range s.byID {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Registry owns the live registry state. Writes are serialized by mu (a leaf lock
// never held across a call into another subsystem, so no ABBA is possible);
// reads go through an atomic snapshot pointer and take no lock.
type Registry struct {
	mu  sync.Mutex
	cur atomic.Pointer[Snapshot]
	lim limits.CatalogLimits
}

// New returns an empty Registry bounded by lim.
func New(lim limits.CatalogLimits) *Registry {
	r := &Registry{lim: lim}
	r.cur.Store(&Snapshot{
		byID:    map[ServerID]*ServerRecord{},
		byEndpt: map[Endpoint]ServerID{},
	})
	return r
}

// Current returns the current immutable snapshot (lock-free).
func (r *Registry) Current() *Snapshot { return r.cur.Load() }

// Register validates in and adds a new enabled+verified server, returning a copy
// of the stored record. It fails on a malformed field, a duplicate id, an
// already-registered canonical endpoint, a non-Gateway capability, or when the
// server capacity is reached — leaving the current snapshot unchanged on any error.
func (r *Registry) Register(in Registration) (ServerRecord, error) {
	if err := in.validate(r.lim); err != nil {
		return ServerRecord{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	base := r.cur.Load()
	if _, dup := base.byID[in.ID]; dup {
		return ServerRecord{}, invalidReg("server id already registered")
	}
	if _, dup := base.byEndpt[in.Endpoint]; dup {
		return ServerRecord{}, invalidReg("canonical endpoint already registered to another server")
	}
	if len(base.byID) >= r.lim.MaxServers() {
		return ServerRecord{}, mcperr.New(mcperr.ReasonCapacityExceeded, "registry.register", "server capacity reached")
	}
	rev := base.revision + 1
	rec := &ServerRecord{
		ID:                in.ID,
		Endpoint:          in.Endpoint,
		PinnedIdentity:    in.PinnedIdentity,
		Capability:        in.Capability,
		CredentialProfile: in.CredentialProfile,
		OwnerScope:        in.OwnerScope,
		Enabled:           true,
		Verification:      VerifyVerified,
		Revision:          rev,
		CreatedAt:         in.CreatedAt,
		UpdatedAt:         in.UpdatedAt,
	}
	next := base.clone(rev)
	next.byID[in.ID] = rec
	next.byEndpt[in.Endpoint] = in.ID
	r.cur.Store(next)
	return *rec, nil
}

// VerifyIdentity compares a freshly VERIFIED identity (supplied by the caller —
// the registry does not perform the network verification) against the server's
// pin. On an EXACT match it returns (VerifyVerified, record, nil). On a mismatch
// it DISABLES the server, records VerifyIdentityMismatch in a new snapshot, and
// returns a ReasonServerIdentityMismatch error — a server-level transition that
// can never be downgraded to tool-schema drift (MCP-SERVER-003). An unknown id
// returns ReasonUnregisteredServer.
func (r *Registry) VerifyIdentity(id ServerID, observed Identity) (Verification, ServerRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	base := r.cur.Load()
	cur, ok := base.byID[id]
	if !ok {
		return VerifyIdentityMismatch, ServerRecord{},
			mcperr.New(mcperr.ReasonUnregisteredServer, "registry.verify", "server id is not registered")
	}
	if observed == cur.PinnedIdentity && cur.Verification == VerifyVerified {
		return VerifyVerified, *cur, nil // exact match, no state change
	}
	if observed == cur.PinnedIdentity {
		// Identity matches but the server was previously mismatched/disabled: it stays
		// disabled until a fresh registration re-pins it (re-verification is explicit).
		return cur.Verification, *cur,
			mcperr.New(mcperr.ReasonServerIdentityMismatch, "registry.verify", "server disabled pending re-registration")
	}
	// Mismatch: disable and record the identity-change transition.
	rev := base.revision + 1
	updated := *cur
	updated.Enabled = false
	updated.Verification = VerifyIdentityMismatch
	updated.Revision = rev
	next := base.clone(rev)
	next.byID[id] = &updated
	r.cur.Store(next)
	return VerifyIdentityMismatch, updated,
		mcperr.New(mcperr.ReasonServerIdentityMismatch, "registry.verify", "verified identity does not match the pin")
}

// SetEnabled toggles the admin enable/disable flag. It refuses to re-enable a
// server whose identity mismatched: that transition is cleared only by a fresh
// registration (re-verification), never by an admin flag. An unknown id returns
// ReasonUnregisteredServer.
func (r *Registry) SetEnabled(id ServerID, enabled bool) (ServerRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	base := r.cur.Load()
	cur, ok := base.byID[id]
	if !ok {
		return ServerRecord{}, mcperr.New(mcperr.ReasonUnregisteredServer, "registry.enable", "server id is not registered")
	}
	if enabled && cur.Verification == VerifyIdentityMismatch {
		return ServerRecord{}, mcperr.New(mcperr.ReasonServerIdentityMismatch, "registry.enable", "cannot enable a server pending re-verification")
	}
	if cur.Enabled == enabled {
		return *cur, nil // no-op, no new snapshot
	}
	rev := base.revision + 1
	updated := *cur
	updated.Enabled = enabled
	updated.Revision = rev
	next := base.clone(rev)
	next.byID[id] = &updated
	r.cur.Store(next)
	return updated, nil
}

// Repin is the documented recovery path after an identity change: it re-pins an
// EXISTING server to a freshly VERIFIED identity (supplied by the caller — the
// registry does not perform the verification), clears the mismatch, and re-enables
// the server under its stable ServerID. It fails for an unknown id or a malformed
// identity, leaving the snapshot unchanged. This is the ONLY transition that
// clears VerifyIdentityMismatch, so a mismatched server is never permanently
// stuck: an operator re-verifies out of band and calls Repin.
func (r *Registry) Repin(id ServerID, newIdentity Identity, updatedAt time.Time) (ServerRecord, error) {
	if newIdentity == "" {
		return ServerRecord{}, invalidReg("pinned identity is required")
	}
	if err := validateOpaqueToken(string(newIdentity), r.lim.MaxIdentityBytes(), "identity"); err != nil {
		return ServerRecord{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	base := r.cur.Load()
	cur, ok := base.byID[id]
	if !ok {
		return ServerRecord{}, mcperr.New(mcperr.ReasonUnregisteredServer, "registry.repin", "server id is not registered")
	}
	rev := base.revision + 1
	updated := *cur
	updated.PinnedIdentity = newIdentity
	updated.Verification = VerifyVerified
	updated.Enabled = true
	updated.Revision = rev
	updated.UpdatedAt = updatedAt
	next := base.clone(rev)
	next.byID[id] = &updated
	r.cur.Store(next)
	return updated, nil
}

// clone returns a shallow copy of the snapshot maps stamped with a new revision.
// Record pointers are shared because records are never mutated in place — a
// change replaces the pointer, so old snapshots keep observing the old record.
func (s *Snapshot) clone(rev uint64) *Snapshot {
	byID := make(map[ServerID]*ServerRecord, len(s.byID)+1)
	for k, v := range s.byID {
		byID[k] = v
	}
	byEndpt := make(map[Endpoint]ServerID, len(s.byEndpt)+1)
	for k, v := range s.byEndpt {
		byEndpt[k] = v
	}
	return &Snapshot{revision: rev, byID: byID, byEndpt: byEndpt}
}
