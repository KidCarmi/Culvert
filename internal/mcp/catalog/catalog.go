package catalog

import (
	"sort"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// Eligibility is a catalog entry's usability state. The states make it
// IMPOSSIBLE to confuse a quarantined/disabled tool with an approved one: no
// PR-2 ingestion path ever produces Usable (approval is a later slice), and
// Quarantined is a sticky floor that repeated discovery never auto-clears.
type Eligibility uint8

const (
	// Quarantined — unknown tool or privilege expansion. NEVER auto-allowed; only a
	// (future) human approval action clears it. Survives repeated ingestion.
	Quarantined Eligibility = iota
	// ReviewRequired — semantic drift; routed to human review.
	ReviewRequired
	// PendingNarrowing — safe narrowing; pending notification/review disposition.
	PendingNarrowing
	// ServerDisabled — the server's identity changed; every tool behind it is
	// unusable until the server is re-verified (re-registered).
	ServerDisabled
	// Usable — an approved, known tool with no material change. UNREACHABLE through
	// PR-2 ingestion; only a later approval slice can set it. Present so the model
	// and the no-material-change preservation rule are complete.
	Usable
)

// String returns the eligibility label.
func (e Eligibility) String() string {
	switch e {
	case Quarantined:
		return "quarantined"
	case ReviewRequired:
		return "review_required"
	case PendingNarrowing:
		return "pending_narrowing"
	case ServerDisabled:
		return "server_disabled"
	case Usable:
		return "usable"
	default:
		return "invalid"
	}
}

// ToolRecord is one immutable catalog entry: the tool key, its last-known
// fingerprint, the schema-canonical schema trees (retained for the next diff),
// its eligibility, and the catalog revision at which it was written. Callers
// receive copies; records are never mutated in place.
type ToolRecord struct {
	Key          ToolKey
	Fingerprint  Fingerprint
	InputSchema  *canonical.Node
	OutputSchema *canonical.Node // nil when the tool declares no output schema
	Eligibility  Eligibility
	Revision     uint64
}

// Snapshot is an immutable catalog view; its map is never mutated after
// publication, so any number of readers may use it lock-free while writers
// publish newer ones (copy-on-write).
type Snapshot struct {
	revision uint64
	byKey    map[ToolKey]*ToolRecord
}

// Revision returns the monotonically increasing snapshot revision.
func (s *Snapshot) Revision() uint64 { return s.revision }

// Len returns the number of catalog entries.
func (s *Snapshot) Len() int { return len(s.byKey) }

// Get returns a copy of the record for key and whether it is present.
func (s *Snapshot) Get(key ToolKey) (ToolRecord, bool) {
	r, ok := s.byKey[key]
	if !ok {
		return ToolRecord{}, false
	}
	return *r, true
}

// Records returns copies of all entries in deterministic (server, name) order.
func (s *Snapshot) Records() []ToolRecord {
	out := make([]ToolRecord, 0, len(s.byKey))
	for _, r := range s.byKey {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key.Server != out[j].Key.Server {
			return out[i].Key.Server < out[j].Key.Server
		}
		return out[i].Key.Name < out[j].Key.Name
	})
	return out
}

// maxPublishRetries bounds the optimistic CAS retry loop so a hostile concurrent
// load cannot livelock a publisher forever; on exhaustion the caller sees a stale
// snapshot error and decides.
const maxPublishRetries = 64

// Catalog owns the live catalog state. It is lock-free: reads load the atomic
// snapshot pointer; writes build a new snapshot from a captured base and install
// it with a single CAS (retrying against the newer base on conflict). A failed or
// stale publish leaves the current snapshot byte-for-byte unchanged, and no ABBA
// is possible because no lock is ever held.
type Catalog struct {
	cur atomic.Pointer[Snapshot]
	lim limits.CatalogLimits
}

// New returns an empty Catalog bounded by lim.
func New(lim limits.CatalogLimits) *Catalog {
	c := &Catalog{lim: lim}
	c.cur.Store(&Snapshot{byKey: map[ToolKey]*ToolRecord{}})
	return c
}

// Current returns the current immutable snapshot (lock-free).
func (c *Catalog) Current() *Snapshot { return c.cur.Load() }

// Observation is the per-tool outcome of an ingestion: its key, drift class, the
// deterministic field diffs, and the resulting eligibility.
type Observation struct {
	Key         ToolKey
	Class       DriftClass
	Diffs       []FieldDiff
	Eligibility Eligibility
}

// Report is the outcome of a whole discovery ingestion.
type Report struct {
	ServerID     registry.ServerID
	Observations []Observation
	Revision     uint64
}

// Ingest validates and classifies a discovery result for one server and publishes
// a new catalog snapshot. It is fail-closed at every server-level gate BEFORE any
// tool is processed, so a server-identity problem can never be laundered into a
// tool-schema verdict, and it is all-or-nothing (a validation error publishes
// NOTHING, leaving the previous snapshot unchanged):
//
//   - the server must be registered and usable (else unregistered/mismatch error);
//   - the supplied verified identity must EXACTLY match the pin (else a
//     server-identity mismatch — discovery is not processed);
//   - the whole result parses and validates strictly (else malformed/limit error).
//
// Each tool is classified against its last-known record and written with a
// disposition that never yields Usable and never auto-clears an existing
// quarantine.
func (c *Catalog) Ingest(server registry.ServerRecord, in DiscoveryInput) (*Snapshot, *Report, error) {
	if server.ID != in.ServerID {
		return nil, nil, mcperr.New(mcperr.ReasonUnregisteredServer, "catalog.ingest", "server record does not match input server id")
	}
	if !server.Usable() {
		if server.Verification == registry.VerifyIdentityMismatch {
			return nil, nil, mcperr.New(mcperr.ReasonServerIdentityMismatch, "catalog.ingest", "server disabled by identity mismatch")
		}
		return nil, nil, mcperr.New(mcperr.ReasonUnregisteredServer, "catalog.ingest", "server is not enabled")
	}
	if in.Identity != server.PinnedIdentity {
		return nil, nil, mcperr.New(mcperr.ReasonServerIdentityMismatch, "catalog.ingest", "verified identity does not match the server pin")
	}
	observed, err := parseDiscovery(server, in, c.lim)
	if err != nil {
		return nil, nil, err
	}
	return c.publishIngest(server.ID, observed)
}

// publishIngest classifies observed records against the current base and installs
// the new snapshot via optimistic CAS, retrying against the newer base on
// conflict (bounded). Classification is recomputed each attempt so a concurrent
// update to the same tool is honored.
func (c *Catalog) publishIngest(serverID registry.ServerID, observed []*ToolRecord) (*Snapshot, *Report, error) {
	for attempt := 0; attempt < maxPublishRetries; attempt++ {
		base := c.cur.Load()
		next, report, err := c.buildIngest(base, serverID, observed)
		if err != nil {
			return nil, nil, err
		}
		if err := c.tryPublish(base, next); err == nil {
			return next, report, nil
		}
	}
	return nil, nil, mcperr.New(mcperr.ReasonStaleSnapshot, "catalog.ingest", "snapshot contention exceeded retry bound")
}

// tryPublish installs next only if base is still current (single-shot optimistic
// CAS). On conflict it returns ReasonStaleSnapshot, leaving the installed
// snapshot unchanged.
func (c *Catalog) tryPublish(base, next *Snapshot) error {
	if c.cur.CompareAndSwap(base, next) {
		return nil
	}
	return mcperr.New(mcperr.ReasonStaleSnapshot, "catalog.publish", "base snapshot is no longer current")
}

// buildIngest is the pure build step: it classifies each observed record against
// base, computes the disposition, and returns the next snapshot + report without
// mutating base. It enforces the total catalog-entry capacity.
func (c *Catalog) buildIngest(base *Snapshot, serverID registry.ServerID, observed []*ToolRecord) (*Snapshot, *Report, error) {
	rev := base.revision + 1
	next := base.clone(rev)
	report := &Report{ServerID: serverID, Revision: rev, Observations: make([]Observation, 0, len(observed))}
	for _, obs := range observed {
		prior := base.byKey[obs.Key] // nil ⇒ unknown tool
		class, diffs := Classify(prior, obs)
		elig := dispositionFor(class, prior)
		rec := *obs
		rec.Eligibility = elig
		rec.Revision = rev
		if _, existed := next.byKey[obs.Key]; !existed {
			if len(next.byKey) >= c.lim.MaxCatalogEntries() {
				return nil, nil, mcperr.New(mcperr.ReasonCapacityExceeded, "catalog.ingest", "catalog entry capacity reached")
			}
		}
		next.byKey[obs.Key] = &rec
		report.Observations = append(report.Observations, Observation{Key: obs.Key, Class: class, Diffs: diffs, Eligibility: elig})
	}
	sort.Slice(report.Observations, func(i, j int) bool {
		return report.Observations[i].Key.Name < report.Observations[j].Key.Name
	})
	return next, report, nil
}

// DisableServer marks every catalog entry behind serverID unusable
// (ServerDisabled) in a single new snapshot. It is the catalog side of a
// server-identity change: called after registry.VerifyIdentity reports a
// mismatch, it makes the whole server's tools unusable atomically — no partial
// mutation, and the mismatch is never expressible as per-tool drift. It is a
// no-op (no new revision) if nothing changes.
func (c *Catalog) DisableServer(serverID registry.ServerID) *Snapshot {
	for attempt := 0; attempt < maxPublishRetries; attempt++ {
		base := c.cur.Load()
		var touched bool
		rev := base.revision + 1
		next := base.clone(rev)
		for key, rec := range next.byKey {
			if key.Server != serverID || rec.Eligibility == ServerDisabled {
				continue
			}
			updated := *rec
			updated.Eligibility = ServerDisabled
			updated.Revision = rev
			next.byKey[key] = &updated
			touched = true
		}
		if !touched {
			return base
		}
		if c.cur.CompareAndSwap(base, next) {
			return next
		}
	}
	return c.cur.Load()
}

// dispositionFor maps a drift class to an eligibility, applying the sticky-
// quarantine floor: once a tool is Quarantined, a later safe-narrowing /
// review / no-material-change observation keeps it Quarantined — only a (future)
// human approval clears it, and only a server-identity change (ServerDisabled)
// overrides it. No mapping ever yields Usable.
func dispositionFor(class DriftClass, prior *ToolRecord) Eligibility {
	switch class {
	case UnknownTool, PrivilegeExpansion:
		return Quarantined
	case IdentityChange:
		return ServerDisabled
	case NoMaterialChange:
		if prior != nil {
			return prior.Eligibility // preserve prior state exactly
		}
		return Quarantined
	case SemanticDrift:
		return stickyFloor(prior, ReviewRequired)
	case SafeNarrowing:
		return stickyFloor(prior, PendingNarrowing)
	default:
		return Quarantined
	}
}

// stickyFloor keeps a prior Quarantined state rather than downgrading severity on
// a less-severe observation.
func stickyFloor(prior *ToolRecord, proposed Eligibility) Eligibility {
	if prior != nil && prior.Eligibility == Quarantined {
		return Quarantined
	}
	return proposed
}

// clone returns a shallow copy of the snapshot map stamped with a new revision.
// Record pointers are shared because records are never mutated in place.
func (s *Snapshot) clone(rev uint64) *Snapshot {
	byKey := make(map[ToolKey]*ToolRecord, len(s.byKey)+1)
	for k, v := range s.byKey {
		byKey[k] = v
	}
	return &Snapshot{revision: rev, byKey: byKey}
}
