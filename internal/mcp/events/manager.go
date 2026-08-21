package events

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/denial"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/events/state"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/secret"
)

// ManagerConfig constructs a Manager. DataDir is the durable root; each capability
// gets an isolated subdirectory (DataDir/gateway, DataDir/management) so the two
// spools never alias. KEK is the mandatory encryption provider (a nil KEK fails
// closed). Backend and Clock are test seams (nil ⇒ real OS backend / time.Now).
type ManagerConfig struct {
	NodeID           string
	DataDir          string
	KEK              *secret.Provider
	GatewayLimits    limits.EventLimits
	ManagementLimits limits.EventLimits
	Backend          spool.Backend
	Clock            func() time.Time
}

// Manager is the composition root. It holds one fully isolated domain per MCP
// capability and routes every operation by capability, so no shared mutable state
// couples Gateway and Management.
type Manager struct {
	nodeID  string
	clock   func() time.Time
	domains map[model.Capability]*domain
}

// domain is one capability's isolated durability stack.
type domain struct {
	capNS model.Capability
	lim   limits.EventLimits
	spool *spool.Spool
	agg   *denial.Aggregator
	state *state.Machine

	// pending critical backlog (criterion-4 input). Commit is synchronous, so this
	// rises only for the duration of an in-flight commit and is ~0 at rest.
	pendingCrit atomic.Int64

	// safe health counters.
	commitOK      atomic.Uint64
	commitFail    atomic.Uint64
	denialAgg     atomic.Uint64
	ordinaryLoss  atomic.Uint64
	recoveryTries atomic.Uint64
	recoveryOK    atomic.Uint64

	mu     sync.Mutex // guards the denial flush / probe sequencing per domain
	closed bool
}

// NewManager builds and opens both capability domains, recovering durable state
// and reconstructing each degraded-state machine. Any per-domain open/recover
// error is returned; a partially constructed manager is never returned.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.NodeID == "" {
		return nil, mgrErr(mcperr.ReasonEventInvalid, "empty node id")
	}
	if cfg.DataDir == "" {
		return nil, mgrErr(mcperr.ReasonEventInvalid, "empty data dir")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	m := &Manager{nodeID: cfg.NodeID, clock: clock, domains: map[model.Capability]*domain{}}

	specs := []struct {
		capNS model.Capability
		sub   string
		lim   limits.EventLimits
	}{
		{model.CapGateway, "gateway", cfg.GatewayLimits},
		{model.CapManagement, "management", cfg.ManagementLimits},
	}
	for i := range specs {
		sp := &specs[i] // pointer: the value carries an EventLimits (avoid a per-iter copy)
		root := filepath.Join(cfg.DataDir, sp.sub)
		spl, err := spool.New(spool.Config{
			Root: root, Capability: sp.capNS, NodeID: cfg.NodeID,
			Limits: sp.lim, KEK: cfg.KEK, Backend: cfg.Backend, Clock: clock,
		})
		if err != nil {
			return nil, err
		}
		rep, rerr := spl.Recover()
		if rerr != nil {
			return nil, rerr
		}
		st := state.New(state.Config{
			Capability: sp.capNS, NodeID: cfg.NodeID,
			Persist: state.NewFilePersist(filepath.Join(root, "degraded_state.json")),
			Clock:   clock,
		})
		if err := st.Load(); err != nil {
			return nil, err
		}
		// If spool recovery found corruption, fail the affected domain toward the
		// narrow critical state (never normal).
		if rep.Corrupt {
			_ = st.OnCriticalCommitFailure(spl.DomainID(model.PartCrit), "recovery detected spool corruption: "+rep.CorruptReason)
		}
		agg := denial.NewAggregator(denial.Config{
			Capability: sp.capNS, NodeID: cfg.NodeID, Window: sp.lim.AggregationWindow(),
			MaxBuckets: sp.lim.MaxDenialBuckets(), MaxPerSource: sp.lim.MaxBucketsPerSource(),
			IDGen: randID,
		})
		m.domains[sp.capNS] = &domain{capNS: sp.capNS, lim: sp.lim, spool: spl, agg: agg, state: st}
	}
	return m, nil
}

func mgrErr(r mcperr.Reason, detail string) error {
	return mcperr.New(r, "events.manager", detail)
}

// domainFor returns the isolated domain for a capability.
func (m *Manager) domainFor(capNS model.Capability) (*domain, error) {
	d, ok := m.domains[capNS]
	if !ok {
		return nil, mgrErr(mcperr.ReasonEventInvalid, "unknown capability")
	}
	return d, nil
}

// WriteAllowedCritical reports whether the given capability's critical track is
// normal (not degraded/recovering). The runtime consults this to fail a critical
// operation closed while its domain is degraded.
func (m *Manager) WriteAllowedCritical(capNS model.Capability) bool {
	d, err := m.domainFor(capNS)
	if err != nil {
		return false
	}
	return d.state.WriteAllowedCritical()
}

// Spool exposes the capability spool for the export foundation (read-only reads /
// export ack). It returns nil for an unknown capability.
func (m *Manager) Spool(capNS model.Capability) *spool.Spool {
	d, ok := m.domains[capNS]
	if !ok {
		return nil
	}
	return d.spool
}

// Close stops accepting work and drains bounded pending state. It flushes any open
// denial aggregates (best-effort) so their evidence is not lost on a clean stop.
func (m *Manager) Close() error {
	for _, d := range m.domains {
		d.mu.Lock()
		d.closed = true
		d.mu.Unlock()
		// Best-effort final denial flush at shutdown.
		for _, e := range d.agg.Flush(m.clock(), true) {
			ev := e
			_, _ = d.spool.Commit(ev) //nolint:errcheck // shutdown best-effort; loss is counted on failure elsewhere
		}
	}
	return nil
}
